import { randomBytes, createCipheriv, createDecipheriv, createHash } from "node:crypto";
import { open, chmod, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";

// 设备密钥（HMAC 对称密钥）绝不允许明文落盘：
//   内存中：serverKey 为明文，供验签使用；
//   磁盘上：serverKey 替换为 AES-256-GCM 密文信封 serverKeyEnc。
//
// 密文必须绑定「用途 + 设备标识」（GCM Additional Authenticated Data）：
//   AAD = "ring-device-hmac|v2|<deviceId>"
// 这样把甲设备的信封复制/交换到乙设备记录上，解密时 AAD 不匹配，
// GCM 认证直接失败——攻击者无法用一台设备的密钥给另一台设备的签名背书。
//
// 信封版本：
//   v2：带 AAD 的现版格式；
//   v1：早期无 AAD 信封，仅在启动加载时按旧格式解开并立刻原子重写为 v2（安全升级）；
//   v0：更早期的明文 serverKey 字段，同样启动即升级，升级后原设备仍可正常校验。
//
// 主密钥来源（优先级）：
//   1) 环境变量 RING_MASTER_KEY（32 字节 hex/base64，或任意口令经 SHA-256 派生）
//   2) 独立密钥文件 <dataDir>/master.key（首启自动生成 32 字节随机，权限 0600）
// 主密钥丢失/更换后历史密文无法解开；v2 信封被换绑到别的设备时启动 fail-fast。

export const KEY_PURPOSE = "ring-device-hmac";
export const ENVELOPE_VERSION = 2;

export class KeyEnvelopeError extends Error {
  constructor(code, message, { deviceId } = {}) {
    super(message);
    this.code = code;
    this.deviceId = deviceId;
  }
}

const aadFor = (deviceId) => Buffer.from(`${KEY_PURPOSE}|v2|${deviceId}`, "utf8");

export class KeyManager {
  constructor(masterKey) {
    if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) {
      throw new Error("master key must be a 32-byte buffer");
    }
    this.masterKey = masterKey;
  }

  static async create({ dataDir, env = process.env } = {}) {
    const fromEnv = env.RING_MASTER_KEY;
    if (fromEnv) {
      return new KeyManager(parseMasterKey(fromEnv));
    }
    const file = join(dataDir, "master.key");
    if (!existsSync(file)) {
      const key = randomBytes(32);
      const handle = await open(file, "w", 0o600);
      try {
        await handle.writeFile(key);
        await handle.sync();
      } finally {
        await handle.close();
      }
      await chmod(file, 0o600);
      return new KeyManager(key);
    }
    const raw = (await readFile(file)).subarray(0, 32);
    if (raw.length !== 32) throw new Error("master.key must contain 32 bytes");
    return new KeyManager(raw);
  }

  #seal(plaintext, { deviceId, version, aad }) {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.masterKey, iv, aad ? { authTagLength: 16 } : undefined);
    if (aad) cipher.setAAD(aad, { plaintextLength: Buffer.byteLength(String(plaintext)) });
    const data = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
    return { v: version, iv: iv.toString("hex"), tag: cipher.getAuthTag().toString("hex"), data: data.toString("hex") };
  }

  #open(envelope, { deviceId, aad }) {
    const iv = Buffer.from(envelope.iv, "hex");
    const tag = Buffer.from(envelope.tag, "hex");
    const data = Buffer.from(envelope.data, "hex");
    const decipher = createDecipheriv("aes-256-gcm", this.masterKey, iv, aad ? { authTagLength: 16 } : undefined);
    if (aad) decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
  }

  // 现版加密：信封绑定设备（v2，带 AAD）。
  encrypt(deviceId, plaintext) {
    if (!deviceId) throw new Error("encrypt requires deviceId for AAD binding");
    if (plaintext == null) return null;
    return this.#seal(plaintext, { deviceId, version: ENVELOPE_VERSION, aad: aadFor(deviceId) });
  }

  // 现版解密：必须通过 AAD 校验，信封换绑设备即认证失败。
  decrypt(deviceId, envelope) {
    if (!envelope) return null;
    if (envelope.v === ENVELOPE_VERSION) {
      try {
        return this.#open(envelope, { deviceId, aad: aadFor(deviceId) });
      } catch (error) {
        throw new KeyEnvelopeError(
          "key_envelope_mismatch",
          `设备 ${deviceId} 的密钥信封认证失败（疑似跨设备替换或主密钥不符）`,
          { deviceId }
        );
      }
    }
    if (envelope.v === 1) {
      // 旧信封无 AAD：仅允许在启动升级路径使用，不能当作现版解密结果直接信任。
      return this.#openLegacy(envelope, deviceId);
    }
    throw new KeyEnvelopeError("bad_key_envelope", `不支持的密钥信封版本: ${envelope.v}`, { deviceId });
  }

  // v1（无 AAD）旧信封：能解开即视为合法旧数据，调用方据此触发升级重写为 v2。
  #openLegacy(envelope, deviceId) {
    try {
      return this.#open(envelope, { deviceId, aad: undefined });
    } catch (error) {
      throw new KeyEnvelopeError("key_envelope_corrupt", `设备 ${deviceId} 的旧密钥信封损坏`, { deviceId });
    }
  }

  // 仅供测试/数据迁移工具构造历史 v1（无 AAD）信封。
  sealLegacyV1(plaintext) {
    return this.#seal(plaintext, { deviceId: null, version: 1, aad: undefined });
  }

  // 落盘视图：内存明文 serverKey → 绑定设备的 v2 密文信封，明文不进入序列化文本。
  serialize(state) {
    const onDisk = structuredClone(state);
    for (const d of onDisk.devices) {
      if (Object.prototype.hasOwnProperty.call(d, "serverKey")) {
        d.serverKeyEnc = d.serverKey ? this.encrypt(d.deviceId, d.serverKey) : null;
        delete d.serverKey;
      }
    }
    return onDisk;
  }

  // 加载视图：密文信封 → 内存明文；检测旧格式（v0 明文 / v1 无 AAD 信封）并标记 migrated，
  // 由存储层在同次启动内原子重写为 v2。v2 信封跨设备替换会在此 fail-fast。
  deserialize(onDisk) {
    let migrated = false;
    const state = structuredClone(onDisk);
    for (const d of state.devices || []) {
      if (d.serverKeyEnc) {
        if (d.serverKeyEnc.v === 1) {
          d.serverKey = this.#openLegacy(d.serverKeyEnc, d.deviceId);
          migrated = true;
          delete d.serverKeyEnc;
        } else {
          // v2：带设备绑定 AAD 解密；换绑设备/篡改密文在此抛错拒绝启动。
          d.serverKey = this.decrypt(d.deviceId, d.serverKeyEnc);
          delete d.serverKeyEnc;
        }
      } else if (Object.prototype.hasOwnProperty.call(d, "serverKey")) {
        // v0：明文旧数据，加载后立即升级重写。
        migrated = true;
      }
    }
    return { state, migrated };
  }
}

function parseMasterKey(raw) {
  if (/^[0-9a-fA-F]{64}$/.test(raw)) return Buffer.from(raw, "hex");
  const b64 = Buffer.from(raw, "base64");
  if (b64.length === 32 && Buffer.from(b64.toString("base64"), "base64").equals(b64)) return b64;
  // 任意口令：SHA-256 派生 32 字节
  return createHash("sha256").update(raw, "utf8").digest();
}
