import { randomBytes, createCipheriv, createDecipheriv, createHash } from "node:crypto";
import { open, chmod, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";

// 设备密钥（HMAC 对称密钥）绝不允许明文落盘：
//   内存中：serverKey 为明文，供验签使用；
//   磁盘上：serverKey 替换为 AES-256-GCM 密文信封 serverKeyEnc。
// 主密钥来源（优先级）：
//   1) 环境变量 RING_MASTER_KEY（32 字节 hex/base64，或任意口令经 SHA-256 派生）
//   2) 独立密钥文件 <dataDir>/master.key（首启自动生成 32 字节随机，权限 0600）
// 主密钥丢失/更换后历史密文无法解开，设备需重新激活——这是加密落盘的固有代价。

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

  // 返回磁盘信封：{ v:1, iv, tag, data }（全部 hex）
  encrypt(plaintext) {
    if (plaintext == null) return null;
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.masterKey, iv);
    const data = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { v: 1, iv: iv.toString("hex"), tag: tag.toString("hex"), data: data.toString("hex") };
  }

  decrypt(envelope) {
    if (!envelope || envelope.v !== 1) throw new Error("bad_key_envelope");
    const iv = Buffer.from(envelope.iv, "hex");
    const tag = Buffer.from(envelope.tag, "hex");
    const data = Buffer.from(envelope.data, "hex");
    const decipher = createDecipheriv("aes-256-gcm", this.masterKey, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
  }

  // ---- rings 状态的落盘/加载变换 ----
  // 落盘视图：内存明文 serverKey → 密文信封 serverKeyEnc，不把明文写进序列化文本。
  serialize(state) {
    const onDisk = structuredClone(state);
    for (const d of onDisk.devices) {
      if (Object.prototype.hasOwnProperty.call(d, "serverKey")) {
        d.serverKeyEnc = d.serverKey ? this.encrypt(d.serverKey) : null;
        delete d.serverKey;
      }
    }
    return onDisk;
  }

  // 加载：密文信封 → 内存明文；同时对旧版本数据做安全升级——
  // 旧版本把 serverKey 明文直接存在 JSON 里，读到后解密为内存明文，
  // 并返回 migrated=true 触发立刻重写为加密格式（明文从此不再在磁盘留存）。
  deserialize(onDisk) {
    let migrated = false;
    const state = structuredClone(onDisk);
    for (const d of state.devices || []) {
      if (d.serverKeyEnc) {
        d.serverKey = d.serverKeyEnc.data ? this.decrypt(d.serverKeyEnc) : null;
        delete d.serverKeyEnc;
      } else if (Object.prototype.hasOwnProperty.call(d, "serverKey")) {
        // 旧版明文数据：升级标记（内存里保留明文供本次运行验签）。
        migrated = true;
      }
    }
    return { state, migrated };
  }
}

function parseMasterKey(raw) {
  const hex = Buffer.from(raw, "hex");
  if (/^[0-9a-fA-F]{64}$/.test(raw)) return hex;
  const b64 = Buffer.from(raw, "base64");
  if (b64.length === 32 && Buffer.from(b64.toString("base64"), "base64").equals(b64)) return b64;
  // 任意口令：SHA-256 派生 32 字节
  return createHash("sha256").update(raw, "utf8").digest();
}
