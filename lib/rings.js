import { randomBytes, createHash, createHmac, timingSafeEqual } from "node:crypto";

export const VOUCHER_TTL_MS = 24 * 60 * 60 * 1000; // 一次性激活凭证有效期 24 小时
export const VERIFY_WINDOW_MS = 5 * 60 * 1000;    // 校验请求允许的时钟偏差 ±5 分钟
const NONCE_RETENTION_MS = VERIFY_WINDOW_MS * 2;  // nonce 仅保留一个窗口多一点
const MAX_VERIFICATIONS = 5000;

export class DomainError extends Error {
  constructor(code, status = 400, extra = {}) {
    super(code);
    this.code = code;
    this.status = status;
    Object.assign(this, extra);
  }
}

export const randomToken = (bytes = 32) => randomBytes(bytes).toString("hex");
export const sha256 = (text) => createHash("sha256").update(text).digest("hex");
export const hmacSha256Hex = (key, message) => createHmac("sha256", key).update(message).digest("hex");

// 签名原文（设备端/校验端必须逐字节一致）：deviceId|loft|timestamp|nonce|pigeonRingNo
export function signMessage({ deviceId, loft, timestamp, nonce, pigeonRingNo }) {
  return [deviceId, loft, timestamp, nonce, pigeonRingNo].join("|");
}

export function sign(key, fields) {
  return hmacSha256Hex(key, signMessage(fields));
}

function equalLengthHex(a, b) {
  const bufA = Buffer.from(String(a), "hex");
  const bufB = Buffer.from(String(b), "hex");
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
}

export function initialRingsState() {
  return { devices: [], verifications: [] };
}

export class RingsService {
  // store: JsonStore；getPigeon: (ringNo) => pigeon | undefined
  constructor(store, { clock = () => Date.now(), getPigeon } = {}) {
    this.store = store;
    this.clock = clock;
    this.getPigeon = getPigeon || (() => undefined);
  }

  #now() { return this.clock(); }

  #findDeviceLocked(state, id) {
    return state.devices.find(d => d.deviceId === id);
  }

  // ---------- 管理员：发放电子环 + 一次性激活凭证 ----------
  issue({ ringCode, pigeonRingNo, issuedBy = "admin", voucherTtlMs = VOUCHER_TTL_MS }) {
    if (!ringCode || !pigeonRingNo) throw new DomainError("missing_fields", 400);
    return this.store.mutate(async state => {
      const pigeon = this.getPigeon(pigeonRingNo);
      if (!pigeon) throw new DomainError("pigeon_not_found", 404);
      if (state.devices.some(d => d.ringCode === ringCode)) throw new DomainError("ring_code_exists", 409);
      // 同一鸽只能绑定一次：已有（或曾有）电子环都不能再发。
      if (state.devices.some(d => d.pigeonRingNo === pigeonRingNo)) {
        throw new DomainError("pigeon_already_bound", 409);
      }
      const now = this.#now();
      const voucher = randomToken(20);
      const device = {
        deviceId: `EID-${randomBytes(6).toString("hex").toUpperCase()}`,
        ringCode,
        pigeonRingNo,
        loftAtIssue: pigeon.loft || "",
        status: "issued", // issued -> active -> lost/damaged/revoked（终态不可逆）
        voucherHash: sha256(voucher),
        voucherExpiresAt: now + voucherTtlMs,
        activatedAt: null,
        activatedBy: null,
        loft: null,
        keyVersion: 0,
        serverKey: null,
        keyFingerprint: null,
        issuedAt: now,
        issuedBy,
        events: [{ at: now, type: "issued", by: issuedBy, detail: { ringCode, pigeonRingNo } }],
        nonces: [] // [{ nonce, at }]
      };
      state.devices.unshift(device);
      // 明文凭证只返回这一次，磁盘上只有哈希。
      return { device: this.publicDevice(device), voucher, voucherExpiresAt: device.voucherExpiresAt };
    });
  }

  // ---------- 棚管员：激活本棚设备 ----------
  activate({ voucher, loft, keeper }) {
    if (!voucher || !loft || !keeper) throw new DomainError("missing_fields", 400);
    return this.store.mutate(async state => {
      const hash = sha256(voucher);
      const device = state.devices.find(d => d.voucherHash === hash);
      if (!device || device.voucherHash !== hash) throw new DomainError("invalid_voucher", 401);
      if (device.status !== "issued") throw new DomainError("voucher_already_used", 409);
      if (this.#now() > device.voucherExpiresAt) throw new DomainError("voucher_expired", 410);
      // 棚管员只能激活本棚设备：激活棚必须与建档棚一致。
      if (device.loftAtIssue !== loft) {
        throw new DomainError("cross_loft_activation_denied", 403, { deviceLoft: device.loftAtIssue, requestLoft: loft });
      }
      // 同一鸽只能绑定一次（发环时拦一道，激活时再兜底）。
      const pigeon = this.getPigeon(device.pigeonRingNo);
      if (!pigeon) throw new DomainError("pigeon_not_found", 404);
      if (state.devices.some(d => d !== device && d.pigeonRingNo === device.pigeonRingNo &&
        (d.status === "active" || d.activatedAt !== null))) {
        throw new DomainError("pigeon_already_bound", 409);
      }
      const now = this.#now();
      const key = randomToken(32);
      device.status = "active";
      device.activatedAt = now;
      device.activatedBy = keeper;
      device.loft = loft;
      device.keyVersion = 1;
      // HMAC 为对称密码：登记站作为可信校验方留存当前密钥才能验签；
      // 设备端在激活/轮换响应里拿到同一把密钥。对外视图永不返回该字段。
      device.serverKey = key;
      device.keyFingerprint = sha256(key);
      device.events.push({ at: now, type: "activated", by: keeper, detail: { loft } });
      // 一次性凭证立即作废旧凭证哈希不能再通过校验：删除哈希引用。
      device.voucherHash = null;
      device.voucherExpiresAt = null;
      // 初始设备密钥只在激活响应里明文返回这一次。
      return { device: this.publicDevice(device), deviceKey: key, keyVersion: 1 };
    });
  }

  // ---------- 激活后轮换密钥（旧密钥立即失效）----------
  // expectedVersion：客户端必须携带自己看到的当前密钥版本；
  // 并发重复轮换时只有携带匹配版本的那一个成功，其余 409。
  rotate({ deviceId, loft, keeper, role, expectedVersion }) {
    return this.store.mutate(async state => {
      const device = this.#findDeviceLocked(state, deviceId);
      if (!device) throw new DomainError("device_not_found", 404);
      if (device.status !== "active") throw new DomainError("device_not_active", 409);
      if (role !== "admin" && device.loft !== loft) throw new DomainError("cross_loft_denied", 403);
      if (expectedVersion !== undefined && Number(expectedVersion) !== device.keyVersion) {
        throw new DomainError("version_conflict", 409, { currentVersion: device.keyVersion });
      }
      const now = this.#now();
      const key = randomToken(32);
      device.keyVersion += 1;
      device.serverKey = key;
      device.keyFingerprint = sha256(key); // 旧密钥立即不再留存，旧签名立刻验不过
      device.events.push({ at: now, type: "rotated", by: keeper || role, detail: { keyVersion: device.keyVersion } });
      return { device: this.publicDevice(device), deviceKey: key, keyVersion: device.keyVersion };
    });
  }

  // ---------- 丢失 / 损坏（本棚棚管员）或管理员撤销：立即失效 ----------
  mark({ deviceId, reason, loft, keeper, role }) {
    const r = reason === "damaged" ? "damaged" : "lost";
    return this.store.mutate(async state => {
      const device = this.#findDeviceLocked(state, deviceId);
      if (!device) throw new DomainError("device_not_found", 404);
      if (device.status !== "active") throw new DomainError("device_not_active", 409);
      if (role !== "admin" && device.loft !== loft) throw new DomainError("cross_loft_denied", 403);
      const now = this.#now();
      device.status = r;
      device.serverKey = null; // 密钥立刻注销
      device.keyFingerprint = null;
      device.nonces = [];
      device.markedAt = now;
      device.events.push({ at: now, type: r, by: keeper || role || "keeper", detail: {} });
      return { device: this.publicDevice(device) };
    });
  }

  revoke({ deviceId, by = "admin" }) {
    return this.store.mutate(async state => {
      const device = this.#findDeviceLocked(state, deviceId);
      if (!device) throw new DomainError("device_not_found", 404);
      if (device.status === "revoked") throw new DomainError("already_revoked", 409);
      const now = this.#now();
      const from = device.status;
      device.status = "revoked";
      device.serverKey = null;
      device.keyFingerprint = null;
      device.nonces = [];
      device.revokedAt = now;
      device.events.push({ at: now, type: "revoked", by, detail: { from } });
      return { device: this.publicDevice(device) };
    });
  }

  // ---------- 校验：验签 + 有效期 + 随机数 + 跨棚/重放 ----------
  verify(input) {
    const { deviceId, loft, timestamp, nonce, pigeonRingNo, signature } = input;
    // 注意：拒绝也必须留下审计记录。事务内只产出结论并落盘，提交后再抛错，
    // 否则抛错回滚会把拒绝记录一起吞掉。
    return this.store.mutate(async state => {
      const now = this.#now();
      const device = this.#findDeviceLocked(state, deviceId);
      const reject = (code, status = 401) => ({
        failure: { code, status, record: this.#record({
          deviceId, loft, timestamp, nonce, pigeonRingNo, ok: false, code, now
        }) }
      });
      let verdict;
      if (!device) verdict = reject("device_not_found", 404);
      else if (device.status !== "active" || !device.serverKey) verdict = reject("device_inactive", 403);
      // 跨棚请求拒绝：校验棚必须是设备绑定棚。
      else if (!loft || device.loft !== loft) verdict = reject("cross_loft_denied", 403);
      else if (device.pigeonRingNo !== pigeonRingNo) verdict = reject("pigeon_mismatch", 409);
      else {
        // 有效期：时间戳必须落在 ±5 分钟窗口。
        const ts = Number(timestamp);
        if (!Number.isFinite(ts)) verdict = reject("bad_timestamp", 400);
        else if (Math.abs(now - ts) > VERIFY_WINDOW_MS) verdict = reject("timestamp_expired", 401);
        else if (!nonce || typeof nonce !== "string") verdict = reject("bad_nonce", 400);
        else {
          // 重放拒绝：同一设备同一 nonce 只能成功一次（先验签，避免恶意方用伪造请求烧 nonce）。
          const expected = sign(device.serverKey, { deviceId, loft, timestamp: ts, nonce, pigeonRingNo });
          if (!signature || !equalLengthHex(signature, expected)) verdict = reject("bad_signature", 401);
          else if (device.nonces.some(n => n.nonce === nonce)) verdict = reject("replay_detected", 409);
          else {
            device.nonces.push({ nonce, at: now });
            verdict = {
              success: {
                ok: true,
                verificationId: null,
                deviceId,
                pigeonRingNo,
                loft,
                keyVersion: device.keyVersion,
                status: device.status
              },
              record: this.#record({
                deviceId, loft, timestamp: ts, nonce, pigeonRingNo, ok: true, code: "ok", now,
                keyVersion: device.keyVersion
              })
            };
          }
        }
      }
      // 无论通过还是拒绝，审计记录都在本事务内落盘。
      state.verifications.unshift(verdict.record || verdict.failure.record);
      prune(state, now);
      return verdict;
    }).then(verdict => {
      if (verdict.failure) {
        throw new DomainError(verdict.failure.code, verdict.failure.status, {
          verificationId: verdict.failure.record.verificationId
        });
      }
      return { ...verdict.success, verificationId: verdict.record.verificationId };
    });
  }

  #record({ deviceId, loft, timestamp, nonce, pigeonRingNo, ok, code, now, keyVersion = null }) {
    return {
      verificationId: `VFY-${randomBytes(8).toString("hex")}`,
      at: now,
      deviceId: deviceId || null,
      pigeonRingNo: pigeonRingNo || null,
      loft: loft || null,
      timestamp: Number(timestamp) || null,
      nonce: nonce || null,
      keyVersion,
      ok,
      code
    };
  }

  // ---------- 查询 ----------
  async listDevices({ loft, role } = {}) {
    const state = await this.store.read();
    let devices = state.devices;
    if (role !== "admin") devices = devices.filter(d => d.loft === loft || d.status === "issued" && d.loftAtIssue === loft);
    return devices.map(d => this.publicDevice(d));
  }

  async getDevice(deviceId, { loft, role } = {}) {
    const state = await this.store.read();
    const device = this.#findDeviceLocked(state, deviceId);
    if (!device) throw new DomainError("device_not_found", 404);
    if (role !== "admin" && device.loft !== loft && device.loftAtIssue !== loft) {
      throw new DomainError("cross_loft_denied", 403);
    }
    return this.publicDevice(device);
  }

  async listVerifications({ deviceId, loft, role } = {}) {
    const state = await this.store.read();
    return state.verifications
      .filter(v => !deviceId || v.deviceId === deviceId)
      .filter(v => role === "admin" || v.loft === loft)
      .slice(0, 200);
  }

  // 对外视图：绝不泄露凭证哈希/密钥/nonce。
  publicDevice(d) {
    return {
      deviceId: d.deviceId,
      ringCode: d.ringCode,
      pigeonRingNo: d.pigeonRingNo,
      loftAtIssue: d.loftAtIssue,
      status: d.status,
      loft: d.loft,
      keyVersion: d.keyVersion,
      keyFingerprint: d.keyFingerprint ? d.keyFingerprint.slice(0, 12) : null,
      issuedAt: d.issuedAt,
      activatedAt: d.activatedAt,
      voucherExpiresAt: d.voucherExpiresAt,
      markedAt: d.markedAt || null,
      revokedAt: d.revokedAt || null,
      events: d.events
    };
  }
}

function prune(state, now) {
  for (const d of state.devices) {
    if (d.nonces && d.nonces.length) {
      d.nonces = d.nonces.filter(n => now - n.at <= NONCE_RETENTION_MS);
    }
  }
  if (state.verifications.length > MAX_VERIFICATIONS) {
    state.verifications.length = MAX_VERIFICATIONS;
  }
}
