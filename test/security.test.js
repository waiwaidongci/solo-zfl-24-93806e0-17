import { test } from "node:test";
import assert from "node:assert/strict";
import { rm, mkdtemp, readFile, writeFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { JsonStore } from "../lib/store.js";
import { KeyManager } from "../lib/keystore.js";
import { RingsService, initialRingsState, sign } from "../lib/rings.js";

const PIGEONS = [
  { ringNo: "P-001", loft: "北岸A棚", owner: "北岸棚" },
  { ringNo: "P-002", loft: "种鸽棚", owner: "育种棚" }
];

async function makeHarness({ masterEnv } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "rings-sec-"));
  const km = await KeyManager.create({ dataDir: dir, env: masterEnv ? { RING_MASTER_KEY: masterEnv } : {} });
  const store = new JsonStore(join(dir, "rings.json"), initialRingsState(), {
    serialize: (s) => km.serialize(s),
    deserialize: (d) => km.deserialize(d)
  });
  const svc = new RingsService(store, { getPigeon: (r) => PIGEONS.find(p => p.ringNo === r) });
  return {
    dir, km, store, svc,
    async rawDisk() { return readFile(store.file, "utf8"); },
    async parsedDisk() { return JSON.parse(await readFile(store.file, "utf8")); },
    async cleanup() { await rm(dir, { recursive: true, force: true }); }
  };
}

async function issueActivate(h, ringCode = "ES-1", pigeon = "P-001", loft = "北岸A棚") {
  const issued = await h.svc.issue({ ringCode, pigeonRingNo: pigeon });
  const act = await h.svc.activate({ voucher: issued.voucher, loft, keeper: "k" });
  return { ...act, deviceId: act.device.deviceId };
}

test("KeyManager：AES-GCM 信封加解密往返，每次 IV 随机，篡改即失败", async () => {
  const km = new KeyManager(randomBytes(32));
  const a = km.encrypt("hello-secret");
  const b = km.encrypt("hello-secret");
  assert.equal(a.v, 1);
  assert.notEqual(a.iv, b.iv, "IV 必须随机");
  assert.equal(km.decrypt(a), "hello-secret");
  assert.throws(() => km.decrypt({ ...a, tag: "00".repeat(16) }), /auth/);
  const tampered = { ...a, data: Buffer.from("xx").toString("hex") };
  assert.throws(() => km.decrypt(tampered));
});

test("密钥绝不明文落盘：磁盘只有 GCM 信封，内存可验签", async () => {
  const h = await makeHarness();
  try {
    const { deviceId, deviceKey } = await issueActivate(h);
    const raw = await h.rawDisk();
    assert.ok(!raw.includes(deviceKey), "设备密钥明文不得出现在磁盘文件中");
    assert.ok(!/"serverKey"\s*:/.test(raw), "磁盘不得含 serverKey 明文字段");
    const disk = await h.parsedDisk();
    const d = disk.devices.find(x => x.deviceId === deviceId);
    assert.ok(d.serverKeyEnc && d.serverKeyEnc.v === 1, "必须落加密信封");
    assert.equal(d.serverKeyEnc.data.length, deviceKey.length * 2);
    assert.ok(!("serverKey" in d));
    // 内存态是明文，验签正常
    const mem = await h.store.read();
    assert.equal(mem.devices[0].serverKey, deviceKey);
    const fields = { deviceId, loft: "北岸A棚", timestamp: Date.now(), nonce: "s1", pigeonRingNo: "P-001" };
    assert.equal((await h.svc.verify({ ...fields, signature: sign(deviceKey, fields) })).ok, true);
  } finally { await h.cleanup(); }
});

test("轮换与撤销后磁盘仍不含任何明文密钥", async () => {
  const h = await makeHarness();
  try {
    const { deviceId, deviceKey } = await issueActivate(h);
    const rot = await h.svc.rotate({ deviceId, loft: "北岸A棚", keeper: "k", role: "keeper", expectedVersion: 1 });
    const rawAfterRotate = await h.rawDisk();
    assert.ok(!rawAfterRotate.includes(deviceKey), "旧密钥不得残留");
    assert.ok(!rawAfterRotate.includes(rot.deviceKey), "新密钥同样只能以密文落盘");

    await h.svc.revoke({ deviceId });
    const disk = await h.parsedDisk();
    const d = disk.devices.find(x => x.deviceId === deviceId);
    assert.equal(d.serverKeyEnc, null, "撤销后信封清空");
    assert.ok(!("serverKey" in d));
  } finally { await h.cleanup(); }
});

test("轮换：缺版本号 → 400 missing_version；旧版本 → 409 version_conflict", async () => {
  const h = await makeHarness();
  try {
    const { deviceId, deviceKey } = await issueActivate(h);
    // 缺字段
    await assert.rejects(
      h.svc.rotate({ deviceId, loft: "北岸A棚", keeper: "k", role: "keeper" }),
      e => e.code === "missing_version" && e.status === 400
    );
    // null / 非整数
    for (const bad of [null, "abc", 1.5]) {
      await assert.rejects(
        h.svc.rotate({ deviceId, loft: "北岸A棚", keeper: "k", role: "keeper", expectedVersion: bad }),
        e => e.code === "missing_version"
      );
    }
    // 旧版本号
    await assert.rejects(
      h.svc.rotate({ deviceId, loft: "北岸A棚", keeper: "k", role: "keeper", expectedVersion: 0 }),
      e => e.code === "version_conflict" && e.status === 409
    );
    // 被拒后密钥版本未前进、旧密钥仍可校验（没有副作用）
    const state = await h.store.read();
    assert.equal(state.devices[0].keyVersion, 1);
    const fields = { deviceId, loft: "北岸A棚", timestamp: Date.now(), nonce: "sv1", pigeonRingNo: "P-001" };
    assert.equal((await h.svc.verify({ ...fields, signature: sign(deviceKey, fields) })).ok, true);
    // 正确版本号成功一次；之后同版本立即变旧
    const rot = await h.svc.rotate({ deviceId, loft: "北岸A棚", keeper: "k", role: "keeper", expectedVersion: 1 });
    assert.equal(rot.keyVersion, 2);
    await assert.rejects(
      h.svc.rotate({ deviceId, loft: "北岸A棚", keeper: "k", role: "keeper", expectedVersion: 1 }),
      e => e.code === "version_conflict"
    );
  } finally { await h.cleanup(); }
});

test("并发轮换同一版本：只有一次成功，其余全部 version_conflict", async () => {
  const h = await makeHarness();
  try {
    const { deviceId } = await issueActivate(h);
    const results = await Promise.allSettled(
      Array.from({ length: 10 }, () =>
        h.svc.rotate({ deviceId, loft: "北岸A棚", keeper: "k", role: "keeper", expectedVersion: 1 }))
    );
    assert.equal(results.filter(r => r.status === "fulfilled").length, 1);
    assert.ok(results.filter(r => r.status === "rejected").every(r => r.reason.code === "version_conflict"));
    assert.equal((await h.store.read()).devices[0].keyVersion, 2);
  } finally { await h.cleanup(); }
});

test("旧版明文数据启动即安全升级：自动重写为密文，升级后仍能校验", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rings-legacy-"));
  try {
    // 手工构造旧版本格式（v1：serverKey 明文）。
    const legacyKey = "a".repeat(64);
    const now = Date.now();
    const legacy = {
      devices: [{
        deviceId: "EID-LEGACY01", ringCode: "LEG-1", pigeonRingNo: "P-001",
        loftAtIssue: "北岸A棚", status: "active", voucherHash: null, voucherExpiresAt: null,
        activatedAt: now - 1000, activatedBy: "k", loft: "北岸A棚",
        keyVersion: 1, serverKey: legacyKey, keyFingerprint: "fingerprint-x",
        issuedAt: now - 2000, issuedBy: "admin",
        events: [{ at: now - 2000, type: "issued", by: "admin", detail: {} }],
        nonces: []
      }],
      verifications: []
    };
    const file = join(dir, "rings.json");
    await writeFile(file, JSON.stringify(legacy, null, 2));

    // 用同一主密钥启动新存储：加载时检测到明文并立刻原子重写。
    const km = new KeyManager(randomBytes(32));
    const store = new JsonStore(file, initialRingsState(), {
      serialize: s => km.serialize(s),
      deserialize: d => km.deserialize(d)
    });
    await store.load();
    const afterBoot = await readFile(file, "utf8");
    assert.ok(!afterBoot.includes(legacyKey), "升级后明文密钥必须从磁盘消失");
    assert.ok(/"serverKeyEnc"\s*:/.test(afterBoot), "磁盘应改为密文信封");
    assert.ok(!/"serverKey"\s*:/.test(afterBoot));

    // 内存里已解密，旧设备重启后仍可正常验签
    const svc = new RingsService(store, { getPigeon: r => PIGEONS.find(p => p.ringNo === r) });
    const fields = { deviceId: "EID-LEGACY01", loft: "北岸A棚", timestamp: Date.now(), nonce: "legacy-1", pigeonRingNo: "P-001" };
    assert.equal((await svc.verify({ ...fields, signature: sign(legacyKey, fields) })).ok, true);

    // 再“重启”一次：这次走密文路径，无需迁移，重放仍拦
    await store.simulateRestart();
    const svc2 = new RingsService(store, { getPigeon: r => PIGEONS.find(p => p.ringNo === r) });
    await assert.rejects(svc2.verify({ ...fields, signature: sign(legacyKey, fields) }), e => e.code === "replay_detected");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("主密钥错误时 fail-fast：启动解密即失败，绝不静默使用乱码密钥", async () => {
  const h = await makeHarness({ masterEnv: "correct-horse-battery-staple" });
  try {
    const { deviceId, deviceKey } = await issueActivate(h);
    // 用错误主密钥新建存储打开同一份密文文件（模拟换机/错误配置）
    const wrong = new KeyManager(randomBytes(32));
    const file2 = join(h.dir, "rings-copy.json");
    await writeFile(file2, await h.rawDisk());
    const store2 = new JsonStore(file2, initialRingsState(), {
      serialize: s => wrong.serialize(s),
      deserialize: d => wrong.deserialize(d)
    });
    await assert.rejects(store2.load(), /auth|Unsupported state/);
    // 正确主密钥打开则正常且可校验
    const kmRight = await KeyManager.create({ dataDir: h.dir, env: { RING_MASTER_KEY: "correct-horse-battery-staple" } });
    const store3 = new JsonStore(join(h.dir, "rings.json"), initialRingsState(), {
      serialize: s => kmRight.serialize(s),
      deserialize: d => kmRight.deserialize(d)
    });
    await store3.simulateRestart();
    const svc3 = new RingsService(store3, { getPigeon: r => PIGEONS.find(p => p.ringNo === r) });
    const fields = { deviceId, loft: "北岸A棚", timestamp: Date.now(), nonce: "right-km", pigeonRingNo: "P-001" };
    assert.equal((await svc3.verify({ ...fields, signature: sign(deviceKey, fields) })).ok, true);
  } finally { await h.cleanup(); }
});

test("主密钥文件自动生成且权限 0600", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rings-mk-"));
  try {
    await KeyManager.create({ dataDir: dir });
    const st = await stat(join(dir, "master.key"));
    assert.equal(st.size, 32);
    assert.equal(st.mode & 0o777, 0o600);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
