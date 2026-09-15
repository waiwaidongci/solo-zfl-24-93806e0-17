import { test } from "node:test";
import assert from "node:assert/strict";
import { rm, mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JsonStore } from "../lib/store.js";
import {
  RingsService, initialRingsState, sign, DomainError,
  VOUCHER_TTL_MS, VERIFY_WINDOW_MS
} from "../lib/rings.js";

const PIGEONS = [
  { ringNo: "P-001", loft: "北岸A棚", owner: "北岸棚" },
  { ringNo: "P-002", loft: "种鸽棚", owner: "育种棚" }
];

async function makeHarness(now0 = 1_000_000) {
  const dir = await mkdtemp(join(tmpdir(), "rings-"));
  let now = now0;
  const clock = () => now;
  const setClock = (t) => { now = t; };
  const store = new JsonStore(join(dir, "rings.json"), initialRingsState(), { clock });
  const svc = new RingsService(store, { clock, getPigeon: (r) => PIGEONS.find(p => p.ringNo === r) });
  return {
    dir, store, svc, clock, setClock,
    async cleanup() { await rm(dir, { recursive: true, force: true }); }
  };
}

async function issueActivate(h, { ringCode = "E-1", pigeon = "P-001", loft = "北岸A棚", keeper = "北岸A棚" } = {}) {
  const issued = await h.svc.issue({ ringCode, pigeonRingNo: pigeon });
  const activated = await h.svc.activate({ voucher: issued.voucher, loft, keeper });
  return { issued, activated, deviceId: activated.device.deviceId, key: activated.deviceKey };
}

test("全生命周期：发放→激活→校验→轮换旧密钥失效→撤销即失效", async () => {
  const h = await makeHarness();
  try {
    const { deviceId, key } = await issueActivate(h);

    const fields = { deviceId, loft: "北岸A棚", timestamp: h.clock() + 1000, nonce: "n1", pigeonRingNo: "P-001" };
    const ok = await h.svc.verify({ ...fields, signature: sign(key, fields) });
    assert.equal(ok.ok, true);

    // 轮换后旧密钥立刻失效，新密钥可用。
    const rot = await h.svc.rotate({ deviceId, loft: "北岸A棚", keeper: "k", role: "keeper", expectedVersion: 1 });
    assert.equal(rot.keyVersion, 2);
    await assert.rejects(
      h.svc.verify({ ...fields, nonce: "n2", signature: sign(key, { ...fields, nonce: "n2" }) }),
      (e) => e.code === "bad_signature"
    );
    const ok2 = await h.svc.verify({
      ...fields, nonce: "n2", timestamp: h.clock() + 2000,
      signature: sign(rot.deviceKey, { ...fields, nonce: "n2", timestamp: h.clock() + 2000 })
    });
    assert.equal(ok2.ok, true);

    // 撤销立即失效。
    await h.svc.revoke({ deviceId });
    await assert.rejects(
      h.svc.verify({
        ...fields, nonce: "n3", timestamp: h.clock() + 3000,
        signature: sign(rot.deviceKey, { ...fields, nonce: "n3", timestamp: h.clock() + 3000 })
      }),
      (e) => e.code === "device_inactive"
    );
  } finally { await h.cleanup(); }
});

test("一次性凭证：重复激活/过期凭证/错误凭证均拒绝", async () => {
  const h = await makeHarness();
  try {
    const issued = await h.svc.issue({ ringCode: "E-9", pigeonRingNo: "P-001" });
    const first = await h.svc.activate({ voucher: issued.voucher, loft: "北岸A棚", keeper: "k" });
    assert.equal(first.device.status, "active");
    // 凭证激活后即作废（voucherHash 被清除），旧凭证无法再次匹配。
    await assert.rejects(
      h.svc.activate({ voucher: issued.voucher, loft: "北岸A棚", keeper: "k2" }),
      (e) => e.code === "invalid_voucher"
    );
    // 磁盘上不应残留凭证明文或哈希。
    const raw = await readFile(h.store.file, "utf8");
    assert.ok(!raw.includes(issued.voucher));

    // 过期凭证不可激活。
    const issued2 = await h.svc.issue({ ringCode: "E-10", pigeonRingNo: "P-002" });
    h.setClock(h.clock() + VOUCHER_TTL_MS + 1);
    await assert.rejects(
      h.svc.activate({ voucher: issued2.voucher, loft: "种鸽棚", keeper: "z" }),
      (e) => e.code === "voucher_expired"
    );
    // 随便编的凭证
    await assert.rejects(
      h.svc.activate({ voucher: "deadbeef".repeat(10), loft: "种鸽棚", keeper: "z" }),
      (e) => e.code === "invalid_voucher"
    );
  } finally { await h.cleanup(); }
});

test("同一环、同一鸽只能绑定一次", async () => {
  const h = await makeHarness();
  try {
    await h.svc.issue({ ringCode: "DUP", pigeonRingNo: "P-001" });
    await assert.rejects(h.svc.issue({ ringCode: "DUP", pigeonRingNo: "P-002" }), e => e.code === "ring_code_exists");
    await assert.rejects(h.svc.issue({ ringCode: "OTHER", pigeonRingNo: "P-001" }), e => e.code === "pigeon_already_bound");
  } finally { await h.cleanup(); }
});

test("棚管员只能激活/校验本棚，跨棚请求拒绝", async () => {
  const h = await makeHarness();
  try {
    const issued = await h.svc.issue({ ringCode: "E-X", pigeonRingNo: "P-001" }); // 建档棚：北岸A棚
    await assert.rejects(
      h.svc.activate({ voucher: issued.voucher, loft: "种鸽棚", keeper: "z" }),
      (e) => e.code === "cross_loft_activation_denied"
    );
    // 被拒后本棚仍可正常激活。
    const act = await h.svc.activate({ voucher: issued.voucher, loft: "北岸A棚", keeper: "b" });
    const fields = { deviceId: act.device.deviceId, loft: "种鸽棚", timestamp: h.clock(), nonce: "x1", pigeonRingNo: "P-001" };
    await assert.rejects(
      h.svc.verify({ ...fields, signature: sign(act.deviceKey, fields) }),
      (e) => e.code === "cross_loft_denied"
    );
  } finally { await h.cleanup(); }
});

test("校验：验签/时间窗/nonce 重放/鸽只不符", async () => {
  const h = await makeHarness();
  try {
    const { deviceId, key } = await issueActivate(h);
    const base = { deviceId, loft: "北岸A棚", timestamp: h.clock(), nonce: "u1", pigeonRingNo: "P-001" };

    await h.svc.verify({ ...base, signature: sign(key, base) });
    // 重放同一 nonce
    await assert.rejects(
      h.svc.verify({ ...base, signature: sign(key, base) }),
      e => e.code === "replay_detected"
    );
    // 坏签名（且不能因坏签名请求烧掉 nonce）
    const b2 = { ...base, nonce: "u2" };
    await assert.rejects(h.svc.verify({ ...b2, signature: "0".repeat(64) }), e => e.code === "bad_signature");
    await h.svc.verify({ ...b2, signature: sign(key, b2) }); // 同 nonce 的正确签名仍可成功一次
    // 过期时间戳
    const b3 = { ...base, nonce: "u3", timestamp: h.clock() - (VERIFY_WINDOW_MS + 1) };
    await assert.rejects(h.svc.verify({ ...b3, signature: sign(key, b3) }), e => e.code === "timestamp_expired");
    // 鸽只不匹配
    const b4 = { ...base, nonce: "u4", pigeonRingNo: "P-002" };
    await assert.rejects(h.svc.verify({ ...b4, signature: sign(key, b4) }), e => e.code === "pigeon_mismatch");
    // 不存在的设备
    await assert.rejects(
      h.svc.verify({ deviceId: "EID-NOPE", loft: "北岸A棚", timestamp: h.clock(), nonce: "u9", pigeonRingNo: "P-001", signature: "a" }),
      e => e.code === "device_not_found"
    );
  } finally { await h.cleanup(); }
});

test("并发激活同一凭证只有一个成功", async () => {
  const h = await makeHarness();
  try {
    const issued = await h.svc.issue({ ringCode: "E-C1", pigeonRingNo: "P-001" });
    const results = await Promise.allSettled(
      Array.from({ length: 12 }, () => h.svc.activate({ voucher: issued.voucher, loft: "北岸A棚", keeper: "k" }))
    );
    const fulfilled = results.filter(r => r.status === "fulfilled");
    const rejected = results.filter(r => r.status === "rejected");
    assert.equal(fulfilled.length, 1);
    assert.equal(rejected.length, 11);
    assert.ok(rejected.every(r => ["invalid_voucher", "voucher_already_used"].includes(r.reason.code)));
  } finally { await h.cleanup(); }
});

test("并发轮换携带相同版本号，只有一个成功", async () => {
  const h = await makeHarness();
  try {
    const { deviceId, key } = await issueActivate(h);
    const results = await Promise.allSettled(
      Array.from({ length: 8 }, () =>
        h.svc.rotate({ deviceId, loft: "北岸A棚", keeper: "k", role: "keeper", expectedVersion: 1 }))
    );
    assert.equal(results.filter(r => r.status === "fulfilled").length, 1);
    assert.ok(results.filter(r => r.status === "rejected").every(r => r.reason.code === "version_conflict"));
    const state = await h.store.read();
    const d = state.devices.find(x => x.deviceId === deviceId);
    assert.equal(d.keyVersion, 2); // 只前进一格
    // 旧密钥确实失效
    const fields = { deviceId, loft: "北岸A棚", timestamp: h.clock(), nonce: "c", pigeonRingNo: "P-001" };
    await assert.rejects(h.svc.verify({ ...fields, signature: sign(key, fields) }), e => e.code === "bad_signature");
  } finally { await h.cleanup(); }
});

test("并发撤销/报失只有一个成功，后续操作拒绝", async () => {
  const h = await makeHarness();
  try {
    const { deviceId } = await issueActivate(h);
    const results = await Promise.allSettled([
      ...Array.from({ length: 5 }, () => h.svc.revoke({ deviceId })),
      ...Array.from({ length: 5 }, () => h.svc.mark({ deviceId, reason: "lost", loft: "北岸A棚", keeper: "k", role: "keeper" }))
    ]);
    assert.equal(results.filter(r => r.status === "fulfilled").length, 1);
    const codes = results.filter(r => r.status === "rejected").map(r => r.reason.code);
    assert.ok(codes.every(c => c === "already_revoked" || c === "device_not_active"));
    // 撤销后再轮换也拒绝
    await assert.rejects(
      h.svc.rotate({ deviceId, loft: "北岸A棚", keeper: "k", role: "keeper", expectedVersion: 1 }),
      e => e.code === "device_not_active"
    );
  } finally { await h.cleanup(); }
});

test("落盘失败：事务整体回滚，不留半条记录", async () => {
  const h = await makeHarness();
  try {
    const { deviceId, key } = await issueActivate(h);
    const before = JSON.stringify(await h.store.read());

    h.store.injectWriteFailure(1);
    // 激活后再发环：失败注入下 rotate 不得留下“版本+1但密钥未更新”等半状态。
    await assert.rejects(
      h.svc.rotate({ deviceId, loft: "北岸A棚", keeper: "k", role: "keeper", expectedVersion: 1 }),
      e => e.message === "injected_disk_failure"
    );
    const afterFail = JSON.stringify(await h.store.read());
    assert.equal(afterFail, before, "内存状态必须回滚到事务前");

    // 磁盘文件也没有被截断/写坏，且不含临时残留。
    const onDisk = JSON.parse(await readFile(h.store.file, "utf8"));
    const d = onDisk.devices.find(x => x.deviceId === deviceId);
    assert.equal(d.keyVersion, 1);
    const files = await readdir(h.dir);
    assert.ok(!files.some(f => f.includes(".tmp-")), "临时文件应已清理");

    // 故障恢复后服务继续可用，旧密钥照常校验
    const fields = { deviceId, loft: "北岸A棚", timestamp: h.clock(), nonce: "recover-1", pigeonRingNo: "P-001" };
    const ok = await h.svc.verify({ ...fields, signature: sign(key, fields) });
    assert.equal(ok.ok, true);
  } finally { await h.cleanup(); }
});

test("重启保留：设备、凭证状态、密钥、校验记录从磁盘恢复", async () => {
  const h = await makeHarness();
  try {
    const { deviceId, key } = await issueActivate(h);
    const fields = { deviceId, loft: "北岸A棚", timestamp: h.clock(), nonce: "persist-1", pigeonRingNo: "P-001" };
    await h.svc.verify({ ...fields, signature: sign(key, fields) });
    await assert.rejects(h.svc.verify({ ...fields, signature: sign(key, fields) }), e => e.code === "replay_detected");

    // 模拟进程重启：丢弃内存，重新从同一文件加载。
    await h.store.simulateRestart();
    const state = await h.store.read();
    const d = state.devices.find(x => x.deviceId === deviceId);
    assert.equal(d.status, "active");
    assert.equal(d.serverKey, key, "当前密钥必须落盘以便重启后继续验签");
    assert.equal(state.verifications.filter(v => v.ok).length, 1);
    assert.equal(state.verifications.filter(v => !v.ok).length, 1);
    // 重启后重放仍被识别
    await assert.rejects(h.svc.verify({ ...fields, signature: sign(key, fields) }), e => e.code === "replay_detected");

    // 全新服务实例 + 全新存储实例（更接近真实重启）
    const store2 = new JsonStore(h.store.file, initialRingsState(), { clock: h.clock });
    const svc2 = new RingsService(store2, { clock: h.clock, getPigeon: (r) => PIGEONS.find(p => p.ringNo === r) });
    const fields2 = { ...fields, nonce: "persist-2" };
    const ok = await svc2.verify({ ...fields2, signature: sign(key, fields2) });
    assert.equal(ok.ok, true);
  } finally { await h.cleanup(); }
});

test("报失/报损立即失效且不可逆", async () => {
  const h = await makeHarness();
  try {
    const { deviceId, key } = await issueActivate(h);
    await h.svc.mark({ deviceId, reason: "lost", loft: "北岸A棚", keeper: "k", role: "keeper" });
    const fields = { deviceId, loft: "北岸A棚", timestamp: h.clock(), nonce: "m1", pigeonRingNo: "P-001" };
    await assert.rejects(h.svc.verify({ ...fields, signature: sign(key, fields) }), e => e.code === "device_inactive");
    await assert.rejects(
      h.svc.mark({ deviceId, reason: "damaged", loft: "北岸A棚", keeper: "k", role: "keeper" }),
      e => e.code === "device_not_active"
    );
  } finally { await h.cleanup(); }
});

test("发环事务落盘失败时不留设备记录", async () => {
  const h = await makeHarness();
  try {
    h.store.injectWriteFailure(1);
    await assert.rejects(h.svc.issue({ ringCode: "E-FAIL", pigeonRingNo: "P-001" }), e => e.message === "injected_disk_failure");
    const state = await h.store.read();
    assert.equal(state.devices.length, 0);
    // 回滚后同一环号/同一鸽仍可重新发放
    const issued = await h.svc.issue({ ringCode: "E-FAIL", pigeonRingNo: "P-001" });
    assert.ok(issued.voucher);
  } finally { await h.cleanup(); }
});
