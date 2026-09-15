// 真实进程验证：旧版本（明文 serverKey）数据启动后自动安全升级，升级后仍能校验。
// 独立起服务，不复用 http.test.js 的进程。Node 20 / 22 均可直接运行。
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm, readFile, writeFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHmac, randomUUID } from "node:crypto";

const PORT = 3902;
const BASE = `http://127.0.0.1:${PORT}`;
const ADMIN = { "X-Role": "admin", "X-Admin-Token": "admin-secret" };
const BEIAN = { "X-Role": "keeper", "X-Keeper-Token": "keeper-beian" };

const hmac = (key, f) => createHmac("sha256", key)
  .update([f.deviceId, f.loft, f.timestamp, f.nonce, f.pigeonRingNo].join("|")).digest("hex");

async function waitUp() {
  for (let i = 0; i < 60; i++) {
    try { if ((await fetch(BASE + "/api/pigeons")).ok) return; } catch {}
    await new Promise(r => setTimeout(r, 100));
  }
  throw new Error("legacy server failed to start");
}

test("旧明文数据启动即升级为密文，升级后校验/重放/轮换/撤销均正常", async () => {
  const dataDir = await mkdtemp(join(tmpdir(), "rings-legacy-http-"));
  const legacyKey = "c".repeat(64);
  const now = Date.now();
  const legacy = {
    devices: [{
      deviceId: "EID-OLDHTTP001", ringCode: "OLD-1", pigeonRingNo: "CHN-2026-001",
      loftAtIssue: "北岸A棚", status: "active", voucherHash: null, voucherExpiresAt: null,
      activatedAt: now - 5000, activatedBy: "k", loft: "北岸A棚",
      keyVersion: 1, serverKey: legacyKey, keyFingerprint: null,
      issuedAt: now - 6000, issuedBy: "admin", events: [], nonces: []
    }],
    verifications: []
  };
  await writeFile(join(dataDir, "rings.json"), JSON.stringify(legacy, null, 2));

  const proc = spawn(process.execPath, ["server.js"], {
    cwd: process.cwd(),
    env: { ...process.env, PORT: String(PORT), DATA_DIR: dataDir, NODE_ENV: "legacy-test" },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let stderr = "";
  proc.stderr.on("data", d => { stderr += d; });
  try {
    await waitUp();

    // 启动加载时已经原子重写：明文消失、信封出现
    const onDisk = await readFile(join(dataDir, "rings.json"), "utf8");
    assert.ok(!onDisk.includes(legacyKey), "升级后明文密钥必须消失");
    assert.ok(/"serverKeyEnc"\s*:/.test(onDisk), "必须写为密文信封");
    assert.ok(!/"serverKey"\s*:/.test(onDisk), "不得残留明文 serverKey 字段");
    assert.equal((await stat(join(dataDir, "master.key"))).mode & 0o777, 0o600);

    // 升级后旧设备仍可校验（主密钥文件本次新生成，但明文→密文升级在同次启动内完成）
    const fields = { deviceId: "EID-OLDHTTP001", loft: "北岸A棚", timestamp: Date.now(), nonce: randomUUID(), pigeonRingNo: "CHN-2026-001" };
    const ok = await fetch(BASE + "/api/rings/verify", {
      method: "POST", headers: { "Content-Type": "application/json", ...BEIAN },
      body: JSON.stringify({ ...fields, signature: hmac(legacyKey, fields) })
    });
    assert.equal(ok.status, 200, stderr);
    // 重放拦截仍生效
    const replay = await fetch(BASE + "/api/rings/verify", {
      method: "POST", headers: { "Content-Type": "application/json", ...BEIAN },
      body: JSON.stringify({ ...fields, signature: hmac(legacyKey, fields) })
    });
    assert.equal(replay.status, 409);

    // 跨棚拦截
    const cross = await fetch(BASE + "/api/rings/verify", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Role": "keeper", "X-Keeper-Token": "keeper-zhong" },
      body: JSON.stringify({ ...fields, loft: "种鸽棚", nonce: randomUUID(), signature: hmac(legacyKey, fields) })
    });
    assert.equal(cross.status, 403);

    // 缺版本号轮换拒绝；带当前版本成功且全程磁盘无明文
    const noVer = await fetch(BASE + "/api/rings/devices/EID-OLDHTTP001/rotate", {
      method: "POST", headers: { "Content-Type": "application/json", ...BEIAN }, body: "{}"
    });
    assert.equal(noVer.status, 400);
    const rotRes = await fetch(BASE + "/api/rings/devices/EID-OLDHTTP001/rotate", {
      method: "POST", headers: { "Content-Type": "application/json", ...BEIAN },
      body: JSON.stringify({ keyVersion: 1 })
    });
    assert.equal(rotRes.status, 200);
    const newKey = (await rotRes.json()).deviceKey;
    const disk2 = await readFile(join(dataDir, "rings.json"), "utf8");
    assert.ok(!disk2.includes(legacyKey) && !disk2.includes(newKey), "轮换后新旧密钥都不得明文落盘");

    // 撤销
    const rev = await fetch(BASE + "/api/rings/devices/EID-OLDHTTP001/revoke", {
      method: "POST", headers: { "Content-Type": "application/json", ...ADMIN }, body: "{}"
    });
    assert.equal(rev.status, 200);

    // 审计记录可查
    const recs = await (await fetch(BASE + "/api/rings/verifications", { headers: ADMIN })).json();
    assert.ok(recs.some(v => v.ok) && recs.some(v => v.code === "replay_detected") && recs.some(v => v.code === "cross_loft_denied"));
  } finally {
    proc.kill("SIGTERM");
    await new Promise(r => proc.on("exit", r));
    await rm(dataDir, { recursive: true, force: true });
  }
});
