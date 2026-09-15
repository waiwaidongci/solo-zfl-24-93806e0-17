import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHmac, randomUUID } from "node:crypto";

const PORT = 3901;
const BASE = `http://127.0.0.1:${PORT}`;
const ADMIN = { "X-Role": "admin", "X-Admin-Token": "admin-secret" };
const BEIAN = { "X-Role": "keeper", "X-Keeper-Token": "keeper-beian" };
const ZHONG = { "X-Role": "keeper", "X-Keeper-Token": "keeper-zhong" };

let dataDir;
let proc;

async function api(path, { method = "GET", headers = {}, body } = {}) {
  const res = await fetch(BASE + path, {
    method,
    headers: { "Content-Type": "application/json", ...headers },
    body: body ? JSON.stringify(body) : undefined
  });
  let data = null;
  try { data = await res.json(); } catch {}
  return { status: res.status, data };
}

before(async () => {
  dataDir = await mkdtemp(join(tmpdir(), "rings-http-"));
  proc = spawn(process.execPath, ["server.js"], {
    cwd: process.cwd(),
    env: { ...process.env, PORT: String(PORT), DATA_DIR: dataDir, NODE_ENV: "test-http" },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let err = "";
  proc.stderr.on("data", d => { err += d; });
  // 等端口可用
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(BASE + "/api/pigeons");
      if (r.ok) break;
    } catch {}
    await new Promise(r => setTimeout(r, 100));
    if (i === 49) throw new Error("服务未启动: " + err);
  }
});

after(async () => {
  proc.kill("SIGTERM");
  await new Promise(r => proc.on("exit", r));
  await rm(dataDir, { recursive: true, force: true });
});

const hmac = (key, f) => createHmac("sha256", key)
  .update([f.deviceId, f.loft, f.timestamp, f.nonce, f.pigeonRingNo].join("|")).digest("hex");

test("鉴权：无令牌/错令牌被拒", async () => {
  assert.equal((await api("/api/whoami")).status, 401);
  assert.equal((await api("/api/whoami", { headers: { "X-Role": "admin", "X-Admin-Token": "wrong" } })).status, 401);
  assert.equal((await api("/api/whoami", { headers: BEIAN })).status, 200);
  // 棚管员不能发环
  assert.equal((await api("/api/rings/devices", { method: "POST", headers: BEIAN, body: { ringCode: "X", pigeonRingNo: "CHN-2026-001" } })).status, 403);
});

test("HTTP 全链路：发放→激活→校验→重放→跨棚→轮换→撤销", async () => {
  // 发环
  const issue = await api("/api/rings/devices", {
    method: "POST", headers: ADMIN, body: { ringCode: "HTTP-E1", pigeonRingNo: "CHN-2026-001" }
  });
  assert.equal(issue.status, 201);
  const deviceId = issue.data.device.deviceId;
  assert.equal(issue.data.device.status, "issued");
  assert.ok(issue.data.voucher, "必须返回一次性凭证");
  assert.ok(!JSON.stringify(issue.data.device).includes(issue.data.voucher), "设备视图不能泄露凭证");

  // 外棚不能激活
  const crossAct = await api("/api/rings/activate", { method: "POST", headers: ZHONG, body: { voucher: issue.data.voucher } });
  assert.equal(crossAct.status, 403);
  assert.equal(crossAct.data.error, "cross_loft_activation_denied");
  // 本棚激活
  const act = await api("/api/rings/activate", { method: "POST", headers: BEIAN, body: { voucher: issue.data.voucher } });
  assert.equal(act.status, 200);
  const key = act.data.deviceKey;
  // 旧凭证二次使用
  const again = await api("/api/rings/activate", { method: "POST", headers: BEIAN, body: { voucher: issue.data.voucher } });
  assert.equal(again.status, 401);

  // 正常校验
  const fields = { deviceId, loft: "北岸A棚", timestamp: Date.now(), nonce: randomUUID(), pigeonRingNo: "CHN-2026-001" };
  const v1 = await api("/api/rings/verify", { method: "POST", headers: BEIAN, body: { ...fields, signature: hmac(key, fields) } });
  assert.equal(v1.status, 200);
  // 重放
  const v2 = await api("/api/rings/verify", { method: "POST", headers: BEIAN, body: { ...fields, signature: hmac(key, fields) } });
  assert.equal(v2.status, 409);
  assert.equal(v2.data.error, "replay_detected");
  // 跨棚校验（种鸽棚的棚管员拿别的棚设备来验）
  const cf = { ...fields, loft: "种鸽棚", nonce: randomUUID() };
  const v3 = await api("/api/rings/verify", { method: "POST", headers: ZHONG, body: { ...cf, signature: hmac(key, cf) } });
  assert.equal(v3.status, 403);
  assert.equal(v3.data.error, "cross_loft_denied");
  // 篡改签名
  const tf = { ...fields, nonce: randomUUID() };
  let sig = hmac(key, tf);
  sig = sig.slice(0, -2) + (sig.slice(-2) === "00" ? "01" : "00");
  assert.equal((await api("/api/rings/verify", { method: "POST", headers: BEIAN, body: { ...tf, signature: sig } })).status, 401);
  // 过期时间戳
  const ef = { ...fields, nonce: randomUUID(), timestamp: Date.now() - 10 * 60 * 1000 };
  assert.equal((await api("/api/rings/verify", { method: "POST", headers: BEIAN, body: { ...ef, signature: hmac(key, ef) } })).status, 401);

  // 轮换（带版本号）
  const rot = await api(`/api/rings/devices/${deviceId}/rotate`, { method: "POST", headers: BEIAN, body: { keyVersion: 1 } });
  assert.equal(rot.status, 200);
  assert.equal(rot.data.keyVersion, 2);
  // 旧密钥失效
  const of = { ...fields, nonce: randomUUID(), timestamp: Date.now() };
  assert.equal((await api("/api/rings/verify", { method: "POST", headers: BEIAN, body: { ...of, signature: hmac(key, of) } })).status, 401);
  // 外棚不能轮换本棚设备
  assert.equal((await api(`/api/rings/devices/${deviceId}/rotate`, { method: "POST", headers: ZHONG, body: { keyVersion: 2 } })).status, 403);

  // 撤销
  const rev = await api(`/api/rings/devices/${deviceId}/revoke`, { method: "POST", headers: ADMIN, body: {} });
  assert.equal(rev.status, 200);
  // 新密钥也再不能校验
  const nf = { ...fields, nonce: randomUUID(), timestamp: Date.now() };
  assert.equal((await api("/api/rings/verify", { method: "POST", headers: BEIAN, body: { ...nf, signature: hmac(rot.data.deviceKey, nf) } })).status, 403);
  // 二次撤销
  assert.equal((await api(`/api/rings/devices/${deviceId}/revoke`, { method: "POST", headers: ADMIN, body: {} })).status, 409);

  // 校验记录可查（含拒绝记录），且棚管员只能看本棚
  const recsAdmin = await api("/api/rings/verifications", { headers: ADMIN });
  assert.ok(recsAdmin.data.length >= 7);
  assert.ok(recsAdmin.data.some(v => v.code === "cross_loft_denied"));
  assert.ok(recsAdmin.data.some(v => v.code === "replay_detected"));
  const recsZhong = await api("/api/rings/verifications", { headers: ZHONG });
  assert.ok(recsZhong.data.every(v => v.loft === "种鸽棚"));
});

test("HTTP 并发：同时激活同一凭证只有一次 200", async () => {
  const issue = await api("/api/rings/devices", {
    method: "POST", headers: ADMIN, body: { ringCode: "HTTP-C1", pigeonRingNo: "CHN-2022-188" }
  });
  assert.equal(issue.status, 201);
  const results = await Promise.all(Array.from({ length: 10 }, () =>
    api("/api/rings/activate", { method: "POST", headers: ZHONG, body: { voucher: issue.data.voucher } })
  ));
  assert.equal(results.filter(r => r.status === 200).length, 1);
  assert.ok(results.filter(r => r.status !== 200).every(r => r.status === 401));
});

test("HTTP 并发：同版本号轮换只有一次成功", async () => {
  const issue = await api("/api/rings/devices", {
    method: "POST", headers: ADMIN, body: { ringCode: "HTTP-C2", pigeonRingNo: "CHN-2023-512" }
  });
  const act = await api("/api/rings/activate", { method: "POST", headers: ZHONG, body: { voucher: issue.data.voucher } });
  const id = act.data.device.deviceId;
  const results = await Promise.all(Array.from({ length: 8 }, () =>
    api(`/api/rings/devices/${id}/rotate`, { method: "POST", headers: ZHONG, body: { keyVersion: 1 } })
  ));
  assert.equal(results.filter(r => r.status === 200).length, 1);
  assert.ok(results.filter(r => r.status !== 200).every(r => r.status === 409));
});

test("页面与静态健康检查", async () => {
  const home = await fetch(BASE + "/");
  assert.equal(home.status, 200);
  const html = await home.text();
  assert.ok(html.includes("电子环防伪"));
  assert.ok(html.includes("跨棚请求"));
});
