// 真实进程验证（独立起服务，Node 20 / 22 均可直接运行）：
//   1) 旧明文(v0) / 旧无 AAD 信封(v1) 启动即安全升级为绑定设备的 v2，升级后原设备仍可校验；
//   2) 交换两台设备的密钥信封后重启：进程必须 fail-fast 退出，不接受另一台设备的签名。
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { mkdtemp, rm, readFile, writeFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, createHmac, randomUUID } from "node:crypto";

const BASE = (port) => `http://127.0.0.1:${port}`;
const ADMIN = { "X-Role": "admin", "X-Admin-Token": "admin-secret" };
const BEIAN = { "X-Role": "keeper", "X-Keeper-Token": "keeper-beian" };

const hmac = (key, f) => createHmac("sha256", key)
  .update([f.deviceId, f.loft, f.timestamp, f.nonce, f.pigeonRingNo].join("|")).digest("hex");

async function waitUp(port, ms = 6000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    try { if ((await fetch(BASE(port) + "/api/pigeons")).ok) return true; } catch {}
    await new Promise(r => setTimeout(r, 100));
  }
  return false;
}

function startServer(port, dataDir, env = {}) {
  const proc = spawn(process.execPath, ["server.js"], {
    cwd: process.cwd(),
    env: { ...process.env, PORT: String(port), DATA_DIR: dataDir, NODE_ENV: "legacy-test", ...env },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let stderr = "";
  proc.stderr.on("data", d => { stderr += d; });
  return { proc, get stderr() { return stderr; } };
}

function deviceRecord(deviceId, { serverKey, serverKeyEnc, keyPlain, pigeonRingNo = "CHN-2026-001", loft = "北岸A棚", keyVersion = 1 }) {
  const now = Date.now();
  return {
    deviceId, ringCode: deviceId, pigeonRingNo,
    loftAtIssue: loft, status: "active", voucherHash: null, voucherExpiresAt: null,
    activatedAt: now - 5000, activatedBy: "k", loft,
    keyVersion,
    ...(serverKey !== undefined ? { serverKey } : {}),
    ...(serverKeyEnc !== undefined ? { serverKeyEnc } : {}),
    ...(keyPlain !== undefined ? { keyPlain } : {}),
    keyFingerprint: null, issuedAt: now - 6000, issuedBy: "admin", events: [], nonces: []
  };
}

// 用预置主密钥生成历史 v1（无 AAD）信封的数据文件。
function writeV1Data(dataDir, masterKeyHex, devices) {
  const out = execFileSync(process.execPath, ["--input-type=module", "-e", `
    import { writeFileSync } from "node:fs";
    import { KeyManager } from ${JSON.stringify(join(process.cwd(), "lib", "keystore.js"))};
    const km = new KeyManager(Buffer.from(${JSON.stringify(masterKeyHex)}, "hex"));
    const devices = ${JSON.stringify(devices)};
    for (const d of devices) {
      if (d.keyPlain) { d.serverKeyEnc = km.sealLegacyV1(d.keyPlain); delete d.keyPlain; }
    }
    writeFileSync(${JSON.stringify(join(dataDir, "rings.json"))}, JSON.stringify({ devices, verifications: [] }, null, 2));
    writeFileSync(${JSON.stringify(join(dataDir, "master.key"))}, Buffer.from(${JSON.stringify(masterKeyHex)}, "hex"));
  `]);
  return out;
}

test("旧明文(v0)启动即升级为 v2 密文，升级后校验/重放/跨棚/轮换/撤销正常", async () => {
  const port = 3902;
  const dataDir = await mkdtemp(join(tmpdir(), "rings-v0-http-"));
  const legacyKey = "c".repeat(64);
  await writeFile(join(dataDir, "rings.json"), JSON.stringify({
    devices: [deviceRecord("EID-OLDHTTP001", { serverKey: legacyKey })], verifications: []
  }, null, 2));
  const { proc, stderr } = startServer(port, dataDir);
  try {
    assert.equal(await waitUp(port), true, stderr);
    const onDisk = await readFile(join(dataDir, "rings.json"), "utf8");
    assert.ok(!onDisk.includes(legacyKey));
    assert.ok(!/"serverKey"\s*:/.test(onDisk));
    const parsed = JSON.parse(onDisk);
    assert.equal(parsed.devices[0].serverKeyEnc.v, 2, "必须升级为带 AAD 的 v2");
    assert.equal((await stat(join(dataDir, "master.key"))).mode & 0o777, 0o600);

    const fields = { deviceId: "EID-OLDHTTP001", loft: "北岸A棚", timestamp: Date.now(), nonce: randomUUID(), pigeonRingNo: "CHN-2026-001" };
    assert.equal((await fetch(BASE(port) + "/api/rings/verify", {
      method: "POST", headers: { "Content-Type": "application/json", ...BEIAN },
      body: JSON.stringify({ ...fields, signature: hmac(legacyKey, fields) })
    })).status, 200);
    assert.equal((await fetch(BASE(port) + "/api/rings/verify", {
      method: "POST", headers: { "Content-Type": "application/json", ...BEIAN },
      body: JSON.stringify({ ...fields, signature: hmac(legacyKey, fields) })
    })).status, 409, "重放拦截");
    assert.equal((await fetch(BASE(port) + "/api/rings/verify", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Role": "keeper", "X-Keeper-Token": "keeper-zhong" },
      body: JSON.stringify({ ...fields, loft: "种鸽棚", nonce: randomUUID(), signature: hmac(legacyKey, fields) })
    })).status, 403, "跨棚拦截");

    // 缺版本 400；带版本轮换成功；轮换后磁盘无新旧明文
    assert.equal((await fetch(BASE(port) + "/api/rings/devices/EID-OLDHTTP001/rotate", {
      method: "POST", headers: { "Content-Type": "application/json", ...BEIAN }, body: "{}"
    })).status, 400);
    const rotRes = await fetch(BASE(port) + "/api/rings/devices/EID-OLDHTTP001/rotate", {
      method: "POST", headers: { "Content-Type": "application/json", ...BEIAN }, body: JSON.stringify({ keyVersion: 1 })
    });
    assert.equal(rotRes.status, 200);
    const newKey = (await rotRes.json()).deviceKey;
    const disk2 = await readFile(join(dataDir, "rings.json"), "utf8");
    assert.ok(!disk2.includes(legacyKey) && !disk2.includes(newKey));
    assert.equal(JSON.parse(disk2).devices[0].serverKeyEnc.v, 2);

    assert.equal((await fetch(BASE(port) + "/api/rings/devices/EID-OLDHTTP001/revoke", {
      method: "POST", headers: { "Content-Type": "application/json", ...ADMIN }, body: "{}"
    })).status, 200);
    const recs = await (await fetch(BASE(port) + "/api/rings/verifications", { headers: ADMIN })).json();
    assert.ok(recs.some(v => v.code === "replay_detected") && recs.some(v => v.code === "cross_loft_denied"));
  } finally {
    proc.kill("SIGTERM");
    await new Promise(r => proc.on("exit", r));
    await rm(dataDir, { recursive: true, force: true });
  }
});

test("旧 v1 无 AAD 信封启动即升级为 v2，升级后原设备仍能校验，信封不可换绑", async () => {
  const port = 3903;
  const dataDir = await mkdtemp(join(tmpdir(), "rings-v1-http-"));
  const masterKeyHex = randomBytes(32).toString("hex");
  const legacyKey = "d".repeat(64);
  writeV1Data(dataDir, masterKeyHex, [deviceRecord("EID-V1HTTP002", { keyPlain: legacyKey })]);
  // 升级前确认磁盘确实是 v1 信封且无明文
  const before = JSON.parse(await readFile(join(dataDir, "rings.json"), "utf8"));
  assert.equal(before.devices[0].serverKeyEnc.v, 1);
  assert.ok(!(await readFile(join(dataDir, "rings.json"), "utf8")).includes(legacyKey));

  const { proc, stderr } = startServer(port, dataDir);
  try {
    assert.equal(await waitUp(port), true, stderr);
    const after = JSON.parse(await readFile(join(dataDir, "rings.json"), "utf8"));
    assert.equal(after.devices[0].serverKeyEnc.v, 2, "v1 信封必须升级为 v2");

    const fields = { deviceId: "EID-V1HTTP002", loft: "北岸A棚", timestamp: Date.now(), nonce: randomUUID(), pigeonRingNo: "CHN-2026-001" };
    const ok = await fetch(BASE(port) + "/api/rings/verify", {
      method: "POST", headers: { "Content-Type": "application/json", ...BEIAN },
      body: JSON.stringify({ ...fields, signature: hmac(legacyKey, fields) })
    });
    assert.equal(ok.status, 200, "升级后原设备密钥继续有效");
  } finally {
    proc.kill("SIGTERM");
    await new Promise(r => proc.on("exit", r));
    await rm(dataDir, { recursive: true, force: true });
  }
});

test("跨设备替换密钥信封后重启：服务 fail-fast 拒绝启动", async () => {
  const port = 3904;
  const dataDir = await mkdtemp(join(tmpdir(), "rings-swap-http-"));
  const masterKeyHex = randomBytes(32).toString("hex");
  // 两台同棚、不同鸽的设备，各自带 v2 信封（用现版 KeyManager 直接生成）。
  writeV1Data(dataDir, masterKeyHex, []); // 仅放 master.key
  // 用现版服务跑一轮发两只设备，再离线篡改交换信封。
  const seeded = execFileSync(process.execPath, ["--input-type=module", "-e", `
    import { writeFileSync } from "node:fs";
    import { KeyManager } from ${JSON.stringify(join(process.cwd(), "lib", "keystore.js"))};
    import { randomBytes } from "node:crypto";
    const km = new KeyManager(Buffer.from(${JSON.stringify(masterKeyHex)}, "hex"));
    const now = Date.now();
    const mk = (id, pigeon, key) => ({
      deviceId: id, ringCode: id, pigeonRingNo: pigeon, loftAtIssue: "北岸A棚", status: "active",
      voucherHash: null, voucherExpiresAt: null, activatedAt: now - 1000, activatedBy: "k",
      loft: "北岸A棚", keyVersion: 1, serverKeyEnc: km.encrypt(id, key), keyFingerprint: null,
      issuedAt: now - 2000, issuedBy: "admin", events: [], nonces: []
    });
    writeFileSync(${JSON.stringify(join(dataDir, "rings.json"))}, JSON.stringify({
      devices: [mk("EID-SWAP-A","CHN-2026-001","a".repeat(64)), mk("EID-SWAP-B","CHN-2026-002-不存在","b".repeat(64))],
      verifications: []
    }, null, 2));
  `]);

  // 先正常启动一次确认两台设备各自可校验
  const s1 = startServer(port, dataDir);
  try {
    assert.equal(await waitUp(port), true, s1.stderr);
    const fa = { deviceId: "EID-SWAP-A", loft: "北岸A棚", timestamp: Date.now(), nonce: randomUUID(), pigeonRingNo: "CHN-2026-001" };
    assert.equal((await fetch(BASE(port) + "/api/rings/verify", {
      method: "POST", headers: { "Content-Type": "application/json", ...BEIAN },
      body: JSON.stringify({ ...fa, signature: hmac("a".repeat(64), fa) })
    })).status, 200);
  } finally {
    s1.proc.kill("SIGTERM");
    await new Promise(r => s1.proc.on("exit", r));
  }

  // 离线攻击：把 A 的信封复制到 B
  const disk = JSON.parse(await readFile(join(dataDir, "rings.json"), "utf8"));
  const envA = disk.devices.find(d => d.deviceId === "EID-SWAP-A").serverKeyEnc;
  disk.devices.find(d => d.deviceId === "EID-SWAP-B").serverKeyEnc = JSON.parse(JSON.stringify(envA));
  await writeFile(join(dataDir, "rings.json"), JSON.stringify(disk, null, 2));

  const s2 = startServer(port, dataDir);
  try {
    const up = await waitUp(port, 3000);
    if (up) {
      // 极少数情况下端口先起后崩：等待退出
      await new Promise(r => setTimeout(r, 300));
    }
    assert.equal(s2.proc.exitCode !== null, true, "进程应已退出");
    assert.notEqual(s2.proc.exitCode, 0, "退出码必须非 0（fail-fast）");
    assert.match(s2.stderr, /key_envelope_mismatch|EID-SWAP-B/);
  } finally {
    if (s2.proc.exitCode === null) s2.proc.kill("SIGTERM");
    await rm(dataDir, { recursive: true, force: true });
  }
});
