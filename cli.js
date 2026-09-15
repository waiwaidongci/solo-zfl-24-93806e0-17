#!/usr/bin/env node
// 命令行：发放/激活/校验/轮换/报失报损/撤销/查询。
// 默认连接 http://localhost:3024，可用 BASE 环境变量覆盖。
import { randomUUID } from "node:crypto";
import { createHmac } from "node:crypto";

const BASE = process.env.BASE || "http://localhost:3024";
const ADMIN = { "X-Role": "admin", "X-Admin-Token": process.env.ADMIN_TOKEN || "admin-secret" };
const keeper = (token) => ({ "X-Role": "keeper", "X-Keeper-Token": token });

async function api(path, { method = "GET", headers = {}, body } = {}) {
  const res = await fetch(BASE + path, {
    method,
    headers: { "Content-Type": "application/json", ...headers },
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(`${res.status} ${data.error || "error"}`);
    err.status = res.status; err.code = data.error; err.data = data;
    throw err;
  }
  return data;
}

// 与浏览器、服务端逐字节一致的签名规则。
function sign(key, fields) {
  const msg = [fields.deviceId, fields.loft, fields.timestamp, fields.nonce, fields.pigeonRingNo].join("|");
  return createHmac("sha256", key).update(msg).digest("hex");
}

const usage = `赛鸽电子环防伪 CLI
用法:
  node cli.js issue  <ringCode> <pigeonRingNo>                 管理员发环，输出一次性凭证
  node cli.js activate <voucher> --keeper <token>              棚管员激活本棚设备，输出设备密钥
  node cli.js devices [--admin | --keeper <token>]             列出设备
  node cli.js verifications [--admin | --keeper <token>]       列出校验记录
  node cli.js verify <deviceId> --key <deviceKey> --loft <棚>  构造签名并校验（默认随机 nonce/当前时间）
                     [--nonce N] [--ts EPOCH_MS] [--cross <别的棚>]
  node cli.js rotate <deviceId> --admin | --keeper <token>     轮换密钥，输出新设备密钥
  node cli.js report <deviceId> lost|damaged --keeper <token>  本棚报失/报损（管理员用 --admin）
  node cli.js revoke <deviceId> --admin                        管理员撤销

示例:
  node cli.js issue E2026-0001 CHN-2026-001
  node cli.js activate <voucher> --keeper keeper-beian
  node cli.js verify <deviceId> --key <deviceKey> --loft 北岸A棚`;

function arg(args, name) {
  const i = args.indexOf("--" + name);
  return i >= 0 ? args[i + 1] : undefined;
}
function has(args, name) { return args.includes("--" + name); }

async function auth(args) {
  if (has(args, "admin")) return ADMIN;
  const t = arg(args, "keeper");
  if (!t) throw new Error("需要 --admin 或 --keeper <令牌>");
  return keeper(t);
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  switch (cmd) {
    case "issue": {
      const [ringCode, pigeonRingNo] = args;
      if (!ringCode || !pigeonRingNo) throw new Error("用法: issue <ringCode> <pigeonRingNo>");
      const r = await api("/api/rings/devices", { method: "POST", headers: ADMIN, body: { ringCode, pigeonRingNo } });
      console.log(JSON.stringify(r, null, 2));
      console.error(`\n[一次性凭证，仅显示这一次] ${r.voucher}`);
      return;
    }
    case "activate": {
      const voucher = args[0];
      if (!voucher) throw new Error("用法: activate <voucher> --keeper <token>");
      const r = await api("/api/rings/activate", { method: "POST", headers: await auth(args), body: { voucher } });
      console.log(JSON.stringify(r, null, 2));
      console.error(`\n[设备密钥，仅显示这一次，轮换后旧密钥立即失效] ${r.deviceKey}`);
      return;
    }
    case "devices": {
      console.log(JSON.stringify(await api("/api/rings/devices", { headers: await auth(args) }), null, 2));
      return;
    }
    case "verifications": {
      console.log(JSON.stringify(await api("/api/rings/verifications", { headers: await auth(args) }), null, 2));
      return;
    }
    case "rotate": {
      const deviceId = args[0];
      const devs = await api("/api/rings/devices", { headers: await auth(args) });
      const dev = devs.find(d => d.deviceId === deviceId);
      if (!dev) throw new Error("device_not_found");
      const r = await api(`/api/rings/devices/${encodeURIComponent(deviceId)}/rotate`, { method: "POST", headers: await auth(args), body: { keyVersion: dev.keyVersion } });
      console.log(JSON.stringify(r, null, 2));
      console.error(`\n[新设备密钥] ${r.deviceKey}`);
      return;
    }
    case "report": {
      const deviceId = args[0];
      const reason = ["lost", "damaged"].includes(args[1]) ? args[1] : null;
      if (!deviceId || !reason) throw new Error("用法: report <deviceId> lost|damaged --keeper <token>");
      console.log(JSON.stringify(
        await api(`/api/rings/devices/${encodeURIComponent(deviceId)}/report`, { method: "POST", headers: await auth(args), body: { reason } }),
        null, 2
      ));
      return;
    }
    case "revoke": {
      const deviceId = args[0];
      console.log(JSON.stringify(
        await api(`/api/rings/devices/${encodeURIComponent(deviceId)}/revoke`, { method: "POST", headers: ADMIN, body: {} }),
        null, 2
      ));
      return;
    }
    case "verify": {
      const deviceId = args[0];
      const key = arg(args, "key");
      let loft = arg(args, "loft");
      if (!deviceId || !key) throw new Error("用法: verify <deviceId> --key <deviceKey> --loft <棚>");
      // 取设备信息以获得 pigeonRingNo（管理员视角查询，不受棚过滤影响）。
      const devices = await api("/api/rings/devices", { headers: ADMIN }).catch(() => null);
      let pigeonRingNo = arg(args, "pigeon");
      let boundLoft = loft;
      if (devices) {
        const d = devices.find(x => x.deviceId === deviceId);
        if (d) { pigeonRingNo ||= d.pigeonRingNo; boundLoft = d.loft; }
      }
      if (!pigeonRingNo) throw new Error("无法获知 pigeonRingNo，请加 --pigeon <足环号>");
      // --cross 用别的棚号构造并以那个棚的身份发起，用来演示跨棚拦截。
      const cross = arg(args, "cross");
      let h;
      if (cross) { loft = cross; h = keeper(cross === "种鸽棚" ? "keeper-zhong" : process.env.KEEPER_TOKEN || "keeper-beian"); }
      else { h = keeper(process.env.KEEPER_TOKEN || "keeper-beian"); }
      const fields = {
        deviceId,
        loft,
        timestamp: Number(arg(args, "ts")) || Date.now(),
        nonce: arg(args, "nonce") || randomUUID(),
        pigeonRingNo
      };
      const payload = { ...fields, signature: sign(key, fields) };
      try {
        const r = await api("/api/rings/verify", { method: "POST", headers: h, body: payload });
        console.log(JSON.stringify({ request: payload, response: r }, null, 2));
      } catch (e) {
        console.log(JSON.stringify({ request: payload, response: { status: e.status, error: e.code, ...e.data } }, null, 2));
        process.exitCode = 1;
      }
      return;
    }
    default:
      console.log(usage);
  }
}

main().catch(err => {
  console.error("错误:", err.message);
  process.exit(1);
});
