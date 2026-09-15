import http from "node:http";
import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { JsonStore } from "./lib/store.js";
import { RingsService, initialRingsState, DomainError } from "./lib/rings.js";
import { authenticate } from "./lib/auth.js";
import { PAGE } from "./lib/page.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const dataDir = process.env.DATA_DIR || join(__dirname, "data");
const port = Number(process.env.PORT || 3024);

const seedPigeons = {
  pigeons: [
    { ringNo: "CHN-2026-001", owner: "北岸棚", fatherRing: "CHN-2022-188", motherRing: "CHN-2023-512", color: "灰", loft: "北岸A棚", vaccines: [{ date: "2026-04-01", name: "新城疫" }], transfers: [{ date: "2026-04-15", from: "育种棚", to: "北岸棚" }], races: [{ date: "2026-06-01", event: "120公里训放", distance: 120, returnTime: "10:42", rank: 18 }] },
    { ringNo: "CHN-2022-188", owner: "育种棚", fatherRing: "", motherRing: "", color: "雨点", loft: "种鸽棚", vaccines: [], transfers: [], races: [] },
    { ringNo: "CHN-2023-512", owner: "育种棚", fatherRing: "", motherRing: "", color: "红轮", loft: "种鸽棚", vaccines: [], transfers: [], races: [] }
  ]
};

const pigeonStore = new JsonStore(join(dataDir, "pigeons.json"), seedPigeons);
const ringsStore = new JsonStore(join(dataDir, "rings.json"), initialRingsState());
const rings = new RingsService(ringsStore, {
  getPigeon: (ringNo) => {
    // rings 事务期间读取鸽只档案（只读，不与 pigeonStore 事务交叉写）。
    const state = pigeonStore.state;
    return state && state.pigeons.find(p => p.ringNo === ringNo);
  }
});
// 服务启动时把鸽只档案载入内存，供 getPigeon 查询。
await mkdir(dataDir, { recursive: true });
await pigeonStore.load();

async function body(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { throw new DomainError("bad_json", 400); }
}
function sendJson(res, status, data) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(data, null, 2));
}

// 仅管理员；返回 identity 或写响应并返回 null。
function requireAuth(req, res, { admin = false } = {}) {
  const { identity, error } = authenticate(req);
  if (error) { sendJson(res, error.status, { error: error.code }); return null; }
  if (admin && identity.role !== "admin") { sendJson(res, 403, { error: "admin_only" }); return null; }
  return identity;
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const p = url.pathname;

    if (req.method === "GET" && p === "/") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(PAGE);
    }

    if (req.method === "GET" && p === "/api/whoami") {
      const { identity, error } = authenticate(req);
      if (error) return sendJson(res, error.status, { error: error.code });
      return sendJson(res, 200, identity);
    }

    // ---------- 鸽只档案（原有功能）----------
    if (req.method === "GET" && p === "/api/pigeons") {
      const state = await pigeonStore.read();
      return sendJson(res, 200, state.pigeons);
    }
    if (req.method === "POST" && p === "/api/pigeons") {
      if (!requireAuth(req, res, { admin: true })) return;
      const input = await body(req);
      const pigeon = await pigeonStore.mutate(async state => {
        if (state.pigeons.some(item => item.ringNo === input.ringNo)) {
          throw new DomainError("ring_exists", 409);
        }
        const item = {
          ringNo: String(input.ringNo || "").trim(),
          owner: String(input.owner || "").trim(),
          fatherRing: input.fatherRing || "",
          motherRing: input.motherRing || "",
          color: String(input.color || "").trim(),
          loft: String(input.loft || "").trim(),
          vaccines: [], transfers: [], races: []
        };
        if (!item.ringNo || !item.owner || !item.color || !item.loft) throw new DomainError("missing_fields", 400);
        state.pigeons.unshift(item);
        return item;
      });
      return sendJson(res, 201, pigeon);
    }

    // ---------- 电子环防伪 ----------
    if (req.method === "POST" && p === "/api/rings/devices") {
      const identity = requireAuth(req, res, { admin: true });
      if (!identity) return;
      const input = await body(req);
      const result = await rings.issue({
        ringCode: String(input.ringCode || "").trim(),
        pigeonRingNo: String(input.pigeonRingNo || "").trim(),
        issuedBy: "admin"
      });
      return sendJson(res, 201, result);
    }

    if (req.method === "GET" && p === "/api/rings/devices") {
      const identity = requireAuth(req, res);
      if (!identity) return;
      const list = await rings.listDevices({ loft: identity.loft, role: identity.role });
      return sendJson(res, 200, list);
    }

    const oneDevice = p.match(/^\/api\/rings\/devices\/([^/]+)(\/(rotate|report|revoke))?$/);
    if (oneDevice) {
      const identity = requireAuth(req, res);
      if (!identity) return;
      const deviceId = decodeURIComponent(oneDevice[1]);
      const action = oneDevice[3];

      if (req.method === "GET" && !action) {
        return sendJson(res, 200, await rings.getDevice(deviceId, { loft: identity.loft, role: identity.role }));
      }
      if (req.method === "POST" && action === "rotate") {
        const input = await body(req);
        const result = await rings.rotate({
          deviceId, loft: identity.loft, keeper: identity.loft, role: identity.role,
          expectedVersion: input.keyVersion
        });
        return sendJson(res, 200, result);
      }
      if (req.method === "POST" && action === "report") {
        const input = await body(req);
        const result = await rings.mark({ deviceId, reason: input.reason, loft: identity.loft, keeper: identity.loft, role: identity.role });
        return sendJson(res, 200, result);
      }
      if (req.method === "POST" && action === "revoke") {
        if (identity.role !== "admin") return sendJson(res, 403, { error: "admin_only" });
        const result = await rings.revoke({ deviceId, by: "admin" });
        return sendJson(res, 200, result);
      }
    }

    if (req.method === "POST" && p === "/api/rings/activate") {
      const identity = requireAuth(req, res);
      if (!identity) return;
      if (identity.role !== "keeper") return sendJson(res, 403, { error: "keeper_only" });
      const input = await body(req);
      // loft 强制取自令牌身份，请求体无法伪造别的棚。
      const result = await rings.activate({
        voucher: String(input.voucher || "").trim(),
        loft: identity.loft,
        keeper: identity.loft
      });
      return sendJson(res, 200, result);
    }

    if (req.method === "POST" && p === "/api/rings/verify") {
      const identity = requireAuth(req, res);
      if (!identity) return;
      const input = await body(req);
      // 棚管员只能校验本棚设备：loft 强制取自令牌身份，请求体无法伪造别的棚；
      // 设备若不属于本棚，领域服务返回 cross_loft_denied 并落拒绝记录。
      const loft = identity.role === "admin" ? String(input.loft || "") : identity.loft;
      const result = await rings.verify({
        deviceId: input.deviceId,
        loft,
        timestamp: input.timestamp,
        nonce: input.nonce,
        pigeonRingNo: input.pigeonRingNo,
        signature: input.signature
      });
      return sendJson(res, 200, result);
    }

    if (req.method === "GET" && p === "/api/rings/verifications") {
      const identity = requireAuth(req, res);
      if (!identity) return;
      const deviceId = url.searchParams.get("deviceId") || undefined;
      const list = await rings.listVerifications({ deviceId, loft: identity.loft, role: identity.role });
      return sendJson(res, 200, list);
    }

    return sendJson(res, 404, { error: "not_found" });
  } catch (error) {
    if (error instanceof DomainError) return sendJson(res, error.status, { error: error.code });
    sendJson(res, 500, { error: error.message });
  }
});

if (process.env.NODE_ENV !== "test") {
  server.listen(port, () => console.log(`Racing pigeon registry listening on http://localhost:${port}`));
}

export { server, rings, ringsStore, pigeonStore };
