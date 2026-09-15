// 极简角色鉴权（演示/登记站内网场景）：
//   管理员：请求头 x-admin-token，默认 admin-secret（可用 ADMIN_TOKEN 覆盖）
//   棚管员：请求头 x-keeper-token，按“棚号=令牌”映射，默认：
//           北岸A棚=keeper-beian，种鸽棚=keeper-zhong
//           （可用 KEEPER_TOKENS 覆盖，逗号分隔）
// 棚管员的棚号由令牌决定，请求体里的 loft 永远不能越权指定别的棚。

export const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "admin-secret";

export function keeperTokens() {
  const raw = process.env.KEEPER_TOKENS || "北岸A棚=keeper-beian,种鸽棚=keeper-zhong";
  const map = new Map();
  for (const pair of raw.split(",")) {
    const idx = pair.indexOf("=");
    if (idx > 0) map.set(pair.slice(0, idx).trim(), pair.slice(idx + 1).trim());
  }
  return map;
}

export function authenticate(req) {
  const role = req.headers["x-role"];
  if (role === "admin") {
    if (req.headers["x-admin-token"] !== ADMIN_TOKEN) return { error: { code: "bad_admin_token", status: 401 } };
    return { identity: { role: "admin", loft: null } };
  }
  if (role === "keeper") {
    const token = req.headers["x-keeper-token"];
    const map = keeperTokens();
    let matched = null;
    for (const [loft, value] of map) {
      if (value === token) { matched = loft; break; }
    }
    if (!matched) return { error: { code: "bad_keeper_token", status: 401 } };
    return { identity: { role: "keeper", loft: matched } };
  }
  return { error: { code: "auth_required", status: 401 } };
}
