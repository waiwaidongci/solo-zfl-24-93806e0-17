# 赛鸽血统环号登记站 · 电子环防伪

运行：

```bash
npm start          # http://localhost:3024
npm test           # 17 项：领域逻辑 + HTTP 集成（含并发/故障恢复）
```

## 角色与令牌（演示默认值，可用环境变量覆盖）

| 角色 | 请求头 | 默认令牌 | 权限 |
|---|---|---|---|
| 管理员 | `X-Role: admin` + `X-Admin-Token` | `admin-secret` | 发环、撤销、查看全部设备与校验记录 |
| 棚管员·北岸A棚 | `X-Role: keeper` + `X-Keeper-Token` | `keeper-beian` | 只能激活/轮换/报失报损/校验本棚设备 |
| 棚管员·种鸽棚 | 同上 | `keeper-zhong` | 同上 |

棚管员的棚号由令牌决定，请求体里的 `loft` 无法越权。

## 防伪流程

1. **发放** `POST /api/rings/devices`（管理员）：为已建档鸽只发环，生成一次性激活凭证（24h 有效）。
   同一环号、同一鸽只只能绑定一次。凭证明文只返回一次，磁盘只存 SHA-256 哈希。
2. **激活** `POST /api/rings/activate`（本棚棚管员）：只能激活发放给本棚的设备；激活成功后凭证立即作废，
   返回设备密钥（HMAC，仅返回一次）。
3. **校验** `POST /api/rings/verify`：HMAC-SHA256 签名，签名原文
   `deviceId|loft|timestamp|nonce|pigeonRingNo`；每次校验：
   - 验签（常量时间比较），失败 → `bad_signature`；
   - 时间戳 ±5 分钟窗口，超出 → `timestamp_expired`；
   - 每设备 nonce 去重，重复 → `replay_detected`（先验签再查重，伪造请求烧不掉 nonce）；
   - 校验棚 ≠ 设备绑定棚 → `cross_loft_denied`；鸽只不符 → `pigeon_mismatch`；
   - 通过与拒绝都落审计记录 `GET /api/rings/verifications`（棚管员只见本棚）。
4. **轮换** `POST /api/rings/devices/:id/rotate`：携带当前 `keyVersion`（乐观并发控制），
   旧密钥立即失效，新密钥仅返回一次。
5. **报失/报损** `POST /api/rings/devices/:id/report`（本棚）：设备立即失效、密钥注销。
6. **撤销** `POST /api/rings/devices/:id/revoke`（管理员）：立即失效、不可逆。

并发激活/轮换/撤销经进程内互斥 + 乐观版本号保证只成功一次；
存储为「临时文件 fsync + 原子 rename」，写失败整体回滚，不留半条记录；
重启后设备、凭证状态、当前密钥、nonce 与校验记录全部从磁盘恢复。

## 命令行

```bash
node cli.js issue E2026-0001 CHN-2026-001
node cli.js activate <voucher> --keeper keeper-beian
node cli.js verify <deviceId> --key <deviceKey> --loft 北岸A棚
node cli.js verify <deviceId> --key <deviceKey> --cross 种鸽棚   # 跨棚拦截演示
node cli.js rotate <deviceId> --keeper keeper-beian
node cli.js report <deviceId> lost --keeper keeper-beian
node cli.js revoke <deviceId> --admin
node cli.js devices --admin
node cli.js verifications --admin
```

浏览器打开 `http://localhost:3024`：左上角切换管理员/棚管员身份，可直接完成发环、激活、
正常校验、跨棚/重放/篡改/过期演示、轮换与撤销，密钥保存在本浏览器 localStorage。

数据文件：`data/pigeons.json`（鸽只档案）、`data/rings.json`（设备 + nonce + 校验记录）。
