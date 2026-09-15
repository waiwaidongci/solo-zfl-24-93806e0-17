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

并发激活/轮换/撤销经进程内互斥 + 强制乐观版本号保证只成功一次：
轮换必须携带当前 `keyVersion`，缺字段 → `400 missing_version`，旧版本 → `409 version_conflict`。
存储为「临时文件 fsync + 原子 rename」，写失败整体回滚，不留半条记录；
重启后设备、凭证状态、nonce 与校验记录全部从磁盘恢复。

### 密钥安全（密文落盘 + 旧数据安全升级）

- 设备 HMAC 密钥**只在内存中为明文**；落盘时以 AES-256-GCM 信封 `serverKeyEnc`（随机 IV +
  auth tag）写入，磁盘任何位置都不出现明文密钥。
- 主密钥来自环境变量 `RING_MASTER_KEY`（64 位 hex 或任意口令，口令经 SHA-256 派生），
  缺省时首启自动生成 `data/master.key`（32 字节随机，权限 `0600`）。主密钥需妥善备份，
  更换/丢失主密钥后历史密文无法解开（fail-fast 拒绝启动），设备需重新激活。
- **旧版本数据安全升级**：旧文件中的明文 `serverKey` 在启动加载时被检测，
  当次启动内原子重写为密文信封，明文随即从磁盘消失；升级后老设备无需重新发放即可继续校验。


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

## 测试

```bash
npm test   # 27 项，显式列出测试文件，Node 20 / 22 均可直接运行
```

覆盖：全生命周期、一次性凭证、同环/同鸽唯一、跨棚激活与校验、验签/时间窗/nonce 重放、
并发激活/轮换/撤销只成功一次、落盘失败原子回滚、重启保留（含重启后重放拦截）、
密钥 GCM 信封加解密与防篡改、磁盘全文扫描无明文密钥、缺字段/旧版本轮换拒绝、
旧明文数据启动升级、错误主密钥 fail-fast、真实 HTTP 进程全链路。

数据文件：`data/pigeons.json`（鸽只档案）、`data/rings.json`（设备密文信封 + nonce +
校验记录）、`data/master.key`（主密钥，0600，已在 .gitignore）。


