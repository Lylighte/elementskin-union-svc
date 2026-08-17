# union-svc Webhook 向 element-skin 对齐 — 修改计划

> 日期：2026-08-17
> 目标：修改 `elementskin-union-svc` 的 Webhook 实现，使其接收端向 element-skin 主站
> （skin-backend）的出站 Webhook 标准对齐。
> 已确认方向：**全部对齐**（接收格式、认证、回查路径），且 **union-svc 回查 name**。

---

## 1. 对齐目标（element-skin 主站出站 Webhook 标准）

element-skin 主站通过 outbox + worker 向第三方应用投递标准 Webhook（见
`Webhook设计与开发者契约.md` 与 `skin-backend/internal/service/webhook/worker.go`）：

### 1.1 请求信封（HTTP body）

```json
{
  "id": "evt_...",
  "type": "profile.created",
  "created_at": 1786118399000,
  "data": {
    "user_id": "...",
    "profile_id": "..."
  }
}
```

### 1.2 请求头

```http
POST /element-skin HTTP/1.1
Content-Type: application/json
Webhook-Id: evt_...
Webhook-Delivery: whd_...
Webhook-Timestamp: 1786118400123
Webhook-Signature: v1=hex(HMAC-SHA256(secret, timestamp + "." + raw_body))
```

### 1.3 认证与验证

- 签名：`v1=hex(HMAC-SHA256(signing_secret, Webhook-Timestamp + "." + raw_body))`
- 时间戳窗口：允许约 5 分钟时钟偏差
- 幂等键：`Webhook-Id`（接收方应以它作为业务幂等键）
- 恒定时间比较

### 1.4 profile 事件类型与 data

| 事件类型 | data | 说明 |
|---|---|---|
| `profile.created` | `{"user_id","profile_id"}` | 角色创建 |
| `profile.updated` | `{"user_id","profile_id"}` | 角色变化（name/texture_model/skin_hash/cape_hash） |
| `profile.deleted` | `{"user_id","profile_id"}` | 角色删除 |

> **关键**：事件 data **不含 name**。union-svc 同步到 Hub 需要 name，因此必须**回查** element-skin。

---

## 2. 差距分析（union-svc 当前 vs element-skin 标准）

| 维度 | union-svc 当前 | element-skin 标准 | 差距 |
|---|---|---|---|
| 请求格式 | `{"action":"add","name":...,"uuid":...}` | 标准信封 `{id,type,created_at,data}` | **需重写** |
| 事件标识 | `action`（add/update/delete/full_sync） | `type`（profile.created/updated/deleted） | **需映射** |
| 角色标识 | `uuid` | `data.profile_id` | **需映射** |
| 认证 | `Authorization: Bearer {webhook_secret}` | `Webhook-Signature` HMAC + 时间戳 | **需重写** |
| 幂等 | 无 | `Webhook-Id` | **需新增** |
| name 来源 | 请求体直接带 `name` | 事件 data 无 name，需回查 | **需新增回查** |
| full_sync 回查路径 | `/v1/admin/profiles` | element-skin 实际为 `/v2/admin/profiles` | **需修正** |
| 全量同步触发 | `action=full_sync` | 无对应事件；由管理员/其他机制触发 | **需保留独立入口** |

---

## 3. 修改方案

### 3.1 新增 Webhook 验证器（对齐 element-skin 签名）

新增 `internal/server/webhookverify.go`（或 `internal/webhook/` 包），实现 element-skin 标准的
HMAC 签名验证：

- 读取原始 body（不先解析再重序列化）。
- 校验 `Webhook-Timestamp` 与当前时间差 ≤ 5 分钟。
- 计算 `v1=hex(HMAC-SHA256(secret, timestamp + "." + raw_body))`，用恒定时间比较。
- 校验 `Webhook-Id` 与 body 内 `id` 一致。
- 校验 `type` 属于已知 profile 事件。

参考实现：`python-sdk/src/element_skin_sdk/webhook/verifier.py`（`WebhookVerifier`）。

### 3.2 重写 `handleProfileSyncWebhook`（`internal/server/webhook.go`）

将当前基于 `action` 的分发改为基于 element-skin 事件 `type` 的分发：

| element-skin 事件 | union-svc 行为 | 对 Hub 调用 |
|---|---|---|
| `profile.created` | 回查 name → 通知 Hub 新增 | `POST /profile` `{id, name}` |
| `profile.updated` | 回查 name → 通知 Hub 改名 | `PUT /profile/{uuid}` `{name}` |
| `profile.deleted` | 通知 Hub 删除 | `DELETE /profile/{uuid}` |
| （无对应事件） | 全量同步 | `POST /sync` `{profileList}` |

**回查 name**：收到 `profile.created` / `profile.updated` 后，用服务账号 token 调用
element-skin `GET /v2/minecraft/profiles/{profile_id}` 获取 name。

> **为什么不能用 `/v2/admin/profiles` 回查**：该端点的 `q` 参数按 `name`/`email`/`display_name`
> 做 `ILIKE` 模糊搜索（`database/profile/list.go:60`），**不支持按 `profile_id` 查询**，且主站无
> `GET /v2/admin/profiles/{profile_id}` 端点。回查 name 只能用 `GET /v2/minecraft/profiles/{profile_id}`。
> 该端点需要 `minecraft_profile.read.public` 权限（见 3.5 配置）。

回查失败处理：

- `profile.created` 回查失败（profile 不存在）→ 记日志并返回失败，等待主站重试（至少一次投递）。
- `profile.updated` 回查失败（profile 已被删除）→ 按 `delete` 处理（profile 已不存在，通知 Hub 删除）。
- `profile.deleted` **无需回查**，直接 `DELETE /profile/{uuid}`。

**幂等**：以 `Webhook-Id` 为幂等键。element-skin 主站是「至少一次」投递，可能重复发送相同
`Webhook-Id`，**必须**在 SQLite 新增 `webhook_processed` 表记录已处理的 `Webhook-Id` 做去重，
**不能依赖 Hub 侧幂等**（`POST /profile` 重复可能导致重复创建）。

### 3.3 修正 full_sync 回查路径（`internal/bridge/elementskin.go`）

将 `ListAllProfiles` 的请求路径从 `/v1/admin/profiles` 改为 `/v2/admin/profiles`，对齐
element-skin 实际路由。响应格式（`items`/`has_next`/`next_cursor`/`page_size`）已兼容，
cursor 直接透传（element-skin 返回的 `next_cursor` 已是 base64 编码，原样传回即可）。

该端点需要 `profile.read.any` 权限（union-svc 服务账号已具备）。

### 3.4 全量同步入口

element-skin 标准事件目录中没有 `full_sync` 事件。全量同步**只保留**管理端点
`POST /api/union/admin/sync`（已有，`withAdminAPIKey` 认证）作为独立入口，
**不保留** `profile-sync` 端点对 `{"action":...}` 旧格式的兼容处理（避免双格式维护）。

### 3.5 配置

- `union.webhook_secret` 语义从「Bearer token」改为「HMAC signing secret」，与 element-skin
  主站配置的 `signing_secret` 一致。
- 新增可选配置：时间戳容差（默认 5 分钟）。
- **`service_account.scope` 从 `profile.read.any` 改为 `profile.read.any minecraft_profile.read.public`**
  （空格分隔多 scope；element-skin 主站 `token_grants.go` 用 `strings.Fields` 解析，支持多 scope）。
  新增的 `minecraft_profile.read.public` 用于回查 name（见 3.2）。

### 3.6 element-skin 主站侧配置（实施前提）

以下配置必须在 element-skin 主站（skin-backend）完成，否则事件不会投递到 union-svc：

1. **权限授予**：union-svc 服务账号应用（confidential，Client Credentials）申请并经管理员审核
   授予 `client:{client_id}` 主体以下权限：
   - `profile.read.any`（接收全站 profile 事件的前提）
   - `minecraft_profile.read.public`（回查 name 的前提；`ScopePublic`，属于 `appOnlyDefinitions`，
     Client Credentials 可持有）
2. **webhook endpoint 配置在服务账号应用上**（不是用户授权应用）：
   - URL 指向 union-svc 的 `POST /api/union/webhook/profile-sync`
   - 订阅 `profile.created` / `profile.updated` / `profile.deleted`
   - `signing_secret` 与 union-svc 的 `webhook_secret` 一致
   - 依据：`profile.*` 事件的 app-only 权限 `profile.read.any` 只允许 confidential client 订阅
     （`service/oauth/webhook_configuration.go:119`），且只有 app-only 路径能接收**全站**事件。
3. **权限持续有效**：element-skin 主站 worker 投递前会**重检权限**（`endpointAuthorized`，
   `service/webhook/worker.go:346`），若 `client:{client_id}` 主体失去 `profile.read.any`，
   事件会停止投递（标记 dead）。union-svc 服务账号必须持续保持上述权限。

---

## 4. 文件级修改清单

| 文件 | 修改 |
|---|---|
| `internal/server/webhook.go` | 重写：HMAC 验证 + 事件 type 分发 + 回查 name + 幂等去重 |
| `internal/server/webhookverify.go`（新增） | element-skin 标准签名/时间戳/信封验证 |
| `internal/server/webhook_store.go`（新增） | SQLite `webhook_processed` 表（`Webhook-Id` 幂等去重） |
| `internal/server/webhook_test.go` | 重写测试：对齐 element-skin 信封 + 签名验证 |
| `internal/bridge/elementskin.go` | `/v1/admin/profiles` → `/v2/admin/profiles`；新增按 profile_id 回查 name（`GET /v2/minecraft/profiles/{profile_id}`） |
| `internal/bridge/bridge.go` | 新增 `GetProfileNameByID`（用服务账号 token 调 `/v2/minecraft/profiles/{profile_id}`） |
| `internal/union/profiles.go` | 基本不变（SyncProfileAdd/Update/Delete 已对齐 Hub） |
| `internal/config/config.go` | `webhook_secret` 语义调整；新增时间戳容差配置；`service_account.scope` 默认值改为 `profile.read.any minecraft_profile.read.public` |
| `config.yaml.example` | 更新 `webhook_secret` 注释；更新 `service_account.scope` 默认值 |
| `doc/API契约.md` §8 | 更新 Webhook 端点契约为 element-skin 标准 |
| `doc/Webhook对齐报告.md` | 更新为对齐后的契约 |

---

## 5. 测试计划

### 5.1 验证器测试（新增）

- 正确签名通过。
- 错误签名失败（401）。
- 时间戳超窗失败（401）。
- `Webhook-Id` 与 body `id` 不一致失败。
- 未知事件 type 失败。

### 5.2 端点测试（重写）

- `profile.created` → 回查 name → `POST /profile`。
- `profile.updated` → 回查 name → `PUT /profile/{uuid}`。
- `profile.deleted` → `DELETE /profile/{uuid}`。
- 回查 name 失败（profile 不存在）时的处理。
- 幂等：相同 `Webhook-Id` 重复投递只处理一次。
- Hub 失败 → 500。

### 5.3 回查路径测试

- `ListAllProfiles` 请求 `/v2/admin/profiles`（而非 `/v1`）。
- 分页 cursor 透传正确。
- 回查 name 请求 `GET /v2/minecraft/profiles/{profile_id}`（服务账号 token，`minecraft_profile.read.public`）。

### 5.4 配置与前提测试

- `service_account.scope` 默认值为 `profile.read.any minecraft_profile.read.public`。
- 配置校验：`webhook_secret` 必填、时间戳容差合法。

---

## 6. 兼容性与迁移

- **破坏性变更**：union-svc 的 `profile-sync` 端点请求格式从自定义 `action` 改为 element-skin
  标准信封，旧 `{"action":...}` 格式**不再支持**（避免双格式维护）。调用方（element-skin 主站）
  需同步改造。
- **element-skin 主站侧**：需在**服务账号应用**上配置出站 Webhook endpoint（订阅
  `profile.created`/`profile.updated`/`profile.deleted`），配置 `signing_secret` 与 union-svc
  的 `webhook_secret` 一致，并授予服务账号 `profile.read.any` + `minecraft_profile.read.public`
  （见 3.6 实施前提）。
- **权限依赖**：element-skin 主站 worker 投递前会重检权限；服务账号权限被撤销时事件投递停止。
- **幂等**：union-svc 新增 `webhook_processed` 表；已有部署需迁移（建表即可，无需迁移旧数据）。
- **全量同步**：只保留 `POST /api/union/admin/sync` 管理入口，不依赖标准事件。

---

## 7. 待确认

- `profile.updated` 回查 name 成功但 name 未变（如仅皮肤变化触发的事件）时，是否仍 PUT 到 Hub
  （建议：直接 PUT，依赖 Hub 幂等；已按此写入 3.2）。
- `webhook_processed` 表的保留期限与清理策略（建议：仅保留最近 N 天，避免无限增长）。

---

## 8. 审阅意见记录（2026-08-17，对照 element-skin 主站代码验证）

> 以下问题经对照 `skin-backend` 实际代码验证。**问题与修正均已整合进正文（第 3、4、5、6 节）**，
> 本节仅作为验证依据与决策记录保留。

### 8.1 [严重] 回查 name 的 API 选择与权限前提

**问题**：计划 3.2 提出用 `GET /v2/minecraft/profiles/{profile_id}` 或 `/v2/admin/profiles?q=` 回查 name，但：

1. `GET /v2/admin/profiles` 的 `q` 参数按 `name`/`email`/`display_name` 做 `ILIKE` 模糊搜索
   （`database/profile/list.go:60`），**不支持按 `profile_id` 查询**；且无
   `GET /v2/admin/profiles/{profile_id}` 端点。因此**不能用 admin profiles 回查 name**。
2. `GET /v2/minecraft/profiles/{profile_id}` 需要 `minecraft_profile.read.public` 权限
   （`service/minecraft/minecraft.go:19`），而 union-svc 服务账号当前**只申请了
   `profile.read.any`**，**没有** `minecraft_profile.read.public`。

**修正**：
- 回查 name **必须**用 `GET /v2/minecraft/profiles/{profile_id}`。
- union-svc 服务账号应用需**额外申请** `minecraft_profile.read.public` 权限，并经管理员审核
  授予 `client:{client_id}` 主体。
- `minecraft_profile.read.public` 的 scope 是 `ScopePublic`，属于 `appOnlyDefinitions()`
  （`permission/roles.go:264`），Client Credentials 可持有，方案可行。
- union-svc 配置 `service_account.scope` 从 `profile.read.any` 改为
  `profile.read.any minecraft_profile.read.public`（空格分隔多 scope，element-skin 主站
  `token_grants.go` 用 `strings.Fields` 解析，支持多 scope）。

### 8.2 [严重] webhook endpoint 必须配置在服务账号应用上

**问题**：计划未明确 webhook endpoint 应配置在哪个 OAuth 应用上。

**验证**：
- `profile.created`/`profile.updated`/`profile.deleted` 的 app-only 权限是 `profile.read.any`，
  只允许 **confidential client** 订阅（`service/oauth/webhook_configuration.go:119`）。
- union-svc 有两个 OAuth 应用：用户授权应用（`account.read.self` + `profile.read.owned`）和
  服务账号应用（`profile.read.any`，Client Credentials，confidential）。
- 要接收**全站**所有用户的 profile 事件，必须走 app-only 路径，因此 webhook endpoint **必须
  配置在服务账号应用上**。

**修正**：在计划「element-skin 主站侧配置」中明确：webhook endpoint 配置在服务账号应用上，
订阅 `profile.created`/`profile.updated`/`profile.deleted`，`signing_secret` 与 union-svc 的
`webhook_secret` 一致。

### 8.3 [严重] element-skin 主站投递前权限重检

**问题**：计划未提及 element-skin 主站 worker 在投递前会**重检权限**（`endpointAuthorized`）。

**验证**：`service/webhook/worker.go:346` 的 `endpointAuthorized` 对 app-only 事件会检查
`client:{client_id}` 主体是否仍拥有 `profile.read.any`。若管理员后续撤销该权限，事件会停止投递
（标记 dead），而非继续泄露。

**修正**：计划应说明此依赖——union-svc 服务账号必须持续保持 `profile.read.any`（和
`minecraft_profile.read.public`）权限，否则事件投递会停止。

### 8.4 [中] `profile.updated` 触发条件包含非 name 变化

**问题**：`profiles_webhook_event` 触发器是
`AFTER UPDATE OF name, texture_model, skin_hash, cape_hash`（`database/schema.go:897`），
即皮肤/材质变化也会触发 `profile.updated`。

**影响**：union-svc 收到 `profile.updated` 后回查 name，若 name 未变，`PUT /profile/{uuid}` 是
无意义的（但 Hub 侧应幂等，无害）。

**修正**：计划应明确 `profile.updated` 的处理策略——直接回查 name 并 PUT（依赖 Hub 幂等），
还是与 Hub 现有值比较后决定是否 PUT。建议直接 PUT，保持简单。

### 8.5 [中] `profile.deleted` 回查问题

**问题**：`profile.deleted` 事件 data 含 `profile_id`，union-svc 直接 `DELETE /profile/{uuid}`
即可，**无需回查 name**。计划 3.2 的表格已正确区分（deleted 不回查），但 8.1 的回查 API 修正
应明确：只有 `profile.created`/`profile.updated` 需要回查 name。

### 8.6 [低] `full_sync` 回查路径修正的响应格式

**验证**：`/v2/admin/profiles` 响应字段 `items`/`has_next`/`next_cursor`/`page_size` 与 union-svc
`adminProfilesResponse`（`bridge/elementskin.go:41`）**完全兼容**，cursor 直接透传可行
（element-skin 返回的 `next_cursor` 已是 base64 编码，union-svc 原样传回即可）。
计划 3.3 的判断正确，无需额外修改。

### 8.7 [低] 幂等去重的必要性

**问题**：element-skin 主站是「至少一次」投递，可能重复发送相同 `Webhook-Id`。

**验证**：union-svc 当前 SQLite 仅存 session，无去重表。若不持久化 `Webhook-Id`：
- `profile.created` 重复 → Hub 侧 `POST /profile` 可能创建重复（取决于 Hub 幂等）。
- `profile.updated` 重复 → 幂等（PUT）。
- `profile.deleted` 重复 → 取决于 Hub 是否容忍删除不存在的 profile。

**修正**：建议在 SQLite 新增 `webhook_processed(event_id, processed_at)` 表做去重，避免依赖
Hub 侧幂等。这是计划 3.2 已提及的，审阅确认其必要性。

---

## 9. 修正后的实施前提清单

实施前必须满足（element-skin 主站侧）：

1. union-svc 服务账号应用申请并经管理员授予：
   - `profile.read.any`（接收全站 profile 事件，webhook 订阅前提）
   - `minecraft_profile.read.public`（回查 name）
2. 在服务账号应用上配置 webhook endpoint：
   - URL 指向 union-svc 的 `POST /api/union/webhook/profile-sync`
   - 订阅 `profile.created`/`profile.updated`/`profile.deleted`
   - `signing_secret` 与 union-svc 的 `webhook_secret` 一致
3. union-svc 服务账号持续保持上述权限，否则事件投递会停止。
