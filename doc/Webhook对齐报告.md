# union-svc Webhook 对齐报告

> 日期：2026-08-17
> 考察对象：`elementskin-union-svc`（独立 Go sidecar）
> 上游参考：`tmp/yggdrasil-connect`（PHP 原版 Blessing Skin 插件）
> 目的：明确 union-svc 实际要求的 Webhook 契约，供 Element-Skin 主站（skin-backend）作为调用方对齐实现。

---

## 1. 结论摘要

union-svc 是 element-skin 为实现 Union 联邦功能而做的**外挂 sidecar 应用**。它独立部署后
**不再嵌入主站进程**，因此无法像 PHP 原版那样通过 Illuminate Event 监听
`PlayerWasAdded` / `PlayerProfileUpdated` / `PlayerWillBeDeleted` 事件。

它把「事件钩子」替换为**一个入站 Webhook 端点**：

```text
POST /api/union/webhook/profile-sync
```

**关键定位**：这个 Webhook 是 union-svc 对外暴露的**唯一**接收端点，其调用方**必须是
element-skin 主站（skin-backend）**。也就是说，union-svc 的 Webhook 要求，本质上是
「element-skin 主站需要在角色生命周期事件发生时，主动向 union-svc 推送 `profile-sync` 请求」。
本报告以 element-skin 作为调用方视角，明确 union-svc 期望收到的请求契约，以及 element-skin
应如何把自身角色事件映射为这些请求。

---

## 2. union-svc 实际要求的 Webhook 契约（已对齐 element-skin 标准）

### 2.1 端点与认证

| 项 | 值 |
|---|---|
| 方法 | `POST` |
| 路径 | `/api/union/webhook/profile-sync` |
| 认证 | Element-Skin 标准 HMAC-SHA256 签名 |
| 签名 | `Webhook-Signature: v1=hex(HMAC-SHA256(secret, timestamp + "." + raw_body))` |
| 时间戳 | `Webhook-Timestamp`，允许 5 分钟时钟偏差（可配置） |
| 幂等 | 以 `Webhook-Id` 做去重（SQLite `webhook_processed` 表） |
| 认证失败 | `401` |
| 无 CORS | 该端点为内部通信，不设置 CORS 头 |

`webhook_secret` 由 `openssl rand -hex 32` 生成，配置在 `union.webhook_secret`，**必须与
Element-Skin 主站出站 webhook endpoint 的 `signing_secret` 一致**。

### 2.2 请求头与请求体

```http
POST /api/union/webhook/profile-sync HTTP/1.1
Content-Type: application/json
Webhook-Id: evt_...
Webhook-Delivery: whd_...
Webhook-Timestamp: 1786118400123
Webhook-Signature: v1=...
```

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

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` / `Webhook-Id` | string | 稳定事件 ID，作为幂等键 |
| `type` | string | `profile.created` / `profile.updated` / `profile.deleted` |
| `data.profile_id` | string | 角色 UUID |
| `data.user_id` | string | 角色所属用户 UUID |

> 关键：事件 data **不含角色名**。union-svc 通过服务账号（`profile.read.any
> minecraft_profile.read.public`）回查 `GET /v2/minecraft/profiles/{profile_id}` 解析角色名。

### 2.3 支持的事件类型与 Hub 调用映射

| 事件类型 | union-svc 行为 | 对 Hub 的调用 |
|---|---|---|
| `profile.created` | 回查 name → 通知 Hub 新增 | `POST /profile`，body `{"id": uuid, "name": name}` |
| `profile.updated` | 回查 name → 通知 Hub 改名；回查不到则按删除处理 | `PUT /profile/{uuid}`，body `{"name": name}` 或 `DELETE /profile/{uuid}` |
| `profile.deleted` | 通知 Hub 删除（无需回查） | `DELETE /profile/{uuid}` |

> 全量同步不在 webhook 契约内，由管理端点 `POST /api/union/admin/sync` 触发。

### 2.4 响应

| 场景 | 状态码 | body |
|---|---|---|
| 成功（含幂等重复） | `200` | `{"detail":"ok"}` |
| 签名/时间戳验证失败 | `401` | `{"detail":"..."}` |
| 未知事件类型 / `Webhook-Id` 不匹配 | `400` | `{"detail":"..."}` |
| 回查不到角色（created） | `404` | `{"detail":"profile not found"}` |
| 回查或 Hub 同步失败 | `502` | `{"detail":"failed to sync profile"}` 等 |

---

## 3. full_sync 的完整链路（管理端点）

`full_sync` 不在 webhook 事件目录中，由 `POST /api/union/admin/sync`（`withAdminAPIKey` 认证）
触发，链路如下：

1. union-svc 用**服务账号**（Client Credentials，scope `profile.read.any`）获取 access token。
2. 调用 Element-Skin `GET /v2/admin/profiles?limit=100&next_cursor=...`，按 cursor 分页拉取全部角色
   （每页 100，直到 `has_next=false`，有最大页数保护）。
3. 组装 `profileList = {name: uuid}`。
4. 调用 Hub `POST /sync`，body `{"profileList": {...}}`。

因此，Element-Skin 主站若要支持 `full_sync`，其 `/v2/admin/profiles` 端点必须可被服务账号
（`profile.read.any`）访问，并支持 `limit` / `next_cursor` 分页。

---

## 4. 与 PHP 原版（tmp/yggdrasil-connect）的对应关系

### 4.1 事件钩子 → Webhook

PHP 原版在 `bootstrap.php` 中通过 Illuminate Event 监听三个事件，直接调用 Hub：

| PHP 事件 | PHP 行为（直接调 Hub） | Go sidecar 对应 |
|---|---|---|
| `App\Events\PlayerWasAdded` | `POST /profile` `{id, name}` | Webhook `profile.created` |
| `App\Events\PlayerProfileUpdated` | `PUT /profile/{uuid}` `{name}` | Webhook `profile.updated` |
| `App\Events\PlayerWillBeDeleted` | `DELETE /profile/{uuid}` | Webhook `profile.deleted` |
| 管理员手动触发 `triggerSync` | `POST /sync` `{profileList}` | 管理端点 `POST /api/union/admin/sync` |

### 4.2 认证差异

| 维度 | PHP 原版 | Go sidecar |
|---|---|---|
| 事件来源 | 主进程内 Illuminate Event | 外部 HTTP Webhook（element-skin 出站投递） |
| 认证 | 无（进程内直接调用） | Element-Skin 标准 HMAC-SHA256 签名（`Webhook-Signature`） |
| 与 Hub 通信认证 | `X-Union-Member-Key` header | 仍用 `X-Union-Member-Key`（union-svc 内部处理） |

> 关键点：PHP 原版的事件监听发生在**主站进程内**，无需认证；Go sidecar 独立部署后，
> 主站必须通过 Webhook 端点把角色事件**推送**给 union-svc，因此对齐 element-skin 出站
> Webhook 标准的 HMAC 签名认证。

---

## 5. 对 Element-Skin 主站（skin-backend）的调用方要求

> 现状核查：element-skin 主站（`skin-backend`）当前**没有任何 union-svc 集成代码**。
> 它现有的 Webhook 系统（`webhook_endpoints` / `webhook_events` / `webhook_deliveries` + worker）
> 是**出站**投递到第三方应用的，与 union-svc 的**入站** `profile-sync` 端点不是同一套机制。
> 要让 union-svc 工作，element-skin 主站需要在**服务账号应用**上配置出站 Webhook endpoint，
> 把角色事件投递给 union-svc。

### 5.1 配置

- 在 union-svc 的 `union.webhook_secret` 与 element-skin 主站出站 endpoint 的 `signing_secret`
  填入相同的值（`openssl rand -hex 32`）。
- union-svc 服务账号 scope 配置为 `profile.read.any minecraft_profile.read.public`。

### 5.2 推送时机与事件映射

element-skin 主站的角色生命周期事件本身就是标准事件，无需转换：

| element-skin 事件 | union-svc 处理 | 对 Hub 调用 |
|---|---|---|
| `profile.created` | 回查 name | `POST /profile` `{id, name}` |
| `profile.updated` | 回查 name | `PUT /profile/{uuid}` `{name}` |
| `profile.deleted` | 无需回查 | `DELETE /profile/{uuid}` |
| 全量同步（管理员触发） | 管理端点 | `POST /sync` `{profileList}` |

element-skin 主站已有对应的角色生命周期事件（`profile.created` / `profile.updated` /
`profile.deleted`，由 `profiles_webhook_event` 触发器产生），由 outbox worker 投递。

### 5.3 请求与响应处理

- 请求为 element-skin 标准信封（`id`/`type`/`created_at`/`data`），带 `Webhook-Id` /
  `Webhook-Delivery` / `Webhook-Timestamp` / `Webhook-Signature` 头。
- union-svc 以 `Webhook-Id` 幂等去重；element-skin 主站「至少一次」投递，重复事件会被丢弃。
- union-svc 端点是**同步**转发到 Hub 的（无 outbox/重试队列），非 `2xx` 时 element-skin 主站
  worker 会按指数退避重试。

---

## 6. 与 Element-Skin 主站 Webhook 契约（Webhook设计与开发者契约.md）的关系

> 注意区分两套「Webhook」概念，不要混淆：

| 维度 | Element-Skin 主站 Webhook（出站） | union-svc Webhook（入站） |
|---|---|---|
| 方向 | 主站 → 第三方应用（出站投递） | element-skin 主站 → union-svc（入站接收） |
| 端点 | 第三方应用配置的 endpoint | `POST /api/union/webhook/profile-sync` |
| 认证 | HMAC-SHA256 签名（`Webhook-Signature`） | 相同：HMAC-SHA256 签名（`Webhook-Signature`） |
| 事件 | `profile.created` / `profile.updated` / `profile.deleted` 等 | 相同的事件类型 |
| 语义 | 提示资源变化，应用自行回查 API | 直接转发角色同步到 Union Hub |
| 实现状态 | 已实现（outbox + worker） | union-svc 侧已对齐实现；element-skin 主站侧需配置 endpoint |

union-svc 的 Webhook 是**入站**接收端点，但已对齐 element-skin 主站出站 Webhook 的**同一套
信封、签名与事件类型契约**。element-skin 主站现有的出站 Webhook 系统可以把事件直接投递给
union-svc（在服务账号应用上配置 endpoint 即可），无需单独开发调用方（见第 5 节）。

---

## 7. 关键实现文件索引

| 文件 | 内容 |
|---|---|
| `internal/server/webhook.go` | Webhook 端点实现（HMAC 验证 + 事件 type 分发 + 回查 name + 幂等） |
| `internal/server/webhookverify.go` | element-skin 标准签名/时间戳/信封验证 |
| `internal/server/webhook_store.go` | SQLite `webhook_processed` 幂等去重表 |
| `internal/server/webhook_test.go` | Webhook 测试（认证、created/updated/deleted、幂等、回查） |
| `internal/union/profiles.go` | `SyncProfileAdd` / `SyncProfileUpdate` / `SyncProfileDelete` |
| `internal/union/client.go` | `SyncProfiles`（`/sync`） |
| `internal/bridge/bridge.go` | `ListAllProfilesForSync`、`GetProfileNameByID` |
| `internal/bridge/elementskin.go` | `ListAllProfiles`（`/v2/admin/profiles` 分页）、`GetProfileNameByID`（`/v2/minecraft/profiles/{id}`） |
| `doc/API契约.md` §8 | Webhook 端点契约 |
| `config.yaml.example` | `union.webhook_secret`、`union.webhook_timestamp_tolerance_seconds`、`service_account.scope` |

---

## 8. 待确认 / 建议

- **element-skin 主站侧配置**：在**服务账号应用**（confidential）上配置出站 Webhook endpoint，
  指向 union-svc 的 `POST /api/union/webhook/profile-sync`，订阅 `profile.created` /
  `profile.updated` / `profile.deleted`，`signing_secret` 与 union-svc 的 `webhook_secret` 一致。
- **权限前提**：服务账号应用需经管理员授予 `profile.read.any`（事件投递）和
  `minecraft_profile.read.public`（回查 name）；element-skin 主站 worker 投递前会重检权限，
  权限被撤销时事件投递停止。
- union-svc 的 Webhook 是**同步**转发到 Hub 的（无 outbox/重试队列），非 `2xx` 时由
  element-skin 主站 worker 按指数退避重试；重复事件由 union-svc 以 `Webhook-Id` 幂等丢弃。
- `full_sync` 由管理端点 `POST /api/union/admin/sync` 触发，依赖 element-skin
  `/v2/admin/profiles` 可被服务账号（`profile.read.any`）访问。
