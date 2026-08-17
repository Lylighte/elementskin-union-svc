# union-svc API 契约

> v1.0 | 面向 union-svc 所有端点的权威文档

## 1. 健康检查

### `GET /health`

**认证**：无

**响应**：`{"status":"ok"}`

---

## 2. OAuth 授权流程

### `GET /oauth/authorize`

OAuth 授权入口。构造授权 URL 并跳转到 Element-Skin。

**认证**：无

**响应**：302 重定向到 Element-Skin OAuth 端点。

### `GET /oauth/callback`

OAuth 回调端点。处理 Element-Skin 返回的授权码，创建 Session Cookie。

**认证**：无（但校验 state 参数）

**响应**：302 重定向并设置 `union_svc_session` Cookie。

---

## 3. Profiles API

### `GET /api/profiles?username={name}`

查询用户在 Union Hub 中的角色档案列表。

**认证**：`withBearerToken`（`Authorization: Bearer {element-skin token}`）

**请求参数**：

| 参数 | 位置 | 类型 | 必填 | 说明 |
|------|------|------|------|------|
| `username` | Query | string | 是 | 角色名称 |

**响应示例**（200）：

```json
{
  "items": [
    {"uuid": "u1", "name": "Steve"}
  ]
}
```

**错误**：

| 状态码 | detail | 说明 |
|--------|--------|------|
| 400 | username is required | 未提供 username 参数 |
| 401 | unauthorized | 无效或缺失 Bearer Token |
| 502 | failed to list union profiles | Union Hub 不可用 |

---

## 4. Union Hub 回调（Member 端点）

所有 `/api/union/member/*` 端点（不含 `oauth2/*`）使用 `withUnionVerify` 中间件验证 Hub RSA 签名。

### `GET /api/union/member/`

hello 端点，返回成员站基础信息。

**认证**：无（公开端点）

**CORS**：受 `CORSAllowOrigin` 配置影响

**响应示例**（200）：

```json
{
  "hello": "union member server",
  "version": "1.0.0",
  "links": {
    "oauth2_sig_public_key": "/api/union/member/oauth2/"
  }
}
```

### `POST /api/union/member/updatelist`

更新成员列表。由 Hub 调用。

**认证**：`withUnionVerify`（Hub RSA 签名）

### `POST /api/union/member/updateprivatekey`

更新成员私钥。由 Hub 调用。

**认证**：`withUnionVerify`

### `POST /api/union/member/updatebackendkey`

更新后端密钥。由 Hub 调用。

**认证**：`withUnionVerify`

### `POST /api/union/member/sync`

同步角色档案到 Hub。会查询 Element-Skin 的实际档案列表并与 Hub 同步。

**认证**：`withUnionVerify`

### `GET /api/union/member/queryemail?username={name}`

根据角色名称查询邮箱。由 Hub 调用。

**认证**：`withUnionVerify`

### `POST /api/union/member/diagnose`

诊断端点。由 Hub 调用。

**认证**：`withUnionVerify`

---

## 5. OAuth2 跨站授权端点

### `GET /api/union/member/oauth2/`

获取 OAuth2 签名公钥。

**认证**：无（公开端点）

**CORS**：受 `CORSAllowOrigin` 配置影响

**响应示例**（200）：

```json
{
  "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

### `GET /api/union/member/oauth2/grant?state={state}`

OAuth2 授权 grant 端点。需要 Session Cookie（来自 `/oauth/callback`）。

**认证**：Session Cookie

**CORS**：受 `CORSAllowOrigin` 配置影响

**请求参数**：

| 参数 | 位置 | 类型 | 必填 | 说明 |
|------|------|------|------|------|
| `state` | Query | string | 是 | 授权 state |

**响应**：302 重定向到 Hub，携带 `userInfoToken` 加密参数。

---

## 6. 管理接口（Admin 端点）

所有 `/api/union/admin/*` 端点使用 `withAdminAPIKey` 中间件验证 API Key。

### `GET /api/union/admin/blacklist?status={status}&page_size={size}`

查询黑名单。代理到 Hub。

**认证**：`withAdminAPIKey`（`Authorization: Bearer {admin_api_key}`）

### `POST /api/union/admin/blacklist`

创建黑名单记录。代理到 Hub。

**认证**：`withAdminAPIKey`

### `PUT /api/union/admin/blacklist/invalidate/{id}`

失效黑名单记录。代理到 Hub。

**认证**：`withAdminAPIKey`

### `DELETE /api/union/admin/blacklist/{id}`

删除黑名单记录。代理到 Hub。

**认证**：`withAdminAPIKey`

---

## 7. 用户角色绑定端点

所有 `/api/union/profile/*` 端点使用 `withBearerToken` 中间件验证 Element-Skin token。

### `POST /api/union/profile/bind`

绑定用户角色到 Union Hub。

**认证**：`withBearerToken`

**请求体**：

```json
{"uuid": "profile-uuid-abc"}
```

### `POST /api/union/profile/unbind`

解除用户角色绑定。

**认证**：`withBearerToken`

**请求体**：

```json
{"uuid": "profile-uuid-abc"}
```

### `POST /api/union/profile/bindto`

绑定用户到指定角色的 Union 账号。

**认证**：`withBearerToken`

**请求体**：

```json
{"uuid": "profile-uuid-abc", "token": "target-union-token"}
```

### `GET /api/union/security/level`

获取当前用户的 Union 安全等级。

**认证**：`withBearerToken`

**响应示例**（200）：

```json
{"level": 0}
```

---

## 8. Webhook 端点

### `POST /api/union/webhook/profile-sync`

接收 Element-Skin 主站出站 Webhook 的标准事件回调，同步角色档案到 Hub。

**认证**：`withWebhookVerify`（Element-Skin 标准 HMAC-SHA256 签名）

**请求头**：

```http
Content-Type: application/json
Webhook-Id: evt_...
Webhook-Timestamp: 1786118400123
Webhook-Signature: v1=hex(HMAC-SHA256(webhook_secret, timestamp + "." + raw_body))
```

**请求体**（Element-Skin 标准事件信封）：

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

**支持的事件类型**：

| 事件类型 | union-svc 行为 | 对 Hub 调用 |
|---|---|---|
| `profile.created` | 回查 name → 通知 Hub 新增 | `POST /profile` `{id, name}` |
| `profile.updated` | 回查 name → 通知 Hub 改名 | `PUT /profile/{uuid}` `{name}` |
| `profile.deleted` | 通知 Hub 删除 | `DELETE /profile/{uuid}` |

- 事件 data 只携带 `user_id` 与 `profile_id`，union-svc 通过服务账号
  （`profile.read.any minecraft_profile.read.public`）回查角色名后同步到 Hub。
- 以 `Webhook-Id` 做幂等去重（SQLite `webhook_processed` 表）。
- 全量同步由管理端点 `POST /api/union/admin/sync` 触发，不通过 webhook 事件。

**响应示例**（200）：

```json
{"detail": "ok"}
```

**错误响应**：签名/时间戳验证失败返回 `401`；未知事件类型、`Webhook-Id` 不匹配返回 `400`；
回查或 Hub 同步失败返回 `502`。

---

## 9. 认证汇总

| 中间件 | 路径前缀 | 认证方式 | Header 格式 |
|--------|----------|----------|-------------|
| 无 | `/health` | 无 | — |
| 无 | `/oauth/*` | 无 / Session Cookie | — |
| 无 | `/api/union/member/`（hello） | 无 | — |
| 无 | `/api/union/member/oauth2/*` | 公开 / Session Cookie | — |
| `withUnionVerify` | `/api/union/member/*`（non-oauth2） | Hub RSA 签名 | 校验 Hub signature header |
| `withAdminAPIKey` | `/api/union/admin/*` | Config Key | `Authorization: Bearer {key}` |
| `withBearerToken` | `/api/union/profile/*`、`/api/profiles` | Element-Skin Token | `Authorization: Bearer {token}` |
| `withWebhookVerify` | `/api/union/webhook/*` | HMAC-SHA256 签名 | `Webhook-Signature` + `Webhook-Timestamp` |

> **CORS**：仅 `/api/union/member/`（hello）和 `/api/union/member/oauth2/*` 受 `CORSAllowOrigin` 配置影响。其余端点为内部通信，不设 CORS。

## 10. 错误响应格式

所有错误响应使用统一的 JSON 格式：

```json
{"detail": "错误描述"}
```

HTTP 状态码语义：

| 状态码 | 含义 |
|--------|------|
| 200 | 成功 |
| 400 | 请求参数错误 |
| 401 | 认证失败 |
| 500 | 内部服务器错误 |
| 502 | 上游服务不可用（Element-Skin 或 Hub） |
| 503 | 服务未就绪（Union Hub 未配置） |