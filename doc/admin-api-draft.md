# Admin API 管理面板端点 - 计划草稿

> 状态：草稿（待 Prometheus 细化为完整 work plan）
> 目标：为 union-svc 新增管理员 API，支持全站角色投送和 Union 网络管理操作

## 背景

当前 union-svc 角色同步依赖 Hub 推送（`POST /api/union/member/sync`）或用户手动操作。管理员无法主动触发全站角色投送或执行 Union 网络管理操作。PHP/Python 实现有完整的管理面板端点，Go 版缺失。

## 已有基础设施

### 认证
- `withAdminAPIKey` 中间件已实现（`blacklist_admin.go`），`subtle.ConstantTimeCompare` 常量时间比较
- 黑名单管理端点已使用此中间件

### Hub Client 方法（全部已实现，`internal/union/`）

| 方法 | Hub API | 用途 |
|---|---|---|
| `FetchServerList(ctx)` | `GET /serverlist` | 拉取服务器列表 |
| `FetchPrivateKey(ctx)` | `GET /privatekey` | 拉取共享私钥 |
| `SyncProfiles(ctx, profileList)` | `POST /sync` | 全量角色同步 |
| `SyncProfileAdd(ctx, name, uuid)` | `POST /sync/profile/add` | 增量添加 |
| `SyncProfileUpdate(ctx, uuid, name)` | `POST /sync/profile/update` | 增量更新 |
| `SyncProfileDelete(ctx, uuid)` | `POST /sync/profile/delete` | 增量删除 |
| `GetOAuth2BackendPublicKey(ctx)` | `GET /oauth2/backend` | Hub OAuth2 公钥 |
| `ProxyToHub(ctx, method, path, body)` | 通用代理 | 透传 Hub 响应 |
| `SearchBlacklist(ctx, query)` | 黑名单查询 | 已有端点 |
| `CreateBlacklist(ctx, entry)` | 黑名单创建 | 已有端点 |
| `DeleteBlacklist(ctx, entryID)` | 黑名单删除 | 已有端点 |
| `InvalidateBlacklist(ctx, entryID)` | 黑名单失效 | 已有端点 |

### Bridge 方法（已实现，`internal/bridge/`）

| 方法 | 用途 |
|---|---|
| `ListAllProfilesForSync(ctx)` | 用服务账号 token 调 element-skin `GET /v1/admin/profiles` 全量拉取本地角色 |

### Settings Store（已实现，`internal/union/settings.go`）

| 方法 | 用途 |
|---|---|
| `Get(ctx, key)` | 读取运行时配置（member_key、版本号等） |
| `Set(ctx, key, value)` | 写入运行时配置 |

## 需新增的 Admin API 端点

全部用 `withAdminAPIKey` 认证，路径前缀 `/api/union/admin/`。

### Tier 1: 全站角色投送（核心需求）

| 方法 | 路径 | 调用链 | 说明 |
|---|---|---|---|
| `POST` | `/api/union/admin/sync` | `bridge.ListAllProfilesForSync` → `unionClient.SyncProfiles` | 管理员主动触发全站角色投送到 Hub。复用 `handleSync`（Hub 推送触发）的逻辑，但从 admin API 入口调用。 |

### Tier 2: Union 网络管理操作

| 方法 | 路径 | 调用链 | 说明 |
|---|---|---|---|
| `POST` | `/api/union/admin/update-list` | `unionClient.FetchServerList` → 存 settings | 手动拉取服务器列表，不等 Hub 推送 |
| `POST` | `/api/union/admin/update-key` | `unionClient.FetchPrivateKey` → 存 settings | 手动拉取共享私钥 |
| `POST` | `/api/union/admin/diagnose` | `unionClient.ProxyToHub("POST", "/diagnose", nil)` | 手动触发 Hub 诊断 |
| `GET` | `/api/union/admin/status` | 读 settings store + 检查 Hub 连通性 | 返回当前 Union 状态：member_key 是否已配置、serverlist 版本、privatekey 版本、Hub 是否可达 |

### Tier 3: OAuth2 密钥管理

| 方法 | 路径 | 调用链 | 说明 |
|---|---|---|---|
| `POST` | `/api/union/admin/regenerate-keypair` | 删除 PEM 文件 → `union.EnsureSigKeyPair` 重新生成 | 轮换 OAuth2 签名密钥 |
| `GET` | `/api/union/admin/keypair-fingerprint` | 读公钥 PEM → SHA256 指纹 | 查看当前签名密钥指纹（不泄露密钥本身） |

### 已有端点（不需改动）

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET/POST/PUT/DELETE` | `/api/union/admin/blacklist/*` | 黑名单 CRUD，已实现 |

## 与 Hub 推送端点的关系

Hub 推送端点（`/api/union/member/*`，`withUnionVerify` 认证）和管理员端点（`/api/union/admin/*`，`withAdminAPIKey` 认证）是两个独立入口，调用相同的底层方法：

| 操作 | Hub 推送入口 | Admin API 入口 |
|---|---|---|
| 角色同步 | `POST /api/union/member/sync` → `handleSync` | `POST /api/union/admin/sync` → `handleAdminSync`（新增） |
| 拉取 server list | `POST /api/union/member/updatelist` → `handleUpdateList` | `POST /api/union/admin/update-list` → `handleAdminUpdateList`（新增） |
| 拉取私钥 | `POST /api/union/member/updateprivatekey` → `handleUpdatePrivateKey` | `POST /api/union/admin/update-key` → `handleAdminUpdateKey`（新增） |
| 诊断 | `POST /api/union/member/diagnose` → `handleDiagnose` | `POST /api/union/admin/diagnose` → `handleAdminDiagnose`（新增） |

Hub 推送是 Hub 主动发起（RSA 签名验证），Admin API 是管理员主动发起（API Key 验证）。两条路径复用底层 Hub client 方法。

## 实现要点

1. **全站角色投送** `POST /api/union/admin/sync`：
   - 调 `bridge.ListAllProfilesForSync(ctx)` 拉取 element-skin 全量角色（服务账号 token）
   - 转为 `map[string]string`（name → uuid）
   - 调 `unionClient.SyncProfiles(ctx, profileList)` 推送到 Hub
   - 返回同步的角色数量和 Hub 响应

2. **状态查询** `GET /api/union/admin/status`：
   - 读 settings store：member_key、serverlist_version、privatekey_version
   - 检查 Hub 连通性：调 `FetchServerList` 或简单 HEAD
   - 返回 JSON 状态

3. **密钥轮换** `POST /api/union/admin/regenerate-keypair`：
   - 删除 PEM 文件
   - 调 `union.EnsureSigKeyPair` 重新生成
   - 返回新公钥指纹

4. **错误处理**：
   - Hub 不可达 → 502
   - element-skin 不可达（仅 sync） → 502
   - 配置缺失 → 503

## 不在本次范围

- 前端管理面板 UI（Python/PHP 有 Vue/Blade 页面，Go 版仅 API）
- element-skin 侧 webhook 发送（用户手动投送角色）
- 运行时修改 config.yaml（需要重启生效的配置项仍需手动改文件）
- 通知/日志系统

## 验证策略

- 每个端点补充测试：认证失败（401）、Hub 故障（502）、成功响应
- `go build + go test + go vet + gofmt` 全绿
- Admin API 端点用 `withAdminAPIKey` 包装，`grep` 确认无裸露路由
