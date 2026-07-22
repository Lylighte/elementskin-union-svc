# union-svc Go 实现手册

> 基于 Element-Skin 的 Go sidecar 实现，对应 PHP 插件 `yggdrasil-connect` 的成员站功能。
> 版本：v1.1 | 最后更新：2026-07-07

---

## 1. 架构定位

union-svc 是 Element-Skin 的独立 sidecar 服务，实现 Union 联邦协议中**成员站**的全部功能。与 PHP 参考实现（`yggdrasil-connect` Blessing Skin 插件）不同，union-svc 不嵌入 Blessing Skin 进程，而是通过 Element-Skin 的 OAuth2 和 HTTP API 独立运行。

```
┌──────────────────────┐                              ┌──────────────────────┐
│   MUA Union Hub      │    UnionHostVerify (签名)     │     union-svc         │
│   (PHP/BSS)          │ ──POST /api/union/member/*──→ │     (Go sidecar)      │
│                      │                              │                      │
│                      │ ←──X-Union-Member-Key──────── │                      │
└──────────────────────┘                              └──────────┬───────────┘
                                                                │ OAuth2 / HTTP API
                                                         ┌──────┴───────────┐
                                                         │   Element-Skin    │
                                                         │   (Go + Vue)     │
                                                         └──────────────────┘
```

**职责边界：**
- union-svc 实现：Hub 回调处理、黑名单代理、OAuth2 跨站授权、用户角色绑定、Webhook 同步
- union-svc 不实现：remapuuid（已弃用）、Union 前端页面、updateplugin

---

## 2. 与 PHP 实现的差异

### 2.1 架构差异

| 维度 | PHP (`yggdrasil-connect`) | Go (`union-svc`) |
|------|--------------------------|-------------------|
| 运行方式 | Blessing Skin 插件，嵌入主进程 | 独立 sidecar 进程 |
| 用户认证 | Blessing Skin Web Session | Element-Skin OAuth2 + Session Cookie |
| 管理员认证 | Blessing Skin Admin Session | Config Key（`Authorization: Bearer {admin_api_key}`） |
| OAuth2 页面 | PHP 模板渲染 HTML 页面 | 仅 JSON API，无 UI |
| 事件钩子 | Illuminate Event 监听 | Webhook 端点 |
| 黑名单管理 | 管理员 Web 页面 + API | 纯 API 代理到 Hub |
| 存储 | Blessing Skin 数据库 | 独立 SQLite |
| RSA 密钥 | 存储在 Blessing Skin 数据库 | 独立 PEM 文件 |

### 2.2 端点映射

| PHP 端点 | Go 端点 | 差异 |
|----------|---------|------|
| `GET /union/oauth2/sigPublicKey` | `GET /api/union/member/oauth2/` | 路径不同，协议相同 |
| `GET /union/oauth2/grant` | `GET /api/union/member/oauth2/grant` | 认证从 Session 改为 Session Cookie |
| `GET/POST/DELETE /admin/union/blacklist/*` | `* /api/union/admin/blacklist/*` | 管理员认证从 Session 改为 API Key |
| `POST /union/profile/bind` 等 | `POST /api/union/profile/*` | 用户认证改为 Bearer Token |
| Illuminate Event `ProfileUpdated` 等 | `POST /api/union/webhook/profile-sync` | 事件钩子 → Webhook |
| `GET /union` (用户面板) | 未实现 | 前端页面推迟到后续 fork |
| `POST /api/union/member/remapuuid` | 未实现 | 已弃用 |

### 2.3 OAuth2 加密实现

加密算法与 PHP 完全一致：

- **MAC**：`hex.EncodeToString(HMAC-SHA256(base64_userInfo, memberKey))`，对应 PHP `hash_hmac('sha256', ..., true)` 转 hex
- **签名**：`rsa.SignPKCS1v15(SHA256)`，对应 PHP `openssl_sign`（PKCS1v15, SHA256）
- **加密**：chunked `rsa.EncryptPKCS1v15`，chunk size = `keySize - 11`，对应 PHP `RSAPublicTrait::public_encrypt`

---

## 3. 模块结构

```
union-svc/
├── cmd/union-svc/           # 程序入口
├── internal/
│   ├── bridge/              # Element-Skin 客户端
│   │   └── elementskin.go   #   GetUserInfo, CreateProfile, ListAllProfiles 等
│   ├── config/              # 配置加载（YAML + 环境变量）
│   ├── oauth/               # OAuth2 令牌管理
│   ├── server/              # HTTP 路由与处理函数
│   │   ├── server.go        #   路由注册、Server 生命周期
│   │   ├── oauth.go         #   /oauth/authorize, /oauth/callback
│   │   ├── inbound.go       #   Hub 回调处理（sync, queryEmail 等）
│   │   ├── oauth2_union.go  #   OAuth2 端点（sigPublicKey, grant）
│   │   ├── blacklist_admin.go # 黑名单管理代理
│   │   ├── profile_union.go #   用户角色绑定
│   │   └── webhook.go       #   Webhook 同步端点
│   ├── session/             # Session 存储与 Cookie
│   │   ├── store.go         #   SQLite 存储
│   │   └── cookie.go        #   Cookie 读写
│   └── union/               # Union Hub 客户端
│       ├── client.go        #   ProxyToHub, 缓存, ProfileBind 等
│       ├── sigkeys.go       #   RSA 4096 密钥生成与持久化
│       └── ...
├── Dockerfile
├── docker-compose.yml
├── config.yaml.example
└── README.md
```

---

## 4. 认证机制一览

| 中间件 | 路径前缀 | 认证方式 | 说明 |
|--------|----------|----------|------|
| `withUnionVerify` | `/api/union/member/*`（回调） | Hub RSA 签名 | UnionHostVerify 协议 |
| 无 | `/api/union/member/oauth2/*` | 公开 / Session Cookie | OAuth2 端点 |
| `withAdminAPIKey` | `/api/union/admin/*` | `Bearer {admin_api_key}` | 管理接口 |
| `withBearerToken` | `/api/union/profile/*` | `Bearer {element-skin token}` | 用户接口 |
| `withWebhookSecret` | `/api/union/webhook/*` | `Bearer {webhook_secret}` | Webhook 回调 |

所有密钥对比均使用 `crypto/subtle.ConstantTimeCompare`，防时序攻击。

---

## 5. 新增功能详情

### 5.1 Session 存储

OAuth2 grant 流程需要一个 session 来标识已登录用户。PHP 使用 Blessing Skin 内置的 Web Session，union-svc 独立实现：

- SQLite 表 `union_sessions(session_id, access_token, created_at_ms, expires_at_ms)`
- Session ID = 32 字节 `crypto/rand` + `base64.RawURLEncoding`
- Cookie：`union_svc_session`，`HttpOnly`、`Secure`、`SameSite=Lax`
- 在 `/oauth/callback` 中创建，在 grant 端点中读取

### 5.2 OAuth2 签名密钥

RSA 4096 密钥对，首次启动时自动生成并保存为 PEM 文件：

- 私钥：`oauth2_sig_private.pem`（权限 0600）
- 公钥：`oauth2_sig_public.pem`（权限 0644）
- 通过 `union.EnsureSigKeyPair` 加载/生成，损坏时返回错误，不自动覆盖
- 轮换方式：删除文件后重启

### 5.3 ProxyToHub

绕过 `Client.request()` 的原始代理方法。`request()` 会将 HTTP >= 400 包装为 `HubError` 且对 `[]byte` body 做 `json.Marshal`（会 base64 编码），黑名单代理需要原样透传 Hub 的响应。

---

## 6. 测试

### 运行

```bash
cd union-svc

# 全部测试
go test ./...

# 带缓存刷新
go test ./... -count=1

# 单个包详细输出
go test ./internal/server/... -v

# 只跑 OAuth2 相关
go test ./internal/server/... -run TestOAuth2 -v

# 只跑 E2E 集成
go test ./internal/server/... -run TestE2E -v

# 构建 + 静态检查
go build ./cmd/union-svc && go vet ./... && gofmt -l .
```

### 测试覆盖

| 包 | 测试文件 | 覆盖内容 |
|----|----------|----------|
| `internal/config` | `config_test.go` | 配置加载、默认值、必填校验、环境变量覆盖 |
| `internal/session` | `store_test.go`, `cookie_test.go` | 创建/查找/删除/过期/清理、Cookie 安全属性 |
| `internal/union` | `sigkeys_test.go`, `client_test.go` | RSA 4096 密钥生成/持久化/损坏检测、ProxyToHub、缓存分离、ProfileBind 系列 |
| `internal/bridge` | `elementskin_test.go` | GetUserInfo 成功/401/500、请求路径与 Header |
| `internal/server` | `oauth2_union_test.go` | OAuth2 端点 9 场景（公钥、禁用、CORS、grant 完整流程、state 白名单、Hub 故障） |
| | `blacklist_admin_test.go` | 黑名单代理 7 场景（认证、查询/创建/失效/删除、错误透传） |
| | `profile_union_test.go` | 用户绑定 12 场景（认证失败/成功、4 个 handler、错误映射） |
| | `webhook_test.go` | Webhook 9 场景（认证、add/update/delete/full_sync、未知 action） |
| | `extensions_test.go` | E2E 集成 4 场景（OAuth 回调→grant、黑名单列表、角色绑定、webhook 全量同步） |

### E2E 测试设计

`extensions_test.go` 使用 `httptest.Server` 模拟 Element-Skin 和 Hub，通过 `Server.Handler()` 发起真实 HTTP 请求，覆盖完整路由和中间件链路。验证项包括：

- OAuth 回调是否设置了 session cookie
- grant 端点是否正确解密 `userInfoToken` 并验证 `uid`/`nickname`/`email` 字段
- 黑名单代理是否正确透传 Hub 原始响应和状态码
- Webhook 全量同步是否正确调用 `ListAllProfilesForSync` + `SyncProfiles`

---

## 7. 部署

### Docker

```bash
cd union-svc
cp config.yaml.example config.yaml
# 编辑 config.yaml
docker compose up -d
```

### 二进制

```bash
go build ./cmd/union-svc
./union-svc --config config.yaml
```

### 必填配置

| 字段 | 说明 |
|------|------|
| `elementskin.base_url` | Element-Skin 后端地址 |
| `elementskin.oauth.*` | OAuth 客户端凭据 |
| `union.hub_url` | Union Hub 地址 |
| `union.member_key` | 成员密钥 |
| `union.admin_api_key` | 管理接口认证密钥（自选随机字符串） |
| `union.webhook_secret` | Webhook 认证密钥（自选随机字符串） |
