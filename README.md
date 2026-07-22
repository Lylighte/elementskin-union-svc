# union-svc

union-svc 是 Element-Skin 的独立 sidecar 服务，通过 Element-Skin 的 OAuth2 和 HTTP API
与主站点通信。负责 Union 网络的成员注册、角色同步、远程角色导入、OAuth2 跨站授权、
黑名单管理代理和 Webhook 同步。

## 本地运行

```bash
cd union-svc
cp config.yaml.example config.yaml
# 编辑 config.yaml — 所有标为空的字段均为必填
go build ./cmd/union-svc
./union-svc --config config.yaml
```

## 配置

配置从 `--config` 指定的 YAML 文件加载，可通过 `UNION_` 前缀的环境变量覆盖。启动时所有必填字段为空
会列出全部缺失项并退出。

### 服务

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `UNION_SERVER_ADDR` | - | 监听地址 |
| `UNION_SERVER_PORT` | `8001` | 监听端口 |

### Element-Skin（全部必填）

| 环境变量 | 说明 |
|---|---|
| `UNION_ELEMENTSKIN_BASE_URL` | Element-Skin API 地址 |
| `UNION_ELEMENTSKIN_SITE_URL` | Element-Skin 前端地址，用于 OAuth 授权页面跳转 |
| `UNION_ELEMENTSKIN_OAUTH_CLIENT_ID` | OAuth 客户端 ID（需在 Element-Skin 创建 Confidential 应用，申请 `account.read.self` 权限） |
| `UNION_ELEMENTSKIN_OAUTH_CLIENT_SECRET` | OAuth 客户端密钥 |
| `UNION_ELEMENTSKIN_OAUTH_REDIRECT_URI` | OAuth 回调地址 |
| `UNION_ELEMENTSKIN_SERVICE_ACCOUNT_CLIENT_ID` | 服务账号客户端 ID（需在 Element-Skin 创建 Confidential 应用，申请 `profile.read.any` 权限） |
| `UNION_ELEMENTSKIN_SERVICE_ACCOUNT_CLIENT_SECRET` | 服务账号客户端密钥 |
| `UNION_ELEMENTSKIN_SERVICE_ACCOUNT_SCOPE` | 服务账号 scope，默认 `profile.read.any` |

### 存储

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `UNION_STORAGE_PATH` | `./union-svc.db` | SQLite 数据库路径 |

### Union 网络（全部必填）

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `UNION_UNION_HUB_URL` | - | Union Hub 地址 |
| `UNION_UNION_MEMBER_KEY` | - | 成员密钥 |
| `UNION_UNION_ADMIN_API_KEY` | - | 管理接口认证密钥（通过 `openssl rand -hex 32` 生成） |
| `UNION_UNION_WEBHOOK_SECRET` | - | Webhook 认证密钥（通过 `openssl rand -hex 32` 生成，需与 Element-Skin 调用方一致） |
| `UNION_UNION_CORS_ALLOW_ORIGIN` | - | CORS 允许来源，为空时不发送 CORS 头 |
| `UNION_UNION_TIMEOUT_SECONDS` | `30` | 与 Hub 通信的超时秒数 |
| `UNION_UNION_ENABLE_OAUTH2` | `true` | 是否启用 Union OAuth2 协议端点 |
| `UNION_UNION_OAUTH2_SIG_PRIVATE_KEY_PATH` | `./oauth2_sig_private.pem` | OAuth2 签名私钥文件路径 |
| `UNION_UNION_OAUTH2_SIG_PUBLIC_KEY_PATH` | `./oauth2_sig_public.pem` | OAuth2 签名公钥文件路径 |

### 日志

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `UNION_LOG_LEVEL` | `info` | 日志级别 |

## 功能说明

### 1. Union 成员管理

与 Union Hub 建立成员关系、接收服务端列表和密钥更新、角色同步、按用户名查邮箱、诊断握手。

### 2. Element-Skin 集成

通过 OAuth2 授权码流程登录 Element-Skin，管理用户角色（列出、导入）。

### 3. Union OAuth2 授权 (`v1.1` 新增)

为 Union 网络的跨站授权提供 OAuth2 协议端点。当 Element-Skin 用户访问其他 Union 成员站点时，
经过授权后 union-svc 会生成加密的用户信息令牌，由 Hub 转发给目标站点完成登录。

启用条件：`enable_oauth2: true`，否则两个端点均返回 403。

- 签名密钥为 RSA 4096，首次启动时自动生成并保存到 PEM 文件。
- 如需轮换密钥，删除 PEM 文件后重启即可自动重新生成。

### 4. 黑名单管理代理

将管理后台的黑名单 CRUD 请求透明代理到 Union Hub，不做任何业务逻辑处理。
认证方式为 `Authorization: Bearer {admin_api_key}`。

### 5. 用户角色绑定

允许已登录 Element-Skin 的用户通过自己的 session 绑定/解绑 Union 网络角色。
认证方式为 `Authorization: Bearer {Element-Skin 用户 access token}`。

### 6. Webhook 同步

接收来自 skin-backend 的 Webhook 回调，触发角色变化同步到 Union Hub。
支持的操作：添加（`add`）、更新（`update`）、删除（`delete`）、全量同步（`full_sync`）。
认证方式为 `Authorization: Bearer {webhook_secret}`。

## API 端点

### 公开接口

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/health` | 健康检查 |
| `GET` | `/oauth/authorize` | 发起 OAuth 授权 |
| `GET` | `/oauth/callback` | OAuth 回调 |

### Union Hub 回调（Hub 签名认证）

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/union/member/` | Hub 问候 |
| `POST` | `/api/union/member/updatelist` | 更新服务器列表 |
| `POST` | `/api/union/member/updateprivatekey` | 更新私钥 |
| `POST` | `/api/union/member/updatebackendkey` | 更新后端密钥 |
| `POST` | `/api/union/member/sync` | 触发全量角色同步 |
| `GET` | `/api/union/member/queryemail` | 按角色名查邮箱 |
| `POST` | `/api/union/member/diagnose` | Hub 诊断握手 |

### Union OAuth2（公开，受 `enable_oauth2` 开关控制）

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/union/member/oauth2/` | 获取签名公钥 |
| `GET` | `/api/union/member/oauth2/grant` | OAuth2 授权流程入口 |

### 黑名单管理（`Authorization: Bearer {admin_api_key}`）

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/union/admin/blacklist` | 查询黑名单 |
| `POST` | `/api/union/admin/blacklist` | 新增黑名单 |
| `PUT` | `/api/union/admin/blacklist/invalidate/{id}` | 标记黑名单失效 |
| `DELETE` | `/api/union/admin/blacklist/{id}` | 删除黑名单 |

### 用户角色（`Authorization: Bearer {element-skin access token}`）

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/api/union/profile/bind` | 绑定角色 |
| `POST` | `/api/union/profile/unbind` | 解绑角色 |
| `POST` | `/api/union/profile/bindto` | 绑定到其他成员 |
| `GET` | `/api/union/security/level` | 查询安全等级 |

### Webhook（`Authorization: Bearer {webhook_secret}`）

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/api/union/webhook/profile-sync` | 角色变化同步 |

## 测试

```bash
cd union-svc

# 运行全部测试
go test ./...

# 运行单个包的测试
go test ./internal/server/... -v

# 运行指定测试
go test ./internal/server/... -run TestOAuth2GrantWithValidSession -v
go test ./internal/server/... -run TestE2E -v

# 构建验证
go build ./cmd/union-svc

# 静态检查
go vet ./...
gofmt -l .
```

### 包测试覆盖概况

| 包 | 说明 |
|---|---|
| `internal/bridge` | Element-Skin 客户端（GetUserInfo 等） |
| `internal/config` | 配置加载与校验 |
| `internal/oauth` | OAuth2 令牌管理 |
| `internal/server` | HTTP 路由与所有端点处理（含 4 条 E2E 流程） |
| `internal/session` | Session 存储与 Cookie 辅助函数 |
| `internal/union` | Union Hub 客户端（代理、绑定、签名密钥生成） |
