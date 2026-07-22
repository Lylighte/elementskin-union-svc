# admin-api-and-auth - Work Plan

## TL;DR (For humans)

**What you'll get:** union-svc 新增管理员 API（7 个端点）和内置管理面板 UI。管理员可以一键全站角色投送到 Union Hub、手动拉取服务器列表/私钥、触发诊断、查看 Union 状态、轮换 OAuth2 密钥。用户侧页面增加角色绑定/解绑按钮和安全等级显示。Admin API 有速率限制防护。

**Why this approach:** 底层 Hub client 和 bridge 方法已全部实现，只差 admin API 入口和 UI。复用 `withAdminAPIKey` 认证 + 新增 `withRateLimit` 内存限流。UI 纯静态 HTML+JS 内嵌 Go 二进制，与现有 index.html 一致。

**What it will NOT do:** 不新增认证机制（复用 admin_api_key）、不做前端框架、不依赖外部存储做限流、不改 Hub 推送端点、不做 element-skin 侧 webhook 发送。

**Effort:** Medium — 7 个端点 + 2 个 HTML 页面 + 1 个中间件 + 测试
**Risk:** Low — 纯新增，不改已有逻辑；鉴权复用已验证的中间件
**Decisions to sanity-check:** 速率限制 10/min/IP 是否合适；admin UI API key 存 localStorage 是否可接受

Your next move: approve or run a high-accuracy review. Full execution detail follows below.

---

> TL;DR (machine): Medium effort, Low risk, 7 admin API endpoints + rate limit middleware + 2 embedded HTML UI pages

## Scope

### Must have
- `withRateLimit` 中间件：IP 内存计数器，10 次/分钟，仅 `/api/union/admin/*`，超限 429 + `Retry-After`
- `POST /api/union/admin/sync`：全站角色投送到 Hub
- `POST /api/union/admin/update-list`：手动拉取服务器列表
- `POST /api/union/admin/update-key`：手动拉取共享私钥
- `POST /api/union/admin/diagnose`：手动触发 Hub 诊断
- `GET /api/union/admin/status`：Union 状态查询（只返回 bool 指示器，不泄露密钥）
- `POST /api/union/admin/regenerate-keypair`：轮换 OAuth2 签名密钥（需 `{"confirm":true}`）
- `GET /api/union/admin/keypair-fingerprint`：查看当前密钥指纹
- `static/admin.html`：管理面板 UI（API key 登录 + 状态/同步/管理/密钥/黑名单）
- `static/index.html` 增强：角色绑定/解绑按钮 + 安全等级显示
- 全部新端点经 `withAdminAPIKey` + `withRateLimit` + `route()` 包装
- 每个端点测试覆盖：401（无 key）、401（错误 key）、429（超限）、成功、Hub 故障
- 所有 admin 操作加 slog 审计日志

### Must NOT have
- 不新增认证机制（复用 `withAdminAPIKey`）
- 不依赖 Redis/外部存储做限流（内存 `sync.Map`）
- 不做前端框架（纯 HTML + vanilla JS）
- 不改 Hub 推送端点（`/api/union/member/*`）
- 不做 element-skin 侧 webhook 发送
- status 端点不返回 member_key 原文、private key PEM、admin_api_key、webhook_secret
- regenerate-keypair 不需要 `confirm` 时返回 400

## Verification strategy
> Zero human intervention - all verification is agent-executed.
- Test decision: tests-after（先写实现再写测试，与现有代码风格一致）
- Framework: Go 标准 `testing` + `httptest`
- Evidence: .omo/evidence/task-N-admin-api-and-auth.txt

## Execution strategy

### Parallel execution waves

**Wave 1:** Todo 1（限流中间件）+ Todo 8（session cookie 中间件）— 全局前置依赖，可并行
**Wave 2:** Todo 2（sync）、Todo 3（Union 管理 4 端点）、Todo 4（密钥管理 2 端点）— 可并行
**Wave 3:** Todo 5（admin UI）、Todo 6（用户 UI 增强）— 可并行
**Wave 4:** Todo 7（最终验证）

### Dependency matrix
| Todo | Depends on | Blocks | Can parallelize with |
| --- | --- | --- | --- |
| 1. withRateLimit | — | 2,3,4 | 8 |
| 2. admin sync | 1 | 7 | 3, 4 |
| 3. Union 管理 | 1 | 7 | 2, 4 |
| 4. 密钥管理 | 1 | 7 | 2, 3 |
| 5. admin UI | 2,3,4 | 7 | 6 |
| 6. 用户 UI | 8 | 7 | 5 |
| 7. 最终验证 | 1-6,8 | — | — |
| 8. withSessionCookie | — | 6 | 1 |

## Todos

- [ ] 1. withRateLimit 中间件
  What to do: 新建 `internal/server/ratelimit.go`，实现基于 IP 的内存速率限制中间件。用 `sync.Mutex` 保护 `map[string]*rateEntry{count, windowStart}`（**不用 sync.Map——read-modify-write 非原子，Oracle v2 Issue 4**），1 分钟滑动窗口，超过 10 次返回 429 + `Retry-After` header。**限流在认证之前**——中间件链顺序为 `withRateLimit(withAdminAPIKey(handler))`，所有请求（含认证失败）都消耗限流配额，防止 admin_api_key 暴力探测。IP 提取优先读 `X-Real-IP` header（nginx `proxy_set_header X-Real-IP $remote_addr`），fallback `X-Forwarded-For` 第一个值，最后 fallback `r.RemoteAddr`。启动后台 goroutine 每 5 分钟清理过期 IP 条目（`windowStart + 60s < now`）。新建 `internal/server/ratelimit_test.go`。
  Must NOT do: 不依赖外部存储；不应用于非 admin 端点；**限流必须在认证之前**（Oracle Issue 1）；不做 per-user 限流（只做 per-IP）
  Parallelization: Wave 1 | Blocked by: — | Blocks: 2,3,4
  References:
    - `internal/server/blacklist_admin.go:16-32`（withAdminAPIKey 模式参考）
    - `internal/server/server.go:97-99`（route() helper）
    - 新文件 `internal/server/ratelimit.go`
    - 新文件 `internal/server/ratelimit_test.go`
  Acceptance criteria:
    - `withRateLimit` 函数签名 `func (s *Server) withRateLimit(fn http.HandlerFunc) http.HandlerFunc`
    - 路由注册顺序为 `s.withRateLimit(s.withAdminAPIKey(s.handleXxx))`——限流在外层
    - 第 11 次请求（含认证失败）返回 429 + `Retry-After: 60`
    - 前 10 次（含认证失败的 401）正常通过限流
    - 不同 IP 各自独立计数
    - 后台 goroutine 清理过期条目（测试：插入过期条目 → 触发清理 → 确认被删除）
    - `go test ./internal/server/ -count=1 -run TestRateLimit` 全部 PASS
    - `go build ./cmd/union-svc` 通过
  QA scenarios:
    - happy: 10 次错误 key 请求全部 401，第 11 次返回 429。`go test -v -run TestRateLimitBruteForceProtection`
    - failure: 不同 IP 各自独立计数。`go test -v -run TestRateLimitPerIP`
    Evidence: .omo/evidence/task-1-admin-api-and-auth.txt
  Commit: Y | feat(server): add ip-based rate limit middleware for admin endpoints

- [ ] 8. withBearerOrSession 复合认证中间件
  What to do: 新建 `internal/server/session_auth.go`，实现两个中间件：
    1. `withSessionCookie(next)` — 复用 `handleOAuth2Grant`（`oauth2_union.go:72-91`）模式：读 session cookie → 查 sessionStore 获取 access token → 调 GetUserInfo 验证 → 存 UserInfo + access token 到 context（与 withBearerToken 相同的 `userInfoKey`/`accessTokenKey`）。无 session 或过期时返回 401。
    2. `withBearerOrSession(next)` — **复合中间件**（Oracle v2 Issue 1 + Metis Gap 2）：检查 `Authorization: Bearer` header 是否存在——有则走 `withBearerToken(next)`，无则走 `withSessionCookie(next)`。**同一 path 只注册一次**，用此中间件包装。
    Go 1.22 ServeMux 不允许同一 method+path 注册两次，不能用"两套路由"方案。新建 `internal/server/session_auth_test.go`。
  Must NOT do: 不暴露 access token 给 JS；不新增 token 交换端点；不修改 HttpOnly cookie 属性；不修改 withBearerToken 本身；**不注册重复路由**（Oracle v2 Issue 1）
  Parallelization: Wave 1 | Blocked by: — | Blocks: 6 | Can parallelize with: 1
  References:
    - `internal/server/oauth2_union.go:72-91`（已有的 session cookie → access token → GetUserInfo 模式）
    - `internal/server/profile_union.go:27-56`（withBearerToken 中间件——context key 参考）
    - `internal/session/cookie.go:26-32`（GetSessionCookie）
    - `internal/session/store.go`（Lookup 方法）
  Acceptance criteria:
    - `withSessionCookie` 函数签名 `func (s *Server) withSessionCookie(next http.HandlerFunc) http.HandlerFunc`
    - `withBearerOrSession` 函数签名 `func (s *Server) withBearerOrSession(next http.HandlerFunc) http.HandlerFunc`
    - `withBearerOrSession`：有 Bearer header → 走 Bearer 认证；无 Bearer header → 走 session cookie 认证
    - 无 cookie 且无 Bearer → 401
    - 有 cookie 但 session 过期 → 401
    - 有有效 session → 调 GetUserInfo → 存 UserInfo + access token 到 context（与 withBearerToken 完全兼容）
    - `go test ./internal/server/ -count=1 -run TestSessionCookie|TestBearerOrSession` 全部 PASS
  QA scenarios:
    - happy: 有效 Bearer token → 通过；有效 session cookie → 通过
    - failure: 无 Bearer 且无 cookie → 401；过期 session → 401
    Evidence: .omo/evidence/task-8-admin-api-and-auth.txt
  Commit: Y | feat(server): add composite bearer-or-session auth middleware

- [ ] 2. POST /api/union/admin/sync — 全站角色投送
  What to do: 新建 `internal/server/admin_ops.go`，实现 `handleAdminSync`。调用 `bridge.ListAllProfilesForSync(ctx)` 拉取 element-skin 全量角色（服务账号 token），转为 `map[string]string`（name→uuid），调 `unionClient.SyncProfiles(ctx, profileList)` 推送到 Hub。返回 `{"synced": N, "detail": "ok"}`。slog.Info 审计日志。在 `server.go` 路由注册：`s.route("POST /api/union/admin/sync")`，包装 `s.withRateLimit(s.withAdminAPIKey(s.handleAdminSync))`——**限流在外层，认证在内层**。
  Must NOT do: 不使用用户 token；不调用 validateProfileOwnership；不修改 Hub 推送的 handleSync
  Parallelization: Wave 2 | Blocked by: 1 | Blocks: 7 | Can parallelize with: 3, 4
  References:
    - `internal/bridge/bridge.go:55-61`（ListAllProfilesForSync）
    - `internal/union/client.go:190-198`（SyncProfiles）
    - `internal/server/webhook.go:74-99`（full_sync 逻辑参考——同样的调用链）
    - `internal/server/server.go:121`（路由注册模式参考）
    - 新文件 `internal/server/admin_ops.go`
    - 新文件 `internal/server/admin_ops_test.go`
  Acceptance criteria:
    - 无 Bearer header → 401
    - 错误 key → 401
    - 11 次请求（同 IP）→ 第 11 次 429
    - 成功 → 200 + `{"synced": N}` (N 为实际角色数)
    - Hub 故障 → 502
    - element-skin 故障 → 502
    - `go test ./internal/server/ -count=1 -run TestAdminSync` 全部 PASS
  QA scenarios:
    - happy: mock element-skin 返回 2 个 profile + mock Hub 返回 200 → 响应 `{"synced":2,"detail":"ok"}`
    - failure: mock Hub 返回 500 → 响应 502
    Evidence: .omo/evidence/task-2-admin-api-and-auth.txt
  Commit: Y | feat(admin): add full profile sync endpoint

- [ ] 3. Union 管理端点 — update-list、update-key、diagnose、status
  What to do: 在 `internal/server/admin_ops.go` 中实现 4 个 handler：
    - `handleAdminUpdateList`：调 `unionClient.FetchServerList(ctx)`，存版本号到 settings store，返回 `{"version": N}`
    - `handleAdminUpdateKey`：调 `unionClient.FetchPrivateKey(ctx)`，存版本号到 settings store，返回 `{"version": N}`
    - `handleAdminDiagnose`：调 `unionClient.ProxyToHub(ctx, "POST", "/diagnose", nil)`，透传 Hub 响应
    - `handleAdminStatus`：读 settings store（member_key 是否已配置 bool、serverlist 版本、privatekey 版本），检查 Hub 连通性（调 FetchServerList 或简单 GET），返回 JSON `{"member_key_configured": bool, "serverlist_version": int, "privatekey_version": int, "hub_reachable": bool, "oauth2_enabled": bool}`。**禁止返回任何密钥原文。**
    全部加 slog.Info 审计日志。路由注册同 Todo 2 模式。
  Must NOT do: status 端点不返回 member_key 原文、private key PEM、admin_api_key、webhook_secret；不修改 Hub 推送的 handleUpdateList/handleUpdatePrivateKey/handleDiagnose
  Parallelization: Wave 2 | Blocked by: 1 | Blocks: 7 | Can parallelize with: 2, 4
  References:
    - `internal/union/client.go:153-168`（FetchServerList）
    - `internal/union/client.go:172-188`（FetchPrivateKey）
    - `internal/union/client.go:204-244`（ProxyToHub）
    - `internal/server/inbound.go:53-87`（handleUpdateList 逻辑参考）
    - `internal/server/inbound.go:89-117`（handleUpdatePrivateKey 逻辑参考）
    - `internal/server/inbound.go:221-250`（handleDiagnose 逻辑参考）
    - `internal/union/settings.go`（SettingsStore Get/Set）
    - 新文件 `internal/server/admin_ops.go`（追加到 Todo 2 的文件）
    - 新文件 `internal/server/admin_ops_test.go`（追加测试）
  Acceptance criteria:
    - 4 个端点全部 401（无 key）、401（错误 key）、429（超限）
    - status 返回 5 个 bool/int 字段，无任何密钥字符串
    - update-list 成功 → 200 + `{"version": N}`
    - update-key 成功 → 200 + `{"version": N}`
    - diagnose 成功 → 200 + Hub 原始响应
    - Hub 故障 → 502
    - `go test ./internal/server/ -count=1 -run TestAdminUpdate|TestAdminDiagnose|TestAdminStatus` 全部 PASS
  QA scenarios:
    - happy: mock Hub 返回 serverlist version=5 → update-list 返回 `{"version":5}`
    - failure: mock Hub 500 → 502；status 端点 grep 确认无 "member_key" 值（只有 bool）
    Evidence: .omo/evidence/task-3-admin-api-and-auth.txt
  Commit: Y | feat(admin): add union management endpoints

- [ ] 4. 密钥管理端点 — regenerate-keypair、keypair-fingerprint
  What to do: 在 `internal/server/admin_ops.go` 中实现 2 个 handler：
    - `handleAdminKeypairFingerprint`：读 `cfg.Union.OAuth2SigPublicKeyPath` PEM 文件，计算 SHA256 指纹，返回 `{"fingerprint": "sha256:hex..."}`。不返回 PEM 原文。
    - `handleAdminRegenerateKeypair`：解析请求体 `{"confirm": bool}`，confirm 不为 true 时返回 400 + `{"detail":"confirm is required to regenerate keypair"}`。confirm=true 时：**先读旧 PEM 文件到内存** → 删除 PEM 文件 → 调 `union.EnsureSigKeyPair` 重新生成 → **如果生成失败，将旧 PEM 写回文件** → 返回新指纹。slog.Warn 审计日志（含成功/失败 + IP）。
    路由注册同 Todo 2 模式。
  Must NOT do: 不返回 PEM 原文；confirm 缺失或 false 时必须返回 400；**删除文件前必须先读取旧内容**（Oracle Issue 3）；生成失败时必须恢复旧文件
  Parallelization: Wave 2 | Blocked by: 1 | Blocks: 7 | Can parallelize with: 2, 3
  References:
    - `internal/union/sigkeys.go`（EnsureSigKeyPair）
    - `internal/server/oauth2_union.go:45-54`（EnsureSigKeyPair 调用模式）
    - `crypto/sha256`、`encoding/hex`（指纹计算）
    - `os.ReadFile`、`os.WriteFile`（读旧文件 + 恢复）
    - `internal/server/admin_ops.go`（追加到 Todo 2/3 的文件）
    - `internal/server/admin_ops_test.go`（追加测试）
  Acceptance criteria:
    - fingerprint 返回 `{"fingerprint": "sha256:..."}` 格式，不含 PEM 原文
    - regenerate 无 `confirm` → 400
    - regenerate `{"confirm": false}` → 400
    - regenerate `{"confirm": true}` → 200 + 新指纹
    - regenerate 后旧指纹 ≠ 新指纹
    - **EnsureSigKeyPair 失败时旧 PEM 文件被恢复**（测试：mock 确保生成失败 → 确认文件内容与操作前一致）
    - 401、429 鉴权测试同其他 admin 端点
    - `go test ./internal/server/ -count=1 -run TestAdminKeypair` 全部 PASS
  QA scenarios:
    - happy: regenerate with confirm=true → 200 + 指纹变化
    - failure: regenerate without confirm → 400；regenerate 生成失败 → 旧文件恢复 + 500
    Evidence: .omo/evidence/task-4-admin-api-and-auth.txt
  Commit: Y | feat(admin): add oauth2 keypair management endpoints

- [ ] 5. Admin UI — static/admin.html + admin.js
  What to do: 新建两个文件：
    `internal/server/static/admin.html` — 纯 HTML 结构（无内联 JS），页面结构：
    - 登录区：input + button 输入 admin_api_key，存 localStorage
    - 状态概览区：调 `GET api/union/admin/status`，显示 member_key_configured、hub_reachable、版本号、oauth2_enabled
    - 角色同步区：「全站同步」按钮 → `POST api/union/admin/sync` → 显示 synced 数量
    - Union 管理区：三个按钮（拉取服务器列表、拉取私钥、诊断）→ 分别调对应端点 → 显示结果
    - 密钥管理区：显示当前指纹（`GET api/union/admin/keypair-fingerprint`）+ 轮换按钮（需勾选 confirm 复选框 → `POST api/union/admin/regenerate-keypair`）
    - 黑名单管理区：查询列表 + 新增表单 + 失效/删除按钮
    - `<script src="admin.js"></script>` 引用外部 JS 文件（**不用内联 `<script>`——CSP `script-src 'self'` 会阻止内联脚本，Oracle v2 Issue 2**）
    `internal/server/static/admin.js` — 全部 vanilla JS 逻辑，fetch 请求带 `Authorization: Bearer {localStorage中的key}` header，路径用相对路径（配合 root_path）。
    在 `server.go` 注册路由 `s.route("/admin")` → 返回 admin.html，**响应头设置 `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'`**（Oracle Issue 4 XSS 防护）。注册路由 `s.route("/admin.js")` → 返回 admin.js（`Content-Type: application/javascript`）。更新 `//go:embed` 指令包含 admin.html 和 admin.js。
  Must NOT do: 不内联 API key 到 HTML；不用 cookie 存 key（避免 CSRF）；不引入外部 JS/CSS 依赖；**不省略 CSP header**；**不用内联 `<script>` 标签**（CSP 阻止）；**不用 `'unsafe-inline'`**（ defeats CSP 目的）
  Parallelization: Wave 3 | Blocked by: 2,3,4 | Blocks: 7 | Can parallelize with: 6
  References:
    - `internal/server/static/index.html`（现有 UI 模式参考）
    - `internal/server/server.go:17-18`（embed.FS 声明，需更新）
    - `internal/server/server.go:128-139`（根路由处理，需添加 /admin 和 /admin.js）
  Acceptance criteria:
    - `internal/server/static/admin.html` 存在且内嵌到二进制
    - `internal/server/static/admin.js` 存在且内嵌到二进制
    - `//go:embed` 包含 `static/index.html static/admin.html static/admin.js`
    - 访问 `/admin` 返回 admin.html，响应头含 `Content-Security-Policy`
    - 访问 `/admin.js` 返回 admin.js，`Content-Type: application/javascript`
    - admin.html 中 `grep -n "<script" internal/server/static/admin.html` 只匹配 `<script src="admin.js"></script>`，无内联 `<script>` 块
    - `grep -n "localStorage" internal/server/static/admin.js` 确认 key 存储在 JS 文件中
    - `grep -n "Bearer" internal/server/static/admin.js` 确认认证 header
    - `go build ./cmd/union-svc` 通过
  QA scenarios:
    - happy: `curl {base}/admin` 返回 HTML 含 "Union 管理" 文本和 `<script src="admin.js"`
    - failure: `grep "api_key\|apikey" internal/server/static/admin.html internal/server/static/admin.js` 确认无硬编码 key；`grep "<script>" internal/server/static/admin.html` 零匹配（无内联脚本）
    Evidence: .omo/evidence/task-5-admin-api-and-auth.txt
  Commit: Y | feat(ui): add admin management panel

- [ ] 6. 用户 UI 增强 — index.html 绑定/解绑 + 安全等级 + 路由认证更新
  What to do: 
    **路由变更（server.go）**：将以下 5 个端点的中间件从 `withBearerToken` 改为 `withBearerOrSession`（Todo 8 复合中间件，单路由注册）：
    - `/api/profiles`（Oracle v2 Issue 3 + Metis Gap 4——用户 UI 查询角色需要 session cookie 支持）
    - `/api/union/profile/bind`
    - `/api/union/profile/unbind`
    - `/api/union/profile/bindto`
    - `/api/union/security/level`
    Go ServeMux 不允许同 path 重复注册，所以用 `withBearerOrSession` 替换 `withBearerToken`，不新增路由。`handleListProfiles` 不使用 access token（只用 `s.bridge.ListProfiles` 走服务账号），所以加 session cookie 认证对它无副作用。
    **index.html 修改**：增加：
    - 查询结果列表每行旁显示「绑定」/「解绑」按钮
    - 点击「绑定」→ `POST api/union/profile/bind` body `{"uuid":"..."}`——不设 Authorization header，session cookie 自动携带
    - 点击「解绑」→ `POST api/union/profile/unbind` body `{"uuid":"..."}`——同上
    - 页面顶部显示安全等级：`GET api/union/security/level`——同上
    - fetch 请求**不设 Authorization header**——浏览器自动发送 session cookie
  Must NOT do: 不修改 HttpOnly cookie 属性；不在 URL 中暴露 token；不新增 token 交换端点；不在 JS 中存 access token；**不注册重复路由**（用 withBearerOrSession 替换 withBearerToken）
  Parallelization: Wave 3 | Blocked by: 8 | Blocks: 7 | Can parallelize with: 5
  References:
    - `internal/server/static/index.html`（现有 UI）
    - `internal/server/server.go:109`（/api/profiles 当前路由）
    - `internal/server/server.go:126-129`（bind/unbind/bindto/security-level 当前路由）
    - `internal/session/cookie.go`（session cookie HttpOnly=true）
    - `internal/server/session_auth.go`（Todo 8 新建的 withBearerOrSession）
    - `internal/server/import.go:11-36`（handleListProfiles——不使用 access token）
  Acceptance criteria:
    - `/api/profiles` 路由使用 `withBearerOrSession`（不再是 `withBearerToken`）
    - bind/unbind/bindto/security-level 路由使用 `withBearerOrSession`
    - index.html 包含「绑定」/「解绑」按钮
    - index.html 包含安全等级显示区
    - index.html 的 fetch 请求**不含 Authorization header**
    - `grep -n "withBearerToken" internal/server/server.go` 中 bind/unbind/bindto/security-level/api/profiles 行不再出现（已替换为 withBearerOrSession）
    - `grep -n "withBearerOrSession" internal/server/server.go` 有 5 处匹配
    - `grep -n "Authorization" internal/server/static/index.html` 零匹配
    - `grep -n "document.cookie\|sessionStorage\|localStorage" internal/server/static/index.html` 零匹配
    - `go build ./cmd/union-svc` 通过
  QA scenarios:
    - happy: 有 session cookie → /api/profiles、bind/unbind/security-level 请求通过；有 Bearer token → 同样通过
    - failure: 无 session cookie 且无 Bearer → 401
    Evidence: .omo/evidence/task-6-admin-api-and-auth.txt
  Commit: Y | feat(ui): add profile bind/unbind and security level to user page

- [ ] 7. 最终验证
  What to do: 运行全部验证命令，确认无遗漏。
  Must NOT do: 不修复问题——发现问题则回退到对应 todo
  Parallelization: Wave 4 | Blocked by: 1-6,8 | Blocks: —
  References: 全仓库
  Acceptance criteria:
    - `go build ./cmd/union-svc` 成功
    - `go test ./... -count=1` 全部 PASS
    - `go vet ./...` 无输出
    - `gofmt -l .` 无输出
    - `grep -rn "withAdminAPIKey" internal/server/server.go` 确认所有 admin 端点有认证包装
    - `grep -rn "withRateLimit" internal/server/server.go` 确认所有 admin 端点有限流包装
    - `grep -rn "withBearerOrSession" internal/server/server.go` 确认用户 UI 端点（/api/profiles、bind/unbind/bindto/security-level）使用复合认证
    - `grep -rn "Content-Security-Policy" internal/server/` 确认 admin UI 有 CSP header
    - `grep -rn "withAdminAPIKey\|withRateLimit" internal/server/admin_ops.go` 确认 handler 文件不直接调用中间件
    - `grep -c "<script>" internal/server/static/admin.html` 确认零内联脚本（只有 `<script src="admin.js">`）
  QA scenarios:
    - happy: 全部命令退出码 0
    - failure: 任何命令非零退出 → 报告具体失败
    Evidence: .omo/evidence/task-7-admin-api-and-auth.txt
  Commit: N

## Final verification wave
> Runs in parallel after ALL todos. ALL must APPROVE.
- [ ] F1. Plan compliance audit: 每个端点有 withRateLimit(withAdminAPIKey(handler)) 包装（限流在外层）；status 不泄露密钥；regenerate 需要 confirm 且失败时恢复旧密钥；/api/profiles + bind/unbind/bindto/security-level 使用 withBearerOrSession（单路由注册）
- [ ] F2. Code quality review: 无 orphaned import；gofmt 干净；slog 日志覆盖所有 admin 操作；CSP header 设置在 admin UI 路由；admin.html 无内联 `<script>` 块
- [ ] F3. Real manual QA: build + test + vet + gofmt 全绿；admin.html + admin.js + index.html 可访问；admin.html 有 CSP header
- [ ] F4. Scope fidelity: 不改 Hub 推送端点；不引入外部依赖；index.html 不在 JS 中存 access token；限流器用 sync.Mutex（非 sync.Map）

## Commit strategy

6 个原子 commit：
1. `feat(server): add ip-based rate limit middleware for admin endpoints`（Todo 1）
2. `feat(server): add composite bearer-or-session auth middleware`（Todo 8）
3. `feat(admin): add full profile sync endpoint`（Todo 2）
4. `feat(admin): add union management endpoints`（Todo 3）
5. `feat(admin): add oauth2 keypair management endpoints`（Todo 4）
6. `feat(ui): add admin panel and enhance user page`（Todo 5+6 合并）

## Success criteria

- 7 个新 admin API 端点全部有 `withRateLimit(withAdminAPIKey(handler))` 包装（限流在外层）
- 速率限制 10/min/IP，含认证失败请求，超限返回 429，用 sync.Mutex 保证原子性
- status 端点不泄露任何密钥原文
- regenerate-keypair 需要 `{"confirm":true}`，生成失败时恢复旧密钥
- admin.html + admin.js 内嵌到 Go 二进制，API key 存 localStorage，CSP header 设置，无内联 `<script>` 块
- index.html 有绑定/解绑按钮和安全等级，不在 JS 中存 access token
- /api/profiles + bind/unbind/bindto/security-level 使用 `withBearerOrSession`（单路由，Bearer 优先 + session cookie fallback）
- 所有 admin 操作有 slog 审计日志
- build + test + vet + gofmt 全绿