# Draft: admin-api-and-auth

## Metadata
- intent: clear
- review_required: false
- status: plan-complete
- pending: awaiting user start-work
- oracle_review: APPROVE after fixes (bg_4b928057)
- oracle_fixes: 3 blocking + 3 recommended, all integrated into plan
  - Issue 1: rate limit before auth (reordered middleware)
  - Issue 2: withSessionCookie middleware (Todo 8, no token exchange)
  - Issue 3: read-before-delete + restore on keypair regen failure
  - Issue 4: CSP header on admin UI
  - Issue 5: stale IP cleanup goroutine
  - Issue 6: X-Real-IP header for nginx
- v2_review: APPROVE after fixes (bg_7479fd00 + bg_399367aa)
- v2_fixes: 4 issues, all integrated
  - v2-1: composite withBearerOrSession middleware (no duplicate routes)
  - v2-2: admin.js separate file (CSP script-src 'self' blocks inline)
  - v2-3: /api/profiles added to withBearerOrSession scope
  - v2-4: sync.Mutex instead of sync.Map (atomic rate limit)

## Auth analysis (核心)

### A1: admin_api_key 认证机制评估
`withAdminAPIKey`（blacklist_admin.go:16-32）使用 `subtle.ConstantTimeCompare` 对比 Bearer token 与 config 中的 `admin_api_key`。
- ✅ 常量时间比较，防时序攻击
- ✅ 空 key 时任何 token 都不匹配（自然拒绝）
- ⚠️ 无速率限制——key 泄露后可被滥用
- ⚠️ key 明文存于 config.yaml——靠文件权限保护
- 结论：机制本身正确，与已有黑名单端点一致。新增端点复用此中间件，不引入新认证机制。

### A2: 状态端点敏感信息泄露
`GET /api/union/admin/status` 会读取 settings store。
- ❌ 禁止返回：member_key 原文、private key PEM、admin_api_key、webhook_secret
- ✅ 允许返回：member_key 是否已配置（bool）、serverlist 版本号、privatekey 版本号、Hub 是否可达（bool）、OAuth2 是否启用
- 实现：settings.Get 后只返回 bool 指示器，不返回值本身

### A3: 密钥轮换是破坏性操作
`POST /api/union/admin/regenerate-keypair` 删除 PEM 文件并重新生成 RSA 4096 密钥对。
- 影响：所有用旧私钥签名的 OAuth2 令牌立即失效，其他 Union 成员缓存的旧公钥在重新拉取前无法验证
- 鉴权要求：需要请求体 `{"confirm": true}` 参数，缺少或为 false 时返回 400 + 警告说明
- 操作后记录日志（s.logger.Warn）

### A4: Admin sync 绕过用户级归属验证
`POST /api/union/admin/sync` 用服务账号 token（client_credentials, scope: profile.read.any）拉取全量角色。
- 这是设计意图：admin 操作使用服务账号，不是用户操作
- 用户级 `validateProfileOwnership` 仅适用于 bind/unbind/bindto（用户 token + profile.read.owned scope）
- 两套认证域完全独立：admin_api_key（入站）→ service account token（出站到 element-skin）→ member_key（出站到 Hub）
- plan 中明确记录此设计决策

### A5: Hub 操作通过 admin API 暴露
update-list、update-key、diagnose 通过 admin API 触发 Hub 操作。
- 持有 admin_api_key = 完整 Union 管理能力
- 这是预期行为（管理员管理 Union 成员关系）
- 但需记录操作日志（s.logger.Info），便于审计

### A6: 诊断响应内容
`POST /api/union/admin/diagnose` 代理 Hub 的 /diagnose 端点。
- Hub 诊断是 echo 操作，响应内容由 Hub 控制
- 透明代理（与黑名单代理一致），不在 union-svc 侧过滤
- 记录为已知风险：Hub 可能返回内部信息，但这是 Hub 的责任

### A7: 审计日志
当前 admin 操作无审计日志。新增端点应记录：
- 操作类型、调用者 IP、时间戳、成功/失败
- 使用 s.logger.Info（slog 结构化日志）
- 密钥轮换用 s.logger.Warn

## User decisions (confirmed)
1. Admin API 需要基本速率限制——防止 key 泄露后被滥用
2. 内置简单 UI——admin 管理面板 + 用户侧页面增强

## Rate limit design
- 基于 IP 的简单内存计数器（`sync.Map` + 时间窗口）
- 仅应用于 `/api/union/admin/*` 端点
- 默认限制：10 次/分钟/IP（够管理操作，阻止暴力探测）
- 超限返回 429 + `Retry-After` header
- 不依赖 Redis/外部存储——union-svc 是单实例 sidecar，内存计数器足够
- 中间件链：`withAdminAPIKey` → `withRateLimit` → handler（先认证后限流，未认证请求不消耗限流配额）

## UI design

### Admin 管理面板 (`/admin`)
- 单页面，内嵌 `static/admin.html`
- 登录：输入 admin_api_key → 存 localStorage → 后续请求带 Bearer header
- 功能区块：
  - **状态概览**：Union 状态、Hub 连通性、版本号、OAuth2 密钥指纹
  - **角色同步**：一键全站同步按钮 + 结果显示
  - **Union 管理**：拉取服务器列表、拉取私钥、诊断——三个按钮 + 结果
  - **密钥管理**：查看指纹、轮换密钥（需输入 confirm）
  - **黑名单管理**：查询/新增/失效/删除——简单表格 + 表单

### 用户侧页面增强 (`/`)
- 当前 index.html 只有授权 + 查询
- 新增：
  - **角色绑定/解绑**：查询结果列表中每个角色旁显示「绑定」/「解绑」按钮
  - **安全等级**：显示当前用户的安全等级
  - 绑定/解绑调用 `/api/union/profile/bind`、`/api/union/profile/unbind`（带 Bearer token from session）
  - Bearer token 来源：OAuth 登录后 session 中的 access token

### UI 技术约束
- 纯 HTML + vanilla JS，无框架、无构建步骤
- 与 index.html 一致：内嵌 `embed.FS`，无外部依赖
- 路径用相对路径（配合 root_path）

## Components
1. **速率限制中间件** — `withRateLimit` 内存 IP 计数器，10/min，仅 admin 端点
2. **Tier 1 全站同步** — `POST /api/union/admin/sync` + handler
3. **Tier 2 Union 管理** — update-list、update-key、diagnose、status + handlers
4. **Tier 3 密钥管理** — regenerate-keypair（confirm）、keypair-fingerprint + handlers
5. **路由注册** — 全部经 `withAdminAPIKey` + `withRateLimit` + `route()`
6. **Admin UI** — `static/admin.html` 内嵌面板，API key 登录，状态/同步/管理/密钥/黑名单
7. **用户 UI 增强** — `static/index.html` 增加绑定/解绑按钮 + 安全等级
8. **测试** — 每个端点覆盖 401、429、成功、Hub 故障
9. **最终验证** — build + test + vet + gofmt + grep