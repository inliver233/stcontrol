# 验证记录

## 2026-08-07：接手基线

- `go test ./...`：通过；大多数 package 无测试。
- `npm run build`：通过；仅证明前端可编译。
- `git ls-remote --symref https://github.com/inliver233/stcontrol.git HEAD`：成功但无引用，确认远端为空。
- 已创建并推送基线提交 `9f91435 chore: establish audited demo baseline`。

## 2026-08-07：事实模型与活动租约批次

实现范围：

- 嵌入式、带 checksum 的顺序迁移和 PostgreSQL advisory transaction lock。
- 新增控制世代、统一身份、节点账号、持久会话、活动租约、工作流、快照、副本、严格票据、enrollment/Agent 命令、管理员关联、审计、告警和指标事实表。
- 新注册同步写 legacy compatibility row 与 normalized facts；不再写可逆密码，迁移会清空 demo `password_enc`。
- 活动租约使用全局用户行 `FOR UPDATE`、唯一用户 lease、递增 epoch 和 operation ID，未过期 writer 不会被新节点覆盖。
- User/Node API 序列化隐藏密码 hash/ciphertext、OAuth subject、Agent URL/PSK；启动缺少主密钥时 fail closed，不打印临时密钥。

已执行证据：

- `go test ./...`：通过。
- `go vet ./...`：通过。
- `go test -coverprofile=coverage\\unit.coverprofile ./...`：通过；总覆盖率 8.3%，`internal/store` 21.4%。覆盖率远未达到最终 80% 门禁，已保留为明确缺口。
- `git diff --check`：通过。

环境限制与未冒充的证据：

- `docker version` 无法连接本机 Docker daemon。
- `psql` 未安装。因此本批迁移尚未在真实 PostgreSQL 15+ 执行；嵌入迁移顺序/checksum 和事务调用有单元测试，但 SQL 方言、约束和真实并发仍属于未验证。
- `go test -race ./...` 因本机 C 编译器不支持 Go 所需的 64 位 cgo 而无法构建（`cc1.exe: 64-bit mode not compiled in`）；这不是竞态测试通过。

剩余风险：

- Agent/SillyTavern 尚未执行 session fencing，真实 PostgreSQL 并发语义仍待环境验证。

## 2026-08-07：安全登录交接批次

- 浏览器交接改为短命、不透明、一次性 POST 短码；前端不再使用查询参数或 `window.location.href` 携带凭证。
- 登录租约和严格 control ticket 在同一 serializable 事务提交；operation ID 重试返回原 JTI，A 的未过期 writer 不会被 B 覆盖。
- 核销路由强制节点 HMAC 认证，并校验节点、票据类型、时窗、活动 epoch、session、controller generation、撤销/消费状态。
- Agent HMAC nonce 摘要持久化并一次性插入，补上时间窗内重放缺口；请求体限制为 1 MiB，认证错误不回显内部原因。
- `go test ./...`：通过。
- `go vet ./...`：通过。
- `npm run build`：通过。
- 新增测试覆盖租约/票据同事务提交与回滚、operation ID 重试、单次核销、nonce 重放、短码解析与错误输入。

## 2026-08-07：持久 Controller 会话批次

- 删除进程内 session map；opaque token 仅以 SHA-256 digest 写入 `controller_sessions`，重启后仍可验证。
- Session 绑定 active `controller_generation`；旧世代、已撤销、过期或主体禁用的会话均失败关闭。
- 登录会轮换已有 session；注销原子写撤销时间；后台定期清理过期/旧撤销记录，并节流更新 `last_seen_at`。
- Cookie 使用 host-only、HttpOnly、SameSite；HTTPS 部署自动设置 Secure。所有已登录写请求要求 header/cookie 双提交 CSRF token，并与数据库 digest 常量时间比对。
- `go test ./...`：通过。
- `go vet ./...`：通过。
- `npm run build`：通过。
- 新增测试覆盖非法主体、创建/恢复、旧世代/过期拒绝、touch/revoke/cleanup、cookie 标志、CSRF 绑定与错误 token。

## 2026-08-07：持久 OAuth 流程批次

- OAuth state 从无锁进程 map 迁移到数据库 hash，一次性原子核销并绑定 provider、节点和 active controller generation。
- 新 OAuth 用户的 subject、昵称、头像不再进入 `/select-node` 查询串；资料保留在可认领/释放/完成的持久 pending enrollment，浏览器仅持有限定完成路径的 HttpOnly 随机 cookie。
- Pending enrollment 支持处理租约、并发拒绝、失败释放和完成结果重放，避免重启或丢失响应后重复注册。
- 登录、注册和 OAuth 完成增加 Origin/Sec-Fetch-Site 校验；Provider 调用使用可注入的 15 秒 HTTP client，强制 HTTPS、检查状态码、限制响应为 1 MiB，且不回显上游正文。
- 配置 Discord guild 时会显式验证成员资格。
- `go test ./...`：通过；`controller` 10.8%，`store` 46.0%。
- `go vet ./...`：通过。
- `npm run build`：通过。
- 新增数据库生命周期、并发 claim、结果重放、cookie 范围、来源校验以及模拟 LinuxDo/Discord provider 的测试。
- 旧 demo 表仍作为 API 兼容层；后续 endpoint 迁移完成前不能删除。
- 真实 PostgreSQL 集成环境、并发争抢测试和 migration upgrade/rollback 演练必须在提交后续功能前补齐。

## 2026-08-07：Agent 主动控制通道与 hash-only 账号供应批次

- enrollment token 改为 SHA-256 摘要、15 分钟有效、绑定预建节点/角色/可选指纹，并与 Agent 凭据版本轮换在 serializable 事务中单次消费；旧 demo 明文注册 token 在迁移时删除。
- Agent 主动长轮询领取数据库持久命令，支持短租约、`FOR UPDATE SKIP LOCKED`、ACK、结果摘要、超时重领、operation ID 语义冲突拒绝和 active controller generation 围栏。
- Agent 将 worker ID、最高已见世代和最近 1000 个命令结果原子保存到本地状态；重启或结果响应丢失后不会重复执行同一 command ID，损坏状态文件会 fail closed。
- 扫描、用户供应、改密和备份中止已迁移到出站命令通道；命令 payload 以节点凭据派生的独立 AES-GCM key 加密后才写数据库。
- 密码账号生成 SillyTavern 兼容的 NFC + scrypt(N=16384,r=8,p=1,keyLen=64) hash/salt；OAuth 节点账号不创建占位密码。Agent 只访问 loopback SillyTavern adapter，并对请求签名。
- 节点账号供应状态和密码材料版本进入 `pending/active/error` 持久事实，成功后才激活 recovering 用户。
- `go test ./...`：通过。
- `go test -coverprofile=coverage/agent_channel.coverprofile ./...`：通过；`internal/agent` 26.1%、`internal/controller` 11.3%、`internal/store` 49.7%，仍远低于最终 80% 门禁。
- `go vet ./...`：通过。
- `web/npm run build`：通过。
- `git diff --check`：通过。
- 新增测试覆盖 enrollment 范围/单次事务、命令精确幂等/租约围栏、世代回退、Agent 重启去重、密文摘要/队列无明文、loopback 约束和 scrypt 兼容参数。
- 仍未完成且未冒充完成：旧备份数据面仍转发永久目标 PSK；SillyTavern adapter 因另一个工具的未提交冲突尚未挂载；真实 PostgreSQL、TLS/NAT 与进程崩溃集成测试待补。

## 2026-08-07：持久快照工作流与 capability 数据面批次

- 删除 Controller 到 Agent 的直接回连客户端和旧入站备份/扫描/上报路由；节点表迁移删除 `agent_url/agent_psk`，只保留 Agent 自报的独立传输地址。
- 快照工作流在 Agent 变更前原子创建 workflow、7 个 step、building manifest、备份关联和 hash-only 传输 capability；工作流支持租约认领、合法 actor 状态推进、指数退避、尝试级 operation ID 和启动后恢复扫描。
- 源 Agent 通过 loopback 签名 adapter 建立单用户写门并排空，再复制到任务专属不可变目录；写门在后续进度失败、取消和打包失败时也会尝试释放。
- 目标 Agent 持久单次消费 capability，通过独立 HTTPS 接收；校验归档摘要、manifest scope、逐文件摘要、路径、文件类型、数量、单文件/总大小、zstd window、展开比和磁盘余量后才执行同文件系统可回滚 rename。
- 发布回执丢失时 Controller 可查询目标持久回执；成功发布在 serializable 事务内同时固化 manifest、replica、legacy read model、capability 和 workflow，并只保留最新成功副本。
- 每次重试轮换 capability；同一个已消费 token 即使传输失败也不能重新启用。所有带 HMAC/Bearer/OAuth 认证头的 HTTP client 禁止跟随重定向。
- `go test -coverprofile=coverage/snapshot_workflow.coverprofile ./...`：通过；总覆盖率 28.6%，其中 `internal/agent` 36.3%、`internal/controller` 11.1%、`internal/store` 47.3%，仍未达到最终 80% 门禁。
- `go vet ./...`：通过。
- `web/npm run build`：通过。
- `GOOS=linux GOARCH=amd64 go build ./cmd/...`：通过。
- `git diff --check`：通过（Windows Git 仅提示示例 YAML 将来可能转换为 CRLF，没有空白错误）。
- 仍未完成且未冒充完成：SillyTavern adapter 尚未挂载；直连失败时的加密中转、真实 PostgreSQL/TLS/NAT/磁盘满/掉电集成测试和快照恢复流程仍缺。

## 2026-08-07：持久多管理员与控制台认证批次

- 删除配置文件中的默认 `admin/admin` 明文语义；数据库没有管理员时，Controller 要求从指定环境变量读取至少 12 位引导密码，bcrypt 后原子创建首位管理员，已有记录绝不会被引导密码覆盖。
- 管理员使用与用户隔离的登录入口和 12 小时持久 Controller session；未知管理员也执行 dummy bcrypt，登录错误不区分账号和密码。
- 支持创建多个同级管理员、列出非敏感资料、禁用/启用和密码重置；禁用或改密在同一事务撤销目标管理员全部 session，且禁止禁用最后一名有效管理员。
- `/api/users/me` 可识别管理员 principal；管理前端新增独立登录和管理员页面，全部管理写请求携带双提交 CSRF token，管理员退出不再误入用户节点页面。
- 单元测试覆盖首次引导互斥、既有管理员不覆盖、hash 不序列化、创建/登录、最后管理员保护、禁用/改密 session 撤销及管理员 session principal。
- `go test -coverprofile=coverage/admin_lifecycle.coverprofile ./...`：通过；总覆盖率 30.0%，`internal/controller` 12.6%、`internal/store` 49.9%，仍未达到最终 80% 门禁。
- `go vet ./...`：通过。
- `web/npm run build`：通过。
- `GOOS=linux GOARCH=amd64 go build ./cmd/...` 与 `git diff --check`：通过。
- 节点原生管理员关联验证和专用短期跳转票据仍未实现，因此 R17 保持 `部分`。

## 2026-08-07：三种身份绑定与密码同步收敛批次

- OAuth/密码登录查询从 legacy 单一 `auth_provider` 投影切换到 `auth_identities`；同一个全局用户可各绑定密码、Discord、LinuxDo，active/pending 身份由 partial unique index 保证 provider/subject 唯一。
- OAuth 绑定使用 hash-only、一次性 state，并绑定当前 global user、Controller session 和 active generation；无有效原 session 的回调不能把身份绑到其他账号。
- 解绑在 serializable 事务中锁定全局用户，拒绝删除最后一种身份，同时更新 legacy 兼容投影与全部 `node_accounts` 的期望 password/OAuth 材料；API 不返回 provider subject。
- 密码新增/改密继续只保存 bcrypt 与 SillyTavern 兼容 NFC+scrypt hash/salt；authoritative verifier 与全部现有节点的版本化期望材料在同一个 serializable 事务落库，再由单活动主控互斥投递。离线、崩溃或失败节点保留 pending/error 材料，后台只对已有本地账号、在线且静置的记录重试。
- `set_password` 命令把每次队列 operation ID 注入 loopback adapter，使重试可由节点幂等处理；不在命令队列存明文密码。
- 前端新增账号安全页，提供三种身份状态、OAuth 绑定、密码绑定/改密、至少一种身份保护与错误反馈。
- 单元测试覆盖身份列表、OAuth/密码绑定事务、最后身份保护、legacy 投影、OAuth state session/generation scope、规范化 OAuth 登录、pending 密码重试材料和 adapter operation ID。
- `go test ./...` 与 `go vet ./...`：通过；覆盖率总计 `31.6%`（`internal/store 52.0%`、`internal/controller 13.9%`），仍低于项目 80% 目标，后续批次必须继续补齐控制器与命令状态机测试。
- `GOOS=linux GOARCH=amd64 go build ./cmd/...`、`web/npm run build` 与 `git diff --check`：通过。
- 尚未完成且未冒充完成：SillyTavern adapter 的本地身份增删仍因冲突 WIP 未挂载，OAuth node-account 期望材料暂不能自动下发到酒馆。

## 2026-08-07：节点自有注册策略 fail-closed 批次

- 新增节点注册策略事实：`unknown/open/invitation_required/closed/error`、单调版本、观测时间、短期过期时间和有限安全错误码；迁移会把未上报策略的既有节点统一重置为 `unknown`。
- Agent 每次心跳通过仅 loopback、HMAC 签名的 adapter 端点读取策略；读取失败或响应无效只上报安全错误，不沿用可能过期的旧策略。
- Controller 限制策略 freshness 最长 10 分钟，并在数据库条件更新中拒绝版本回退；节点策略未知、错误、过期、关闭或无正版本时 `nodeRegistrable` 必定为 false。
- 注册页只公开 `invitation_required`，不公开内部策略版本或诊断；节点卡片明确标示“需邀请码”。
- 单元测试覆盖成功策略读取、adapter 不可用 fail-closed、freshness/诊断规范化、节点可注册门禁、心跳策略持久化与节点事实读取。
- `go test ./...`、`go vet ./...`、`GOOS=linux GOARCH=amd64 go build ./cmd/...`、`web/npm run build` 与 `git diff --check`：通过。
- 本批次仍未替换 legacy 总控邀请码消费，也未实现注册 workflow；这些边界保留在 R15 `部分`，下一批继续收敛。

## 2026-08-08：持久注册 workflow 事实层

- 新增 `registration_workflows`：成功前不创建 `users/global_users`，只保留 active handle 预留、32-byte HMAC 请求摘要、hash-only 客户端状态令牌、bcrypt/scrypt 材料、加密邀请码和所选节点 policy version；表约束保证密码/OAuth 模式互斥。
- 创建 workflow 在 serializable 事务中先处理 operation replay，再锁定用户所选节点的 policy 事实；邀请码必需但未提供、节点/策略过期或版本不一致均 fail-closed，不会静默换节点。
- runnable 查询、active-generation claim、lease-owner fenced retry/fail/complete 均已持久化；失败释放 handle 并清除身份材料/邀请码，客户端令牌只允许在有限期限查询安全状态。
- 节点确认成功后，`users`、`global_users`、`auth_identities`、`node_accounts`、home `user_replicas`、workflow/step 成功状态在同一个 serializable 事务发布；事务完成后清除 workflow 中的临时身份材料。
- 单元测试覆盖新建、相同摘要 replay、不同摘要冲突、hash-only 状态查询、runnable/claim/retry/release、失败释放和完整发布事务。
- `go test ./...`、`go vet ./...` 与 `git diff --check`：通过。Controller/Agent 尚未路由到新 workflow，因此 R15 仍为 `部分`。
