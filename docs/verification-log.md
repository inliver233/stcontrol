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

## 2026-08-08：注册 saga 端到端控制面接线批次

- 密码注册和 OAuth 首次注册均已切到持久 workflow；浏览器提交稳定 operation ID，响应丢失后相同请求会轮换 hash-only 状态 token 并重放原 workflow，不会创建第二个用户或静默换节点。OAuth 发起前所选节点经 state 带回确认页并重新校验策略及邀请码。
- 新增固定 `/api/auth/registration/status` 状态端点和 `Strict`、`HttpOnly`、路径限定 cookie；响应只公开 pending/retrying/succeeded 与安全错误，不公开 workflow、operation、节点策略版本或内部任务 ID。注册页和 OAuth 选点页支持刷新恢复及有界轮询。
- worker 由 active controller generation 与 lease owner 双重 fencing；节点策略版本必须与创建时完全一致且仍新鲜。稳定 registration ID 交给节点 adapter 做供应和邀请码单次消费，每次 Agent 投递使用独立派生 operation ID。
- Agent 仅把 `invitation_invalid/handle_conflict/policy_changed/registration_closed` 视为确定业务拒绝。超时、断连、无法解析结果、空本地用户 ID 及中心发布失败均视为可能已在节点执行，保留 handle/身份材料并持续幂等重试；只有投递前节点长期不可用或命令未能入队才在五次后安全终止。
- legacy Controller 邀请码 API、管理 UI、Store 方法和 `invitation_codes` 表已删除；邀请码只在内存、Controller 加密 workflow 字段和 Agent AES-GCM 命令信封中短暂存在。命令的 durable 比较摘要升级为独立派生密钥的 HMAC-SHA256 v2，Agent 仅为已入队旧命令保留 v1 验证兼容，防止数据库读取者离线枚举低熵邀请码。
- 心跳策略更新拒绝“同一版本更改状态”并记录 `version_reuse`；相同版本仅允许同状态刷新有效期，避免节点用复用版本绕过 workflow 的精确版本绑定。
- 单元测试覆盖请求 HMAC、Strict cookie/安全状态、策略版本变化、第五次以后不确定结果仍重试、投递前安全失败终止、Agent 确定拒绝 allowlist、v2 密钥化摘要、稳定 registration ID/投递 ID 以及完整发布事务。
- `go test -coverprofile=coverage/registration_integration.coverprofile ./...`：通过，总覆盖率 `34.9%`（`internal/controller 16.9%`、`internal/agent 39.9%`、`internal/store 55.0%`），仍未达到最终 80% 门禁。
- `go vet ./...`、`GOOS=linux GOARCH=amd64 go build ./cmd/...`、`web/npm run build` 与 `git diff --check`：通过。
- 尚未完成且未冒充完成：SillyTavern federation adapter 仍因另一个工具的未提交冲突未挂载，因此节点侧真实策略、幂等供应及邀请码单次消费尚未形成真实闭环；真实 PostgreSQL、进程崩溃和网络响应丢失集成测试也待补，R15 保持 `部分`。

## 2026-08-08：老节点账号安全库存与 OAuth 自动关联批次

- 新增 `account_import_batches/account_import_candidates` 持久事实：批次以 operation ID 幂等、以完整安全库存摘要拒绝不同内容重放，并绑定 active controller generation、发起管理员、节点和扫描时间。候选保存节点 local user ID、目录指纹、身份指纹、分类和关联结果，但 API 不公开本地 ID、指纹、批次/候选内部 ID或内部 reason code。
- Agent 新增精确账号库存契约，优先从签名 loopback adapter 读取 local user ID、handle、密码存在性、OAuth stable subject、管理员标记、大小及目录摘要；原始 OAuth subject 在 Agent 进程内立即变成按节点 PSK 和用途隔离的 HMAC 指纹，durable command result 不含原 subject。adapter 读取失败只回退到目录摘要，标记 `directory_fallback/unknown` 且禁止声明 OAuth/管理员事实。
- 单批库存上限固定为 500 个账号以满足单节点数百基线并保持 Agent durable result 在 1 MiB 认证请求上限内；超限会整批失败而非静默截断。万级跨节点容量不受影响，更大单节点所需的分页扫描仍列入容量阶段。
- Controller 用同一节点凭据对现有 active OAuth identities 计算指纹，只允许唯一 global UUID 所属用户命中后自动关联。关联在 serializable 事务中插入 active `node_accounts`；无既有 home 时把导入节点设为 home/ready，已有其他 home 时仅建 stale hot standby，避免未经数据校验进入登录候选。
- handle 只用于识别 `claim_required`，从不作为全局关联键；无匹配身份分别进入 `oauth_unmatched/recovery_required`，多身份命中不同全局用户、local ID/handle 冲突或同用户已有另一节点账号均进入 `identity_conflict`，不会覆盖旧映射。
- 管理台扫描使用稳定浏览器 operation ID；响应不确定时保留同一操作重试，也可读取节点最近的持久库存。界面明确区分已管理、OAuth 自动关联、需控制权证明、需身份恢复、OAuth 未匹配和身份冲突，不提供尚未接线的假“合并成功”按钮。
- 单元测试覆盖节点/用途隔离的库存 HMAC、adapter subject 脱敏、目录回退限制、Controller 唯一 OAuth 指纹匹配、同名账号必须证明、OAuth 自动 node-account/home replica 事务、operation digest 冲突、最新批次读取及 API 模型脱敏。
- `go test -coverprofile=coverage/account_import.coverprofile ./...`：通过，总覆盖率 `37.1%`（`internal/controller 18.7%`、`internal/agent 42.3%`、`internal/store 56.1%`、`internal/crypto 26.5%`），继续提升但仍低于最终 80% 门禁。
- `go vet ./...`、`GOOS=linux GOARCH=amd64 go build ./cmd/...`、`web/npm run build` 与 `git diff --check`：通过。
- 尚未完成且未冒充完成：SillyTavern adapter 尚未挂载，当前真实节点只能得到目录回退库存；同名账号控制权证明、OAuth 未匹配认领、冲突合并/区分和管理员人工身份恢复尚未实现，因此 R16 保持 `部分`。
