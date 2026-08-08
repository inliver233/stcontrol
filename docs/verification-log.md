# 验证记录

## 2026-08-08：保守灾难模式与恢复排空

- Agent 在原子写入的 runtime state 中持久化节点控制模式、模式世代、双探针失败计数、失联/独立时间和 adapter 排空计数。
- 单次/抖动心跳失败只会暂停受管新操作；只有签名心跳与独立健康探针均持续失败达到时长和次数门槛，计算节点才可进入 `independent`。
- 恢复心跳绑定更高或相同 Controller generation；独立模式只能先进入 `independent-draining`，有活动灾难会话或待同步用户时 Agent 与 Controller 双方都拒绝直接恢复 managed。
- PostgreSQL migration 0022 增加节点报告/期望模式、模式世代、失联证据和不可省略的模式事件；启动时以 active epoch 和所有计算节点模式重建新操作门禁。
- 新登录、选点、密码/OAuth 注册与备份在门禁关闭时返回可重试错误；Agent 同时停止领取新的受管命令。
- `go test ./...`：通过；新增覆盖抖动、长期双信号失联、重启恢复、旧世代、排空计数、数据库世代回退和控制面门禁。

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

## 2026-08-08：管理员人工身份恢复批次

- 新增 `identity_recovery_operations`：稳定 operation ID、global UUID 所属用户、发起管理员、32-byte keyed HMAC 请求摘要、密码版本、暂存节点数和 active controller generation 构成持久幂等事实；不同管理员、用户或密码复用同一 operation ID 会冲突关闭。
- 管理员可为现有 global UUID 创建缺失的密码身份或重置既有密码身份。bcrypt verifier、NFC+scrypt 节点材料、`users/global_users` 恢复状态、全部用户 session 撤销、操作事实和结构化安全审计在同一 serializable 事务提交；无 active generation 时整体回滚，数据库从不接收可逆明文密码。
- 节点即时投递和响应丢失重放均按用户重新读取数据库已暂存的 hash/salt/version，不使用该 HTTP 请求重新生成的随机盐。在线成功节点转 active；离线/失败节点保持 pending/error，由后台使用同一持久材料重试。禁用用户只更新身份凭据并保持禁用，重新启用前不投递节点密码。
- 管理台用户主标识改为 global UUID，并提供一次新密码的人工恢复表单。浏览器仅在失败重试期间保留同一 operation ID，不显示内部操作/任务 ID；成功提示明确说明会话撤销和待同步节点。
- 单元测试覆盖缺失密码身份创建、既有密码版本递增、恢复中转 active、禁用状态保留、节点全量暂存、会话撤销、相同摘要 replay、不同摘要冲突、无 active generation 回滚、持久材料定向读取、HMAC 密钥/管理员/密码绑定、UUID 输入校验和 JSON 脱敏。
- `go test -coverprofile=coverage/identity_recovery.coverprofile ./...`：通过，总覆盖率 `37.5%`（`internal/controller 18.9%`、`internal/agent 42.3%`、`internal/store 56.8%`、`internal/crypto 26.5%`），仍低于最终 80% 门禁。
- `go vet ./...`、`GOOS=linux GOARCH=amd64 go build ./cmd/...`、`web/npm run build` 与 `git diff --check`：通过。
- 尚未完成且未冒充完成：真实 SillyTavern adapter 未挂载，因而节点改密仍无法形成应用侧闭环；导入候选的控制权证明/合并和无 global UUID 候选的恢复绑定仍待实现，R14/R16 保持 `部分`。

## 2026-08-08：持久节点容量与多维健康批次

- 新增 `0015_node_health_capacity.sql`：节点分别保存连通性、运营、容量、兼容性、窗口均值/峰值、真实磁盘/配额、受管分配量、在线用户、任务负载及状态机游标；组合索引服务新分配门禁，指标样本保留 24 小时。
- Agent 以并行探测采集 CPU/内存、数据分区真实总量和可用字节、受管目录大小、注册策略以及 adapter 健康契约；存储节点要求私有备份根。显式配额上限为真实文件系统总量，无法可靠采集时上报无效并使容量失败关闭。
- 容量状态机使用 120 秒窗口；约 50% 进入 `busy`，关键资源达到 60% 并持续 120 秒进入 `full`。真实磁盘/配额低水位、在线人数和任务上限立即满载；退出满载必须连续低于繁忙水位 180 秒且完成 300 秒冷却，避免抖动恢复。
- 心跳在 serializable 事务中锁定节点、写入样本、聚合窗口、推进容量游标并更新注册策略和兼容事实。节点心跳过期会将连通性置离线、容量置未知；新注册和新备份数据只选择连通、运营、兼容且容量开放/繁忙的节点，已有用户操作不会因容量满载被错误中断。
- 公开节点 API 不再返回 CPU/内存/磁盘及内部原因码，只显示开放/繁忙/满载/维护/备份/故障、推荐、邀请码需求和浏览器实测延迟。管理员页展示四维健康、窗口指标、真实字节、在线用户/队列和安全原因，并可审计地进入/结束维护。
- 单元测试覆盖 50% 降权、持续 60% 硬门槛、磁盘/配额/人数/队列立即关闭、恢复滞后与冷却、指标无效、整数边界、配额真实性、兼容能力/版本、公开模型脱敏、推荐排序、心跳事务、迁移所需 UUID 和陈旧节点清理。
- `go test -coverprofile=coverage/node_capacity.coverprofile ./...`：通过；总覆盖率 `39.6%`（`internal/agent 44.8%`、`internal/controller 20.6%`、`internal/store 58.7%`），仍低于最终 80% 门禁。
- `go vet ./...`、`GOOS=linux GOARCH=amd64 go build ./cmd/...`、`web/npm run build` 与 `git diff --check`：通过。
- 尚未完成且未冒充完成：真实 SillyTavern adapter 会话遥测、插件指纹、客户端延迟持久化与综合推荐评分尚缺；真实 PostgreSQL 迁移/并发、目标规模容量压测和故障接管状态机仍未验证，因此 R18 保持 `部分`，R19/R21 继续作为后续工作。

## 2026-08-08：用户保护投影与显式热备接管批次

- 新增 `0016_user_protection_takeover.sql`：持久保存七种用户保护状态、当前/恢复节点、最近不可变恢复点和版本；接管操作记录稳定 UUID、32-byte HMAC 请求摘要、源/目标、快照、旧活动 epoch、主控 generation、确认和完成时间。
- 周期调和同时读取 legacy 副本兼容投影、规范化 `replica_copies`、属于该用户的 immutable snapshot 及节点连通/运营/兼容事实。纯存储副本才是正常保护；只有计算热备时标记临时保护，存储故障不会中断当前 home。临时/未保护状态使用可配置宽限期，紧急状态立即写入去重告警。
- 真实 replica conflict 会锁存：同一调和事务把 global/legacy 用户置为 conflict，冻结普通业务 session 的解析、撤销未消费登录短码，并把写租约置为 conflict。后续冲突恢复认证批次改为保留身份令牌但只允许进入专用恢复路由；周期仍不会自行解锁或覆盖任何原始副本。
- 用户接管 API 必须显式确认数据丢失风险并使用稳定 operation ID；请求摘要绑定用户、目标、精确 immutable 恢复时间和确认，事务也要求恢复时间未变化。serializable 事务锁定 global user，拒绝仍有效的写租约，只接受 active 节点账号、合格计算节点和属于该用户的 compatible immutable ready 热备，然后原子降级旧 home、晋升唯一权威 home、撤票、更新节点账号/保护投影并审计。完全相同重试返回原结果，不同事实复用 ID 冲突关闭。
- 用户选点页显示产品化保护状态和恢复时间；A 仍有活动 writer 时提示返回 A，只有没有活动 writer 时才显示精确恢复点的接管确认。热备不能直接登录，存在热备时保留用户选择机会；成功接管但登录交接失败时页面仍会把新 home 保持为可重试。管理员保护告警页读取真实后端，只展示达到 `notify_after` 的 open/acknowledged 告警并每 30 秒刷新。
- 单元测试覆盖保护投影事务、冲突锁存/失败关闭 SQL、告警宽限、公开模型脱敏、所有产品状态、接管 HMAC 绑定、显式风险确认、活动租约拒绝、跨用户快照校验条件、完整原子晋升和精确 operation replay。
- `go test -coverprofile=coverage/protection_takeover.coverprofile ./...`：通过；总覆盖率 `40.2%`（`internal/agent 44.8%`、`internal/controller 21.5%`、`internal/store 59.2%`），仍低于最终 80% 门禁。
- `go vet ./...`、`GOOS=linux GOARCH=amd64 go build ./cmd/...`、`web/npm run build` 与 `git diff --check`：通过。
- 尚未完成且未冒充完成：当前没有可用的真实 PostgreSQL 服务，因此迁移、data-modifying CTE、行锁和并发接管仅有 SQL mock/静态语义证据；纯存储到计算恢复、冲突差异/来源选择/有限合并、节点退役/升级/损坏状态机和 SillyTavern 逐请求写门闭环仍待实现，R19 保持 `部分`。

## 2026-08-08：纯存储保护自动修复批次

- 新增持久事实驱动的修复候选查询：只选 `temporary/unprotected`、active 用户、健康 ready home，排除有效写租约、在途读写、independent/quiescing 和活动 snapshot workflow；同时直接复核不存在属于该用户的健康 compatible immutable archive，避免保护投影延迟造成重复修复。
- 调度器每 30 秒优先处理存储修复，并复用全局快照并发槽。目标只允许启用备份、具有数据面、连通/运营/兼容/容量合格的纯存储节点；优先 `open` 再选 `busy`，没有目标时保持未保护和告警，不降级到计算节点。
- 修复完全复用既有单用户写门、不可变 snapshot、短期 capability、端到端校验和原子发布流程，`backup_jobs.trigger=storage_repair` 映射为副本来源 `temporary_failure_protection`。
- `CompleteSnapshotWorkflow` 只有在新 archive manifest/归档摘要、capability 和数据库发布全部通过后，才把其他 ready archive 降为 stale；不可达旧节点的物理数据与 manifest 保留，避免在故障期间盲删唯一可用原件。
- 单元测试覆盖无 writer/无 archive 候选 SQL、纯存储角色门禁、open 优先及 busy 回退、自动修复来源和“新发布后旧副本才 stale”的原子事务顺序。
- `go test -coverprofile=coverage/storage_repair.coverprofile ./...`：通过；总覆盖率 `40.3%`（`internal/agent 44.8%`、`internal/controller 21.6%`、`internal/store 59.3%`），仍低于最终 80% 门禁。
- `go vet ./...`、`GOOS=linux GOARCH=amd64 go build ./cmd/...`、`web/npm run build` 与 `git diff --check`：通过。
- 尚未完成且未冒充完成：真实 PostgreSQL 并发调度、存储掉线/回归和完整 Agent-to-Agent 修复尚未故障注入；SillyTavern adapter 未挂载时活动事实仍不完整。纯存储到计算恢复、旧 archive 的受审计物理清理和稳定后的临时计算副本清理待后续实现，R09/R19 保持 `部分`。

## 2026-08-08：纯存储到计算恢复批次

- 新增 `0017_restore_workflows.sql`：`restore_operations` 保存稳定 operation ID、32-byte keyed 请求摘要、源/结果两个不可变 snapshot ID、源/目标、用户确认的精确恢复时间和完成时间；`node_accounts.provisioning_workflow_id` 将恢复账号与通用密码同步 worker 隔离。
- 恢复目标查询只公开连通、运营、兼容和容量合格的计算节点，并排除冲突副本、禁用/冲突账号、同 handle 账号占用及无法供应账号的用户。创建事务锁定 global user，要求保护状态仍为 `restore_required`、恢复时间未变化、源为用户自己的 compatible immutable ready archive、无有效/在途写租约；相同 operation/HMAC 重放原 workflow，不同请求复用 ID 冲突关闭。
- workflow 持久步骤为 `provision_account -> prepare_target -> transfer -> verify -> publish`。目标没有 active 账号时，使用已持久化节点 scrypt 材料或 active OAuth identity 下发专用、幂等、固定能力 `restore_user_account` 命令；账号确认后才准备数据接收。active controller generation、worker lease、指数退避、重启扫描和短期 capability 轮换均复用既有围栏。
- storage Agent 在 archive 原子发布时写入只读私有元数据。恢复时重新序列化原 manifest 并与 Controller 的原 digest 比对，再逐文件重算大小/SHA-256；缺元数据、未知/尾随 JSON、额外文件、重复路径、符号链接、非普通文件、越界或内容漂移均失败。新 restore manifest/snapshot 独立作用域后，通过 Authorization capability 直传 compute Agent；目标限额验证并同文件系统原子发布。
- Controller 只有取得目标持久回执后才在一个 serializable 事务内固化结果 manifest、降级旧 home、晋升唯一 authoritative home、更新 legacy/normalized 副本与节点账号、结束旧租约、撤销未消费短码、写保护状态和审计。终止失败会撤 capability、把结果 manifest 标 invalid、把未纳管目标标 error，并保留旧 home/archive；不会删除可能有取证价值的数据。
- 用户 API 提供恢复目标、提交和按用户/operation 查询状态，不公开 workflow/snapshot/capability。节点页展示目标加载/空态、精确恢复点、显式数据丢失确认及准备/传输/校验/发布/重试/失败状态；浏览器 session 保存稳定 operation ID，只有后端 `succeeded` 才刷新副本并登录。
- `go test ./...`、`go vet ./...`、`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/...`、`web/npm run build` 与 `git diff --check`：通过。`go test -coverprofile=coverage/archive_restore.coverprofile ./...`：通过，总覆盖率 `40.8%`（`internal/agent 46.0%`、`internal/controller 20.2%`、`internal/store 60.1%`）。
- Windows race 构建因主机安装的 `cc1.exe` 不支持 64 位而未执行；本机仍没有可用真实 PostgreSQL，因此 serializable/行锁/迁移和双 Agent 崩溃只能以 SQL mock、静态语义和单进程测试为证据。SillyTavern 专用 `/api/stcontrol/internal/users/restore` adapter 因既有未提交 WIP 冲突尚未挂载；冲突差异/来源选择、节点退役/升级/损坏和物理清理仍缺，R19/R20 保持 `部分`。

## 2026-08-08：冲突案件与恢复认证边界批次

- 新增 `0018_replica_conflicts.sql`：每用户最多一个开放案件；案件保存检测时保护版本/主控世代并以 `sources_captured_at` 锁定一次性来源捕获。来源仅保存节点身份、副本事实、legacy 版本和合格 immutable snapshot 的摘要/规模/发布时间，不保存文件路径或内容。
- 保护调和在同一 serializable 事务中先投影 conflict、创建案件并捕获来源，再冻结 global/legacy 用户、未消费短码和写租约。周期重跑不会新增后发现的来源或改写原始来源事实。
- 冲突时不再销毁尚有效的身份令牌。普通 session 查询继续只接受 active 用户；专用 conflict session 同时要求 global/legacy 均为 conflict、开放案件、active controller generation 和有效用户令牌，且只挂载 `/api/conflicts`。冲突用户可用既有密码/OAuth 重新认证；禁用等其他状态仍拒绝。
- 只读 `/api/conflicts/me` 返回案件版本、来源节点/类型/状态、是否权威、immutable 证据规模与捕获需求，不公开 snapshot ID、manifest digest、文件名或内部 workflow。manifest scope 不同只标记需检查，不宣称内容一定不同。
- 针对性测试覆盖案件来源读取与公开最小化、非法用户、开放案件 session 条件、密码冲突登录、专用路由可达和普通业务路由失败关闭，以及调和 SQL 的创建/一次捕获顺序。
- `go test ./...`、`go vet ./...`、`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/...`、`web/npm run build` 与 `git diff --check`：通过。`go test -coverprofile=coverage/conflict_foundation.coverprofile ./...`：通过，总覆盖率 `42.8%`（Agent `46.0%`、Controller `25.0%`、Store `60.4%`），仍低于最终 80% 门禁。
- 当前仅完成冲突闭环的身份与事实基础。Agent 逐文件证据捕获、分块/限额差异、用户来源选择、不同路径自动合并、同路径选边/双份保留、最终原子解冻和前端页面尚未实现；R19 仍为 `部分`。

## 2026-08-08：冲突不可变证据与加密差异批次

- 新增 `0019_conflict_evidence.sql`：来源拥有稳定 evidence ID、pending/capturing/retry_wait/ready/failed 状态、租约/尝试/退避和最终 entries digest/规模/捕获依据；manifest page 只保存 Controller 二次加密后的 ciphertext 与明文摘要，不保存可查询文件名。
- compute Agent 在数据分区的隐藏控制目录中以任务暂存、两遍源检查、逐文件 SHA-256 和同文件系统 rename 发布冻结现场证据；该隐藏目录不会进入用户活动遥测。storage Agent 先读取严格私有 metadata，将原 manifest 重新绑定数据库摘要并复核全树，再复制证据。两种来源的重放都要验证作用域和现存证据全树，额外文件、篡改、符号链接、非普通文件、路径/大小/数量/磁盘门禁失败关闭。
- Agent 固定命令 `capture_conflict_evidence` 只返回无路径 receipt；`read_conflict_evidence_page` 只返回以命令内响应密钥加密的 ciphertext，且不进入 Agent 通用完成结果缓存。Controller worker 使用持久 claim/lease/attempt，复核每页作用域、游标、严格排序、路径、摘要、总数/总字节和 entries digest，再用 evidence ID 用途隔离 key 重新加密并在 serializable 事务发布全部 pages、来源 ready、案件阶段和无路径审计；同事务把已摄取的命令结果改写为无路径摘要。第五次失败后保持 frozen/failed，不带不完整证据前进。
- conflict 专用差异 API 从加密页重构并再次验证 manifest，只在响应正文返回认证用户自己的路径；URL 仅含数字 offset/limit。相同文件不显示，不同路径标记后续可自动并入，同路径不同内容标记必须选源或保留双份；聊天/JSON/文本/二进制仅分类，不宣称语义合并。
- 新增 `/conflict` 页面和冲突登录分流。页面轮询案件与来源捕获状态，展示证据规模/依据、失败关闭、相同结果、差异摘要和分页表格；普通 auth 状态仍为空，不因此获得业务页面权限。
- 单元测试覆盖 compute/storage 捕获、archive digest 绑定、加密分页无路径泄露、证据篡改重放拒绝、隐藏目录不进入用户遥测、任务 list/claim/retry/terminal、encrypted pages 原子完成/读取、持久页二次解密校验和不同路径/同路径差异分类。
- `go test ./...`、`go vet ./...`、`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/...`、`web/npm run build` 与 `git diff --check`：通过。`go test -coverprofile=coverage/conflict_evidence.coverprofile ./...`：通过，总覆盖率 `44.4%`（Agent `51.4%`、Controller `26.0%`、Store `60.8%`），仍低于最终 80% 门禁。
- 当前仍未实现用户来源选择、同路径决策、不同路径实际合并、双份原件保留、结果原子发布/解冻；没有可用真实 PostgreSQL/双 Agent 环境，迁移、租约竞争、重启续跑和大清单仍只有 SQL mock/单进程证据，R19/R20 保持 `部分`。

## 2026-08-08：用户主导冲突有限合并与原子解冻批次

- 新增 `0020_conflict_resolutions.sql`：稳定 operation/request HMAC、冲突版本、最终计算节点、结果 snapshot、逐路径决策和每来源短期传输 capability 都是 PostgreSQL 事实；长路径以 SHA-256 建索引而不把 4096-byte 路径直接放入 B-tree 主键。
- 提交事务只接受 `awaiting_decision`、全部证据 ready、用户/旧账号仍冻结、无在途请求、active controller generation、健康 compatible 计算主节点；冲突版本、来源、逐路径 source 和用户请求摘要全部失败关闭。相同 operation 可重放，失败终态只能复用原 operation 和原冻结证据重启。
- 非主来源通过独立数据面、15 分钟 hash-only 单次 capability 直接传到最终计算 Agent；响应丢失先查询目标持久回执，明确失败/过期才轮换 capability。Controller 只下发加密固定命令，不接收大文件，也不记录路径明文命令结果。
- Agent 在准备阶段重新验证本地和汇集证据的 scope、entries digest 与逐文件内容。不同路径自动并入；同路径可选源。`preserve_both` 会把每个不同内容版本复制到 `conflict-preserved/<conflict>/<source>/...`，源路径和目标路径分别校验，避免把重命名后的目标路径误当源路径或覆盖用户原文件；所有结果排序、限文件数/总字节并在同文件系统原子换代。
- PostgreSQL 只有在 Agent 返回绑定 operation/conflict/result 的回执后，才在 serializable 事务固化 immutable manifest、降级旧 conflict 副本、晋升唯一权威计算副本、更新 legacy home、结束冲突写租约、解冻用户、撤销原恢复 session 并写审计。原始 conflict evidence 和来源事实不物理删除；保护投影随后重新调和并触发纯存储保护修复。
- 冲突页面现可选择最终计算节点、全局保守策略和逐路径来源/双份保留；分页间保存选择，稳定 operation 写入 sessionStorage，显示准备/发布/退避/失败状态，失败可从同一证据重试。未显式逐项的同路径冲突按用户确认的全局策略处理；若主来源没有该路径且其他来源彼此不同，后端强制逐项选择。
- `go test ./...`、`go vet ./...`、`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/...`、`web/npm run build`、嵌入迁移顺序测试与 `git diff --check`：通过。
- `go test -coverprofile=coverage/conflict_resolution.coverprofile ./...`：通过；总覆盖率 `41.3%`（Agent `48.8%`、Controller `24.7%`、Store `54.6%`）。新状态机增加的 SQL/Controller 路径尚未达到 80% 门禁。
- 本机 Docker daemon 与 PostgreSQL 均不可用，因此 `0020` 的真实迁移、serializable 并发、双 Agent 直传、进程崩溃恢复和大清单/磁盘满仍缺运行证据；SillyTavern 写门 adapter 尚未挂载，节点退役/升级/损坏也未实现，R19/R20 仍严格保持 `部分`。

## 2026-08-08：逐管理员节点关联与原生后台短码批次

- 新增 `0021_admin_node_links.sql`：关联保存节点 local identity、权限版本、失效原因和最近复核时间；验证 operation 保存 32-byte keyed HMAC 请求摘要、结果、active controller generation 和安全审计。节点 local identity 在同一节点只能绑定一个有效总控管理员，避免多人共享同一原生管理员身份冒充独立关联。
- 首次关联要求当前总控管理员输入自己的既有节点账号密码。Controller 不保存明文，只把它放入绑定 operation 的 Agent 加密固定命令；Agent 通过签名 loopback adapter 验证。成功/拒绝都成为 durable operation，相同请求可重放，不同管理员、节点、handle 或密码复用 operation ID 会冲突关闭。
- 后续进入后台不再要求密码，但每次都用独立 `check_node_admin` 命令读取节点当前权威权限。local identity 不同或权限降级时，关联会在 serializable 事务进入 stale 并撤销全部未消费 `node_admin` 票据；手工撤销和禁用总控管理员同样原子撤销关联/票据。
- 管理员短码与用户登录短码使用不同 HMAC 用途域，只保存 secret hash；票据强制 admin principal、目标节点、local handle、active controller generation、有效管理员和 verified 关联，目标 Agent 核销时以 data-modifying CTE 原子单次消费。浏览器使用临时 `no-referrer` POST form，短码不进入 URL。
- 管理台节点页读取真实逐管理员关联事实，支持验证/重新验证、进入原生后台和撤销；密码提交后立即清空，失败不显示内部 ID。失效关联明确要求重新验证，不伪造跳转成功。
- 单元测试覆盖签名 adapter 验证/复核及不完整权限事实拒绝、成功/拒绝 operation 持久化、权限失效/手工撤销/管理员禁用的级联撤票、签发与单次核销、管理员/用户短码用途隔离、验证摘要绑定和所有新增公共入口非法输入。
- `go test -coverprofile=coverage/admin_node_handoff.coverprofile ./...`：通过；总覆盖率 `41.1%`（Agent `48.6%`、Controller `24.0%`、Store `54.7%`），仍低于最终 80% 门禁。
- `go test ./...`、`go vet ./...`、`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/...`、`web/npm run build` 和 `git diff --check`：通过。
- 尚未完成且未冒充完成：SillyTavern 尚未提供 `/api/stcontrol/internal/admin/verify`、`/check` 和 `/federated-admin-login` 的真实 adapter，也未把核销结果转换为本地管理员 session；本机没有可用 PostgreSQL，迁移、约束和并发核销仍缺真实运行证据。因此 R17 保持 `部分`。

## 2026-08-08：SillyTavern adapter 挂载、真实 HTTP 交接与三项酒馆修复批次

- SillyTavern 的 stcontrol adapter 已挂载到真实 `server-main`：内部能力只接受 loopback Agent HMAC/nonce；持久模式、session、写门和幂等回执移到独立 `_stcontrol` 目录并以 0700/0600 原子保存，兼容旧路径迁移。进程实例变化时只清除无法证明仍存活的 orphan in-flight 计数，继续保留模式世代、session 和 lease 围栏。
- 用户和管理员交接均使用 POST body 中的一次性短码；adapter 经 Agent HMAC 向 Controller 核销，绑定 session/activity epoch/controller generation 或管理员 permission version，写入隔离的本地 session。测试确认短码不进入 URL、重放拒绝、管理员降权拒绝、伪造 Agent secret 拒绝，并通过完整 SillyTavern server 的 cookie-backed CSRF 路径。
- 注册供应先以稳定 `registration_id` 原子 claim 节点邀请码，再创建账号；同 claim/同身份可在账号已落盘但 adapter 回执丢失后续跑，不同 claim 或身份漂移失败关闭。实际 Express 路由测试删除幂等回执后重启调用，验证账号不重复、邀请码不二次消费。
- 单用户 snapshot gate 在真实路由中拒绝新写并等待该用户读写排空，只有精确 token 可 release；错误 token 不能开门。陈旧 writer lease 只能保留读而不能写；受控浏览器页面即使可见但闲置也继续低频 heartbeat，standalone 历史行为不变。
- 酒馆三项用户问题同时闭环：聊天初始 range/page size 读取“设置→聊天/消息处理”的 `chat_truncation`（0 为全部、1–1000 可调，缓存按 page size 隔离）；Free Gemini 为每个模型持久保存 `gemini/openai` 请求格式且旧配置默认原生 Gemini；“重置一切”只校验当前用户名，错误/缺失用户名不删除，正确用户名经真实路由删除并重新初始化数据，不再存在重置码。
- SillyTavern 定向套件：`node --test` 覆盖 adapter、真实路由、heartbeat、邀请注册、聊天分页、Free Gemini 和账户重置，共 93 项、86 通过、7 项因测试配置明确跳过、0 失败；`npm run test:optimizations` 128/128 通过；`npm run test:registration` 15/15 通过。相关新增源文件 ESLint 与 `git diff --check` 通过。
- stcontrol `go test ./...`、`go vet ./...`、`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/...` 通过。新增跨仓库测试由 Go Agent 调用真实 adapter fixture，并启动完整 SillyTavern server 验证实际 router 挂载与 CSRF；缺少 sibling/Node 时只在非验收环境显式 skip。
- 尚未完成且未冒充完成：当前账号 inventory 硬限 500 且没有分页，不能满足 10k 规模；本批次仍没有真实 PostgreSQL，所以 Controller→数据库→Agent→酒馆的注册、并发写租约和 snapshot durable workflow 尚未闭环；多标签页/休眠、扩展绕过、跨机 TLS/NAT、全故障矩阵与 80% 覆盖率门禁仍待后续阶段。因此相关 R01–R06、R13–R19、R22 均保持 `部分`。

## 2026-08-08：真实 PostgreSQL 迁移、领导锁与原子核销批次

- 在项目内隔离的 `.test-postgres` 运行 EDB Windows PostgreSQL 17.10（官方 PostgreSQL Windows 下载页提供的 advanced-user binary archive，下载 SHA-256 `EF9B1E5E23D2E8A83914BA13D9DC536A72210FBA53FD1808FF1F7E06BB22B106`）；cluster 只监听 `127.0.0.1:55432`，runtime/data/log 均由 `.gitignore` 排除，没有写入两个项目之外。
- 首次真实并发启动暴露迁移锁缺陷：8 个 `Store.Open` 会因逐 migration 的 SERIALIZABLE 快照在等待 advisory xact lock 前已建立而出现 `40001`，且 migration lock 与长生命周期 Controller leadership 复用了同一 ID，使被动副控在活动主控期间无法完成启动迁移核对。
- 修复后迁移使用独立 `STMIGRAT` lock domain，并在专用 `sql.Conn` 上以 session lock 覆盖完整 migration 序列；各 migration 仍独立事务提交，失败不会伪造 `schema_migrations`。8 个同时启动的 Store 全部成功，28 个版本/name/checksum 与 embedded 文件逐项一致。
- 真实 session-level 领导锁验证第一个主控独占、第二个失败关闭、释放后第二个可取得；活动领导锁存在时另一 Store 在 5 秒门禁内完成迁移核对，证明被动副控启动不再被迁移锁错误阻塞。
- 真实 PostgreSQL 上 32 个并发 A/B 选点得到恰好 1 个 acquired、31 个 existing、数据库仅一行 writer 且所有调用无错误。发现 activity operation replay 原先只按 operation ID 读取结果，现同时绑定原 user/node/session；精确重试重放原结果，改 payload 明确返回 `ErrLeaseOperationConflict`。
- 真实登录 handoff 的 data-modifying CTE 以 32 个并发消费者验证，只有一次成功；错 secret 不消费，成功后的重复核销失败。创建 handoff 与 writer lease 同事务、精确创建重试返回同一 JTI/activity epoch。
- 新增 `TestPostgresCriticalConcurrency`：没有 `STCONTROL_TEST_POSTGRES_DSN` 时快速单元套件明确 skip；验收/CI 提供 DSN 后每次创建隔离 schema，覆盖并发迁移、领导锁、单写租约、operation 绑定和一次性核销，并在结束时 `DROP SCHEMA CASCADE`。
- `STCONTROL_TEST_POSTGRES_DSN=... go test -coverprofile=coverage/real_postgres.coverprofile ./...`、`go vet ./...`、`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/...` 通过；总覆盖率 `43.7%`（Agent `52.5%`、Controller `24.6%`、Store `56.8%`），仍远低于最终 80% 门禁。
- 尚未完成且未冒充完成：snapshot/restore/registration/conflict/relay durable workflow 尚需真实 PostgreSQL 故障、重启、重复请求和双 Agent 注入；Controller 完整 HTTP→Agent→酒馆进程闭环、migration upgrade/restore 演练、目标容量与覆盖率门禁继续后续阶段。

## 2026-08-08：万级账号库存分页批次

- 真实酒馆 adapter 以 node-keyed revision 固定账号事实，按 `local_user_id` 严格稳定排序，每页最多 250、总量最多 10,000；续页必须绑定首请求 revision，账号变化、无 revision 续页、重复 ID 和越界游标失败关闭。
- Agent 固定命令、Controller durable page operation 和导入分类器逐页复核 revision/cursor/total/source/严格顺序，最多 40 页；管理 API/UI 再按最多 100 条分页，不会一次渲染万级 DOM。
- 620 个真实 Express 账号跨三页无重复遗漏，10,000 条状态机完整接收；真实 PostgreSQL 17.10 在约 9.2 秒内分类持久化并读取首末页。
- stcontrol 全量真实 PostgreSQL 测试、`go vet`、Linux CGO0 build、web build，以及 SillyTavern 15 项定向 Node 测试和受影响源文件 ESLint 均通过；当时总覆盖率 43.8%，仍未达到 80%。

## 2026-08-08：TLS 失败关闭与真实 Linux Agent 数据面批次

- 恢复此前入口引用但实现缺失的 Agent HTTP 数据面，并把暴露面缩到无节点拓扑的 `/agent/health` 和 capability-scoped snapshot 接收；供应、改密、备份和扫描等全部控制动作只允许 Agent 主动拉取的加密固定命令，旧入站控制路径测试为 404。
- Agent 数据面先校验无 query、精确 content type/长度、UUID、SHA-256 和有限 Authorization header，再以 4 路 semaphore 限并发；错误为固定 reason code，不反射 capability，响应带 `no-store/nosniff`。一次性 capability 仍由本地持久状态做 hash-only 原子消费。
- Controller 主监听与 Agent 监听新增直接 TLS 配置；Controller、relay、Agent 的非 loopback 明文监听全部拒绝，直接 TLS 模式固定最低 TLS 1.3。证书/私钥必须成对，进程在数据库或后台 worker 启动前先预加载检查；Controller/Agent 启动日志不再回显外部 endpoint。
- Docker 部署改为 PostgreSQL 17、`:8443` 直接 TLS、只读证书挂载和独立容器配置；通用示例保留 loopback 反向代理模式。安装脚本的源文件与 embedded 副本重新同步，并明确生成 TLS 字段与灾难阈值。`docker-compose config --quiet` 静态校验通过；本机 daemon 未运行，所以未把镜像启动冒充运行验收。
- 在项目内下载官方 `go1.26.5.linux-amd64.tar.gz`，SHA-256 为 `5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053`，并由 WSL Ubuntu-E 执行 Linux-only HTTP 数据面测试。首轮真实运行发现首次副本的最终父目录尚不存在时错误地对该不存在路径查询磁盘空间；修复为对与最终路径同文件系统且已存在的 task root 查询。修复后完整 tar.zst 经 HTTP 接收、manifest/逐文件校验、元数据写入和原子发布成功，同 capability 重放被拒绝。
- `STCONTROL_TEST_POSTGRES_DSN=... go test -count=1 -coverprofile=coverage/tls_data_plane.coverprofile ./...`、`go vet ./...`、Linux amd64 CGO0 build、Linux WSL 定向 E2E、`git diff --check` 和 Docker Compose 静态解析通过；总覆盖率 44.2%（Agent 54.1%、Controller 25.2%、Store 56.8%）。
- 尚未完成且未冒充完成：真实受信 CA 的跨机 TLS/NAT、断网/磁盘满/掉电和双 Agent 进程故障矩阵、全仓日志敏感样本扫描及 80% 覆盖率门禁仍是主流程验收缺口。

## 2026-08-08：节点生命周期确定性门禁加固批次

- `TransitionNodeLifecycle` 的幂等重放不再只比较目标状态，而是绑定 operation ID、节点、目标状态、机器 reason code 和管理员；跨节点或修改载荷复用 operation 明确失败关闭。新转换先以共享锁取得 active controller generation，再锁节点并把精确 generation 写入事件，避免没有活动主控时更新节点却漏写审计事件。
- reason code 只允许 `^[a-z][a-z0-9_]{0,63}$`，数据库以 `NOT VALID` check 保留历史审计但约束所有新写入；Controller 与 Store 双层校验，拒绝自由文本、大小写和超长输入。
- 最终退役只允许 reported/desired control mode 均为 managed，并检查 legacy home/副本、规范化 `replica_copies`、节点账号、非终态 workflow/backup job、写租约、独立模式对账和 relay transfer。维护/排空不再清除 operator 的 `allow_register/is_backup_target` 配置；注册创建、公开推荐、备份/修复目标改为同时要求 reported/desired managed，配置意图与运行准入分离。
- 排空完成后的最终退役在同一个 serializable 事务内关闭注册/备份与节点状态，并撤销 Agent 凭据、pending 凭据轮换、未消费 enrollment、在途固定命令、管理员关联、控制票据/遗留票据及 orphan prepared transfer capability。真实 PostgreSQL 首轮测试发现 lib/pq 不允许带参数的多命令 prepared statement，随后把级联改为同一事务中的逐条参数化语句并通过真实运行，避免把 sqlmock 成功误当生产可执行。
- 新增真实 PostgreSQL 矩阵验证维护/排空保留 operator 配置、精确重放成功、跨节点/改 reason 重放拒绝、active node account/规范化 ready 副本/independent-draining 阻止退役，以及排空后所有凭据/票据/能力原子撤销并可精确重放最终结果。
- `STCONTROL_TEST_POSTGRES_DSN=... go test -count=1 -coverprofile=coverage/node_lifecycle_hardening.coverprofile ./...` 通过；总覆盖率 44.3%（Agent 54.1%、Controller 25.4%、Store 56.9%）。`go vet ./...`、Linux amd64 CGO0 build、web production build、29 个 embedded migration 并发应用/checksum 校验和 `git diff --check` 通过。
- 尚未完成且未冒充完成：本批次只加固最终退役安全边界，没有把“进入 draining”冒充自动迁移。持久化 retirement operation/items、逐用户迁移与验证、retiring/decommissioned 进度、失败节点转普通恢复、升级失败和静默数据损坏矩阵仍是 R19 后续；总覆盖率也仍低于 80%。

## 2026-08-08：节点退役持久清单与排空准入批次

- 新增 `0030_node_retirement_workflows.sql`，运营状态图加入 `retiring/decommissioned`；`node_retirement_operations` 持久保存原 lifecycle operation、节点、管理员、机器 reason、controller generation、调度/租约/退避/终态，且每节点最多一个开放退役；`node_retirement_items` 按用户保存 source/target、责任类型、workflow、状态、重试和完成事实。
- `active/degraded/maintenance -> draining` 与节点状态、lifecycle event、retirement operation/items 在同一个 serializable 事务提交。清单从 legacy home、副本、规范化 replica、node account 交叉生成，每用户只产生一个最高优先级责任：authoritative home 优先，其次 storage archive、compute redundant replica、最后 account metadata。相同 operation 精确重放不重复入队；切回 maintenance/active 原子取消 operation 并把未完成 item 标为 superseded，不回滚已安全完成的迁移事实。
- 生命周期禁止 `draining -> retired` 跳步；本批只建立由后续执行器消费的 durable 清单，要求先进入 retiring、逐项完成并验证，再进入 decommissioned，之后管理员才能做兼容性的最终 retired 标记。空节点也会留下 state=verifying 的 durable operation，而不是因为“没有用户”绕过可审计流程。
- 登录 handoff 在取得候选 lease 后再次读取节点的 connectivity/compatibility/reported+desired control mode 和 operational state。新 lease 只允许 active；已有 writer 可在 draining/retiring 返回原节点。新分配若撞上排空会让 lease operation 和票据一起回滚。真实 PostgreSQL 验证排空节点没有残留 writer 行。
- 管理 API 新增 `/api/admin/nodes/{id}/retirement`，只返回 bounded progress 计数和机器错误码；节点页每 15 秒刷新完成/等待离线/阻塞/失败计数，显示 retiring/decommissioned 产品状态，并按后端合法图收窄排空、隔离和最终退役按钮。
- 真实 PostgreSQL 验证 authoritative home 只捕获一个 item、精确 drain 重放不重复、暂停后 operation=cancelled/item=superseded、空清单进入 verifying，以及新登录 lease 全事务回滚。30 个 embedded migration 由并发 Store 完整应用并核对 checksum。
- `STCONTROL_TEST_POSTGRES_DSN=... go test -count=1 -coverprofile=coverage/node_retirement_foundation.coverprofile ./...`、`go vet ./...`、Linux amd64 CGO0 build、web production build 和 `git diff --check` 通过；总覆盖率 44.4%（Agent 54.1%、Controller 25.4%、Store 57.2%）。
- 尚未完成且未冒充完成：这一批只建立可重启的清单/准入/进度基础；后台 claim/lease、账号供应、不可变快照、权威 home 原子迁移、storage archive 重建和最终 decommission verifier 将在下一批实现，因此 R19 仍为 `部分`。

## 2026-08-09：节点退役执行器与原子迁移批次

- Controller 新增最多 2 路并发的节点退役 reconciler；每次执行使用唯一 lease owner，并以 operation lease、controller generation 和退避时间领取任务，进程重启或 lease 过期后可由同代 Controller 接续，竞争 worker、同 owner 重入和旧执行器延迟释放均不能夺取或清除新 lease。用户在线时只记录 bounded 机器状态并等待，不强制踢线。
- compute 退役按稳定排序选择受管、健康且兼容的 compute 目标；storage 退役从当前健康 compute home 重建到纯 storage 目标。目标账号先通过既有固定命令供应，目标容量、handle 冲突、角色、控制模式和兼容性均失败关闭，不向 Agent 下发任意 shell。
- retirement item 与既有 durable snapshot workflow/backup job 原子绑定；共享快照 worker 产生 manifest/hash 已验证且原子发布的 immutable hot copy 后，才允许在同一 serializable 事务中切换 active/authoritative home、结束旧 writer lease、撤销旧票据并陈旧化源副本。storage archive 只有在新 copy ready 后才陈旧化旧 copy；重复完成请求必须逐项核对已提交事实。
- 最终 verifier 要求所有 item 终态且节点已无 home、规范化/遗留副本、账号、非终态 workflow、写租约、independent-draining 和 relay transfer 依赖，随后原子进入 decommissioned/offline 并撤销 Agent 凭据、轮换、enrollment、固定命令、管理员关联、控制票据及 prepared capability。空节点同样经过 claim、retiring、verify、decommission 流程。
- 真实 PostgreSQL 覆盖空节点 claim/同 owner 重入拒绝/竞争租约/释放重领/最终化、陈旧 generation 拒绝、compute 账号供应、满容量目标零 artifact 拒绝、完整快照阶段推进、权威 home 原子迁移与精确重放，以及 storage archive 替换和最终化；10,000-item 清单也在真实数据库运行。
- `STCONTROL_TEST_POSTGRES_DSN=... go test -count=1 -coverprofile=coverage/node_retirement_executor.coverprofile ./...`、`go vet ./...`、Linux amd64 CGO0 build、web production build、30 个 embedded migration 并发应用/checksum 校验和 `git diff --check` 通过；总覆盖率 44.6%（Agent 54.1%、Controller 25.1%、Store 57.6%）。
- 尚未完成且未冒充完成：物理节点清理/最终兼容性 retired 标记、跨 generation 自动接管、升级失败隔离、权威数据静默损坏恢复、双进程/掉电/磁盘满矩阵和 80% 覆盖率门禁仍是后续验收缺口，因此 R19/R22 保持 `部分`。
