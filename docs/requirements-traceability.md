# 需求追踪矩阵

更新日期：2026-08-07

本矩阵以工作区根目录的 `详细任务.txt` 为总验收入口，并以较晚的 `.workflow/.analysis/ANL-多节点云酒馆总控方案复盘优化-2026-08-07/discussion.md` 问答结论覆盖早期方案冲突。状态只依据当前代码和已执行测试，不把 README 声明、静态页面或正常演示当作完成证据。

状态定义：

- `缺失`：没有可执行实现，或只有注释/占位。
- `错误`：已有实现与确认需求、安全边界或故障语义冲突。
- `部分`：存在可复用代码，但缺少关键状态、事务、认证或异常闭环。
- `待验证`：实现看似存在，但尚无覆盖目标范围的测试或运行证据。
- `完成`：对应实现和验收证据均已满足；目前没有条目标为完成。

## 核心需求矩阵

| ID | 已确认需求 | Controller | Agent | SillyTavern 最小改造 | 前端 | PostgreSQL 事实状态 | 必须测试 | 当前证据与判定 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R01 | 总控只管理统一身份、调度、用户私有副本、恢复、容量、审计和告警；节点论坛、公告、公共角色、Gemini、全局插件保持独立 | 需按边界输出用户副本清单和兼容门禁 | 仅允许用户目录和精确账号元数据能力 | 暴露用户目录/账号边界，不复制节点全局数据 | 用户与管理员视图分层 | `global_users`、`node_accounts`、副本与节点状态分开 | 全局目录永不进入快照；用户插件数据保留 | `excludedDirs` 有初步排除，但扫描只看目录；账号元数据、插件兼容指纹缺失，`部分` |
| R02 | 受控节点关闭原生密码登录、OAuth、注册、改密、删号等入口；独立灾难模式仅允许已有用户登录 | 管理节点模式和恢复排空状态 | 持久化并执行固定模式切换命令 | 默认关闭的 federation adapter；请求级模式守卫 | 给出受控/独立/排空提示 | 节点控制模式、世代、切换原因、时间 | 所有原生入口绕过测试；模式重启恢复 | 当前只有不安全联邦登录草稿；原生入口未关闭，`缺失` |
| R03 | 登录凭证不得进 URL；票据必须校验算法、`typ`、`iss`、`aud`、`sub`、用户 UUID、节点、会话、活动世代、`iat/nbf/exp`、`kid`、一次性 `jti` | 签发 POST/短码交换，原子消费并绑定节点身份 | 不接触浏览器长期令牌 | POST body 或一次性短码落地；严格 no-store/referrer 策略 | 表单自动提交/短码交换，失败可恢复 | 票据用途、签发世代、key version、消费时间唯一约束 | claim 缺失/类型混淆/重放/错节点/日志泄露 | 已改为 HMAC 派生的不透明短码、浏览器 POST body、数据库仅存 hash；节点认证核销同时检查用途、节点、会话/活动 epoch、主控 generation、时窗、撤销和单次消费，且响应 `no-store/no-referrer`。节点适配尚未接入新协议，真实端到端测试待补，`部分` |
| R04 | 每个用户任意时刻只有一个权威写入节点；A 活跃时选择 B 只能回 A | 事务取得/续约/结束活动租约，条件更新活动世代 | 缓存最后已确认租约并上报，不自行授予新写权 | 会话带 `session_id/activity_epoch/writer_node_id`，逐请求拒绝陈旧写 | 显示当前节点和“请返回 A” | `user_activity_leases` 唯一活动租约、operation ID、epoch | 并发选点、重复请求、网络分区、A/B 双写 | 登录交接已在同一 serializable 事务内取得/保留租约并创建票据；A 活跃时选择 B 返回 A 的交接结果，operation ID 可重放原结果；续约/结束/核销均带 fencing。Agent/酒馆逐请求守卫和真实 PG 并发测试仍待补，`部分` |
| R05 | 页面打开但闲置时低频保活；约 15 分钟无页面、无请求、无在途写才离线；陈旧页面恢复必须重新登录 | 会话/页面租约参数化并持久化 | 上报会话与请求计数，不用目录 mtime 猜测在线 | 前后台心跳、用户级请求计数、写门状态、陈旧会话响应 | 明确重新登录提示 | 页面会话、最后活动、租约到期 | 多标签页、后台页、休眠恢复、长请求 | Agent 用目录 mtime 推断，Controller 内存 map；`错误` |
| R06 | 快照前只冻结单用户、拒绝新写并排空其在途读写，不停整台酒馆 | 创建绑定租约世代的持久工作流 | 发起写门、等待排空、超时取消并保证最终开门 | 用户级写门及 in-flight 计数覆盖核心/扩展请求 | 展示短暂等待和可重试状态 | workflow/steps、门状态和清理结果 | 请求排空、超时、进程重启、用户回归 | Agent 已使用 loopback 签名 adapter 发起单用户 quiesce/drain，并保证已取得的写门在后续失败或取消时尝试释放；工作流绑定 activity epoch。SillyTavern 侧写门/in-flight 守卫尚未挂载，用户回归的真实闭环未验证，`部分` |
| R07 | 快照工作流为 `scheduled -> quiescing -> drained -> snapshotting -> transferring -> verifying -> publishing -> succeeded`，并支持 `retry_wait/cancelled/failed` | 合法状态机、租约认领、恢复调度 | 本地持久状态、幂等步骤、双端取消与清理 | 冻结/快照内部能力 | 管理员可见阶段与安全错误摘要 | workflows、workflow_steps、operation ID、snapshot ID | 每一分支、重复投递、重启恢复 | PostgreSQL 已实现完整阶段、步骤事实、工作流租约、指数退避、重启扫描和终态；Agent 持久保存传输状态/结果，重试轮换 capability 并使用尝试级 operation ID。仍缺真实 PostgreSQL、双进程崩溃和管理员阶段 UI 测试，`部分` |
| R08 | 使用任务临时目录、不可变 snapshot ID、manifest、端到端校验；验证成功后同文件系统原子发布；旧副本后删 | 保存快照与发布事实，拒绝半副本 | 安全打包、限额解包、manifest 重算、原子换代 | 提供受控快照边界 | 显示同步/恢复进度 | snapshot_manifests、replica_copies、发布世代 | 路径穿越、符号链接、炸弹、超大文件、磁盘满、校验失败 | Linux Agent 已实现任务目录、不可变 ID、manifest-first tar.zst、归档/逐文件 SHA-256、路径/类型/数量/大小/窗口/展开比/磁盘余量门禁和同文件系统可回滚 rename；Controller 在单事务发布 manifest/replica/legacy read model 并标记旧 manifest 删除。磁盘满、掉电窗口和真实文件系统集成测试仍缺，`部分` |
| R09 | 默认活动计算副本 + 一个纯存储副本；只保留最新成功副本，不提供 PITR/误删回退 | 角色/配额调度、高低水位、冷却期 | 上报实际可用字节和分配配额 | 无额外核心改造 | 显示保护状态，不承诺历史恢复 | 副本来源、保留原因、保护级别、清理条件 | 存储满、迁移失败、旧副本保留、稳定后清理 | 默认和示例配置已固定只保留 1 个成功副本，成功发布后物理换代并把旧 manifest 标为 deleted；目标仍取第一台在线节点，缺配额、滞回和保护级调度，`部分` |
| R10 | 直连 Agent-to-Agent 优先，无法直连才用受控、加密、短期中转；控制面与数据面隔离 | 下发每任务短期传输授权和路径选择 | 主动控制连接；数据面用任务能力凭证/TLS | 仅本机内部接口 | 管理员查看路径和进度，不暴露密钥 | Agent 连接、命令 ACK、任务 capability、nonce 消费 | NAT、断线重连、重放、过期授权、中转清理 | 控制面为 Agent 主动长轮询；数据面已移除永久目标 PSK/Controller 回连，改用独立 HTTPS 地址和仅存 hash、短期、作用域绑定、持久单次消费的 capability，且禁重定向避免 Authorization 泄露。无法直连时的加密中转和真实 NAT/TLS 测试未实现，`部分` |
| R11 | Agent 一次性短期 enrollment 后自动接入；高权限但仅固定能力、路径 allowlist、可取消、可审计，绝不任意 shell | 绑定角色/任务/指纹原子消费 token；轮换凭证 | 主动出站、固定命令、路径根校验、本地审计 | loopback/Unix socket 能力 API | 一行安装及清晰诊断 | enrollment、credential version、revocation、capability | token 重放/错角色/路径越权/任意命令 | enrollment token 仅存 SHA-256、15 分钟、绑定预建节点/角色/可选指纹并在 serializable 事务单次消费；凭据加密存储且带版本/世代。Agent 持久保存最高世代、worker ID、最近 1000 个命令结果和传输 capability 状态；固定命令拒绝未知类型，systemd 默认 loopback 控制监听和 0077 umask。mTLS、凭据自动轮换和完整本地审计仍缺，`部分` |
| R12 | 单活动主控 + 可选被动副控；单调 `controller_generation`，更高世代才接管，恢复后对账/轮换/撤票 | 控制世代事务和 rebuild 状态 | 持久保存最高世代并拒绝旧命令 | 节点模式与票据世代检查 | 管理员接管/重建状态 | controller_epochs、恢复锁、key version | 双主、旧命令、数据库恢复、凭证轮换 | 已持久化唯一 active generation，登录短码、活动租约和 Controller session 均绑定 active generation，旧世代会话/票据失败关闭；被动副控、原子晋升、恢复对账与密钥轮换仍待实现，`部分` |
| R13 | 短失联维持合法会话但暂停新登录/选点/备份；确认长期失联进入独立模式；恢复为 `independent-draining` | 失联状态机与新操作门禁 | 多信号确认、最后活动归属、有限同伴协调 | managed/independent/draining 状态机 | 简明灾难提示和接管确认 | 模式世代、证据、用户接管事件 | 抖动、分区、长期失联、drain、双故障 | 完全缺失，`缺失` |
| R14 | 统一身份支持密码/Discord/LinuxDo，最多绑定三种且至少一种，无邮箱；密码同步兼容 scrypt hash/salt，不存可逆明文 | 身份表、绑定/解绑、管理员恢复、版本化改密 saga | 精确读写兼容密码材料 | 内部账号供应/查询/改密；受控模式禁原生改密 | 三种登录、绑定管理、无邮箱文案 | auth_identities、node_accounts、password material version | 三种注册登录、绑定上限、部分改密失败 | 登录查询已切到规范化 `auth_identities`；支持密码/Discord/LinuxDo 各一项、最多三项、至少保留一项的绑定/解绑和账号安全 UI。OAuth 绑定 state 绑定用户/session/主控世代；密码使用 bcrypt + NFC/scrypt，verifier 与全部节点版本化期望材料在同一事务提交，失败节点从持久 hash/salt 自动重试且命令 operation ID 传入 adapter。SillyTavern adapter 尚未挂载，OAuth 本地身份增删 reconciliation 与管理员身份恢复仍缺，`部分` |
| R15 | 注册由用户选择合格节点；邀请码策略属于节点，未知/过期/读取失败时禁止注册；不确定结果幂等查询/重试 | 注册 saga，不静默换节点 | 上报策略版本并幂等供应账号 | 内部供应接口复用真实校验且 operation ID 单次消费 | 重新选节点、pending/确认中/冲突状态 | registration workflows、policy version、node account mapping | 响应丢失、重复请求、邀请码只消费一次 | Agent 已从签名 loopback adapter 读取节点自有策略并随心跳上报 mode、单调版本及短期 freshness；Controller 对未知、错误、过期、无版本或版本回退全部 fail-closed，注册页只显示是否需要邀请码且永不静默换节点。节点账号仍以 recovering/pending 事实和密文命令供应；但邀请码消费仍在 legacy 总控表，持久注册 workflow/reconciler 尚待下一批替换，`部分` |
| R16 | 老节点自动扫描账号库；OAuth stable subject 自动关联；同名密码账号必须证明控制权；UUID 是全局主键 | 导入批次、歧义状态、认领/合并工作流 | 扫描 `_storage` 账号、OAuth、管理员与目录摘要 | 安全内部扫描接口 | 冲突/认领/合并 UI | node_accounts、import_batches、identity conflicts | 多节点同名、OAuth 关联、不可覆盖旧账号 | 只扫用户目录且结果仅写审计，`缺失` |
| R17 | 多个同级总控管理员；节点原生管理员逐节点可撤销关联；短期管理员票据进入后台，不保存明文密码 | 持久管理员会话、关联验证、撤销和审计 | 校验节点当前管理员权限 | 管理员用途专用票据 | 管理员/节点关联状态与跳转 | admins、admin_node_links、admin tickets | 权限降级、撤销、票据类型混淆 | 首位管理员只从环境变量引导且数据库仅存 bcrypt；已实现独立 12 小时持久 session、多个同级管理员创建/禁用/改密、现有 session 撤销、最后有效管理员保护、CSRF 前端接线和管理 UI。节点管理员关联验证及 `node_admin` 专用票据仍待实现，`部分` |
| R18 | 健康分离连通性、角色、容量、兼容、用户副本、运营状态；约 50% 降权，持续 60% 硬门槛并有滞回/冷却/磁盘水位 | 窗口指标、准入原因、可解释推荐 | 上报窗口/峰值/字节/配额/在线数/队列/延迟/版本指纹 | 能力/版本/插件指纹 | 用户只看开放/繁忙/满载/维护/备份/故障 | metrics windows、policy version、compatibility | 波动、滞回、磁盘余量、容量压测 | 仅三个瞬时百分比和一个 status，`错误` |
| R19 | 计算故障、存储故障、陈旧副本、真实分叉、恢复、节点退役/升级/损坏均进入明确状态机 | 自动编排、用户确认风险、分层告警 | 检测/隔离/按用户恢复/低频校验 | 单用户冻结/恢复接口 | 故障确认、恢复目标选择、冲突差异 UI | lifecycle、conflicts、alerts、integrity checks | 全故障矩阵和进程重启 | 当前只有 offline 与简单 ready/error，恢复函数占位，`缺失` |
| R20 | 所有控制台页面连接真实后端、权限、加载/失败/空状态/分页/筛选/审计/进度并响应式可用 | 分页和权限 API、结构化错误 | 上报真实进度 | 提供可观测状态 | 全页面/按钮逐项接线 | 审计/告警/任务可查询 | 组件、API、E2E、权限、响应式 | 构建通过但无前端测试；多处按钮/状态依赖 demo API，`待验证/部分` |
| R21 | 目标容量：注册过万、同时在线四位数、单节点数百并留冗余；控制请求和大文件传输隔离 | 索引、批处理、限流、队列、公平调度 | 并发/带宽/磁盘限额 | 心跳与写门低开销 | 大列表分页/虚拟化 | 关键索引与队列事实表 | 登录/心跳/队列/备份/数据库压测 | 没有压测或覆盖数据，列表全量读取，`缺失` |
| R22 | 安全和隐私：TLS、目录权限、日志脱敏；不记录聊天/API key/密码/token；恶意归档与权限绕过必测 | 安全头、限流、错误脱敏、审计摘要 | TLS 校验、日志脱敏、安全解包 | no-store/referrer/本地接口认证 | 不泄露内部拓扑/任务 ID | 最小化审计数据和保留策略 | token/nonce/路径/归档/日志扫描 | 已禁止打印主密钥、隐藏敏感字段、持久化一次性 nonce；登录短码不进 URL。Session/CSRF 仅存 digest并有 cookie/Origin 防护；OAuth PII 不进查询串且 provider 强制 HTTPS/限时限量。快照 capability 只进 Authorization 头，所有含认证头的 HTTP client 禁重定向；接收端拒绝 traversal、符号链接、非普通文件、超限归档并使用 0700/0600。服务端 TLS 强制、日志扫描和权限绕过全套测试仍待补，`部分` |

## 当前基线证据

- `go test ./...`：通过；已覆盖持久会话/OAuth、活动租约/票据、enrollment、命令租约/围栏、Agent 重启去重、密文载荷、兼容 scrypt 材料以及快照 capability/manifest/发布事务，但尚未达到最终 80% 覆盖率。
- `npm run build`：通过，只证明 TypeScript/Vite 能构建，不证明页面行为、权限、错误状态或后端接线。
- `Sillytarven-online` 当前存在既有未提交 `src/server-main.js`、`src/endpoints/federated-login.js`、`简要开发思路.md`；它们按协作规则视为其他工具的 WIP，尚未覆盖或提交。
- `stcontrol` 已建立 `main` 并持续推送至指定远端 `https://github.com/inliver233/stcontrol.git`。

## 完成判定规则

每一行只有同时满足以下条件才可改为 `完成`：

1. 数据模型、后端、Agent、酒馆适配器和前端中适用的实现均已落地；
2. 正常、失败、重试、重复请求、重启和安全边界测试覆盖本行范围；
3. 运行/集成/压测证据与需求规模相匹配；
4. 文档、配置和部署方式没有继续声明已废弃的 demo 语义；
5. 不依赖未提交 WIP 或人工补步骤冒充自动闭环。
