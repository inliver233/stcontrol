# 架构决策记录

## ADR-001：以较晚确认结论覆盖 demo 设计

- 决定：`详细任务.txt` 与 `.workflow` 中后续问答是实现依据；`详细控制开发.md` 和当前 stcontrol 只作为历史输入。
- 影响：删除“酒馆只改两个端点”“总控直连 127.0.0.1 Agent”“URL query 携带 JWT”“默认保留 4 个历史副本”“总控长期保存可逆密码”等 demo 假设。

## ADR-002：登录票据采用严格、互斥的 JWT profile

- 决定：每类票据具有独立 `typ`、必需 claims、受众和用途；验证端显式限制算法和 key version。
- 依据：[RFC 8725](https://www.rfc-editor.org/info/rfc8725/) 要求算法验证、issuer/subject/audience 校验，并建议新 JWT 用途使用显式类型和互斥验证规则。
- 影响：票据消费还必须在 PostgreSQL 内原子完成；JWT 只证明声明未被篡改，不替代一次性消费、节点身份或活动租约事务。

## ADR-003：单写权使用数据库条件更新和行级锁

- 决定：活动租约、控制世代、副本发布等竞争状态在短事务内用条件更新或 `SELECT ... FOR UPDATE`，固定锁顺序并处理事务重试。
- 依据：[PostgreSQL 行级锁文档](https://www.postgresql.org/docs/17/explicit-locking.html) 明确 `FOR UPDATE` 会阻止并发修改直到事务结束；[事务隔离文档](https://www.postgresql.org/docs/current/sql-set-transaction.html) 说明可序列化事务可能回滚，调用方必须重试。
- 影响：不能用 Controller 内存 map 或先查后改的两个独立 SQL 证明唯一 writer。

## ADR-004：副本发布只依赖同文件系统的原子重命名边界

- 决定：任务临时目录和正式副本目录必须位于同一受控文件系统；验证后通过可回滚的 rename 交换发布，跨文件系统复制不能标为原子发布。
- 依据：[POSIX `rename`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/rename.html) 规定 rename 行为是原子的；平台和文件系统能力仍须在 Agent 启动时探测并纳入门禁。
- 影响：Windows 暂不宣称具有同等发布保证；Linux 支持也必须验证目标路径、挂载点和失败回滚。

## ADR-005：控制面命令与快照数据面使用不同凭证和连接

- 决定：Controller 只把加密的固定能力命令放入持久队列，由 Agent 主动领取；快照正文由源 Agent 通过独立 HTTPS 地址直传目标 Agent。
- 决定：每个工作流/尝试使用新的短期 capability，Controller 和目标 Agent 只持久化 SHA-256 摘要，明文只存在于源命令密文和单次 Authorization 头中；HTTP 重定向一律不跟随。
- 影响：目标节点永久 Agent 凭据不再进入源节点或快照 payload；重试必须轮换 capability 和 operation ID。无法直连时仍需另行实现受控加密中转，不能退回 Controller 内存转发或永久 PSK。

## ADR-006：容量准入使用持久多维事实与滞后状态机

- 决定：连通性、角色、运营状态、容量和兼容性独立持久化；旧的单一 `status` 仅保留为兼容投影，不能单独证明节点可接收新用户或数据。
- 决定：Agent 上报数据分区真实总量/可用字节、受管目录已分配字节、显式配额、在线用户和本地任务负载。磁盘配额不得超过真实文件系统总量；指标无效时容量进入 `unknown` 并停止新分配。
- 决定：120 秒窗口均值达到约 50% 时标为 `busy` 并降权；关键资源达到 60% 后需持续 120 秒才进入 `full`。真实磁盘或配额低水位、在线人数和任务上限立即进入 `full`。恢复必须连续低于繁忙水位 180 秒，并同时满足 300 秒冷却期。
- 决定：计算节点还必须通过协议版本 1 和固定能力集合的 loopback adapter 健康契约；版本、能力、报告格式或 adapter 不可用均不得接收新分配。存储节点用 Agent 自身能力契约，不伪造酒馆版本事实。
- 依据：gopsutil 的 [`disk.Usage`](https://pkg.go.dev/github.com/shirou/gopsutil/v3/disk#Usage) 提供文件系统总量、可用量和使用率，[`cpu.Percent`](https://pkg.go.dev/github.com/shirou/gopsutil/v3/cpu#Percent) 提供区间 CPU 使用率。本实现使用真实 `Free` 字节做硬水位，并把受管目录大小与文件系统可用量分开，避免用百分比替代可分配空间。
- 影响：公开节点 API 只返回产品状态、推荐和邀请码需求，不返回 CPU/内存/磁盘或内部原因码；管理员 API 保留四维健康、窗口均值/峰值、字节事实和安全原因码。真实 adapter 会话遥测、客户端延迟持久化、插件指纹和目标规模压测仍是后续门禁。

## ADR-007：热备接管必须显式确认并原子晋升

- 决定：就绪热备不能直接签发登录短码。用户必须看到最近不可变快照时间和可能丢失的数据范围，并显式确认接管；旧写租约仍有效时拒绝接管。
- 决定：接管目标必须是连通、运营、兼容均合格的计算节点，存在 active 节点账号、ready 热备映射，并引用属于该用户的 immutable snapshot。仅有纯存储副本时进入独立恢复流程，不把存储节点晋升为 writer。
- 决定：Controller 在 serializable 事务中锁定 global user，校验 active controller generation 和源租约；用户看到的精确恢复时间同时进入请求 HMAC 和事务条件。随后撤销未消费短码，原子地把旧 home 标为 stale、目标标为唯一 authoritative home，并写入稳定 operation ID、保护投影和安全审计。完全相同的操作可重放原结果，不同事实复用操作 ID 冲突关闭。
- 决定：真实副本冲突是锁存状态；调和器同时冻结用户业务状态、未消费短码和写租约。普通 Controller 会话解析只接受 active 用户，因此冲突令牌不能进入原业务接口；令牌本身保留，且只能通过独立恢复认证边界访问开放冲突案件。只有后续显式差异/来源选择流程可以解锁，任何周期性调和都不得自行清除冲突或覆盖原始副本。
- 依据：PostgreSQL [`SELECT`](https://www.postgresql.org/docs/18/sql-select.html) 的 locking clause 会锁住所选行并阻止并发修改；[`INSERT`](https://www.postgresql.org/docs/current/sql-insert.html) 允许 `ON CONFLICT DO UPDATE` 同时引用既有目标行和 `excluded` 新行，并保证原子 insert-or-update 结果。
- 影响：保护状态区分纯存储已保护、仅计算临时保护、未保护、可接管、需存储恢复、不可恢复和冲突；短暂未保护按配置宽限后告警，紧急故障立即告警。存储到计算恢复、冲突差异/选择/合并和节点生命周期仍须独立实现，不能由本决策冒充完成。

## ADR-008：存储保护修复复用安全快照，不降级到计算节点

- 决定：保护投影为 `temporary/unprotected` 时，调度器还必须现场确认不存在健康、兼容且属于该用户的 immutable archive；投影延迟不能触发重复修复。
- 决定：只有当前 home 节点及其副本均 ready、没有有效写租约/在途请求、没有活动 snapshot workflow 时才进入修复。工作流创建事务仍会再次锁定用户并复核租约，调度查询不是授权边界。
- 决定：修复目标只允许 `role=storage`、启用备份、数据面可用且通过连通/运营/兼容/容量门禁的节点；优先 `open`，其次 `busy`。没有纯存储目标时保持未保护并由宽限告警升级，绝不把数据静默塞进计算节点冒充正常保护。
- 决定：修复复用现有写门、不可变 snapshot、短期 capability、端到端校验和原子发布流程，并把副本来源记为 `temporary_failure_protection`。新 archive 完整发布后，其他 ready archive 才降为 `stale`；不可达节点上的旧物理数据不盲删，等待后续受审计清理。
- 影响：存储节点故障不打断当前用户，用户安全离线后自动收敛纯存储保护。纯存储到计算恢复、旧副本物理清理和修复故障注入仍是后续门禁。

## ADR-009：纯存储恢复先供应账号，后原子晋升数据

- 决定：用户只能在保护投影为 `restore_required` 时选择恢复目标；目标必须是连通、运营、兼容和容量均合格的计算节点，且不存在同 handle 账号冲突。请求必须携带稳定 operation ID、精确 immutable 恢复时间和显式数据丢失确认，三者与用户、目标一起进入 keyed HMAC 和 serializable 事务条件。
- 决定：恢复是独立的持久 workflow，步骤为 `provision_account -> prepare_target -> transfer -> verify -> publish`，并复用 active generation、任务租约、`retry_wait/failed/succeeded` 和短期单次 capability。没有目标账号时，从已持久化的节点 scrypt 材料或 active OAuth identity 供应账号；`provisioning_workflow_id` 隔离恢复中的 pending 账号，避免通用密码同步 worker 抢占。
- 决定：storage Agent 只从原子发布时写入的私有 archive 元数据恢复。它重新序列化原 manifest 并与 Controller 保存的 SHA-256 比对，再逐文件重算大小和摘要；旧 archive 缺元数据、尾随 JSON、额外文件、符号链接、非普通文件或内容漂移全部失败关闭。新 manifest 使用独立 restore snapshot ID，并由 storage Agent 直传 compute Agent。
- 决定：compute Agent 在任务目录中限额解包、逐文件验证并同文件系统原子发布；Controller 只有取得匹配回执后，才在一个事务内把结果 manifest 设为 immutable、旧 home 降为 stale、目标设为唯一 authoritative home、撤销旧票据/租约、更新账号与保护事实并写审计。失败只标记未纳管副本和清理事实，不删除旧 home 或 archive，也不冒充成功。
- 影响：用户页面只公开目标名称、恢复点和产品阶段，不公开 workflow/snapshot/capability；浏览器会话保留稳定 operation ID 以重放不确定响应，且只在 `succeeded` 后尝试登录。SillyTavern 的专用账号恢复 adapter 端点仍须在现有 WIP 冲突解除后挂载，真实 PostgreSQL/双 Agent 故障注入也仍是上线门禁。

## ADR-010：冲突身份与业务权限分离，来源事实只捕获一次

- 决定：检测到冲突时，在同一个 serializable 调和事务中创建每用户唯一开放案件，并只捕获一次当时的节点名/角色、副本类型/状态、权威标记、legacy 版本以及合格 immutable snapshot 的摘要、文件数、字节数和发布时间。后续节点状态变化不得补写或改写该案件来源；文件路径和内容不进入该事实表、公开响应或审计日志。
- 决定：冲突不再撤销尚有效的 Controller 身份令牌。普通 session 查询仍严格要求 global/legacy 用户均为 active；单独的 conflict session 查询同时要求两层状态均为 conflict、存在开放案件、令牌未撤销/未过期且属于 active controller generation。该认证只挂载 `/api/conflicts`，不能访问改密、身份绑定、登录交接、恢复或其他普通写操作。
- 决定：冲突发生后仍允许用户用既有密码或 OAuth 身份重新认证，但生成的令牌仍只能通过上述恢复边界。禁用、删除、recovering 等其他状态不会因此获得会话。
- 影响：用户能够在不重新开放节点写入的前提下查看冲突来源；既有已被旧版本撤销的令牌可通过身份重新登录恢复。当前批次只建立案件/来源和最小只读 API；逐文件证据捕获、可理解差异、来源选择、不同路径有限合并和最终原子解冻仍需后续实现，不能把 manifest 摘要差异冒充内容差异。
