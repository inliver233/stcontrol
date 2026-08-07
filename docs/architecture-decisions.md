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
- 决定：真实副本冲突是锁存状态；调和器同时冻结用户状态、Controller 会话、未消费短码和写租约。只有后续显式差异/来源选择流程可以解锁，任何周期性调和都不得自行清除冲突或覆盖原始副本。
- 依据：PostgreSQL [`SELECT`](https://www.postgresql.org/docs/18/sql-select.html) 的 locking clause 会锁住所选行并阻止并发修改；[`INSERT`](https://www.postgresql.org/docs/current/sql-insert.html) 允许 `ON CONFLICT DO UPDATE` 同时引用既有目标行和 `excluded` 新行，并保证原子 insert-or-update 结果。
- 影响：保护状态区分纯存储已保护、仅计算临时保护、未保护、可接管、需存储恢复、不可恢复和冲突；短暂未保护按配置宽限后告警，紧急故障立即告警。存储自动修复、存储到计算恢复、冲突差异/选择/合并和节点生命周期仍须独立实现，不能由本决策冒充完成。
