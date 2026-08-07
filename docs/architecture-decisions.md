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
