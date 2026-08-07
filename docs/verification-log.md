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

- Controller 登录选点尚未调用新活动租约，Agent/SillyTavern 尚未执行 session fencing。
- 旧 demo 表仍作为 API 兼容层；后续 endpoint 迁移完成前不能删除。
- 真实 PostgreSQL 集成环境、并发争抢测试和 migration upgrade/rollback 演练必须在提交后续功能前补齐。

