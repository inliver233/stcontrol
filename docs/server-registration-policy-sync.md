# server 分支：节点注册策略同步与部署

## 目标

每个 SillyTavern 节点继续维护自己的注册规则。Agent 从本机签名适配器读取规则，Controller 按节点保存并用于注册页、密码注册、Discord/LinuxDo 注册和注册工作流重试。

Controller 管理台的“注册总控”是最高优先级开关：

- 一键关闭后，该节点的所有新用户注册立即停止。
- 一键开启后，只恢复节点自身已经开放的注册方式，不会擅自开启密码、Discord 或 LinuxDo。
- 现有用户登录不受注册开关影响。

同步内容只有公开策略：方式是否开放、是否需要邀请码，以及 Discord 公会 ID、显示名称和最低入群天数。OAuth `client_secret`、访问令牌、用户 OAuth subject 和邮箱不会通过 Agent 心跳同步。

## 版本要求

- stcontrol Controller/Agent：`server` 分支，Agent `0.4.0` 或更新版本。
- SillyTavern Online：`server` 分支，适配器状态版本 9，健康能力包含 `registration_policy_methods`。
- 数据库迁移 `0053_registration_method_policies.sql` 由新 Controller 启动时自动执行。

升级顺序必须是 Controller → SillyTavern → Agent。升级窗口中旧节点会失败关闭注册，不会根据过期的单一 `open/closed` 状态放行。

## Controller 的 Discord 配置

节点只提供公会规则，Controller 仍需使用自己的 Discord OAuth 应用完成 `test.pixcora.com` 登录。不要把节点上的 OAuth 密钥写入数据库或 Agent 配置。

`controller.docker.yaml` 示例：

```yaml
oauth:
  discord:
    enabled: true
    client_id: "你的 Discord Application ID"
    client_secret: "你的 Discord Client Secret"
    callback_url: "https://test.pixcora.com/api/auth/oauth/discord/callback"
```

Discord Developer Portal 必须把同一个回调地址加入 OAuth2 Redirects。普通登录只申请 `identify`；只有为启用了公会成员规则的节点注册新用户时，才额外申请 `guilds.members.read`。

## 节点配置示例

节点 22 所述规则可以这样保留在 SillyTavern `config.yaml`：

```yaml
registration:
  password:
    enabled: false
    requireInvitationCode: false
  github:
    enabled: false
    requireInvitationCode: false
  discord:
    enabled: true
    requireInvitationCode: false
    guildMembership:
      enabled: true
      guildId: "1134557553011998840"
      guildName: "类脑 ΟΔΥΣΣΕΙΑ"
      minimumDays: 15
  linuxdo:
    enabled: false
    requireInvitationCode: false
```

这只关闭“密码创建新账号”。已有密码账号仍可登录；已有 Discord 绑定也可正常登录。15 天规则只在 Discord 创建新账号时验证。

## 验收

更新后等待两个心跳周期，然后在管理台节点行确认：

- Agent 版本为 `0.4.0`；
- 兼容状态为 `compatible`；
- 节点策略显示 `Discord`，不显示密码/LinuxDo；
- 点击“一键关闭注册”后注册页立即不可选该节点；
- 再点击“一键开启注册”后只恢复 Discord 注册；
- Discord 新用户会看到公会名称和 15 天提示；已有用户仍能 Discord 登录。

若策略显示为空或兼容状态为不兼容，先检查 SillyTavern 是否已更新到 `server`，再检查 Agent 日志中是否有 `missing_capability`、`invalid_policy` 或适配器 403。
