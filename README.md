# stcontrol · 多节点云酒馆总控系统

在不改动酒馆核心逻辑的前提下，盖一层 **总控(Controller) + 子控(Agent/探针)**，实现统一注册分流、统一登录跳转、用户级数据备份与热备切换。任何一台运行本云酒馆的服务器，只要版本匹配，插入子控即可被总控接管，且脱离总控仍能独立完整运行。

## 架构

```
                        ┌──────────────────────────────┐
   用户浏览器 ────────► │   总控 Controller (Go+PG+React) │
   account.example.com  │  注册/登录/节点选择/调度/后台    │
                        └───────┬──────────▲────────────┘
                       签发短码/ │ HTTPS    │ Agent 主动长轮询
                       命令入队  │ +HMAC    │ 心跳/ACK/结果
            ┌────────────────────┼──────────┼────────────────────┐
   ┌────────▼────────┐  ┌────────▼────────┐            ┌────────┴────────┐
   │ 节点A (计算)      │  │ 节点B (计算)      │            │ 节点S (存储)      │
   │ 云酒馆 + 子控     │  │ 云酒馆 + 子控     │            │ 子控(备份池)      │
   │ data/<handle>    │  │ data/<handle>    │            └──────────────────┘
   └──────────────────┘  └──────────────────┘
        ▲──── 节点间热备/备份: tar.zst 流式 + SHA256 校验 ────▲
```

- **总控**：唯一入口。用户注册/登录、节点管理、负载判断、备份调度、管理员后台。
- **计算节点**：云酒馆 Node 服务 + 子控 Agent。服务用户。
- **存储节点**：只跑子控 Agent，作为备份存储池，不服务用户。
- **核心原则**：酒馆本体只增加默认关闭的受控模式守卫与 loopback 内部适配器；论坛、公告、Gemini、公共角色和节点全局插件仍由各节点独立管理。
- **控制通道**：Controller 不回连节点 loopback。Agent 主动领取持久命令，命令带租约、ACK、结果缓存和单调控制世代。
- **数据通道**：快照优先经独立 HTTPS Agent-to-Agent 地址直传；授权是每任务短期 capability，不共享目标节点永久凭据。
- **节点健康与容量**：连通性、运营状态、容量和兼容性分别持久化。Agent 上报真实磁盘可用字节、受管数据占用、配额、在线用户和任务负载；Controller 以窗口指标、持续硬阈值、磁盘水位、恢复滞后和冷却期决定新分配。
- **用户保护与恢复**：Controller 周期性投影纯存储保护、临时计算保护、未保护、可接管、需恢复、不可恢复和冲突状态；短暂风险按宽限期告警，紧急故障立即告警。纯存储保护失效时不打断当前用户，安全离线后只向合格存储节点自动重建；计算 home 故障且只有 archive 时，用户可确认精确恢复点并选择合格计算节点，系统先幂等供应账号，再直传、校验、原子发布并事务晋升唯一 home。

## 目录结构

```
stcontrol/
├── cmd/
│   ├── controller/      # 总控入口
│   └── agent/           # 子控入口
├── internal/
│   ├── config/          # 配置加载(YAML)
│   ├── protocol/        # 总控↔子控协议 + HMAC 签名
│   ├── crypto/          # AES-GCM 凭据、bcrypt/scrypt 与用途隔离密钥派生
│   ├── store/           # PostgreSQL 数据访问 + 迁移
│   ├── controller/      # 总控 HTTP 服务(注册/登录/节点/票据/备份调度/后台)
│   └── agent/           # 子控(探针/心跳/代注册/备份引擎)
├── web/                 # React 前端(用户页+管理后台)
├── scripts/install.sh   # 子控一键安装脚本
├── docker-compose.yml   # 总控+PG 一键部署
└── Dockerfile.controller
```

## 快速开始

### 1. 部署总控（Docker）

```bash
cd stcontrol
cp controller.docker.yaml.example controller.docker.yaml
# 修改域名和 database_url（密码需与 DB_PASSWORD 相同且 URL 转义），
# 并把域名对应的 certs/tls.crt、certs/tls.key 只读挂载进容器。
export CONTROLLER_SECRET_KEY=$(openssl rand -base64 32)
export DB_PASSWORD=<数据库密码>
export CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD=<首次管理员密码，至少12位>
docker compose up -d --build
```

前端与 API 必须同源通过 `https://` 访问。明文 HTTP 只允许
`127.0.0.1/::1` 本机开发或本机反向代理回源；非 loopback 监听没有成对证书时
Controller 会拒绝启动。Docker 示例直接在 `:8443` 终止 TLS；通用
`controller.yaml.example` 默认是 loopback 回源模式，不能直接发布到公网。

### 2. 本地开发总控（不用 Docker）

```bash
# 需要本地 PostgreSQL, 创建数据库 stcontrol
cd stcontrol
export CONTROLLER_SECRET_KEY=$(openssl rand -base64 32)
export CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD=<首次管理员密码，至少12位>
go run ./cmd/controller --config controller.yaml
```

本机开发可使用默认的 `http://127.0.0.1:8080`；任何远端 Agent 和浏览器入口仍必须
使用 HTTPS。

引导密码只在数据库尚无管理员时从环境变量读取；创建首位管理员后只保留 bcrypt hash。后续同级管理员的创建、禁用和密码重置均在管理后台完成，禁用或改密会撤销该管理员的现有会话，系统拒绝禁用最后一名有效管理员。

前端热更新：另开终端 `cd web && npm install && npm run dev`（代理到 :8080）。

### 3. 接入一个节点（子控）

在管理员后台「节点管理」→「注册令牌」生成一次性令牌与安装命令，然后在节点服务器执行：

```bash
curl -sSL https://<总控>/install.sh | bash -s -- \
  --controller https://<总控地址> \
  --token <一次性令牌> \
  --role compute \
  --tavern-dir /path/to/SillyTavern \
  --transfer-url https://a.example.com/agent-data
```

`--transfer-url` 只能填写已经由该 Agent 的 TLS 证书或同机可信反向代理实际提供的
HTTPS 地址；否则应省略，不能发布一个不可达或明文数据面地址。直连不可达时由持久
workflow 明确切换到受控的端到端加密 relay，而不会把 capability 放入 URL。

或手动（已在节点编译好 agent）：

```bash
./agent --register \
  --token <一次性令牌> \
  --controller https://<总控地址> \
  --tavern-dir /path/to/SillyTavern \
  --role compute
./agent --config agent.yaml   # 常驻运行(建议配 systemd)
```

### 4. 酒馆侧改造（一次性）

酒馆侧已挂载默认关闭的 federation control adapter，提供登录短码落地、受控/独立模式守卫、账号 hash/salt 供应、恢复账号供应、真实会话活动、分页账号库存和用户级写门/排空。内部能力仅允许 Agent 从 loopback 调用，并使用独立 adapter 凭据签名。健康端点使用协议版本 1，并至少报告 `account_inventory_paging`、`account_restore`、`activity_leases`、`activity_ownership`、`control_mode`、`independent_reconciliation`、`local_account_proof`、`login_handoff`、`node_admin_handoff`、`node_admin_verify`、`password_update`、`registration_policy`、`snapshot_boundary`、`user_provision`、`write_gate`；缺版本、能力或适配器时计算节点兼容性失败关闭。未挂载该 adapter 的计算节点不会降级调用公开注册/改密接口。

Agent 将控制模式和模式世代写入 `data_dir/runtime-state.json`。默认在连续失联 45 秒后暂停节点的新登录与受管命令；只有签名心跳、本机独立健康探针和配置名单中 Agent 的外部同伴见证法定数都持续确认同一个 Controller 失联 15 分钟且达到最少失败次数，计算节点才进入 `independent`。缺少同伴、同伴不可达、任一合法同伴仍能访问 Controller 或见证身份重复都会失败关闭，绝不只凭本机网络视角开启原生登录。总控恢复后必须先进入 `independent-draining`；酒馆 adapter 报告灾难会话和待同步用户都归零后才恢复 `managed`。

受管登录短码成功核销后，Agent 以 Controller 世代、活动 epoch 和 owner 节点生成不可变最后活动 claim，并复制到同伴法定数。独立登录只接受同一个最大 claim 的多数：owner 仍可用时必须返回原节点；owner 的酒馆 adapter 失效时，用户必须先通过本地密码验证，再确认固定的数据丢失/冲突风险。确认只授权对精确 parent claim 的一次多数 CAS；challenge 仅以 hash 落盘，operation/claim 在 Agent 重启后可安全重试，无同伴多数时始终拒绝登录。成功接管会进入 Agent 脱敏本地审计，并在 Controller 恢复后幂等固化到 PostgreSQL。

见证名单通过 `agent.yaml` 的 `disaster.peer_witness_urls` 配置，最多 8 个，只允许 HTTPS（同机 loopback 测试允许 HTTP），且每个 URL 必须指向同伴 Agent 根地址。所有见证节点使用同一个至少 32 字节的随机密钥，密钥仅放在 `disaster.peer_witness_secret_env` 指定的环境变量（默认 `STCONTROL_PEER_WITNESS_PSK`），不得写入 YAML；安装脚本生成的 systemd unit 会读取可选的 `/opt/stcontrol/agent.env`（若自定义安装目录则读取该目录）。该文件必须保持 root-only，例如 `STCONTROL_PEER_WITNESS_PSK=<随机值>` 并设为 `0600`。未配置名单是安全默认值：节点能进入 `controller-unreachable`，但不能自动进入 `independent`。其余阈值可通过 `disaster.unreachable_after_sec`、`disaster.independent_after_sec` 和 `disaster.min_failed_heartbeats` 保守调大。

## 核心流程

- **注册**：总控注册页由用户选节点（只展示开放/繁忙/满载/维护/备份/故障、推荐与浏览器实测延迟）→ 开放节点优先，约 50% 窗口负载降为繁忙，关键资源持续达到约 60% 或触发磁盘/配额/人数/队列硬水位时停止新分配 → Agent 从节点 adapter 上报带单调版本和短过期时间的注册/邀请码策略；未知、读取失败、版本回退、同版本改状态或过期一律不可注册 → Controller 建立持久注册 workflow，由 Agent 以稳定 registration ID 在节点幂等供应并消费节点自有邀请码 → 节点明确成功后才原子发布全局身份、节点账号和家副本。浏览器只持有 Strict/HttpOnly 状态 cookie，通过固定端点查询；响应丢失或结果不确定时不换节点、不提前建用户并安全重试。
- **登录交接**：总控登录 → 可用节点（家 + 就绪热备）→ 原子取得单写租约并创建一次性短码(60s) → 浏览器自动 `POST /federated-login` → 节点用 HMAC 身份向总控核销 → 写 session → `/app`。短码不进入 URL、历史记录或 referrer。
- **身份管理**：一个全局用户最多各绑定一个密码、Discord、LinuxDo 身份且至少保留一种；OAuth 绑定 state 与当前用户/session/主控世代绑定。改密或新绑密码会将 verifier 和全部节点的版本化期望材料原子落库后再投递，离线/失败节点由持久材料后台重试。全部登录身份不可用时，管理员可按全局 UUID 设置一次新密码；操作幂等、撤销用户现有会话并只从持久事实投递节点材料。
- **备份**：持久 workflow → 单用户关写门并排空 → 同任务目录复制不可变快照 → manifest 先行的 tar.zst → 短期 capability 的 HTTPS 直传 → 目标限制窗口/文件数/大小/展开比并逐文件重算摘要 → 同文件系统换代发布。失败或用户回归只清理未发布临时目录，旧成功副本保持不变。
- **热备接管**：家节点不可用 → 展示最近不可变快照时间和可能丢失的数据 → 用户显式确认 → Controller 在单事务校验旧租约、撤票、把旧 home 标为陈旧并晋升唯一新 home。热备不能绕过该流程直接登录；真实冲突会冻结而不是自动覆盖。
- **纯存储恢复**：只有 archive 可用时展示精确恢复点 → 用户选择通过健康/容量/账号门禁的计算节点并显式确认 → 持久 workflow 先幂等供应账号 → storage Agent 复核原 manifest 和每个文件后直传 → compute Agent 限额验证并原子发布 → Controller 单事务晋升唯一 home。成功前不会签发目标登录交接。
- **冲突恢复边界**：检测到真实分叉后冻结用户写入、短码和租约，并一次性固化当时来源；普通业务 session 失败关闭，但仍有效或重新认证的用户令牌只能进入专用冲突恢复区。Agent 为每个来源生成不可变逐文件证据，清单只以密文进入命令结果和 PostgreSQL；页面分页区分不同路径与同路径内容差异，不同路径自动并入，同路径只执行用户明确的选边/双份保留决策，且不承诺聊天、JSON 或二进制语义合并。结果经准备、应用和原子发布后才解冻。

## 安全

- 总控↔子控：Agent 主动 HTTPS 长轮询；HMAC-SHA256 覆盖方法、路径、时间戳、nonce 和正文摘要，nonce 在 PostgreSQL 单次消费，每节点凭据加密存储并版本化。
- Controller 和直接暴露的 Agent 监听均固定 TLS 1.3；明文监听被限制在 loopback，适用于同机可信 TLS 反向代理。证书和私钥必须成对配置。
- 登录短码：短命(60s) + 一次性原子核销 + 绑定节点/会话/活动世代/主控世代 + `no-store`/`no-referrer` + 仅通过 POST body 传递。
- 用户密码：总控只保存不可逆登录 hash；节点密码同步使用酒馆兼容的 scrypt hash/salt，不保存可逆明文。`CONTROLLER_SECRET_KEY` 只用于控制面凭证等必须可恢复的机器密钥材料。
- 备份数据可能含 API key：只允许 HTTPS 数据面、任务 capability 放在 Authorization 头而非 URL，临时/副本目录权限 0700/0600，不记录文件名或归档正文。首期原子发布只在 Linux 启用。

## 构建产物

```bash
# Windows 一键构建所有二进制
build-bin.bat   # 产出 bin/controller.exe, bin/agent.exe, bin/agent-linux-amd64

# 前端
cd web && npm install && npm run build   # 产出 web/dist
```

## 验收状态

本仓库按 `docs/requirements-traceability.md` 逐条记录实现、测试证据和剩余缺口。
README 的正常流程说明不等于上线完成；只有该矩阵中的异常、重启、重复请求、
安全边界、真实 PostgreSQL、故障矩阵和容量/覆盖率门禁全部收敛后才可发布。
