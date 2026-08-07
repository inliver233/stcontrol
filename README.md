# stcontrol · 多节点云酒馆总控系统

在不改动酒馆核心逻辑的前提下，盖一层 **总控(Controller) + 子控(Agent/探针)**，实现统一注册分流、统一登录跳转、用户级数据备份与热备切换。任何一台运行本云酒馆的服务器，只要版本匹配，插入子控即可被总控接管，且脱离总控仍能独立完整运行。

## 架构

```
                        ┌──────────────────────────────┐
   用户浏览器 ────────► │   总控 Controller (Go+PG+React) │
   account.example.com  │  注册/登录/节点选择/调度/后台    │
                        └───────┬──────────▲────────────┘
                       签发票据/ │ HTTPS    │ 上报负载/心跳
                       下发指令  │ +PSK+HMAC│
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
- **核心原则**：酒馆本体改造最小化（仅加 2 个端点），论坛/公告/Gemini 等是节点自己的事，总控不接管。

## 目录结构

```
stcontrol/
├── cmd/
│   ├── controller/      # 总控入口
│   └── agent/           # 子控入口
├── internal/
│   ├── config/          # 配置加载(YAML)
│   ├── protocol/        # 总控↔子控协议 + HMAC 签名
│   ├── crypto/          # AES-GCM 凭据/bcrypt/JWT 票据
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
cp controller.yaml.example controller.yaml   # 按需修改 public_url / database_url / oauth
export CONTROLLER_SECRET_KEY=$(openssl rand -base64 32)
export DB_PASSWORD=<数据库密码>
docker compose up -d --build
```

总控监听 `:8080`，前端 + API 同源。访问 `http://<总控>:8080` 即 React 界面。

### 2. 本地开发总控（不用 Docker）

```bash
# 需要本地 PostgreSQL, 创建数据库 stcontrol
cd stcontrol
export CONTROLLER_SECRET_KEY=$(openssl rand -base64 32)
go run ./cmd/controller --config controller.yaml
```

前端热更新：另开终端 `cd web && npm install && npm run dev`（代理到 :8080）。

### 3. 接入一个节点（子控）

在管理员后台「节点管理」→「注册令牌」生成一次性令牌与安装命令，然后在节点服务器执行：

```bash
curl -sSL http://<总控>/install.sh | bash -s -- \
  --controller http://<总控地址> \
  --token <一次性令牌> \
  --role compute \
  --tavern-dir /path/to/SillyTavern
```

或手动（已在节点编译好 agent）：

```bash
./agent --register \
  --token <一次性令牌> \
  --controller http://<总控地址> \
  --tavern-dir /path/to/SillyTavern \
  --role compute
./agent --config agent.yaml   # 常驻运行(建议配 systemd)
```

### 4. 酒馆侧改造（一次性）

本项目已对酒馆做了最小改造（`Sillytarven-online`）：

- `src/endpoints/federated-login.js`：票据登录端点（新增）
- `server-main.js`：挂载 federated-login + 新增 `GET /api/ping-public`（无需认证的延迟探测）
- `config.yaml`：新增 `federated:` 配置块（**默认 `enabled: false`，酒馆行为与现状完全一致**）

在某个节点启用总控登录，编辑该节点的 `config.yaml`：

```yaml
federated:
  enabled: true
  controllerUrl: https://account.example.com   # 总控地址
  nodePsk: <该节点的 agent_psk>                 # 子控注册时总控下发(agent.yaml 里可见)
  nodeBaseUrl: https://a.example.com            # 本节点对外地址(校验票据 aud)
  nodeId: <本节点在总控的节点 ID>
```

## 核心流程

- **注册**：总控注册页选节点（显示状态徽章 + 实测延迟，负载全 <50% 可选）→ 总控代注册到节点（节点无感知）→ 绑定家节点。
- **登录跳转**：总控登录 → 可用节点（家 + 就绪热备）→ 一次性票据(60s, 服务端核销防重放) → `https://节点/federated-login?ticket=...` → 写 session → `/app` 落地即登录态。
- **备份**：用户离线（心跳停 + 超过保护期）→ 子控打包 `data/<handle>` 为 tar.zst 流式推到备份目标（默认存储节点，可配热备计算节点）→ SHA256 校验 → 版本+1。备份中用户登录 → 自动中止，不阻塞。
- **热备切换**：家节点宕机 → 自动切到已同步完成的热备；脑裂防护：同一时刻一个用户只有一个可写 home。

## 安全

- 总控↔子控：HMAC-SHA256 签名 + 时间戳 + nonce 防重放，每节点独立 PSK，建议 HTTPS/mTLS。
- 票据：短命(60s) + 一次性(服务端核销) + 绑定节点(aud) + 仅 HTTPS。
- 用户密码：总控只保存不可逆登录 hash；节点密码同步使用酒馆兼容的 scrypt hash/salt，不保存可逆明文。`CONTROLLER_SECRET_KEY` 只用于控制面凭证等必须可恢复的机器密钥材料。
- 备份数据含明文 API key(secrets.json) → 传输 TLS，存储节点备份目录权限 0700。

## 构建产物

```bash
# Windows 一键构建所有二进制
build-bin.bat   # 产出 bin/controller.exe, bin/agent.exe, bin/agent-linux-amd64

# 前端
cd web && npm install && npm run build   # 产出 web/dist
```

## 待完善（后续迭代）

- 节点改密同步接口（`agent.set_password` 当前为占位，需酒馆侧配合内部接口）
- 备份恢复 `restore` 完整实现、存储节点版本保留滚动清理
- 网盘备份扩展（rclone）、mTLS、备份静态加密
- 既有老节点用户的一键导入 UI（当前 scan-existing 已能扫描上报，导入逻辑待补）
- OAuth 注册新用户的选节点流程端到端联调
