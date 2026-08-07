#!/usr/bin/env bash
# 云酒馆子控一键安装脚本
# 用法:
#   curl -sSL https://<总控>/install.sh | bash -s -- \
#     --controller https://<总控地址> --token <一次性令牌> \
#     --role compute --tavern-dir /path/to/SillyTavern [--transfer-url https://node.example/agent-data]
set -euo pipefail

CONTROLLER=""
TOKEN=""
ROLE="compute"
TAVERN_DIR=""
TRANSFER_URL=""
INSTALL_DIR="/opt/stcontrol-agent"
BIN_URL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --controller) CONTROLLER="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --role) ROLE="$2"; shift 2 ;;
    --tavern-dir) TAVERN_DIR="$2"; shift 2 ;;
    --transfer-url) TRANSFER_URL="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --bin-url) BIN_URL="$2"; shift 2 ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

if [[ -z "$CONTROLLER" || -z "$TOKEN" ]]; then
  echo "必须提供 --controller 与 --token"
  exit 1
fi
if [[ "$ROLE" == "compute" && -z "$TAVERN_DIR" ]]; then
  echo "计算节点必须提供 --tavern-dir (酒馆安装目录)"
  exit 1
fi

echo "==> 安装目录: $INSTALL_DIR"
sudo mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# 1. 获取子控二进制
# 优先 --bin-url; 否则从总控下载对应平台二进制; 再否则提示本地编译
ARCH="$(uname -m)"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$ARCH" in
  x86_64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) echo "不支持的架构: $ARCH"; exit 1 ;;
esac

BIN_PATH="$INSTALL_DIR/stcontrol-agent"
if [[ -n "$BIN_URL" ]]; then
  echo "==> 从指定地址下载子控: $BIN_URL"
  sudo curl -sSL "$BIN_URL" -o "$BIN_PATH"
else
  DL="$CONTROLLER/dist/agent-$OS-$GOARCH"
  echo "==> 尝试从总控下载子控: $DL"
  if ! sudo curl -sfSL "$DL" -o "$BIN_PATH"; then
    echo "总控未提供预编译二进制。请在目标机本地编译:"
    echo "  git clone <仓库> && cd stcontrol && GOOS=$OS GOARCH=$GOARCH go build -o stcontrol-agent ./cmd/agent"
    echo "然后将 stcontrol-agent 放到 $BIN_PATH 后重试。"
    exit 1
  fi
fi
sudo chmod +x "$BIN_PATH"

# 2. 生成初始配置
CFG="$INSTALL_DIR/agent.yaml"
if [[ ! -f "$CFG" ]]; then
  sudo tee "$CFG" > /dev/null <<EOF
controller_url: $CONTROLLER
listen: 127.0.0.1:9100
role: $ROLE
tavern_dir: $TAVERN_DIR
tavern_url: http://127.0.0.1:8000
transfer_public_url: $TRANSFER_URL
backup_dir: $INSTALL_DIR/backups
heartbeat_sec: 15
data_dir: $INSTALL_DIR/data
EOF
fi

# 3. 注册到总控
ARGS=(--config "$CFG" --register --token "$TOKEN" --controller "$CONTROLLER" --role "$ROLE")
[[ -n "$TAVERN_DIR" ]] && ARGS+=(--tavern-dir "$TAVERN_DIR")
echo "==> 注册到总控 $CONTROLLER ..."
sudo "$BIN_PATH" "${ARGS[@]}"

# 4. 配置 systemd 开机自启
SERVICE="/etc/systemd/system/stcontrol-agent.service"
echo "==> 配置 systemd 服务"
sudo tee "$SERVICE" > /dev/null <<EOF
[Unit]
Description=ST Control Agent (云酒馆子控)
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$BIN_PATH --config $CFG
Restart=always
RestartSec=5
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable stcontrol-agent
sudo systemctl restart stcontrol-agent

echo ""
echo "==> 安装完成!"
echo "    子控状态: sudo systemctl status stcontrol-agent"
echo "    查看日志: sudo journalctl -u stcontrol-agent -f"
