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
BIN_SHA256=""
UPGRADE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --controller) CONTROLLER="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --role) ROLE="$2"; shift 2 ;;
    --tavern-dir) TAVERN_DIR="$2"; shift 2 ;;
    --transfer-url) TRANSFER_URL="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --bin-url) BIN_URL="$2"; shift 2 ;;
    --bin-sha256) BIN_SHA256="$2"; shift 2 ;;
    --upgrade) UPGRADE=true; shift ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

if [[ "$UPGRADE" != true && ( -z "$CONTROLLER" || -z "$TOKEN" ) ]]; then
  echo "首次安装必须提供 --controller 与 --token"
  exit 1
fi
if [[ "$UPGRADE" == true && -z "$CONTROLLER" && -z "$BIN_URL" ]]; then
  echo "升级时必须提供 --controller，或用 --bin-url 指定二进制地址"
  exit 1
fi
if [[ "$UPGRADE" != true && "$ROLE" == "compute" && -z "$TAVERN_DIR" ]]; then
  echo "计算节点必须提供 --tavern-dir (酒馆安装目录)"
  exit 1
fi

CONTROLLER="${CONTROLLER%/}"

echo "==> 安装目录: $INSTALL_DIR"
sudo mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# 1. 获取并校验子控二进制
# 优先 --bin-url；否则从总控下载对应平台二进制及同名 .sha256。
ARCH="$(uname -m)"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [[ "$OS" != "linux" ]]; then
  echo "当前安装器仅支持 Linux/systemd，检测到: $OS"
  exit 1
fi
case "$ARCH" in
  x86_64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) echo "不支持的架构: $ARCH"; exit 1 ;;
esac

BIN_PATH="$INSTALL_DIR/stcontrol-agent"
if [[ -n "$BIN_URL" ]]; then
  DL="$BIN_URL"
else
  DL="$CONTROLLER/dist/agent-$OS-$GOARCH"
fi

TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/stcontrol-agent"
TMP_SUM="$TMP_DIR/stcontrol-agent.sha256"
BACKUP_PATH="$INSTALL_DIR/.stcontrol-agent.previous"
ROLLBACK_ARMED=false
HAD_PREVIOUS=false
cleanup() {
  status=$?
  if [[ $status -ne 0 && "$ROLLBACK_ARMED" == true ]]; then
    echo "==> 安装失败，恢复原 Agent 二进制" >&2
    if [[ "$HAD_PREVIOUS" == true ]]; then
      sudo mv -f "$BACKUP_PATH" "$BIN_PATH" || true
      sudo systemctl restart stcontrol-agent >/dev/null 2>&1 || true
    else
      sudo rm -f "$BIN_PATH" "$BACKUP_PATH" || true
    fi
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "==> 下载子控: $DL"
curl -fsSL --retry 3 --retry-delay 1 --connect-timeout 10 "$DL" -o "$TMP_BIN"
if [[ -z "$BIN_SHA256" ]]; then
  echo "==> 下载校验和: $DL.sha256"
  curl -fsSL --retry 3 --retry-delay 1 --connect-timeout 10 "$DL.sha256" -o "$TMP_SUM"
  BIN_SHA256="$(awk 'NR == 1 { print $1 }' "$TMP_SUM")"
fi
if [[ ! "$BIN_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "Agent SHA-256 格式无效"
  exit 1
fi
ACTUAL_SHA256="$(sha256sum "$TMP_BIN" | awk '{ print $1 }')"
if [[ "${ACTUAL_SHA256,,}" != "${BIN_SHA256,,}" ]]; then
  echo "Agent SHA-256 校验失败: expected=$BIN_SHA256 actual=$ACTUAL_SHA256"
  exit 1
fi
echo "==> SHA-256 校验通过: $ACTUAL_SHA256"

if sudo test -f "$BIN_PATH"; then
  HAD_PREVIOUS=true
  sudo rm -f "$BACKUP_PATH"
  sudo cp -p "$BIN_PATH" "$BACKUP_PATH"
fi
sudo install -m 0755 "$TMP_BIN" "$BIN_PATH.new"
sudo mv -f "$BIN_PATH.new" "$BIN_PATH"
ROLLBACK_ARMED=true

# 2. 生成初始配置
CFG="$INSTALL_DIR/agent.yaml"
if [[ "$UPGRADE" == true && ! -f "$CFG" ]]; then
  echo "升级要求已有配置文件: $CFG"
  exit 1
fi
if [[ "$UPGRADE" != true && ! -f "$CFG" ]]; then
  sudo tee "$CFG" > /dev/null <<EOF
controller_url: $CONTROLLER
listen: 127.0.0.1:9100
role: $ROLE
tavern_dir: $TAVERN_DIR
tavern_url: http://127.0.0.1:8000
transfer_public_url: $TRANSFER_URL
tls_cert_file: ""
tls_key_file: ""
backup_dir: $INSTALL_DIR/backups
disk_quota_bytes: 0
heartbeat_sec: 15
data_dir: $INSTALL_DIR/data
disaster:
  unreachable_after_sec: 45
  independent_after_sec: 900
  min_failed_heartbeats: 4
  peer_witness_urls: []
  peer_witness_secret_env: STCONTROL_PEER_WITNESS_PSK
EOF
fi

# 3. 首次安装注册到总控；升级保留现有身份和配置。
if [[ "$UPGRADE" != true ]]; then
  ARGS=(--config "$CFG" --register --token "$TOKEN" --controller "$CONTROLLER" --role "$ROLE")
  [[ -n "$TAVERN_DIR" ]] && ARGS+=(--tavern-dir "$TAVERN_DIR")
  echo "==> 注册到总控 $CONTROLLER ..."
  sudo "$BIN_PATH" "${ARGS[@]}"
else
  echo "==> 升级模式: 保留 $CFG 中的节点身份"
fi

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
EnvironmentFile=-$INSTALL_DIR/agent.env
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
ROLLBACK_ARMED=false
sudo rm -f "$BACKUP_PATH"

echo ""
echo "==> 安装完成!"
echo "    子控状态: sudo systemctl status stcontrol-agent"
echo "    查看日志: sudo journalctl -u stcontrol-agent -f"
