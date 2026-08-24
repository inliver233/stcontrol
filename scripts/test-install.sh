#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$(mktemp -d)"
trap 'rm -rf "$FIXTURE"' EXIT

export MOCK_AGENT_LOG="$FIXTURE/agent.log"
export MOCK_SERVICE_FILE="$FIXTURE/stcontrol-agent.service"
export MOCK_SYSTEMCTL_LOG="$FIXTURE/systemctl.log"
mkdir -p "$FIXTURE/bin" "$FIXTURE/install"

cat >"$FIXTURE/bin/sudo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "tee" && "${2:-}" == "/etc/systemd/system/stcontrol-agent.service" ]]; then
  exec tee "$MOCK_SERVICE_FILE"
fi
if [[ "${1:-}" == "systemctl" ]]; then
  printf '%s\n' "$*" >>"$MOCK_SYSTEMCTL_LOG"
  if [[ "${MOCK_SYSTEMCTL_FAIL:-}" == "${2:-}" ]]; then
    exit 1
  fi
  exit 0
fi
exec "$@"
EOF
chmod +x "$FIXTURE/bin/sudo"
export PATH="$FIXTURE/bin:$PATH"

make_agent() {
  local version="$1"
  local path="$2"
  cat >"$path" <<EOF
#!/bin/sh
printf '%s\\n' "$version \$*" >>"\$MOCK_AGENT_LOG"
EOF
  chmod +x "$path"
  (cd "$(dirname "$path")" && sha256sum "$(basename "$path")" >"$(basename "$path").sha256")
}

V1="$FIXTURE/agent-v1"
V2="$FIXTURE/agent-v2"
make_agent v1 "$V1"
make_agent v2 "$V2"

bash "$ROOT/scripts/install.sh" \
  --controller https://controller.example \
  --token one-time-token \
  --role storage \
  --install-dir "$FIXTURE/install" \
  --bin-url "file://$V1"

INSTALLED="$FIXTURE/install/stcontrol-agent"
test -x "$INSTALLED"
test -f "$FIXTURE/install/agent.yaml"
test -f "$MOCK_SERVICE_FILE"
grep -q '^v1 .*--register.*--token one-time-token' "$MOCK_AGENT_LOG"
V1_SHA="$(sha256sum "$INSTALLED" | awk '{print $1}')"

export MOCK_SYSTEMCTL_FAIL=restart
if bash "$ROOT/scripts/install.sh" \
  --upgrade \
  --controller https://controller.example \
  --install-dir "$FIXTURE/install" \
  --bin-url "file://$V2"; then
  echo "upgrade unexpectedly succeeded while systemctl restart was failing" >&2
  exit 1
fi
test "$(sha256sum "$INSTALLED" | awk '{print $1}')" = "$V1_SHA"

unset MOCK_SYSTEMCTL_FAIL
bash "$ROOT/scripts/install.sh" \
  --upgrade \
  --controller https://controller.example \
  --install-dir "$FIXTURE/install" \
  --bin-url "file://$V2"
test "$(sha256sum "$INSTALLED" | awk '{print $1}')" = "$(sha256sum "$V2" | awk '{print $1}')"
test "$(wc -l <"$MOCK_AGENT_LOG")" -eq 1
test ! -e "$FIXTURE/install/.stcontrol-agent.previous"
test ! -e "$FIXTURE/install/stcontrol-agent.new"

if bash "$ROOT/scripts/install.sh" \
  --upgrade \
  --controller https://controller.example \
  --install-dir "$FIXTURE/install" \
  --bin-url "file://$V1" \
  --bin-sha256 0000000000000000000000000000000000000000000000000000000000000000; then
  echo "checksum mismatch unexpectedly succeeded" >&2
  exit 1
fi
test "$(sha256sum "$INSTALLED" | awk '{print $1}')" = "$(sha256sum "$V2" | awk '{print $1}')"

echo "install.sh download, verification, upgrade, and rollback tests passed"
