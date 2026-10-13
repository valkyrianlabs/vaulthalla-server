#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

source "$ROOT_DIR/bin/lib/dev_mode.sh"
source "$ROOT_DIR/bin/lib/platform.sh"
# Production (make install): vaulthalla*.service as always. The dev instance (make dev): vaulthalla-dev*.service,
# rendered from the same templates with its own paths, account and ports (deploy/instance/render.py).
vh_instance_layout "$(vh_selected_instance)"

BINDIR="$VH_BINDIR"
SYSTEMD_UNIT_DIR="$VH_SYSTEMD_UNIT_DIR"
if [[ -z "$VH_INSTANCE" ]]; then CONFIG_DIR="${CONFIG_DIR:-$VH_CONFIG_DIR}"; else CONFIG_DIR="$VH_CONFIG_DIR"; fi

SWTPM_BASE_DIR="/var/lib/swtpm"
SWTPM_STATE_DIR="$VH_SWTPM_STATE_DIR"
TPM_BACKEND_DROPIN="$SYSTEMD_UNIT_DIR/$VH_UNIT_CORE.d/tpm-backend.conf"
TPM_BACKEND_MODE="hardware"

render_unit() {
  local input="$1"
  local output="$2"

  [[ -f "$input" ]] || {
    echo "❗️ Missing systemd template: $input"
    exit 1
  }

  sudo mkdir -p "$(dirname "$output")"
  if [[ -z "$VH_INSTANCE" ]]; then
    sed "s|@BINDIR@|$BINDIR|g" "$input" | sudo tee "$output" >/dev/null
  else
    local rendered node
    node="$(command -v node || true)"
    [[ -n "$node" ]] || { echo "❗️ node is required for the web unit"; exit 1; }
    rendered="$(mktemp)"
    python3 "$ROOT_DIR/deploy/instance/render.py" systemd --instance "$VH_INSTANCE" --bindir "$BINDIR" \
      --node "$node" --web-dir "$VH_WEB_DIR" "$input" "$rendered"
    sudo install -m 0644 "$rendered" "$output"
    rm -f "$rendered"
  fi
  sudo chmod 0644 "$output"
}

install_unit_file() {
  local input="$1"
  local output="$2"

  [[ -f "$input" ]] || {
    echo "❗️ Missing systemd unit: $input"
    exit 1
  }

  sudo install -m 0644 "$input" "$output"
}

retire_legacy_cli_units() {
  # vaulthalla-cli.{socket,service} were retired (#110): the socket unit was an orphaned listener on the
  # daemon's /run/vaulthalla/cli.sock that made `vh` hang. vaulthalla.service owns the socket now.
  local unit
  for unit in vaulthalla-cli.socket vaulthalla-cli.service; do
    sudo timeout 30 systemctl disable --now "$unit" >/dev/null 2>&1 || true
    sudo rm -f "$SYSTEMD_UNIT_DIR/$unit"
  done
}

has_hardware_tpm() {
  [[ -c /dev/tpmrm0 || -c /dev/tpm0 ]]
}

assert_swtpm_listening() {
  if ! command -v ss >/dev/null 2>&1; then
    return 0
  fi
  ss -H -ltn "( sport = :$VH_SWTPM_PORT )" 2>/dev/null | grep -q "127.0.0.1:$VH_SWTPM_PORT"
}

configure_tpm_backend() {
  if has_hardware_tpm; then
    TPM_BACKEND_MODE="hardware"
    echo "🔐 Hardware TPM detected; using hardware TPM backend."
    sudo rm -f "$TPM_BACKEND_DROPIN"
    sudo systemctl disable --now "$VH_UNIT_SWTPM" >/dev/null 2>&1 || true
    return 0
  fi

  TPM_BACKEND_MODE="swtpm"
  echo "🔐 No hardware TPM detected; provisioning managed swtpm backend."

  if ! command -v swtpm >/dev/null 2>&1; then
    echo "❗️ swtpm binary is required when no hardware TPM is present."
    echo "   Install with: sudo apt install swtpm swtpm-tools"
    exit 1
  fi

  sudo install -d -m 0755 "$SWTPM_BASE_DIR"
  sudo install -d -m 0700 -o "$VH_USER" -g "$VH_GROUP" "$SWTPM_STATE_DIR"
  sudo install -d -m 0755 "$(dirname "$TPM_BACKEND_DROPIN")"
  printf '[Service]\nEnvironment=TSS2_TCTI=swtpm:host=127.0.0.1,port=%s\n' "$VH_SWTPM_PORT" \
    | sudo tee "$TPM_BACKEND_DROPIN" >/dev/null
  sudo chmod 0644 "$TPM_BACKEND_DROPIN"
}

if [[ "$(vh_os)" != linux ]]; then
  echo "❗️ install_systemd.sh is Linux-only (macOS: bin/setup/install_service.sh)"
  exit 1
fi

echo "🛠️  Installing Vaulthalla systemd units..."

render_unit \
  "$ROOT_DIR/deploy/systemd/vaulthalla.service.in" \
  "$SYSTEMD_UNIT_DIR/$VH_UNIT_CORE"

render_unit \
  "$ROOT_DIR/deploy/systemd/vaulthalla-web.service.in" \
  "$SYSTEMD_UNIT_DIR/$VH_UNIT_WEB"

render_unit \
  "$ROOT_DIR/deploy/systemd/vaulthalla-swtpm.service.in" \
  "$SYSTEMD_UNIT_DIR/$VH_UNIT_SWTPM"

# The dev instance never had the legacy units; they are production's to retire.
if [[ -z "$VH_INSTANCE" ]]; then
  retire_legacy_cli_units
fi
echo "🧩 Installing service overrides..."
sudo install -d -m 0755 "$SYSTEMD_UNIT_DIR/$VH_UNIT_CORE.d"

if [[ -f "$CONFIG_DIR/vaulthalla.env" ]]; then
  printf '[Service]\nEnvironmentFile=%s/vaulthalla.env\n' "$CONFIG_DIR" \
    | sudo tee "$SYSTEMD_UNIT_DIR/$VH_UNIT_CORE.d/override.conf" >/dev/null
else
  sudo rm -f "$SYSTEMD_UNIT_DIR/$VH_UNIT_CORE.d/override.conf"
fi

configure_tpm_backend

sudo systemctl daemon-reload

echo "🚀 Enabling Vaulthalla services..."
if [[ "$TPM_BACKEND_MODE" == "swtpm" ]]; then
  sudo systemctl enable --now "$VH_UNIT_SWTPM"
  if ! sudo systemctl --quiet is-active "$VH_UNIT_SWTPM"; then
    echo "❗️ $VH_UNIT_SWTPM failed to become active."
    echo "   Inspect with: sudo journalctl -u $VH_UNIT_SWTPM"
    exit 1
  fi
  if ! assert_swtpm_listening; then
    echo "❗️ swtpm expected listener not detected on 127.0.0.1:$VH_SWTPM_PORT."
    echo "   Inspect with: sudo journalctl -u $VH_UNIT_SWTPM"
    exit 1
  fi
fi
sudo systemctl enable --now "$VH_UNIT_CORE"
sudo systemctl enable --now "$VH_UNIT_WEB"

echo
echo "🏁 Vaulthalla installed successfully!"

if [[ "${VH_FOLLOW_LOGS:-0}" == "1" ]]; then
  echo "📜 Tailing $VH_UNIT_CORE logs..."
  sudo journalctl -f -u "$VH_UNIT_CORE"
else
  echo "📜 Recent $VH_UNIT_CORE logs:"
  sudo journalctl -n 25 --no-pager -u "$VH_UNIT_CORE"
fi
