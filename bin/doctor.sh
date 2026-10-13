#!/usr/bin/env bash
set -euo pipefail

# macOS: read-only state of production (the package) and of the dev instance (make dev), side by side.
if [[ "$(uname -s)" == Darwin ]]; then
  # shellcheck source=bin/lib/platform.sh
  source "$(cd "$(dirname "$0")" && pwd)/lib/platform.sh"
  echo "🧠 Vaulthalla Doctor — macOS"
  echo "==========================="
  for instance in "" dev; do
    vh_instance_layout "$instance"
    echo
    vh_print_layout
    if dscl . -read "/Users/$VH_ACCOUNT" UniqueID >/dev/null 2>&1; then
      echo "✅ account $VH_ACCOUNT ($(dscl . -read "/Users/$VH_ACCOUNT" UniqueID | awk '{print "uid " $2}'))"
    else
      echo "❌ account $VH_ACCOUNT missing"
    fi
    for label in "$VH_LABEL_PREFIX.server" "$VH_LABEL_PREFIX.web" "$VH_PG_LABEL"; do
      if out="$(launchctl print "system/$label" 2>/dev/null)"; then
        echo "▶ $label: $(printf '%s\n' "$out" | awk '$1 == "state" {s = $3} $1 == "pid" {p = $3} END {print "state=" s (p ? " pid=" p : "")}')"
      else
        echo "▶ $label: not loaded"
      fi
    done
    if [[ -S "$VH_RUNTIME_DIR/cli.sock" ]] || sudo -n test -S "$VH_RUNTIME_DIR/cli.sock" 2>/dev/null; then
      echo "✅ $VH_RUNTIME_DIR/cli.sock"
    else
      echo "❌ $VH_RUNTIME_DIR/cli.sock missing (or not visible without sudo)"
    fi
  done
  echo
  echo "Mounted FUSE (mount table):"
  /sbin/mount | grep -i vaulthalla || echo "   none"
  exit 0
fi

PROJECT="vaulthalla"

BINDIR="/usr/bin"
CONFIG_DIR="/etc/$PROJECT"
DATA_DIR="/usr/share/$PROJECT"
RUNTIME_DIR="/var/run/$PROJECT"
STATE_DIR="/var/lib/$PROJECT"
SWTPM_STATE_DIR="/var/lib/swtpm/$PROJECT"
LOG_DIR="/var/log/$PROJECT"
MOUNT_DIR="/mnt/$PROJECT"

echo "🧠 Vaulthalla Doctor — System Inspection"
echo "========================================"
echo

check_path() {
  local p="$1"

  if [[ -L "$p" ]]; then
    printf "🔗 %s\n" "$p"
    stat -Lc "   → %N
   type: %F
   perms: %a (%A)
   owner: %U:%G" "$p"
  elif [[ -e "$p" ]]; then
    printf "📁 %s\n" "$p"
    stat -Lc "   type: %F
   perms: %a (%A)
   owner: %U:%G" "$p"
  else
    printf "❌ %s (missing)\n" "$p"
  fi

  echo
}

has_hardware_tpm() {
  [[ -c /dev/tpmrm0 || -c /dev/tpm0 ]]
}

swtpm_listening_locally() {
  if ! command -v ss >/dev/null 2>&1; then
    return 0
  fi
  ss -H -ltn '( sport = :2321 )' 2>/dev/null | grep -q '127.0.0.1:2321'
}

echo "---- 📦 Binaries ----"
check_path "$BINDIR/vaulthalla-server"
check_path "$BINDIR/vaulthalla-cli"
check_path "$BINDIR/vaulthalla"
check_path "$BINDIR/vh"

echo "---- ⚙️ Config ----"
check_path "$CONFIG_DIR"
check_path "$CONFIG_DIR/config.yaml"
check_path "$CONFIG_DIR/vaulthalla.env"

echo "---- 🧱 Runtime ----"
check_path "$RUNTIME_DIR"
check_path "$STATE_DIR"
check_path "$SWTPM_STATE_DIR"
check_path "$LOG_DIR"
check_path "$MOUNT_DIR"

echo "---- 🔐 TPM Backend ----"
if has_hardware_tpm; then
  echo "TPM backend: hardware"
  [[ -c /dev/tpmrm0 ]] && echo "  detected: /dev/tpmrm0"
  [[ -c /dev/tpm0 ]] && echo "  detected: /dev/tpm0"
elif systemctl --quiet is-active vaulthalla-swtpm.service 2>/dev/null; then
  echo "TPM backend: swtpm"
  if swtpm_listening_locally; then
    echo "  listener: 127.0.0.1:2321"
  else
    echo "  listener: not detected on 127.0.0.1:2321"
  fi
else
  echo "TPM backend: unavailable"
  echo "  no hardware TPM device found and vaulthalla-swtpm.service is not active"
fi

echo

echo "---- 🗄️ Data ----"
check_path "$DATA_DIR"
check_path "$DATA_DIR/psql"

echo "---- 👤 User ----"
if id "$PROJECT" &>/dev/null; then
  id "$PROJECT"
else
  echo "❌ user '$PROJECT' missing"
fi

if getent group "$PROJECT" &>/dev/null; then
  getent group "$PROJECT"
else
  echo "❌ group '$PROJECT' missing"
fi

echo
echo "---- 🔧 systemd ----"

for unit in \
  vaulthalla.service \
  vaulthalla-web.service
do
  echo "▶ $unit"

  systemctl status "$unit" --no-pager --lines=2 2>/dev/null || echo "   (not loaded)"

  echo "   ExecStart:"
  systemctl show "$unit" -p ExecStart 2>/dev/null | sed "s/^/   /" || true

  echo
done

echo "---- 🔌 CLI socket ----"
if sudo -n test -S /run/vaulthalla/cli.sock 2>/dev/null || test -S /run/vaulthalla/cli.sock 2>/dev/null; then
  echo "✅ /run/vaulthalla/cli.sock (owned by vaulthalla.service)"
else
  echo "❌ /run/vaulthalla/cli.sock missing (is vaulthalla.service running?)"
fi
for legacy_unit in vaulthalla-cli.socket vaulthalla-cli.service; do
  legacy_state="$(timeout 10 systemctl show -p ActiveState --value "$legacy_unit" 2>/dev/null || true)"
  if [[ -n "$legacy_state" && "$legacy_state" != "inactive" ]]; then
    echo "⚠️  retired $legacy_unit is '$legacy_state'; it can swallow vh clients."
    echo "   Fix: sudo systemctl disable --now vaulthalla-cli.socket vaulthalla-cli.service"
  fi
done
echo

echo "---- 🌍 Env Sanity ----"

if [[ -f "$CONFIG_DIR/vaulthalla.env" ]]; then
  # Key names only: the file holds secrets, and values are never printed (CLAUDE.md).
  echo "📄 $CONFIG_DIR/vaulthalla.env (values masked)"
  sed -nE 's/^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=.*/\2=<set>/p' \
    "$CONFIG_DIR/vaulthalla.env" | nl -ba | sed "s/^/   /"

  echo
  echo "⚠️  suspicious lines (line numbers only):"
  grep -nE "^[[:space:]]*export[[:space:]]+|[[:space:]]+=[[:space:]]*" "$CONFIG_DIR/vaulthalla.env" | cut -d: -f1 \
    | sed 's/^/   line /' || echo "   none"
  if grep -qE '^(export )?VH_TEST_DB_' "$CONFIG_DIR/vaulthalla.env"; then
    echo "⚠️  VH_TEST_DB_* keys are in the daemon's environment file (left by the retired make run_test);"
    echo "   remove them with bin/tests/retire_legacy_test_env.sh"
  fi
else
  echo "❌ env file missing"
fi

echo
echo "---- 🔍 Process Reality ----"

echo "Running vaulthalla processes:"
pgrep -fa vaulthalla || echo "   none"

echo
echo "Mounted FUSE:"
mount | grep vaulthalla || echo "   none"

echo
echo "========================================"
echo "🧙 Diagnosis complete."
