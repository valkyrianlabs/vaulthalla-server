#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=bin/lib/platform.sh
source "$SCRIPT_DIR/../lib/platform.sh"
# Production's units (make uninstall), or only the dev instance's (make dev / uninstall in dev mode).
vh_instance_layout "$(vh_selected_instance)"

echo "🗑️  Removing Vaulthalla systemd services..."
SYSTEMCTL_TIMEOUT="${VH_SYSTEMCTL_STOP_TIMEOUT:-35s}"

UNITS=(
  "$VH_UNIT_WEB"
  "$VH_UNIT_CORE"
  "$VH_UNIT_SWTPM"
)
if [[ -z "$VH_INSTANCE" ]]; then
  # vaulthalla-cli.{service,socket} are retired (#110); kept so older dev installs are cleaned up.
  UNITS=(
    vaulthalla-web.service
    vaulthalla-cli.service
    vaulthalla-cli.socket
    vaulthalla.service
    vaulthalla-swtpm.service
  )
fi

unit_exists() {
  local unit="$1"
  systemctl list-unit-files "$unit" >/dev/null 2>&1 || systemctl status "$unit" >/dev/null 2>&1
}

run_systemctl() {
  if command -v timeout >/dev/null 2>&1; then
    sudo timeout "$SYSTEMCTL_TIMEOUT" systemctl "$@"
  else
    sudo systemctl "$@"
  fi
}

unit_deactivating() {
  local unit="$1"
  [[ "$(systemctl show -p ActiveState --value "$unit" 2>/dev/null || true)" == "deactivating" ]]
}

safe_systemctl() {
  local action="$1" unit="$2"
  if ! unit_exists "$unit"; then
    echo "✅ $unit not installed/loaded."
    return 0
  fi

  echo "• systemctl $action $unit"
  if ! run_systemctl "$action" "$unit"; then
    echo "⚠️  systemctl $action $unit failed; continuing with exact-unit cleanup only."
    return 1
  fi
  return 0
}

for unit in "${UNITS[@]}"; do
  safe_systemctl stop "$unit" || true
done

for unit in "${UNITS[@]}"; do
  safe_systemctl disable "$unit"
done

echo "🧹 Removing exact Vaulthalla unit files and overrides..."
if unit_deactivating "$VH_UNIT_CORE"; then
  echo "⚠️  $VH_UNIT_CORE is still deactivating; preserving drop-ins until the stop job clears."
else
  sudo rm -rf "/etc/systemd/system/$VH_UNIT_CORE.d"
fi

for unit in "${UNITS[@]}"; do
  if unit_deactivating "$unit"; then
    echo "⚠️  Preserving $unit files because systemd still reports it deactivating."
    continue
  fi
  sudo rm -f "/etc/systemd/system/$unit"
  sudo rm -f "/lib/systemd/system/$unit"
  sudo rm -f "/usr/lib/systemd/system/$unit"
done

sudo systemctl daemon-reload

for unit in "${UNITS[@]}"; do
  if ! sudo systemctl reset-failed "$unit" >/dev/null 2>&1; then
    echo "⚠️  Could not reset failed state for $unit."
  fi
done

echo "✅ Exact Vaulthalla systemd units purged."
