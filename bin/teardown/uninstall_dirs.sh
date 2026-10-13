#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=bin/lib/platform.sh
source "$SCRIPT_DIR/../lib/platform.sh"
# Production's directories (make uninstall), or only the dev instance's (/var/lib/vaulthalla-dev, /mnt/vh_dev, ...).
vh_instance_layout "$(vh_selected_instance)"

echo "🗑️  Cleaning Vaulthalla directories..."

is_mounted_path() {
  local path="$1"
  if command -v findmnt >/dev/null 2>&1; then
    findmnt -rn -M "$path" >/dev/null 2>&1
    return $?
  fi
  grep -Fq " $(readlink -f "$path" 2>/dev/null || echo "$path") " /proc/self/mountinfo 2>/dev/null
}

# Exactly the directories this install owns; anything else is refused.
if [[ -z "$VH_INSTANCE" ]]; then
  OWNED_DIRS=(/mnt/vaulthalla /var/lib/vaulthalla /var/log/vaulthalla /run/vaulthalla /etc/vaulthalla /usr/share/vaulthalla
              /usr/lib/vaulthalla)
else
  # The instance's data/lib dirs live under its prefix (bin/teardown/uninstall_binaries.sh removes that).
  OWNED_DIRS=("$VH_MOUNT_DIR" "$VH_STATE_DIR" "$VH_LOG_DIR" "$VH_RUNTIME_DIR" "$VH_CONFIG_DIR" "$VH_WEB_CACHE_DIR")
fi

safe_rm_tree() {
  local path="$1" owned=false dir
  for dir in "${OWNED_DIRS[@]}" "$VH_SWTPM_STATE_DIR"; do
    [[ "$path" == "$dir" ]] && owned=true
  done
  if [[ "$owned" != true ]]; then
    echo "Refusing to remove unexpected path: $path" >&2
    return 1
  fi

  if [[ ! -e "$path" ]]; then
    return 0
  fi

  if is_mounted_path "$path"; then
    echo "Refusing to remove mounted path: $path" >&2
    return 1
  fi

  sudo rm -rf --one-file-system "$path"
}

if [[ -z "$VH_INSTANCE" ]]; then
  # The nginx site is production's (the dev instance never gets one: bin/setup/install_dev_nginx.sh).
  sudo rm -f /etc/nginx/sites-enabled/vaulthalla
  sudo rm -f /etc/nginx/sites-available/vaulthalla
fi

for dir in "${OWNED_DIRS[@]}"; do
  safe_rm_tree "$dir"
done

safe_rm_tree "$VH_SWTPM_STATE_DIR"
if ! sudo rmdir /var/lib/swtpm >/dev/null 2>&1; then
  echo "ℹ️  /var/lib/swtpm not empty or not removable; leaving it in place."
fi
