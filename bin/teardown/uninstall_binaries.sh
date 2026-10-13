#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=bin/lib/platform.sh
source "$SCRIPT_DIR/../lib/platform.sh"
vh_instance_layout "$(vh_selected_instance)"

echo "🧹 Removing installed binaries..."
if [[ -z "$VH_INSTANCE" ]]; then
  sudo rm -f /usr/local/bin/vaulthalla*
  sudo rm -f /usr/bin/vaulthalla*
  exit 0
fi

# An instance owns its whole prefix (/opt/vaulthalla-<name>, /usr/local/vaulthalla-<name>) and its CLI link.
case "$VH_PREFIX" in
  /opt/vaulthalla-?*|/usr/local/vaulthalla-?*) ;;
  *) vh_die "refusing to remove unexpected instance prefix: $VH_PREFIX" ;;
esac
if [[ -L "$VH_PREFIX" ]]; then vh_die "$VH_PREFIX is a symlink; refusing to remove through it"; fi
vh_priv rm -rf "$VH_PREFIX"
if [[ -L "$VH_CLI_LINK" ]]; then vh_priv rm -f "$VH_CLI_LINK"; fi
