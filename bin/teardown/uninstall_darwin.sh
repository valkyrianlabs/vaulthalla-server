#!/bin/bash
# macOS: remove the isolated dev instance (make dev reinstalls it fresh; make uninstall in dev mode). Production is the
# package's to remove (its uninstaller), never this script's. Order: the instance's daemons stop (vaulthalla-provision
# --remove), its PostgreSQL stops, its extra directories go, then provisioning purges its account and private tree,
# then its prefix and CLI link. Every privileged step prints instead with VH_DRY_RUN=1. Bash 3.2 compatible.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
# shellcheck source=bin/lib/platform.sh
source "$SCRIPT_DIR/../lib/platform.sh"
vh_instance_layout "$(vh_selected_instance)"

[ "$(vh_os)" = darwin ] || vh_die "uninstall_darwin.sh is macOS-only"
[ -n "$VH_INSTANCE" ] || vh_die "production on macOS is removed by its package's uninstaller, not by bin/"

PURGE="${1:-}"
PROVISION="$VH_LIBEXEC_DIR/vaulthalla-provision"

mounted_under() {  # mounted_under DIR: anything mounted on or below DIR (from the mount table, never a stat)
  /sbin/mount | while IFS= read -r line; do
    line=${line#* on }
    line=${line% (*}
    case "$line" in "$1"|"$1"/*) echo "$line" ;; esac
  done | grep -q .
}

remove_tree() {  # remove_tree DIR: only the instance's own directories, never through a symlink or a mount
  local dir="$1"
  case "$dir" in "$VH_SUPPORT_DIR"|"$VH_SUPPORT_DIR"/*) ;; *) vh_die "refusing to remove $dir" ;; esac
  case "$VH_SUPPORT_DIR" in */Vaulthalla-?*) ;; *) vh_die "refusing: $VH_SUPPORT_DIR is not an instance directory" ;; esac
  [ -e "$dir" ] || return 0
  [ ! -L "$dir" ] || vh_die "$dir is a symlink; refusing to remove through it"
  ! mounted_under "$dir" || vh_die "something is mounted under $dir; unmount it first"
  vh_priv find "$dir" -xdev -mindepth 1 -delete
  vh_priv rmdir "$dir"
}

echo "🗑️  Removing the $VH_INSTANCE instance ($VH_LABEL_PREFIX.*, $VH_SUPPORT_DIR)..."

if [ -x "$PROVISION" ]; then
  vh_priv "$PROVISION" --remove
else
  echo "ℹ️  $PROVISION is not installed; unloading the daemons by label"
  for label in "$VH_LABEL_PREFIX.server" "$VH_LABEL_PREFIX.web"; do
    if launchctl print "system/$label" >/dev/null 2>&1; then vh_priv launchctl bootout "system/$label"; fi
    vh_priv rm -f "/Library/LaunchDaemons/$label.plist"
  done
fi

if launchctl print "system/$VH_PG_LABEL" >/dev/null 2>&1; then
  vh_priv launchctl bootout "system/$VH_PG_LABEL"
fi
vh_priv rm -f "/Library/LaunchDaemons/$VH_PG_LABEL.plist"

if [ "$PURGE" = --purge ]; then
  remove_tree "$VH_PG_DIR"
  remove_tree "$VH_WEB_CACHE_DIR"
  if [ -x "$PROVISION" ]; then
    vh_priv "$PROVISION" --remove --purge
  fi
  if [ -e "$VH_CONFIG_PATH" ] && [ ! -L "$VH_CONFIG_PATH" ]; then vh_priv rm -f "$VH_CONFIG_PATH"; fi
  if [ -d "$VH_SUPPORT_DIR" ]; then vh_priv rmdir "$VH_SUPPORT_DIR" || echo "ℹ️  $VH_SUPPORT_DIR is not empty; left in place"; fi
fi

"$SCRIPT_DIR/uninstall_binaries.sh"
echo "✅ The $VH_INSTANCE instance is removed${PURGE:+ (account, data and database purged)}."
