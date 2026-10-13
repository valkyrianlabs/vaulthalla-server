#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$REPO_ROOT/bin"

source "$BIN_DIR/lib/dev_mode.sh"
source "$BIN_DIR/lib/platform.sh"

echo "🗡️  Initiating Vaulthalla uninstallation sequence..."

vh_assert_dev_mode_consistency

DEV_MODE=false
vh_is_dev_mode && DEV_MODE=true

echo "🔍 Build mode: ${VH_BUILD_MODE:-unset}"
echo "🔍 Dev mode active: $DEV_MODE"

REMOVE_DB=false
REMOVE_USERS=false
PURGE_DEPS=false

if [[ "$DEV_MODE" == true ]]; then
  REMOVE_DB=true
  REMOVE_USERS=true
fi

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --remove-db        Drop PostgreSQL database and user
  --remove-users     Remove system user/group
  --purge-deps       Uninstall apt dependencies installed for Vaulthalla
  -h, --help         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --remove-db)
      REMOVE_DB=true
      shift
      ;;
    --remove-users)
      REMOVE_USERS=true
      shift
      ;;
    --purge-deps)
      PURGE_DEPS=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

if vh_dry_run && [[ "$(vh_os)" != darwin ]]; then
  vh_die "VH_DRY_RUN covers the macOS scripts only; the Linux steps would still run"
fi

# Which install: production (make uninstall), or only the isolated dev instance (dev mode: make dev reinstalls it).
vh_instance_layout "$(vh_selected_instance)"
echo "📐 Removing $( [ -n "$VH_INSTANCE" ] && echo "the isolated '$VH_INSTANCE' instance" || echo production ):"
vh_print_layout | sed 's/^/   /'

if [[ "$(vh_os)" == darwin ]]; then
  # macOS: only the dev instance is ever installed from source; production belongs to the package's uninstaller.
  [[ -n "$VH_INSTANCE" ]] || vh_die "on macOS, remove production with the package's uninstaller (or brew uninstall --cask)"
  if [[ "$REMOVE_DB" == true || "$REMOVE_USERS" == true ]]; then
    "$BIN_DIR/teardown/uninstall_darwin.sh" --purge
  else
    "$BIN_DIR/teardown/uninstall_darwin.sh"
  fi
  echo
  echo "✅ The '$VH_INSTANCE' instance has been uninstalled."
  exit 0
fi

# The teardown scripts below take the instance from the same layout; kill_dev_artifacts.sh and unmount_fuse.sh get it
# through their environment, so for the dev instance nothing of a production install beside it is ever eligible.
if [[ -n "$VH_INSTANCE" ]]; then
  export VH_UNIT_STEM="$VH_NAME" VH_UNIT_CORE="$VH_UNIT_CORE" VH_INSTANCE_BINDIRS="$VH_BINDIR"
  export VH_MOUNTPOINT="$VH_MOUNT_DIR" VH_WEB_SERVER_PATH="$VH_WEB_DIR/server.js"
  export VH_SWTPM_STATE_DIR="$VH_SWTPM_STATE_DIR" VH_CONFIG_PATH="$VH_CONFIG_PATH"
fi

# 1) Make sure dev-owned stale services/processes are gone before unit files move.
if [[ "$DEV_MODE" == true ]]; then
  "$BIN_DIR/teardown/kill_dev_artifacts.sh"
else
  "$BIN_DIR/teardown/unmount_fuse.sh"
fi

# 2) Stop and remove systemd services
"$BIN_DIR/teardown/uninstall_systemd.sh"

# 3) Remove installed binaries/artifacts
"$BIN_DIR/teardown/uninstall_binaries.sh"
"$REPO_ROOT/web/bin/teardown_web.sh"

# 4) Remove runtime/config dirs
"$BIN_DIR/teardown/uninstall_dirs.sh"

# 5) Optionally remove DB
if [[ "$REMOVE_DB" == true ]]; then
  "$BIN_DIR/teardown/uninstall_db.sh"
fi

# 6) Optionally remove system user/group
if [[ "$REMOVE_USERS" == true ]]; then
  "$BIN_DIR/teardown/uninstall_users.sh"
fi

# 7) Optionally purge dependencies
if [[ "$PURGE_DEPS" == true ]]; then
  "$BIN_DIR/teardown/uninstall_deps.sh"
fi

echo
echo "✅ Vaulthalla has been uninstalled."
echo "🧙‍♂️ If this was a test install, may your next deployment rise stronger from these ashes."
