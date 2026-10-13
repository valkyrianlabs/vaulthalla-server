#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$REPO_ROOT/bin"

source "$BIN_DIR/lib/dev_mode.sh"
source "$BIN_DIR/lib/platform.sh"

echo "🗡️  Initiating Vaulthalla installation sequence..."

vh_assert_dev_mode_consistency

CORE_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--dev)
      export VH_BUILD_MODE=dev
      shift
      ;;
    -m|--manpage)
      CORE_ARGS+=("--manpage")
      shift
      ;;
    --clean)
      CORE_ARGS+=("--clean")
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [options]"
      echo "  -d, --dev        Enable dev mode"
      echo "  -m, --manpage    Build/install manpage"
      echo "      --clean      Clean core build dir first"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

vh_assert_dev_mode_consistency

if vh_dry_run && [[ "$(vh_os)" != darwin ]]; then
  vh_die "VH_DRY_RUN covers the macOS scripts only; the Linux steps would still run"
fi

# Which install: production (make install), or the isolated dev instance (make dev) beside it (bin/lib/platform.sh).
vh_instance_layout "$(vh_selected_instance)"
echo "📐 Installing $( [ -n "$VH_INSTANCE" ] && echo "the isolated '$VH_INSTANCE' instance" || echo production ):"
vh_print_layout | sed 's/^/   /'

case "$(vh_os)" in
  linux)
    "$BIN_DIR/setup/install_deps.sh"
    "$BIN_DIR/setup/install_users.sh"
    "$BIN_DIR/setup/install_dirs.sh"
    "$BIN_DIR/setup/install_core.sh" ${CORE_ARGS[@]+"${CORE_ARGS[@]}"}
    "$REPO_ROOT/web/bin/install_web.sh"
    "$BIN_DIR/setup/install_db.sh"
    "$BIN_DIR/setup/install_systemd.sh"
    "$BIN_DIR/setup/install_dev_nginx.sh"
    ;;
  darwin)
    # install_guard.sh already refused anything but the dev instance here (production: the pkg or the cask).
    [ -n "$VH_INSTANCE" ] || vh_die "macOS production installs come from the package or the Homebrew cask"
    "$BIN_DIR/setup/install_deps.sh"
    "$BIN_DIR/setup/install_core.sh" ${CORE_ARGS[@]+"${CORE_ARGS[@]}"}
    "$REPO_ROOT/web/bin/install_web.sh"
    "$BIN_DIR/setup/install_service.sh"   # vaulthalla-provision: account, private tree, config, LaunchDaemons
    "$BIN_DIR/setup/install_db.sh"        # the instance's own PostgreSQL cluster and the password handoff
    "$BIN_DIR/setup/install_users.sh"     # enrolls you in the instance's group, links vh-<instance>
    ;;
  *) vh_die "unsupported OS: $(uname -s)" ;;
esac

INITIAL_PASSWORD_FILE="$VH_STATE_DIR/super_admin_initial_password"
echo
echo "Web console: sign in as 'admin'. There is no default password: a new database gets a generated one, written to"
echo "  ${INITIAL_PASSWORD_FILE} (read it with: sudo cat $(printf '%q' "$INITIAL_PASSWORD_FILE"))."
echo "  Change it with '${VH_CLI_NAME} setup set-super-admin-password' (removes the file), or keep it and delete the file."
if [ -n "$VH_INSTANCE" ]; then
  echo "  The '$VH_INSTANCE' instance's web console listens on http://127.0.0.1:${VH_WEB_PORT}; its CLI is ${VH_CLI_NAME}."
fi
