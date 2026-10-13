# shellcheck shell=bash
# shellcheck disable=SC2034  # a library: the VH_* layout variables are read by the scripts that source it
# Platform and instance layer for the source install scripts (bin/). Source it; bash 3.2 compatible (macOS).
#
#   vh_os                     linux | darwin
#   vh_instance_layout NAME   sets the VH_* layout of an install: NAME "" is production (Linux: exactly the paths
#                             the scripts always used), NAME "dev" is the isolated instance `make dev` installs
#                             beside it (core/meson.build -Dinstance; nothing is shared with production)
#   vh_priv CMD...            a privileged command: sudo, or printed only when VH_DRY_RUN=1 (VH_PRIV_AS_USER=1, for
#                             tests on a tree the caller owns, runs it without sudo)
#   vh_priv_write FILE MODE   stdin -> FILE (root), printed only when VH_DRY_RUN=1
#   vh_as USER CMD...         CMD as another account (sudo -u), printed only when VH_DRY_RUN=1
#   vh_run CMD...             an unprivileged command that changes something (build, install into the repo): run, or
#                             printed when VH_DRY_RUN=1
#
# VH_DRY_RUN=1 prints every privileged command (to stderr) instead of running it and skips the build; read-only probes
# still run.

vh_os() {
  case "$(uname -s)" in
    Linux) echo linux ;;
    Darwin) echo darwin ;;
    *) echo unsupported ;;
  esac
}

vh_dry_run() { [ "${VH_DRY_RUN:-0}" = 1 ]; }

vh_quote() { printf ' %q' "$@"; }

vh_priv() {
  if vh_dry_run; then
    printf '[dry-run] sudo%s\n' "$(vh_quote "$@")" >&2
    return 0
  fi
  # VH_PRIV_AS_USER=1 (tests only): run as the caller, for a tree the caller owns.
  if [ "$(id -u)" = 0 ] || [ "${VH_PRIV_AS_USER:-0}" = 1 ]; then "$@"; else sudo "$@"; fi
}

vh_priv_write() {  # vh_priv_write FILE MODE [OWNER:GROUP] < content (the content is never echoed: it may be a secret)
  local file="$1" mode="$2" owner="${3:-}"
  if vh_dry_run; then
    cat >/dev/null
    printf '[dry-run] write %s (mode %s%s)\n' "$file" "$mode" "${owner:+, owner $owner}" >&2
    return 0
  fi
  local tmp
  tmp="$(mktemp)"
  cat > "$tmp"
  vh_priv install -m "$mode" ${owner:+-o "${owner%%:*}" -g "${owner##*:}"} "$tmp" "$file"
  rm -f "$tmp"
}

vh_run() {
  if vh_dry_run; then
    printf '[dry-run]%s\n' "$(vh_quote "$@")" >&2
    return 0
  fi
  "$@"
}

vh_as() {  # vh_as USER CMD...: CMD as another (service) account, from / (its home may be /var/empty)
  local user="$1"
  shift
  if vh_dry_run; then
    printf '[dry-run] sudo -u %s --%s\n' "$user" "$(vh_quote "$@")" >&2
    return 0
  fi
  (cd / && sudo -u "$user" -- "$@")
}

vh_log() { printf '%s\n' "$*"; }
vh_die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# The instance this run installs: `make dev` (dev mode) -> "dev", anything else -> production.
vh_selected_instance() {
  if [ -n "${VH_INSTANCE+x}" ]; then printf '%s\n' "$VH_INSTANCE"
  elif [ "${VH_BUILD_MODE:-}" = dev ]; then echo dev
  else echo ""
  fi
}

vh_instance_layout() {
  local instance="$1" os
  os="$(vh_os)"
  case "$instance" in *[!a-z0-9_]*) vh_die "instance must be [a-z0-9_]+: $instance" ;; esac
  VH_INSTANCE="$instance"
  if [ -z "$instance" ]; then
    VH_NAME=vaulthalla
    VH_DB_NAME=vaulthalla
    VH_PORT_OFFSET=0
    VH_BUILD_DIR_NAME=build
  else
    VH_NAME="vaulthalla-$instance"
    VH_DB_NAME="vaulthalla_$instance"
    VH_PORT_OFFSET=100
    VH_BUILD_DIR_NAME="build-$instance"
  fi
  VH_DB_ROLE="$VH_DB_NAME"
  # Production keeps honoring the overrides the Linux scripts always read (VH_USER, VH_GROUP, PREFIX, SYSCONFDIR);
  # an instance never does, so a leftover export can't point it at production's account or paths.
  if [ -z "$instance" ]; then
    VH_USER="${VH_USER:-vaulthalla}"
    VH_GROUP="${VH_GROUP:-vaulthalla}"
  else
    VH_USER="$VH_NAME"
    VH_GROUP="$VH_NAME"
  fi
  VH_CLI_NAME="vh${instance:+-$instance}"
  VH_WEB_PORT=$((36968 + VH_PORT_OFFSET))
  VH_HTTP_PORT=$((36970 + VH_PORT_OFFSET))
  case "$os" in
    linux)
      if [ -z "$instance" ]; then VH_PREFIX="${PREFIX:-/usr}"; else VH_PREFIX="/opt/$VH_NAME"; fi
      if [ -z "$instance" ]; then VH_CONFIG_DIR="${SYSCONFDIR:-/etc}/$VH_NAME"; else VH_CONFIG_DIR="/etc/$VH_NAME"; fi
      VH_CONFIG_PATH="$VH_CONFIG_DIR/config.yaml"
      VH_STATE_DIR="/var/lib/$VH_NAME"
      VH_LOG_DIR="/var/log/$VH_NAME"
      VH_RUNTIME_DIR="/run/$VH_NAME"
      if [ -z "$instance" ]; then VH_MOUNT_DIR=/mnt/vaulthalla; else VH_MOUNT_DIR="/mnt/vh_$instance"; fi
      VH_SWTPM_STATE_DIR="/var/lib/swtpm/$VH_NAME"
      VH_SWTPM_PORT=$((2321 + VH_PORT_OFFSET))
      VH_UNIT_CORE="$VH_NAME.service"
      VH_UNIT_WEB="$VH_NAME-web.service"
      VH_UNIT_SWTPM="$VH_NAME-swtpm.service"
      VH_SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
      VH_WEB_CACHE_DIR="/var/cache/$VH_NAME-web"
      VH_ROOT_GROUP=root
      ;;
    darwin)
      if [ -z "$instance" ]; then
        VH_PREFIX=/usr/local
        VH_SUPPORT_DIR="/Library/Application Support/Vaulthalla"
        VH_LOG_DIR=/Library/Logs/Vaulthalla
        VH_ACCOUNT=_vaulthalla
        VH_LABEL_PREFIX=sh.vaulthalla
      else
        VH_PREFIX="/usr/local/$VH_NAME"
        VH_SUPPORT_DIR="/Library/Application Support/Vaulthalla-$instance"
        VH_LOG_DIR="/Library/Logs/Vaulthalla-$instance"
        VH_ACCOUNT="_vaulthalla_$instance"
        VH_LABEL_PREFIX="sh.vaulthalla.$instance"
      fi
      VH_CONFIG_PATH="$VH_SUPPORT_DIR/config.yaml"
      VH_STATE_DIR="$VH_SUPPORT_DIR/state"
      VH_RUNTIME_DIR="$VH_SUPPORT_DIR/run"
      VH_MOUNT_DIR="$VH_SUPPORT_DIR/mount"
      VH_PG_DIR="$VH_SUPPORT_DIR/postgres"
      VH_PG_PORT=$((5432 + VH_PORT_OFFSET))
      VH_PG_LABEL="$VH_LABEL_PREFIX.postgres"
      VH_WEB_CACHE_DIR="$VH_SUPPORT_DIR/web-cache"
      VH_ROOT_GROUP=wheel
      ;;
    *) vh_die "unsupported OS: $(uname -s)" ;;
  esac
  if [ -z "$instance" ] && [ "$os" = linux ]; then
    VH_BINDIR="${BINDIR:-$VH_PREFIX/bin}"
    VH_DATADIR="${DATADIR:-$VH_PREFIX/share}"
  else
    VH_BINDIR="$VH_PREFIX/bin"
    VH_DATADIR="$VH_PREFIX/share"
  fi
  VH_LIBEXEC_DIR="$VH_PREFIX/lib/vaulthalla"
  VH_WEB_DIR="$VH_DATADIR/vaulthalla-web"
  VH_CLI_LINK="/usr/local/bin/$VH_CLI_NAME"
}

# Prints the layout (make doctor, dry runs).
vh_print_layout() {
  echo "instance:  ${VH_INSTANCE:-production} ($(vh_os))"
  echo "prefix:    $VH_PREFIX"
  echo "config:    $VH_CONFIG_PATH"
  echo "state:     $VH_STATE_DIR"
  echo "runtime:   $VH_RUNTIME_DIR (CLI socket $VH_RUNTIME_DIR/cli.sock)"
  echo "mount:     $VH_MOUNT_DIR"
  echo "logs:      $VH_LOG_DIR"
  echo "account:   ${VH_ACCOUNT:-$VH_USER}"
  echo "database:  $VH_DB_NAME (role $VH_DB_ROLE)"
  echo "web port:  $VH_WEB_PORT"
  if [ "$(vh_os)" = linux ]; then echo "units:     $VH_UNIT_CORE $VH_UNIT_WEB $VH_UNIT_SWTPM"
  else echo "daemons:   $VH_LABEL_PREFIX.server $VH_LABEL_PREFIX.web $VH_PG_LABEL (PostgreSQL on 127.0.0.1:$VH_PG_PORT)"; fi
  echo "CLI:       $VH_CLI_LINK"
}
