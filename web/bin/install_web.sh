#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$WEB_DIR/.." && pwd)"

# shellcheck source=bin/lib/platform.sh
source "$ROOT_DIR/bin/lib/platform.sh"
# Production (make install): $PREFIX/share/vaulthalla-web as always; the dev instance (make dev): its own prefix.
vh_instance_layout "$(vh_selected_instance)"

WEB_INSTALL_DIR="$VH_WEB_DIR"
WEB_STANDALONE_DIR="$WEB_DIR/.next/standalone"
WEB_STATIC_DIR="$WEB_DIR/.next/static"
WEB_PUBLIC_DIR="$WEB_DIR/public"

log() {
  echo "[install_web] $*"
}

fail() {
  echo "[install_web] ERROR: $*" >&2
  exit 1
}

require_command() {
  local command_name="$1"
  local install_hint="$2"

  if ! command -v "$command_name" >/dev/null 2>&1; then
    fail "required command '$command_name' is missing. $install_hint"
  fi
}

setup_web_runtime_cache() {
    local web_root="${WEB_INSTALL_DIR:-/usr/share/vaulthalla-web}"
    local cache_dir="$VH_WEB_CACHE_DIR"
    local cache_link="${web_root}/.next/cache"

    vh_priv install -d -m 0750 -o "$VH_USER" -g "$VH_GROUP" "$cache_dir"
    vh_priv install -d -m 0755 "$web_root/.next"

    if [[ -e "$cache_link" && ! -L "$cache_link" ]]; then
        vh_priv rm -rf "$cache_link"
    fi

    if [[ ! -e "$cache_link" ]]; then
        vh_priv ln -s "$cache_dir" "$cache_link"
    fi

    vh_priv chown -h "$VH_USER:$VH_GROUP" "$cache_link" || true

    echo "[install_web] runtime cache ready: ${cache_link} -> ${cache_dir}"
}

run_in_web_dir() {
  (
    cd "$WEB_DIR"
    "$@"
  )
}

log "resolving paths"
[[ -d "$WEB_DIR" ]] || fail "web project directory not found: $WEB_DIR"
[[ -f "$WEB_DIR/package.json" ]] || fail "web package manifest not found: $WEB_DIR/package.json"
[[ -d "$ROOT_DIR/debian" ]] || fail "debian packaging directory not found: $ROOT_DIR/debian"

log "checking build prerequisites"
require_command "pnpm" "Install pnpm, then rerun the installer."
require_command "node" "Install Node.js, then rerun the installer."

log "installing dependencies"
run_in_web_dir vh_run pnpm install --frozen-lockfile

log "building vaulthalla-web"
run_in_web_dir vh_run pnpm build

if vh_dry_run; then
  log "dry run: would install $WEB_STANDALONE_DIR into $WEB_INSTALL_DIR (root-owned)"
  exit 0
fi

log "validating build artifacts"
if [[ ! -d "$WEB_STANDALONE_DIR" ]]; then
  fail "missing web build output after build: $WEB_STANDALONE_DIR"
fi
if [[ ! -d "$WEB_STATIC_DIR" ]]; then
  fail "missing web build output after build: $WEB_STATIC_DIR"
fi
if [[ ! -f "$WEB_STANDALONE_DIR/server.js" ]]; then
  fail "missing web runtime entrypoint after build: $WEB_STANDALONE_DIR/server.js"
fi

log "installing web artifacts"
vh_priv rm -rf "$WEB_INSTALL_DIR"
vh_priv install -d -m 0755 "$WEB_INSTALL_DIR"

# Mirror Debian packaging artifact layout from debian/rules.
vh_priv cp -a "$WEB_STANDALONE_DIR/." "$WEB_INSTALL_DIR/"
vh_priv install -d -m 0755 "$WEB_INSTALL_DIR/.next"
vh_priv cp -a "$WEB_STATIC_DIR" "$WEB_INSTALL_DIR/.next/"
if [[ -d "$WEB_PUBLIC_DIR" ]]; then
  vh_priv cp -a "$WEB_PUBLIC_DIR" "$WEB_INSTALL_DIR/"
fi

# Debian package payload ownership at rest is root-owned.
vh_priv chown -R "root:$VH_ROOT_GROUP" "$WEB_INSTALL_DIR"

# macOS: the service account doesn't exist until vaulthalla-provision runs, so bin/setup/install_service.sh links the
# runtime cache afterwards.
if [[ "$(vh_os)" == linux ]]; then
  setup_web_runtime_cache

  # Debian package payload ownership at rest is root-owned.
  vh_priv chown -R root:root "$WEB_INSTALL_DIR"
fi

if [[ ! -d "$WEB_INSTALL_DIR" ]]; then
  fail "installed web artifact directory is missing: $WEB_INSTALL_DIR"
fi
if [[ ! -f "$WEB_INSTALL_DIR/server.js" ]]; then
  fail "installed web runtime entrypoint is missing: $WEB_INSTALL_DIR/server.js"
fi
if [[ ! -d "$WEB_INSTALL_DIR/.next/static" ]]; then
  fail "installed Next static payload is missing: $WEB_INSTALL_DIR/.next/static"
fi

log "complete"
