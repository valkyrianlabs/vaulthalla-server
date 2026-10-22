#!/usr/bin/env bash
# Linux: runtime/state directories, CLI links and the shared data payloads of the install bin/lib/platform.sh selects
# (production for make install, the isolated dev instance for make dev). macOS: vaulthalla-provision does this
# (bin/setup/install_service.sh).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=bin/lib/platform.sh
source "$ROOT_DIR/bin/lib/platform.sh"
vh_instance_layout "$(vh_selected_instance)"

[[ "$(vh_os)" == linux ]] || vh_die "install_dirs.sh is Linux-only (macOS: bin/setup/install_service.sh)"

BINDIR="$VH_BINDIR"
DATADIR="$VH_DATADIR"
if [[ -z "$VH_INSTANCE" ]]; then LIBDIR="${LIBDIR:-$VH_PREFIX/lib}"; else LIBDIR="$VH_PREFIX/lib"; fi

CONFIG_DIR="$VH_CONFIG_DIR"
DATA_DIR="$DATADIR/vaulthalla"
LIBEXEC_DIR="$LIBDIR/vaulthalla"
RUNTIME_DIR="$VH_RUNTIME_DIR"
STATE_DIR="$VH_STATE_DIR"
LOG_DIR="$VH_LOG_DIR"
MOUNT_DIR="$VH_MOUNT_DIR"
SWTPM_BASE_DIR="/var/lib/swtpm"
SWTPM_STATE_DIR="$VH_SWTPM_STATE_DIR"

install_dir() {
  local dir="$1"
  local mode="$2"
  vh_priv mkdir -p "$dir"
  vh_priv chmod "$mode" "$dir"
  vh_priv chown "$VH_USER:$VH_GROUP" "$dir"
}

install_file() {
  local src="$1"
  local dst="$2"
  local mode="${3:-0644}"

  vh_priv mkdir -p "$(dirname "$dst")"
  vh_priv install -m "$mode" "$src" "$dst"
}

# An instance's config is production's (the private repo-root override or the shipped default) with its own ports
# and database (deploy/instance/render.py); production installs the file as is.
install_config() {
  local src="$1" dst="$2"
  if [[ -z "$VH_INSTANCE" ]]; then
    install_file "$src" "$dst" 0640
  else
    local rendered
    rendered="$(mktemp)"
    python3 "$ROOT_DIR/deploy/instance/render.py" config --instance "$VH_INSTANCE" "$src" "$rendered"
    install_file "$rendered" "$dst" 0640
    rm -f "$rendered"
  fi
  vh_priv chown "$VH_USER:$VH_GROUP" "$dst"
}

echo "📁 Installing Vaulthalla runtime/data directories..."

install_dir "$RUNTIME_DIR" 750
install_dir "$STATE_DIR" 700
vh_priv install -d -m 0755 "$SWTPM_BASE_DIR"
install_dir "$SWTPM_STATE_DIR" 700
install_dir "$LOG_DIR" 750
install_dir "$MOUNT_DIR" 755

echo "🔗 Installing CLI symlinks..."
vh_priv mkdir -p "$BINDIR"
vh_priv ln -sf "$BINDIR/vaulthalla-cli" "$BINDIR/vaulthalla"
vh_priv ln -sf "$BINDIR/vaulthalla-cli" "$BINDIR/vh"
if [[ -n "$VH_INSTANCE" ]]; then
  # The instance's CLI on PATH under its own name; production's vh is never replaced.
  vh_priv ln -sfn "$BINDIR/vaulthalla-cli" "$VH_CLI_LINK"
fi

echo "📦 Installing shared data/config payloads..."

if [[ -f "$ROOT_DIR/config.yaml" ]]; then
  install_config "$ROOT_DIR/config.yaml" "$CONFIG_DIR/config.yaml"
else
  install_config "$ROOT_DIR/deploy/config/config.yaml" "$CONFIG_DIR/config.yaml"
fi

install_file "$ROOT_DIR/deploy/config/config_template.yaml.in" "$CONFIG_DIR/config_template.yaml.in" 0640
vh_priv chown "$VH_USER:$VH_GROUP" "$CONFIG_DIR/config_template.yaml.in"

echo "🗄️  Installing SQL assets..."
if [[ -d "$ROOT_DIR/deploy/psql" ]]; then
  vh_priv mkdir -p "$DATA_DIR"
  vh_priv rsync -a "$ROOT_DIR/deploy/psql/" "$DATA_DIR/psql/"
fi

echo "🌐 Installing nginx template payload..."
install_file "$ROOT_DIR/deploy/nginx/vaulthalla.conf" "$DATA_DIR/nginx/vaulthalla" 0644

echo "🧰 Installing lifecycle utility..."
install_file "$ROOT_DIR/deploy/lifecycle/main.py" "$LIBEXEC_DIR/lifecycle" 0755

echo "✅ Directory/data installation complete."
