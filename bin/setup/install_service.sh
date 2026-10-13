#!/usr/bin/env bash
# The system service of the selected install. Linux: the systemd units (install_systemd.sh). macOS (the dev instance;
# production comes from the package): the instance's vaulthalla-provision, i.e. its hidden account, private tree,
# config and LaunchDaemons, plus the web console's node runtime and cache. Bash 3.2 compatible.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=bin/lib/platform.sh
source "$ROOT_DIR/bin/lib/platform.sh"
vh_instance_layout "$(vh_selected_instance)"

if [ "$(vh_os)" = linux ]; then
  exec "$SCRIPT_DIR/install_systemd.sh" "$@"
fi
[ -n "$VH_INSTANCE" ] || vh_die "macOS production installs come from the package or the Homebrew cask"

PROVISION="$VH_LIBEXEC_DIR/vaulthalla-provision"
NODE_HOME="$VH_PREFIX/libexec/vaulthalla/node"

# The web LaunchDaemon runs $NODE_HOME/bin/node (the path compiled into vaulthalla-provision). A dev instance uses
# Homebrew's node through a directory link: dyld resolves its @rpath libnode from the real Cellar path.
brew_node="$(brew --prefix node 2>/dev/null || true)"
[ -x "$brew_node/bin/node" ] || vh_dry_run || vh_die "Homebrew node is required for the web console (brew install node)"
echo "🟢 $NODE_HOME -> $brew_node"
vh_priv install -d -m 0755 "$(dirname "$NODE_HOME")"
vh_priv ln -sfn "$brew_node" "$NODE_HOME"

[ -x "$PROVISION" ] || vh_dry_run || vh_die "$PROVISION is not installed (bin/setup/install_core.sh)"
echo "🧭 Provisioning plan for the $VH_INSTANCE instance:"
if vh_dry_run; then
  echo "[dry-run] sudo $PROVISION            (plan: account $VH_ACCOUNT, $VH_SUPPORT_DIR, $VH_LABEL_PREFIX.{server,web})"
  echo "[dry-run] sudo $PROVISION --apply"
else
  vh_priv "$PROVISION"
  vh_priv "$PROVISION" --apply
fi

# The web console's runtime cache (Next writes .next/cache), owned by the service account like the Linux one.
cache_link="$VH_WEB_DIR/.next/cache"
vh_priv install -d -m 0750 -o "$VH_ACCOUNT" -g "$VH_ACCOUNT" "$VH_WEB_CACHE_DIR"
if [ -e "$cache_link" ] && [ ! -L "$cache_link" ]; then vh_priv rm -rf "$cache_link"; fi
vh_priv ln -sfn "$VH_WEB_CACHE_DIR" "$cache_link"
echo "✅ $VH_LABEL_PREFIX.server and $VH_LABEL_PREFIX.web are loaded (the server waits for its database)."
