#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=bin/lib/platform.sh
source "$ROOT_DIR/bin/lib/platform.sh"
# Production: $PREFIX/share/vaulthalla-web as always; the dev instance: its own prefix.
vh_instance_layout "$(vh_selected_instance)"

WEB_INSTALL_DIR="$VH_WEB_DIR"

echo "[teardown_web] removing web runtime payload at '$WEB_INSTALL_DIR'..."
vh_priv rm -rf "$WEB_INSTALL_DIR"
echo "[teardown_web] complete"
