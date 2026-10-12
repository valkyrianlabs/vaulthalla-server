#!/bin/bash
# One-shot macOS (Apple Silicon + Homebrew) build bootstrap for core/:
#
#   tools/macos/bootstrap.sh
#
# 1. brew bundle (tools/macos/Brewfile; formulae only, no upgrades of what is already installed)
# 2. the pinned PDFium SDK and the libpqxx-vh pkg-config alias into $VH_MACOS_DEPS
#    (default ~/.cache/vaulthalla-macos-deps)
# 3. prints the meson commands. Nothing is installed outside Homebrew and that prefix; no service is started.
# Bash 3.2 compatible.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"

[ "$(uname -s)" = Darwin ] || { echo "bootstrap.sh: macOS only" >&2; exit 1; }
command -v brew >/dev/null 2>&1 || { echo "bootstrap.sh: install Homebrew first (https://brew.sh)" >&2; exit 1; }

echo "==> brew bundle ($SCRIPT_DIR/Brewfile)"
brew bundle install --no-upgrade --file "$SCRIPT_DIR/Brewfile"

# shellcheck source=tools/macos/env.sh
. "$SCRIPT_DIR/env.sh"

echo "==> PDFium SDK -> $VH_MACOS_DEPS"
"$SCRIPT_DIR/fetch-pdfium.sh" "$VH_MACOS_DEPS"
echo "==> pkg-config aliases -> $VH_MACOS_DEPS"
"$SCRIPT_DIR/make-pc-aliases.sh" "$VH_MACOS_DEPS"

cat <<EOF

Bootstrap done. Build (from $REPO_ROOT):

  source tools/macos/env.sh && meson setup build-macos -Dbuild_unit_tests=true -Dmanpage=true && meson compile -C build-macos

DB-backed unit tests against a disposable PostgreSQL 16 cluster:

  eval "\$(tools/macos/test-db.sh up)" && meson test -C build-macos --print-errorlogs; tools/macos/test-db.sh down
EOF
