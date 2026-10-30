#!/bin/bash
# Renders a Homebrew cask for a built package:
#
#   tools/macos/pkg/render-cask.sh PKG vaulthalla-server > vaulthalla-server.rb   # the server alone
#   tools/macos/pkg/render-cask.sh PKG vaulthalla > vaulthalla.rb                 # server + Vaulthalla Desktop
#
# `vaulthalla` needs a package built with the Desktop component (build-pkg.sh VH_PKG_DESKTOP_APP).
set -euo pipefail
PKG="${1:?usage: render-cask.sh vaulthalla-<version>-arm64.pkg vaulthalla|vaulthalla-server}"
CASK="${2:?usage: render-cask.sh vaulthalla-<version>-arm64.pkg vaulthalla|vaulthalla-server}"
case "$CASK" in
  vaulthalla-server) ;;
  vaulthalla)
    xar -tf "$PKG" | grep -qx desktop.pkg ||
      { echo "render-cask: $(basename "$PKG") has no Vaulthalla Desktop component" >&2; exit 1; } ;;
  *) echo "render-cask: unknown cask $CASK" >&2; exit 2 ;;
esac
name="$(basename "$PKG")"
version="${name#vaulthalla-}"; version="${version%-arm64.pkg}"
sha="$(shasum -a 256 "$PKG" | cut -d' ' -f1)"
sed -e "s/@VERSION@/$version/g" -e "s/@SHA256@/$sha/g" "$(dirname "$0")/homebrew/$CASK.rb.in"
