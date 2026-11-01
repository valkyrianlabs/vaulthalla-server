#!/bin/bash
# Renders a Homebrew cask for a built package (PKG, with its PKG.sha256 beside it):
#
#   tools/macos/pkg/render-cask.sh PKG vaulthalla-server > vaulthalla-server.rb   # the server
#   tools/macos/pkg/render-cask.sh PKG vaulthalla > vaulthalla.rb                 # the meta cask: server + Desktop
#
# The meta cask downloads only PKG.sha256 (a cask must download something), so it records that file's checksum.
set -euo pipefail
PKG="${1:?usage: render-cask.sh vaulthalla-<version>-arm64.pkg vaulthalla|vaulthalla-server}"
CASK="${2:?usage: render-cask.sh vaulthalla-<version>-arm64.pkg vaulthalla|vaulthalla-server}"
case "$CASK" in
  vaulthalla-server|vaulthalla) ;;
  *) echo "render-cask: unknown cask $CASK" >&2; exit 2 ;;
esac
[ -f "$PKG.sha256" ] || { echo "render-cask: no $(basename "$PKG").sha256 beside the package" >&2; exit 1; }
name="$(basename "$PKG")"
version="${name#vaulthalla-}"; version="${version%-arm64.pkg}"
sha="$(shasum -a 256 "$PKG" | cut -d' ' -f1)"
[ "$(cut -d' ' -f1 "$PKG.sha256")" = "$sha" ] || { echo "render-cask: $name.sha256 doesn't match the package" >&2; exit 1; }
sha_file="$(shasum -a 256 "$PKG.sha256" | cut -d' ' -f1)"
sed -e "s/@VERSION@/$version/g" -e "s/@SHA256@/$sha/g" -e "s/@SHA256_FILE_SHA256@/$sha_file/g" \
  "$(dirname "$0")/homebrew/$CASK.rb.in"
