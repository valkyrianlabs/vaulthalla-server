#!/bin/bash
# Renders the Homebrew cask for a built package: tools/macos/pkg/render-cask.sh PKG > vaulthalla.rb
set -euo pipefail
PKG="${1:?usage: render-cask.sh vaulthalla-<version>-arm64.pkg}"
name="$(basename "$PKG")"
version="${name#vaulthalla-}"; version="${version%-arm64.pkg}"
sha="$(shasum -a 256 "$PKG" | cut -d' ' -f1)"
sed -e "s/@VERSION@/$version/g" -e "s/@SHA256@/$sha/g" "$(dirname "$0")/homebrew/vaulthalla.rb.in"
