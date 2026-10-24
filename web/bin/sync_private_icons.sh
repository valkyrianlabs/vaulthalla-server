#!/usr/bin/env bash
# Copies the private (licensed) icons web/src imports from the local icon store into web/public/icons.
# The store is not in the repository: $VAULTHALLA_WEB_ICON_SRC, default ~/vaulthalla-web-icons.
# Used by CI (.github/actions/sync_web_icons) and by the release web build (build_release_payload.sh).
# Bash 3.2 compatible (macOS): no associative arrays, no mapfile.
set -euo pipefail

WEB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ICON_SRC="${VAULTHALLA_WEB_ICON_SRC:-$HOME/vaulthalla-web-icons}"
ICON_DST="$WEB_DIR/public/icons"

if [[ ! -d "$WEB_DIR/src" ]]; then
  echo "[icons] web source directory not present; skipping private icon sync"
  exit 0
fi

# Import alias -> its directory under the icon store and web/public/icons (empty: unsupported).
ICON_ALIASES="fa-regular fa-light fa-duotone fa-duotone-regular fa-brands"
icon_alias_dir() {
  case "$1" in
    fa-regular) echo "fa/regular" ;;
    fa-light) echo "fa/light" ;;
    fa-duotone) echo "fa/duotone" ;;
    fa-duotone-regular) echo "fa/duotone-regular" ;;
    fa-brands) echo "fa/brands" ;;
    *) echo "" ;;
  esac
}

echo "[icons] scanning web source for consumed private icons"
# One import per line, sorted and unique; no match is not an error.
ICON_IMPORTS="$(
  { grep -RhoE "['\"]@/(fa-regular|fa-light|fa-duotone|fa-duotone-regular|fa-brands)/[^'\"]+\.svg['\"]" "$WEB_DIR/src" || true; } \
    | tr -d "'\"" \
    | sed 's#^@/##' \
    | sort -u
)"

if [[ -z "$ICON_IMPORTS" ]]; then
  echo "[icons] no private icon imports found under $WEB_DIR/src"
  exit 0
fi

if [[ ! -d "$ICON_SRC" ]]; then
  echo "[icons] ERROR: missing private icon directory: $ICON_SRC" >&2
  exit 1
fi

for alias in $ICON_ALIASES; do
  icon_dir="$(icon_alias_dir "$alias")"
  rm -rf "${ICON_DST:?}/${icon_dir:?}"
  mkdir -p "$ICON_DST/$icon_dir"
done

missing=0
copied=0
while IFS= read -r import_path; do
  alias="${import_path%%/*}"
  icon_rel="${import_path#*/}"
  icon_dir="$(icon_alias_dir "$alias")"
  if [[ -z "$icon_dir" ]]; then
    echo "[icons] ERROR: unsupported private icon alias: $alias" >&2
    missing=1
    continue
  fi
  src_file="$ICON_SRC/$icon_dir/$icon_rel"
  dst_file="$ICON_DST/$icon_dir/$icon_rel"
  if [[ ! -f "$src_file" ]]; then
    echo "[icons] ERROR: missing icon: $src_file" >&2
    missing=1
    continue
  fi
  mkdir -p "$(dirname "$dst_file")"
  cp "$src_file" "$dst_file"
  copied=$((copied + 1))
done <<<"$ICON_IMPORTS"

if [[ "$missing" -ne 0 ]]; then
  echo "[icons] ERROR: one or more consumed private icons are missing" >&2
  exit 1
fi
echo "[icons] synced $copied consumed private icon(s)"
