#!/bin/bash
# darwin_private_dylibs.sh PREFIX HOME_DIR: make an installed macOS build load nothing from under HOME_DIR.
#
# A source build links the PDFium SDK from ~/.cache/vaulthalla-macos-deps (tools/macos/bootstrap.sh). The LaunchDaemons
# run as a role account that can't read a 0750 home directory, so dyld would fail at launch. Every Mach-O under
# PREFIX/bin and PREFIX/lib/vaulthalla that references a dylib under HOME_DIR gets a private copy of it in
# PREFIX/lib/vaulthalla (install name = that path), its load command repointed, rpaths into HOME_DIR removed, and an
# ad-hoc signature again (arm64 refuses to run an unsigned or stale-signed binary). Idempotent; VH_DRY_RUN=1 prints.
# Bash 3.2 compatible.
set -euo pipefail

PREFIX="${1:?usage: darwin_private_dylibs.sh PREFIX HOME_DIR}"
HOME_DIR="${2:?usage: darwin_private_dylibs.sh PREFIX HOME_DIR}"
HOME_DIR="${HOME_DIR%/}"
LIBDIR="$PREFIX/lib/vaulthalla"

# shellcheck source=bin/lib/platform.sh
source "$(cd "$(dirname "$0")" && pwd -P)/platform.sh"

is_macho() { file -b "$1" 2>/dev/null | grep -q '^Mach-O'; }

home_deps() {  # the load commands of $1 that point under HOME_DIR
  otool -L "$1" | tail -n +2 | awk '{print $1}' | while IFS= read -r dep; do
    case "$dep" in
      "$LIBDIR"/*) ;;  # already private (also a dylib's own id line)
      "$HOME_DIR"/*) printf '%s\n' "$dep" ;;
    esac
  done
}

home_rpaths() {
  otool -l "$1" | awk '$1 == "cmd" && $2 == "LC_RPATH" {r = 1; next} r && $1 == "path" {print $2; r = 0}' \
    | while IFS= read -r rp; do
        case "$rp" in "$HOME_DIR"/*) printf '%s\n' "$rp" ;; esac
      done
}

if vh_dry_run && [ ! -d "$PREFIX" ]; then
  echo "[dry-run] would repoint dylibs under $HOME_DIR in $PREFIX/bin and $LIBDIR (nothing installed yet)"
  exit 0
fi

find "$PREFIX/bin" "$LIBDIR" -type f -perm -u+x 2>/dev/null | while IFS= read -r bin; do
  is_macho "$bin" || continue
  touched=false
  for dep in $(home_deps "$bin"); do
    private="$LIBDIR/$(basename "$dep")"
    if [ ! -f "$private" ] || ! cmp -s "$dep" "$private"; then
      vh_priv install -d -m 0755 "$LIBDIR"
      vh_priv install -m 0755 "$dep" "$private"
      vh_priv install_name_tool -id "$private" "$private"
      vh_priv codesign -f -s - "$private"
    fi
    vh_priv install_name_tool -change "$dep" "$private" "$bin"
    touched=true
  done
  for rp in $(home_rpaths "$bin"); do
    vh_priv install_name_tool -delete_rpath "$rp" "$bin"
    touched=true
  done
  if [ "$touched" = true ]; then
    vh_priv codesign -f -s - "$bin"
    echo "🔧 $bin no longer loads anything from $HOME_DIR"
  fi
done
echo "✅ installed binaries load no dylib from $HOME_DIR"
