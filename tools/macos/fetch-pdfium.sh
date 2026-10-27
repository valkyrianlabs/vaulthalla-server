#!/bin/bash
# Installs a pinned PDFium SDK for macOS (Apple Silicon) into a prefix, with a pkg-config file.
#
#   tools/macos/fetch-pdfium.sh <prefix>
#
# Linux builds take PDFium from apt.valkyrianlabs.com (libpdfium-dev, Chromium-tracking). On macOS the source is a pinned
# bblanchon/pdfium-binaries release, verified by SHA-256 before anything is unpacked. Nothing from the download is
# executed. The result:
#   <prefix>/lib/libpdfium.dylib          install name = its absolute path, so a Meson-built binary finds it
#   <prefix>/include/pdfium/...           fpdfview.h, cpp/fpdf_scopers.h, ...
#   <prefix>/lib/pkgconfig/pdfium.pc      Version <milestone>.<branch>.<patch> like the Linux SDK (core/meson.build
#                                         requires pdfium >=155.8059,<1000)
# Idempotent: a matching install (same tag and checksum) is left alone. Bash 3.2 compatible (macOS /bin/bash).
set -euo pipefail

# Pin. To bump: pick a chromium/<branch> tag (gh release list -R bblanchon/pdfium-binaries), take the asset digest
# (gh release view chromium/<branch> -R bblanchon/pdfium-binaries --json assets), update all four values.
PDFIUM_TAG="chromium/8066"
PDFIUM_CHROMIUM_VERSION="156.0.8066.0"
PDFIUM_ASSET="pdfium-mac-arm64.tgz"
PDFIUM_SHA256="336219e80580b93c6523f44db7dc1de59cc497b13a7390ddac84223f68ca162b"

die() { printf 'fetch-pdfium: error: %s\n' "$*" >&2; exit 1; }
log() { printf 'fetch-pdfium: %s\n' "$*"; }

[ $# -eq 1 ] && [ -n "$1" ] || die "usage: $0 <prefix>"
[ "$(uname -s)" = Darwin ] || die "macOS only (Linux builds use libpdfium-dev from apt.valkyrianlabs.com)"
[ "$(uname -m)" = arm64 ] || die "only the mac-arm64 build is pinned (this host is $(uname -m))"
for tool in curl tar shasum install_name_tool codesign; do
  command -v "$tool" >/dev/null 2>&1 || die "missing tool: $tool"
done

# <milestone>.<branch>.<patch> from <milestone>.0.<branch>.<patch>, the Linux SDK's version shape.
milestone="${PDFIUM_CHROMIUM_VERSION%%.*}"
branch_patch="${PDFIUM_CHROMIUM_VERSION#*.*.}"
PC_VERSION="${milestone}.${branch_patch}"
STAMP_VALUE="${PDFIUM_TAG} ${PDFIUM_ASSET} ${PDFIUM_SHA256}"

mkdir -p "$1"
PREFIX="$(cd "$1" && pwd -P)"
LIB="$PREFIX/lib/libpdfium.dylib"
PC="$PREFIX/lib/pkgconfig/pdfium.pc"
STAMP="$PREFIX/share/pdfium-binaries/STAMP"

if [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$STAMP_VALUE" ] && [ -f "$LIB" ] && [ -f "$PC" ] \
   && [ -f "$PREFIX/include/pdfium/fpdfview.h" ]; then
  log "PDFium $PC_VERSION ($PDFIUM_TAG) already installed in $PREFIX"
  exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/vh-pdfium.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/dl" "$WORK/x"

url="https://github.com/bblanchon/pdfium-binaries/releases/download/${PDFIUM_TAG}/${PDFIUM_ASSET}"
log "downloading $url"
curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$WORK/dl/$PDFIUM_ASSET" "$url"

actual="$(shasum -a 256 "$WORK/dl/$PDFIUM_ASSET" | awk '{print $1}')"
[ "$actual" = "$PDFIUM_SHA256" ] || die "checksum mismatch for $PDFIUM_ASSET: expected $PDFIUM_SHA256, got $actual"
log "sha256 ok: $actual"

# Refuse absolute or parent-relative member names before unpacking.
if tar -tzf "$WORK/dl/$PDFIUM_ASSET" | grep -Eq '^/|(^|/)\.\.(/|$)'; then
  die "archive contains unsafe paths"
fi
tar -xzf "$WORK/dl/$PDFIUM_ASSET" -C "$WORK/x"
[ -f "$WORK/x/lib/libpdfium.dylib" ] || die "archive has no lib/libpdfium.dylib"
[ -f "$WORK/x/include/fpdfview.h" ] || die "archive has no include/fpdfview.h"
grep -q "^BUILD=${branch_patch%%.*}\$" "$WORK/x/VERSION" 2>/dev/null \
  || die "archive VERSION does not match the pin ($PDFIUM_CHROMIUM_VERSION)"

# Absolute install name: a Meson-built executable records it and loads the library without an rpath.
dylib="$WORK/x/lib/libpdfium.dylib"
chmod u+w "$dylib"
install_name_tool -id "$LIB" "$dylib"
codesign --force --sign - "$dylib" >/dev/null 2>&1 || die "ad-hoc re-signing of libpdfium.dylib failed"

mkdir -p "$PREFIX/lib/pkgconfig" "$PREFIX/include" "$PREFIX/share/pdfium-binaries"
rm -f "$STAMP"
rm -rf "$PREFIX/include/pdfium"
cp -R "$WORK/x/include" "$PREFIX/include/pdfium"
cp "$dylib" "$LIB.tmp" && mv -f "$LIB.tmp" "$LIB"
for f in LICENSE VERSION args.gn; do
  [ -f "$WORK/x/$f" ] && cp "$WORK/x/$f" "$PREFIX/share/pdfium-binaries/$f"
done

cat > "$PC.tmp" <<EOF
prefix=$PREFIX
libdir=\${prefix}/lib
includedir=\${prefix}/include/pdfium

Name: pdfium
Description: PDFium ($PDFIUM_TAG, bblanchon/pdfium-binaries $PDFIUM_ASSET)
URL: https://github.com/bblanchon/pdfium-binaries
Version: $PC_VERSION
Libs: -L\${libdir} -lpdfium
Cflags: -I\${includedir}
EOF
mv -f "$PC.tmp" "$PC"
printf '%s\n' "$STAMP_VALUE" > "$STAMP"
log "installed PDFium $PC_VERSION ($PDFIUM_TAG) into $PREFIX"
