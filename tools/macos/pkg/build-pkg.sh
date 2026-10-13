#!/bin/bash
# Builds the macOS installer package from a staged install (tools/macos/candidate.sh stage, or any DESTDIR of
# `meson install` with the web console, Node runtime and pdfium added the same way):
#
#   tools/macos/pkg/build-pkg.sh STAGE OUTDIR      # -> OUTDIR/vaulthalla-<version>-arm64.pkg (+ .sha256)
#
# The package is self-contained: the bundled PostgreSQL (build-postgres.sh), Caddy with the Cloudflare DNS module for
# `vh setup caddy` (build-caddy.sh), and every non-system library the binaries
# load (bundle_dylibs.py, into /usr/local/lib/vaulthalla) ship inside it, so a Mac without Homebrew runs it. Its
# preinstall stops running services; its postinstall provisions (vaulthalla-provision --apply --enroll <console user>).
#
# Signing (optional; unsigned packages install with `sudo installer` and Homebrew, Installer.app warns):
#   VH_PKG_CODESIGN_IDENTITY   "Developer ID Application: ..." for the binaries (hardened runtime)
#   VH_PKG_INSTALLER_IDENTITY  "Developer ID Installer: ..." for the package
#   VH_PKG_NOTARY_PROFILE      a `xcrun notarytool store-credentials` profile: notarize and staple
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd -P)"
REPO="$(cd "$HERE/../../.." && pwd -P)"
STAGE="${1:?usage: build-pkg.sh STAGE OUTDIR}"
OUT="${2:?usage: build-pkg.sh STAGE OUTDIR}"
VERSION="$(tr -d '[:space:]' < "$REPO/VERSION")"
ID=sh.vaulthalla.server
NAME="vaulthalla-$VERSION-arm64.pkg"

log() { printf 'build-pkg: %s\n' "$*" >&2; }
die() { printf 'build-pkg: error: %s\n' "$*" >&2; exit 1; }

[ -x "$STAGE/usr/local/bin/vaulthalla-server" ] || die "$STAGE has no usr/local/bin/vaulthalla-server"
[ -f "$STAGE/usr/local/share/vaulthalla-web/server.js" ] || die "$STAGE has no web console"
[ -x "$STAGE/usr/local/libexec/vaulthalla/node/bin/node" ] || die "$STAGE has no Node runtime"
[ -f "$STAGE/usr/local/share/vaulthalla/magic.mgc" ] || die "$STAGE has no libmagic database"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/vh-pkg.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
ROOT="$WORK/root"
ditto "$STAGE" "$ROOT"
"$HERE/build-postgres.sh" "$ROOT"
"$HERE/build-caddy.sh" "$ROOT"
python3 "$HERE/bundle_dylibs.py" "$ROOT"

# Nothing in the payload may point into Homebrew or the build tree.
leaks=$(find "$ROOT/usr/local/bin" "$ROOT/usr/local/lib/vaulthalla" "$ROOT/usr/local/libexec/vaulthalla/postgresql" \
  -type f -exec otool -L {} + 2>/dev/null | awk '/^\t/ {print $1}' | grep -E '^/(opt/homebrew|usr/local/(Cellar|opt))|/private/|/Users/' | sort -u || true)
[ -z "$leaks" ] || die "payload still links outside the install: $leaks"

# Notarization needs every Mach-O signed with the hardened runtime; Node's official binary already is (OpenJS).
if [ -n "${VH_PKG_CODESIGN_IDENTITY:-}" ]; then
  find "$ROOT" -type f ! -path '*/libexec/vaulthalla/node/bin/node' -print0 | while IFS= read -r -d '' f; do
    case "$(head -c 4 "$f" | xxd -p)" in
      cffaedfe|cafebabe) codesign -f -s "$VH_PKG_CODESIGN_IDENTITY" --options runtime --timestamp "$f" >/dev/null ;;
    esac
  done
fi

# Root owns everything; nothing group/world-writable.
chmod -R go-w "$ROOT"
pkgbuild --analyze --root "$ROOT" "$WORK/component.plist" >/dev/null
/usr/libexec/PlistBuddy -c "Print" "$WORK/component.plist" >/dev/null 2>&1 && {
  n=$(/usr/libexec/PlistBuddy -c "Print" "$WORK/component.plist" | grep -c BundleIsRelocatable || true)
  for ((i = 0; i < n; i++)); do /usr/libexec/PlistBuddy -c "Set :$i:BundleIsRelocatable false" "$WORK/component.plist"; done
}
pkgbuild --root "$ROOT" --component-plist "$WORK/component.plist" --identifier "$ID" --version "$VERSION" \
  --install-location / --scripts "$HERE/scripts" --ownership recommended "$WORK/component.pkg" >/dev/null
sed "s/@VERSION@/$VERSION/g" "$HERE/distribution.xml.in" > "$WORK/distribution.xml"
mkdir -p "$OUT"
productbuild --distribution "$WORK/distribution.xml" --package-path "$WORK" "$WORK/unsigned.pkg" >/dev/null

if [ -n "${VH_PKG_INSTALLER_IDENTITY:-}" ]; then
  productsign --sign "$VH_PKG_INSTALLER_IDENTITY" --timestamp "$WORK/unsigned.pkg" "$OUT/$NAME"
else
  mv "$WORK/unsigned.pkg" "$OUT/$NAME"
  log "unsigned (set VH_PKG_INSTALLER_IDENTITY to sign)"
fi
if [ -n "${VH_PKG_NOTARY_PROFILE:-}" ]; then
  xcrun notarytool submit "$OUT/$NAME" --keychain-profile "$VH_PKG_NOTARY_PROFILE" --wait
  xcrun stapler staple "$OUT/$NAME"
fi
(cd "$OUT" && shasum -a 256 "$NAME" > "$NAME.sha256")
log "$OUT/$NAME ($(du -h "$OUT/$NAME" | cut -f1), sha256 $(cut -d' ' -f1 "$OUT/$NAME.sha256"))"
