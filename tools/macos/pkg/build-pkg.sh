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
# Vaulthalla Desktop (optional): VH_PKG_DESKTOP_APP names a signed, notarized Vaulthalla.app (fetch-desktop.sh) to add
# as a second component, sh.vaulthalla.desktop in /Applications, behind an Installer choice that is off by default.
# The `vaulthalla` cask turns it on; `vaulthalla-server` and `sudo installer -pkg` leave it off. The component is
# version-checked, so a newer app (Sparkle updates it in place) is never replaced. The app keeps its own signature.
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
# Already in the stage when CI built them in an earlier job (release.yml macos-build); built here otherwise.
[ -x "$ROOT/usr/local/libexec/vaulthalla/postgresql/bin/postgres" ] || "$HERE/build-postgres.sh" "$ROOT"
[ -x "$ROOT/usr/local/libexec/vaulthalla/caddy/caddy" ] || "$HERE/build-caddy.sh" "$ROOT"
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

# Root owns everything; everything readable (the daemons run as _vaulthalla, the CLI as anyone), nothing
# group/world-writable. Nothing secret is in the payload: secrets are generated at install time.
chmod -R u+rwX,go+rX,go-w "$ROOT"
pkgbuild --analyze --root "$ROOT" "$WORK/component.plist" >/dev/null
/usr/libexec/PlistBuddy -c "Print" "$WORK/component.plist" >/dev/null 2>&1 && {
  n=$(/usr/libexec/PlistBuddy -c "Print" "$WORK/component.plist" | grep -c BundleIsRelocatable || true)
  for ((i = 0; i < n; i++)); do /usr/libexec/PlistBuddy -c "Set :$i:BundleIsRelocatable false" "$WORK/component.plist"; done
}
pkgbuild --root "$ROOT" --component-plist "$WORK/component.plist" --identifier "$ID" --version "$VERSION" \
  --install-location / --scripts "$HERE/scripts" --ownership recommended "$WORK/component.pkg" >/dev/null

desktop_outline=""
desktop_choice=""
if [ -n "${VH_PKG_DESKTOP_APP:-}" ]; then
  app="${VH_PKG_DESKTOP_APP%/}"
  [ "$(basename "$app")" = Vaulthalla.app ] || die "VH_PKG_DESKTOP_APP must be a Vaulthalla.app ($app)"
  [ "$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$app/Contents/Info.plist")" = sh.vaulthalla.app ] ||
    die "$app is not sh.vaulthalla.app"
  codesign --verify --deep --strict "$app" || die "$app's signature does not verify"
  desktop_version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$app/Contents/Info.plist")
  mkdir -p "$WORK/desktop-root"
  ditto "$app" "$WORK/desktop-root/Vaulthalla.app"
  pkgbuild --analyze --root "$WORK/desktop-root" "$WORK/desktop.plist" >/dev/null
  # Never relocated to wherever another copy lives, never downgraded: Installer skips the bundle when the installed
  # one has a newer version.
  python3 -I - "$WORK/desktop.plist" <<'PY'
import plistlib, sys
path = sys.argv[1]
with open(path, "rb") as f:
    bundles = plistlib.load(f)
app = [b for b in bundles if b["RootRelativeBundlePath"] == "Vaulthalla.app"]
assert len(app) == 1, "no Vaulthalla.app in the component plist"
for bundle in bundles:  # the app and everything nested in it
    bundle["BundleIsRelocatable"] = False
app[0].update(BundleIsVersionChecked=True, BundleHasStrictIdentifier=True, BundleOverwriteAction="upgrade")
with open(path, "wb") as f:
    plistlib.dump(bundles, f)
PY
  pkgbuild --root "$WORK/desktop-root" --component-plist "$WORK/desktop.plist" --identifier sh.vaulthalla.desktop \
    --version "$desktop_version" --install-location /Applications "$WORK/desktop.pkg" >/dev/null
  desktop_outline='        <line choice="sh.vaulthalla.desktop"/>'
  desktop_choice=$(sed "s/@DESKTOP_VERSION@/$desktop_version/g" "$HERE/distribution-desktop.xml.in")
  log "with Vaulthalla Desktop $desktop_version (choice sh.vaulthalla.desktop, off by default)"
fi
DESKTOP_OUTLINE="$desktop_outline" DESKTOP_CHOICE="$desktop_choice" python3 -c '
import os, sys
text = open(sys.argv[1]).read().replace("@VERSION@", sys.argv[2])
for key in ("DESKTOP_OUTLINE", "DESKTOP_CHOICE"):
    value = os.environ[key]
    text = text.replace("@" + key + "@\n", value + "\n" if value else "")
sys.stdout.write(text)
' "$HERE/distribution.xml.in" "$VERSION" > "$WORK/distribution.xml"
xmllint --noout "$WORK/distribution.xml" || die "distribution.xml is not well-formed"
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
  # What a downloaded package gets: Gatekeeper accepts it as notarized Developer ID.
  pkgutil --check-signature "$OUT/$NAME"
  spctl --assess --type install --verbose=2 "$OUT/$NAME"
fi
(cd "$OUT" && shasum -a 256 "$NAME" > "$NAME.sha256")
log "$OUT/$NAME ($(du -h "$OUT/$NAME" | cut -f1), sha256 $(cut -d' ' -f1 "$OUT/$NAME.sha256"))"
