#!/bin/bash
# Fetches the Vaulthalla Desktop app the package bundles (build-pkg.sh VH_PKG_DESKTOP_APP):
#
#   tools/macos/pkg/fetch-desktop.sh DIR [TAG]     # -> DIR/Vaulthalla.app; TAG defaults to the latest release
#
# Downloads Vaulthalla-<version>.dmg from valkyrianlabs/vaulthalla-desktop's GitHub release (gh, with GH_TOKEN in CI)
# and refuses it unless it matches its .sha256, Gatekeeper accepts it as notarized Developer ID, and the app inside is
# sh.vaulthalla.app signed by the Valkyrian Labs LLC team. Prints the app's path.
set -euo pipefail

DIR="${1:?usage: fetch-desktop.sh DIR [TAG]}"
TAG="${2:-}"
REPO=valkyrianlabs/vaulthalla-desktop
TEAM=ZG2G6V7GLC

die() { printf 'fetch-desktop: error: %s\n' "$*" >&2; exit 1; }
log() { printf 'fetch-desktop: %s\n' "$*" >&2; }

mkdir -p "$DIR"
work="$(mktemp -d "${TMPDIR:-/tmp}/vh-desktop.XXXXXX")"
mount=""
cleanup() { [ -z "$mount" ] || hdiutil detach -quiet "$mount" || true; rm -rf "$work"; }
trap cleanup EXIT

# shellcheck disable=SC2086  # an empty TAG means the latest release
gh release download $TAG -R "$REPO" -p 'Vaulthalla-*.dmg' -p 'Vaulthalla-*.dmg.sha256' -D "$work"
dmg=$(ls "$work"/Vaulthalla-*.dmg)
(cd "$work" && shasum -a 256 -c "$(basename "$dmg").sha256" >/dev/null) || die "$(basename "$dmg") doesn't match its .sha256"
assessment=$(spctl --assess --type open --context context:primary-signature -v "$dmg" 2>&1) ||
  die "Gatekeeper rejects $(basename "$dmg"): $assessment"
[[ $assessment == *"source=Notarized Developer ID"* ]] || die "$(basename "$dmg") isn't notarized: $assessment"

mount="$work/mnt"
mkdir -p "$mount"
hdiutil attach -quiet -nobrowse -readonly -mountpoint "$mount" "$dmg"
app="$mount/Vaulthalla.app"
[ -d "$app" ] || die "no Vaulthalla.app in $(basename "$dmg")"
[ "$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$app/Contents/Info.plist")" = sh.vaulthalla.app ] ||
  die "the app in $(basename "$dmg") is not sh.vaulthalla.app"
codesign --verify --deep --strict "$app" || die "the app's signature does not verify"
details=$(codesign -dv "$app" 2>&1)
[[ $details == *"TeamIdentifier=$TEAM"* ]] || die "the app is not signed by team $TEAM"
assessment=$(spctl --assess --type execute -v "$app" 2>&1) || die "Gatekeeper rejects the app: $assessment"
xcrun stapler validate -q "$app" || die "the app has no stapled notarization ticket"

rm -rf "${DIR:?}/Vaulthalla.app"
ditto "$app" "$DIR/Vaulthalla.app"
log "Vaulthalla Desktop $(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$DIR/Vaulthalla.app/Contents/Info.plist") from $(basename "$dmg")"
echo "$DIR/Vaulthalla.app"
