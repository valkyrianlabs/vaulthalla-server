#!/bin/bash
# Publishes the macOS package to Apthalla's raw repository (release.yml's macos-publish-pkg job), beside the APT
# repository; pkg.vaulthalla.sh serves it:
#
#   tools/macos/pkg/publish-pkg.sh DIR       # DIR holds vaulthalla-<version>-arm64.pkg and its .sha256
#
# Environment: RELEASE_PUBLISH_MODE (only `nexus`, vl-release's shared publish switch, publishes; anything else skips
# with a notice, like vlr publish-deb), PKG_REPO_URL (the raw repository's base URL, default Apthalla on the VPS
# loopback), NEXUS_USER, NEXUS_PASSWORD (the Apthalla login; the secrets keep their old names for now). Uploads to
# <repo>/vaulthalla/<version>/<file> with an X-Checksum-SHA256 header that Apthalla verifies. Released bytes are
# immutable: a file already there with the same sha256 is left as it is, a different one is refused (a re-run never
# replaces a published release; Apthalla itself answers 409 to a PUT of different bytes). Every upload is read back
# and checked. Credentials go to curl through a private netrc file, never on a command line.
set -euo pipefail

DIR="${1:?usage: publish-pkg.sh DIR}"
die() { echo "::error::publish-pkg: $*" >&2; exit 1; }

if [ "${RELEASE_PUBLISH_MODE:-disabled}" != nexus ]; then
  echo "::notice::publish-pkg: RELEASE_PUBLISH_MODE is '${RELEASE_PUBLISH_MODE:-disabled}', not 'nexus': not publishing"
  exit 0
fi
PKG_REPO_URL="${PKG_REPO_URL:-http://127.0.0.1:8090/repository/valkyrian-raw}"
[ -n "${NEXUS_USER:-}" ] && [ -n "${NEXUS_PASSWORD:-}" ] || die "NEXUS_USER/NEXUS_PASSWORD are not set"

shopt -s nullglob
pkgs=("$DIR"/vaulthalla-*-arm64.pkg)
shopt -u nullglob
[ "${#pkgs[@]}" -gt 0 ] || die "no vaulthalla-<version>-arm64.pkg in $DIR"
pkg=${pkgs[0]}
name=$(basename "$pkg")
version=${name#vaulthalla-}; version=${version%-arm64.pkg}
[ -f "$pkg.sha256" ] || die "$name.sha256 is missing"
want=$(cut -d' ' -f1 "$pkg.sha256")
[ "$(sha256sum "$pkg" | cut -d' ' -f1)" = "$want" ] || die "$name doesn't match its .sha256"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
host=$(printf '%s' "$PKG_REPO_URL" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')
( umask 077; printf 'machine %s login %s password %s\n' "$host" "$NEXUS_USER" "$NEXUS_PASSWORD" > "$work/netrc" )
base="${PKG_REPO_URL%/}/vaulthalla/$version"

publish() {  # publish FILE: upload unless the identical bytes are already there
  local file="$1" url code have sum
  url="$base/$(basename "$file")"
  sum=$(sha256sum "$file" | cut -d' ' -f1)
  code=$(curl -sS --netrc-file "$work/netrc" -o "$work/existing" -w '%{http_code}' "$url" || true)
  if [ "$code" = 200 ]; then
    have=$(sha256sum "$work/existing" | cut -d' ' -f1)
    if [ "$have" = "$sum" ]; then echo "already published: $url"; return 0; fi
    die "$url is already published with different bytes; a release is never replaced"
  fi
  code=$(curl -sS --netrc-file "$work/netrc" -H "X-Checksum-SHA256: $sum" --upload-file "$file" \
    -o "$work/put" -w '%{http_code}' "$url" || true)
  case "$code" in
    200|201) ;;
    409) die "$url is already published with different bytes; a release is never replaced" ;;
    *) die "upload of $url failed (HTTP $code)" ;;
  esac
  curl -fsS --netrc-file "$work/netrc" -o "$work/readback" "$url" || die "$url can't be read back"
  cmp -s "$work/readback" "$file" || die "$url reads back different bytes"
  echo "published: $url"
}

publish "$pkg"
publish "$pkg.sha256"
