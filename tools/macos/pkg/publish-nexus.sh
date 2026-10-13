#!/bin/bash
# Publishes the macOS package to the Nexus raw repository (release.yml's macos-publish job), beside the APT repository:
#
#   tools/macos/pkg/publish-nexus.sh DIR       # DIR holds vaulthalla-<version>-arm64.pkg and its .sha256
#
# Environment: RELEASE_PUBLISH_MODE (only `nexus` publishes; anything else skips with a notice, like vlr publish-deb),
# NEXUS_PKG_REPO (the raw repository's base URL), NEXUS_USER, NEXUS_PASSWORD. Uploads to
# <repo>/vaulthalla/<version>/<file>. Released bytes are immutable: a file already there with the same sha256 is left as
# it is, a different one is refused (a re-run never replaces a published release). Every upload is read back and checked.
# Credentials go to curl through a private netrc file, never on a command line.
set -euo pipefail

DIR="${1:?usage: publish-nexus.sh DIR}"
die() { echo "::error::publish-nexus: $*" >&2; exit 1; }

if [ "${RELEASE_PUBLISH_MODE:-disabled}" != nexus ]; then
  echo "::notice::publish-nexus: RELEASE_PUBLISH_MODE is '${RELEASE_PUBLISH_MODE:-disabled}', not 'nexus': not publishing"
  exit 0
fi
[ -n "${NEXUS_PKG_REPO:-}" ] || die "NEXUS_PKG_REPO is not set"
[ -n "${NEXUS_USER:-}" ] && [ -n "${NEXUS_PASSWORD:-}" ] || die "NEXUS_USER/NEXUS_PASSWORD are not set"

pkg=$(ls "$DIR"/vaulthalla-*-arm64.pkg 2>/dev/null | head -1)
[ -n "$pkg" ] || die "no vaulthalla-<version>-arm64.pkg in $DIR"
name=$(basename "$pkg")
version=${name#vaulthalla-}; version=${version%-arm64.pkg}
[ -f "$pkg.sha256" ] || die "$name.sha256 is missing"
want=$(cut -d' ' -f1 "$pkg.sha256")
[ "$(sha256sum "$pkg" | cut -d' ' -f1)" = "$want" ] || die "$name doesn't match its .sha256"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
host=$(printf '%s' "$NEXUS_PKG_REPO" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')
( umask 077; printf 'machine %s login %s password %s\n' "$host" "$NEXUS_USER" "$NEXUS_PASSWORD" > "$work/netrc" )
base="${NEXUS_PKG_REPO%/}/vaulthalla/$version"

publish() {  # publish FILE: upload unless the identical bytes are already there
  local file="$1" url code have
  url="$base/$(basename "$file")"
  code=$(curl -sS --netrc-file "$work/netrc" -o "$work/existing" -w '%{http_code}' "$url" || true)
  if [ "$code" = 200 ]; then
    have=$(sha256sum "$work/existing" | cut -d' ' -f1)
    if [ "$have" = "$(sha256sum "$file" | cut -d' ' -f1)" ]; then echo "already published: $url"; return 0; fi
    die "$url is already published with different bytes; a release is never replaced"
  fi
  curl -fsS --netrc-file "$work/netrc" --upload-file "$file" "$url" >/dev/null || die "upload of $url failed"
  curl -fsS --netrc-file "$work/netrc" -o "$work/readback" "$url" || die "$url can't be read back"
  cmp -s "$work/readback" "$file" || die "$url reads back different bytes"
  echo "published: $url"
}

publish "$pkg"
publish "$pkg.sha256"
