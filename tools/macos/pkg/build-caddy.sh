#!/bin/bash
# Caddy for the macOS package (`vh setup caddy`), built with the Cloudflare DNS module: Homebrew's caddy has no DNS
# providers, and DNS-01 is how a Mac that isn't reachable from the internet gets a public certificate.
#
#   tools/macos/pkg/build-caddy.sh DESTDIR     # installs DESTDIR/usr/local/libexec/vaulthalla/caddy/caddy
#
# Pinned versions, built with xcaddy; Go verifies every module against its checksum database (GOSUMDB), so the build is
# reproducible from these pins. Static (CGO off): it links nothing outside the OS. Cached per version in VH_PKG_CACHE
# (default ~/.cache/vaulthalla-macos-pkg). Needs Go (brew install go; the macOS runners have it). Bash 3.2 compatible.
set -euo pipefail

CADDY_VERSION=v2.11.7
CLOUDFLARE_VERSION=v0.2.4
XCADDY_VERSION=v0.4.7
PREFIX=/usr/local/libexec/vaulthalla/caddy

DEST="${1:?usage: build-caddy.sh DESTDIR}"
CACHE="${VH_PKG_CACHE:-$HOME/.cache/vaulthalla-macos-pkg}"
OUT="$CACHE/caddy-$CADDY_VERSION-cloudflare-$CLOUDFLARE_VERSION-darwin-arm64"

log() { printf 'build-caddy: %s\n' "$*" >&2; }
die() { printf 'build-caddy: error: %s\n' "$*" >&2; exit 1; }

if [ ! -x "$OUT" ]; then
  command -v go >/dev/null || die "Go is not installed (brew install go)"
  mkdir -p "$CACHE/bin"
  # Go's caches inside this one: nothing else on the machine is written, and a cache cleanup removes them too.
  export GOPATH="$CACHE/go" GOCACHE="$CACHE/go/build-cache" GOMODCACHE="$CACHE/go/pkg/mod" GOTOOLCHAIN=local
  GOBIN="$CACHE/bin" GOFLAGS=-mod=mod go install "github.com/caddyserver/xcaddy/cmd/xcaddy@$XCADDY_VERSION" \
    > "$CACHE/caddy-build.log" 2>&1 || { tail -20 "$CACHE/caddy-build.log" >&2; die "xcaddy install failed"; }
  log "building Caddy $CADDY_VERSION with caddy-dns/cloudflare $CLOUDFLARE_VERSION (log: $CACHE/caddy-build.log)"
  CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 "$CACHE/bin/xcaddy" build "$CADDY_VERSION" \
    --with "github.com/caddy-dns/cloudflare@$CLOUDFLARE_VERSION" --output "$OUT.part" \
    >> "$CACHE/caddy-build.log" 2>&1 || { tail -20 "$CACHE/caddy-build.log" >&2; die "xcaddy build failed"; }
  mv "$OUT.part" "$OUT"
fi

"$OUT" list-modules 2>/dev/null | grep -qx 'dns.providers.cloudflare' || die "the built Caddy has no Cloudflare DNS module"
"$OUT" version | grep -q "^${CADDY_VERSION}" || die "the built Caddy isn't $CADDY_VERSION"
bad=$(otool -L "$OUT" | awk '/^\t/ {print $1}' | grep -vE '^(/usr/lib/|/System/)' || true)
[ -z "$bad" ] || die "the built Caddy links outside the OS: $bad"

mkdir -p "$DEST$PREFIX"
install -m 0755 "$OUT" "$DEST$PREFIX/caddy"
log "Caddy $CADDY_VERSION (+cloudflare $CLOUDFLARE_VERSION) -> $DEST$PREFIX/caddy"
