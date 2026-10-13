#!/bin/bash
# PostgreSQL for the macOS package: built from the verified upstream source with its final prefix compiled in, so the
# installed server finds its share/ and lib/ without Homebrew (Homebrew's keg isn't relocatable: its compiled-in
# share dir is /opt/homebrew/opt/postgresql@16/...). Only system libraries: no ICU (clusters use the C locale and
# libc collations), no readline (psql is for the operator's occasional use), no OpenSSL (the cluster listens on
# 127.0.0.1 and a private socket only).
#
#   tools/macos/pkg/build-postgres.sh DESTDIR     # installs into DESTDIR/usr/local/libexec/vaulthalla/postgresql
#
# The build is cached in VH_PKG_CACHE (default ~/.cache/vaulthalla-macos-pkg) per version; the pinned sha256 is the
# one postgresql.org publishes beside the tarball. Bash 3.2 compatible.
set -euo pipefail

PG_VERSION=16.15
PG_SHA256=c1575341fa7bd40f5274ea465b34390f4dc64cdd0770af327005caaeb9f6b7ed
PREFIX=/usr/local/libexec/vaulthalla/postgresql

DEST="${1:?usage: build-postgres.sh DESTDIR}"
CACHE="${VH_PKG_CACHE:-$HOME/.cache/vaulthalla-macos-pkg}"
SRC="$CACHE/postgresql-$PG_VERSION"
BUILT="$CACHE/postgresql-$PG_VERSION-root"
TARBALL="$CACHE/postgresql-$PG_VERSION.tar.bz2"

log() { printf 'build-postgres: %s\n' "$*" >&2; }
die() { printf 'build-postgres: error: %s\n' "$*" >&2; exit 1; }

mkdir -p "$CACHE"
if [ ! -x "$BUILT$PREFIX/bin/postgres" ]; then
  if [ ! -f "$TARBALL" ]; then
    curl -fsSL -o "$TARBALL.part" "https://ftp.postgresql.org/pub/source/v$PG_VERSION/postgresql-$PG_VERSION.tar.bz2"
    mv "$TARBALL.part" "$TARBALL"
  fi
  echo "$PG_SHA256  $TARBALL" | shasum -a 256 -c - >/dev/null || { rm -f "$TARBALL"; die "checksum mismatch"; }
  rm -rf "$SRC" "$BUILT" && tar -xjf "$TARBALL" -C "$CACHE"
  log "configuring $PG_VERSION (log: $CACHE/postgresql-build.log)"
  (
    cd "$SRC"
    # Homebrew's environment must not leak in: only the SDK's libraries may be linked.
    env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$HOME" \
      ./configure --prefix="$PREFIX" --without-icu --without-readline --with-zlib \
      MACOSX_DEPLOYMENT_TARGET=14.0
    env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$HOME" make -j"$(sysctl -n hw.ncpu)" world-bin
    env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$HOME" make install-world-bin DESTDIR="$BUILT"
  ) > "$CACHE/postgresql-build.log" 2>&1 || { tail -30 "$CACHE/postgresql-build.log" >&2; die "build failed"; }
  rm -rf "$BUILT$PREFIX/include" "$BUILT$PREFIX"/lib/*.a "$BUILT$PREFIX/lib/pgxs"
fi

# Nothing outside the OS may be linked.
bad=$(find "$BUILT$PREFIX" -type f \( -perm -u+x -o -name '*.dylib' \) -exec otool -L {} + 2>/dev/null \
  | awk '/^\t/ {print $1}' | grep -vE "^(/usr/lib/|/System/|$PREFIX/|@)" | sort -u || true)
[ -z "$bad" ] || die "non-system libraries linked: $bad"

mkdir -p "$DEST$PREFIX"
ditto "$BUILT$PREFIX" "$DEST$PREFIX"
log "PostgreSQL $PG_VERSION -> $DEST$PREFIX"
