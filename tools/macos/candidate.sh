#!/bin/bash
# A reproducible macOS install candidate and its disposable database, for tools/macos/install-acceptance.sh.
#
#   tools/macos/candidate.sh stage        # release build of this checkout, staged as it would install under /usr/local
#   tools/macos/candidate.sh db up|down   # disposable PostgreSQL 16 cluster for the installed service (port 54331)
#   sudo tools/macos/candidate.sh accept [PHASE]   # install-acceptance.sh with the paths below (default phase: all)
#
# Everything lives in VH_CANDIDATE_DIR (default ~/.cache/vaulthalla-macos-candidate; under sudo, the invoking user's),
# so a reboot doesn't lose it: stage/ (the tree install-acceptance copies), deps/ (pdfium with its install name set to
# /usr/local/lib/vaulthalla), node/ (verified official Node 24 tarballs), venv/ (the client's websockets), pg/ (the
# cluster), report/ (acceptance.json and run.log). `stage` and `db` run as you, never as root.
#
# Stage contents: meson install (prefix /usr/local, -O3, no unit tests) minus headers and static libraries; the web
# console's standalone build (web/.next, rebuilt unless VH_CANDIDATE_REUSE_WEB=1) under share/vaulthalla-web, as
# debian/rules does; the official Node 24 runtime under libexec/vaulthalla/node (Homebrew's node links @rpath
# libnode, which the service can't resolve); libpdfium under lib/vaulthalla. Bash 3.2 compatible.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd -P)"
if [ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ]; then
  USER_HOME="$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory | awk '{print $2}')"
else
  USER_HOME="$HOME"
fi
DIR="${VH_CANDIDATE_DIR:-$USER_HOME/.cache/vaulthalla-macos-candidate}"
DIR="${DIR%/}"
PREFIX=/usr/local
PG_PORT=54331
DB_ROLE=vh_mac_install

log() { printf 'candidate: %s\n' "$*" >&2; }
die() { printf 'candidate: error: %s\n' "$*" >&2; exit 1; }
not_root() { [ "$(id -u)" != 0 ] || die "$1 runs as you, not root"; }

env_setup() {
  # shellcheck source=tools/macos/env.sh
  source "$REPO/tools/macos/env.sh"
}

# pdfium with an install name the installed binaries resolve without DYLD_* (stripped by launchd for system daemons).
deps() {
  local src="$VH_MACOS_DEPS" d="$DIR/deps"
  [ -f "$src/lib/libpdfium.dylib" ] || die "no pdfium in $src (run tools/macos/bootstrap.sh)"
  rm -rf "$d" && mkdir -p "$d/lib/pkgconfig"
  cp "$src/lib/libpdfium.dylib" "$d/lib/" && chmod u+w "$d/lib/libpdfium.dylib"
  install_name_tool -id "$PREFIX/lib/vaulthalla/libpdfium.dylib" "$d/lib/libpdfium.dylib" 2>/dev/null
  codesign -f -s - "$d/lib/libpdfium.dylib" 2>/dev/null
  cp "$src"/lib/pkgconfig/*.pc "$d/lib/pkgconfig/"
  sed -e "s|^prefix=.*|prefix=$d|" -e "s|^includedir=.*|includedir=$src/include/pdfium|" \
    "$src/lib/pkgconfig/pdfium.pc" > "$d/lib/pkgconfig/pdfium.pc"
}

node_runtime() {  # node_runtime DEST: the newest v24 darwin-arm64 tarball, checked against nodejs.org's SHASUMS256
  local dest="$1" v tgz
  mkdir -p "$DIR/node"
  v="$(curl -fsSL https://nodejs.org/dist/index.json | python3 -c \
    'import json,sys; print(next(r["version"] for r in json.load(sys.stdin) if r["version"].startswith("v24.")))')"
  tgz="node-$v-darwin-arm64.tar.gz"
  [ -f "$DIR/node/$tgz" ] || curl -fsSL -o "$DIR/node/$tgz" "https://nodejs.org/dist/$v/$tgz"
  (cd "$DIR/node" && curl -fsSL "https://nodejs.org/dist/$v/SHASUMS256.txt" | grep " $tgz\$" | shasum -a 256 -c - >/dev/null) \
    || die "checksum mismatch for $tgz"
  mkdir -p "$dest" && tar -xzf "$DIR/node/$tgz" -C "$dest" --strip-components=1
  log "node $v"
}

cmd_stage() {
  not_root stage
  env_setup
  mkdir -p "$DIR"
  deps
  export VH_MACOS_DEPS="$DIR/deps"
  env_setup  # again, so PKG_CONFIG_PATH has the relocated pdfium.pc first
  local build="$REPO/build-candidate" stage="$DIR/stage" next="$DIR/stage.next"
  # Meson caches the dependency paths: a build dir configured against another deps dir would link a stale pdfium.
  if [ -f "$build/build.ninja" ] && [ "$(cat "$build/.vh-candidate-deps" 2>/dev/null)" = "$VH_MACOS_DEPS" ]; then
    meson setup --reconfigure "$build" >/dev/null
  else
    rm -rf "$build"
    meson setup "$build" --prefix="$PREFIX" -Dbuildtype=release -Doptimization=3 -Dbuild_unit_tests=false >/dev/null
    printf '%s\n' "$VH_MACOS_DEPS" > "$build/.vh-candidate-deps"
  fi
  log "building (log: $DIR/build.log)"
  meson compile -C "$build" > "$DIR/build.log" 2>&1 || { tail -20 "$DIR/build.log" >&2; die "build failed"; }
  rm -rf "$next"
  DESTDIR="$next" meson install -C "$build" --no-rebuild > "$DIR/install.log" 2>&1 || die "meson install failed"
  rm -rf "$next$PREFIX/include" "$next$PREFIX"/lib/*.a
  if [ "${VH_CANDIDATE_REUSE_WEB:-0}" != 1 ] || [ ! -d "$REPO/web/.next/standalone" ]; then
    log "building the web console (log: $DIR/web.log)"
    pnpm --dir "$REPO/web" build > "$DIR/web.log" 2>&1 || { tail -20 "$DIR/web.log" >&2; die "web build failed"; }
  fi
  local web="$next$PREFIX/share/vaulthalla-web"
  mkdir -p "$web/.next"
  cp -a "$REPO/web/.next/standalone/." "$web/"
  cp -a "$REPO/web/.next/static" "$web/.next/"
  if [ -d "$REPO/web/public" ]; then cp -a "$REPO/web/public" "$web/"; fi
  node_runtime "$next$PREFIX/libexec/vaulthalla/node"
  mkdir -p "$next$PREFIX/lib/vaulthalla" && cp "$DIR/deps/lib/libpdfium.dylib" "$next$PREFIX/lib/vaulthalla/"
  otool -L "$next$PREFIX/bin/vaulthalla-server" | grep -q "$PREFIX/lib/vaulthalla/libpdfium.dylib" \
    || die "vaulthalla-server doesn't link pdfium from $PREFIX/lib/vaulthalla"
  rm -rf "$stage" && mv "$next" "$stage"
  git -C "$REPO" rev-parse --short HEAD > "$DIR/stage.commit"
  if [ ! -x "$DIR/venv/bin/python" ]; then python3 -m venv "$DIR/venv"; fi
  "$DIR/venv/bin/pip" -q install --disable-pip-version-check websockets
  log "staged $(cat "$DIR/stage.commit") in $stage ($(cd "$stage" && find . -mindepth 1 | wc -l | tr -d ' ') paths)"
}

cmd_db() {
  not_root db
  env_setup
  local pg="$DIR/pg"
  export VH_TEST_PG_DIR="$pg" VH_TEST_PG_PORT="$PG_PORT"
  case "${1:-}" in
    up)
      mkdir -p "$DIR"
      "$REPO/tools/macos/test-db.sh" up >/dev/null
      if [ ! -s "$pg/install-role-password" ]; then (umask 077; openssl rand -hex 24 > "$pg/install-role-password"); fi
      # psql reads the password from the file itself (\set with backquotes); it never appears on a command line.
      "$(brew --prefix postgresql@16)/bin/psql" -X -q -v ON_ERROR_STOP=1 -h "$pg/sock" -p "$PG_PORT" -U vh_test_admin \
        -d postgres -v pwfile="$pg/install-role-password" -v role="$DB_ROLE" >/dev/null <<'SQL'
\set pw `cat :'pwfile'`
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE', :'role')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'role', :'pw') \gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'role', :'role')
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'role') \gexec
SQL
      log "ready: $DB_ROLE@127.0.0.1:$PG_PORT/$DB_ROLE"
      ;;
    down) "$REPO/tools/macos/test-db.sh" down ;;
    *) die "usage: candidate.sh db up|down" ;;
  esac
}

cmd_accept() {
  [ "$(id -u)" = 0 ] || die "accept needs root: sudo tools/macos/candidate.sh accept"
  [ -f "$DIR/stage.commit" ] || die "nothing staged in $DIR (tools/macos/candidate.sh stage)"
  [ -s "$DIR/pg/install-role-password" ] || die "no database in $DIR/pg (tools/macos/candidate.sh db up)"
  mkdir -p "$DIR/report"
  chown "${SUDO_USER:-root}" "$DIR/report"
  log "candidate $(cat "$DIR/stage.commit"); log: $DIR/report/run.log"
  "$REPO/tools/macos/install-acceptance.sh" --phase "${1:-all}" --stage "$DIR/stage" \
    --db-port "$PG_PORT" --db-name "$DB_ROLE" --db-user "$DB_ROLE" --db-password-file "$DIR/pg/install-role-password" --db-dir "$DIR/pg" \
    --python "$DIR/venv/bin/python" --report-dir "$DIR/report" 2>&1 | tee -a "$DIR/report/run.log"
}

case "${1:-}" in
  stage) cmd_stage ;;
  db) shift; cmd_db "$@" ;;
  accept) shift; cmd_accept "$@" ;;
  *) sed -n '2,17p' "$0"; exit 2 ;;
esac
