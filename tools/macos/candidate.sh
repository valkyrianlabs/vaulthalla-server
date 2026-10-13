#!/bin/bash
# A reproducible macOS install candidate and its disposable database, for tools/macos/install-acceptance.sh.
#
#   tools/macos/candidate.sh stage        # release build of this checkout, staged as it would install under /usr/local
#   tools/macos/candidate.sh pkg          # the installer package from that stage (tools/macos/pkg/build-pkg.sh)
#   sudo tools/macos/candidate.sh accept [PHASE]   # install-acceptance.sh on that package (default phase: all)
#
# Everything lives in VH_CANDIDATE_DIR (default ~/.cache/vaulthalla-macos-candidate; under sudo, the invoking user's),
# so a reboot doesn't lose it: stage/ (the tree install-acceptance copies), deps/ (pdfium with its install name set to
# /usr/local/lib/vaulthalla), node/ (verified official Node 24 tarballs), venv/ (the client's websockets), pkg/ (the
# package), report/ (acceptance.json and run.log). `stage` and `pkg` run as you, never as root.
#
# Stage contents: meson install (prefix /usr/local, -O3, no unit tests) minus headers and static libraries; the web
# console under share/vaulthalla-web: from VH_CANDIDATE_WEB_TARBALL (a release web bundle, made for macOS by
# tools/macos/pkg/web-for-macos.sh; how CI does it, since only the Linux runner has the licensed icons), left out with
# VH_CANDIDATE_WEB=none (added later), else this checkout's standalone build (web/.next, rebuilt unless
# VH_CANDIDATE_REUSE_WEB=1), as
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
  if [ -n "${VH_CANDIDATE_WEB_TARBALL:-}" ]; then
    "$REPO/tools/macos/pkg/web-for-macos.sh" "$VH_CANDIDATE_WEB_TARBALL" "$next"
  elif [ "${VH_CANDIDATE_WEB:-}" = none ]; then
    log "web console left out (VH_CANDIDATE_WEB=none): add it with tools/macos/pkg/web-for-macos.sh before packaging"
  else
    if [ "${VH_CANDIDATE_REUSE_WEB:-0}" != 1 ] || [ ! -d "$REPO/web/.next/standalone" ]; then
      log "building the web console (log: $DIR/web.log)"
      pnpm --dir "$REPO/web" build > "$DIR/web.log" 2>&1 || { tail -20 "$DIR/web.log" >&2; die "web build failed"; }
    fi
    local web="$next$PREFIX/share/vaulthalla-web"
    mkdir -p "$web/.next"
    cp -a "$REPO/web/.next/standalone/." "$web/"
    cp -a "$REPO/web/.next/static" "$web/.next/"
    if [ -d "$REPO/web/public" ]; then cp -a "$REPO/web/public" "$web/"; fi
  fi
  node_runtime "$next$PREFIX/libexec/vaulthalla/node"
  mkdir -p "$next$PREFIX/lib/vaulthalla" && cp "$DIR/deps/lib/libpdfium.dylib" "$next$PREFIX/lib/vaulthalla/"
  # libmagic's database, which Homebrew keeps in its own share/ (the daemon looks for this copy: VH_MAGIC_DB_PATH).
  cp "$(brew --prefix libmagic)/share/misc/magic.mgc" "$next$PREFIX/share/vaulthalla/magic.mgc"
  otool -L "$next$PREFIX/bin/vaulthalla-server" | grep -q "$PREFIX/lib/vaulthalla/libpdfium.dylib" \
    || die "vaulthalla-server doesn't link pdfium from $PREFIX/lib/vaulthalla"
  rm -rf "$stage" && mv "$next" "$stage"
  git -C "$REPO" rev-parse --short HEAD > "$DIR/stage.commit"
  if [ ! -x "$DIR/venv/bin/python" ]; then python3 -m venv "$DIR/venv"; fi
  "$DIR/venv/bin/pip" -q install --disable-pip-version-check websockets
  log "staged $(cat "$DIR/stage.commit") in $stage ($(cd "$stage" && find . -mindepth 1 | wc -l | tr -d ' ') paths)"
}

cmd_pkg() {
  not_root pkg
  [ -f "$DIR/stage.commit" ] || die "nothing staged in $DIR (tools/macos/candidate.sh stage)"
  rm -rf "$DIR/pkg"
  "$REPO/tools/macos/pkg/build-pkg.sh" "$DIR/stage" "$DIR/pkg"
  cp "$DIR/stage.commit" "$DIR/pkg.commit"
}

cmd_accept() {
  [ "$(id -u)" = 0 ] || die "accept needs root: sudo tools/macos/candidate.sh accept"
  local pkg
  pkg=$(ls "$DIR"/pkg/vaulthalla-*-arm64.pkg 2>/dev/null | head -1)
  [ -n "$pkg" ] || die "no package in $DIR/pkg (tools/macos/candidate.sh stage && tools/macos/candidate.sh pkg)"
  mkdir -p "$DIR/report"
  chown "${SUDO_USER:-root}" "$DIR/report"
  log "package $(basename "$pkg") from $(cat "$DIR/pkg.commit"); log: $DIR/report/run.log"
  "$REPO/tools/macos/install-acceptance.sh" --phase "${1:-all}" --pkg "$pkg" \
    --python "$DIR/venv/bin/python" --report-dir "$DIR/report" 2>&1 | tee -a "$DIR/report/run.log"
}

case "${1:-}" in
  stage) cmd_stage ;;
  pkg) cmd_pkg ;;
  accept) shift; cmd_accept "$@" ;;
  *) sed -n '2,17p' "$0"; exit 2 ;;
esac
