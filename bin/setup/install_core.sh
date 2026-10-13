#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN_DIR="$REPO_ROOT/bin"

source "$BIN_DIR/lib/dev_mode.sh"
source "$BIN_DIR/lib/platform.sh"
vh_instance_layout "$(vh_selected_instance)"

echo "🏗️  Building Vaulthalla core..."

vh_assert_dev_mode_consistency

DEV_MODE=false
vh_is_dev_mode && DEV_MODE=true

CLEAN_BUILD=false
BUILD_MANPAGE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--manpage)
      BUILD_MANPAGE=true
      shift
      ;;
    --clean)
      CLEAN_BUILD=true
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--clean] [--manpage]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Production builds in ./build (as always); an instance in ./build-<instance>, configured with -Dinstance and its own
# prefix, so the two never share a build directory or an install location.
BUILD_DIR="$REPO_ROOT/$VH_BUILD_DIR_NAME"

MESON_ARGS=()

if [[ "$DEV_MODE" == true ]]; then
  MESON_ARGS+=("-Dbuildtype=debug")
else
  MESON_ARGS+=("-Dbuildtype=release")
fi

if [[ "$BUILD_MANPAGE" == true ]]; then
  MESON_ARGS+=("-Dmanpage=true")
else
  MESON_ARGS+=("-Dmanpage=false")
fi

if [[ -n "$VH_INSTANCE" ]]; then
  MESON_ARGS+=("-Dinstance=$VH_INSTANCE" "--prefix=$VH_PREFIX")
fi

# Sanitizers: Linux as always. macOS builds without them (the LaunchDaemon runs the binary as a role account, and
# Apple's ASan runtime needs the toolchain's dylib at a path under the developer's own directories).
if [[ "$(vh_os)" == linux ]]; then
  MESON_ARGS+=("-Db_sanitize=address,undefined")
fi

if [[ "$CLEAN_BUILD" == true && -d "$BUILD_DIR" ]]; then
  vh_run rm -rf "$BUILD_DIR"
fi

if [[ "$(vh_os)" == darwin ]]; then
  # shellcheck source=tools/macos/env.sh
  source "$REPO_ROOT/tools/macos/env.sh"
fi

vh_run mkdir -p "$BUILD_DIR"

vh_run meson setup "$BUILD_DIR" "$REPO_ROOT" "${MESON_ARGS[@]}" --reconfigure
vh_run meson compile -C "$BUILD_DIR"
vh_priv meson install -C "$BUILD_DIR"

case "$(vh_os)" in
  linux)
    vh_priv ldconfig
    ;;
  darwin)
    # The binaries link a few dylibs from under your home directory (the PDFium SDK in ~/.cache), which the service
    # account can't read (home directories are 0750). Copy those into the instance's lib dir and repoint the binaries.
    "$BIN_DIR/lib/darwin_private_dylibs.sh" "$VH_PREFIX" "$HOME"
    ;;
esac
