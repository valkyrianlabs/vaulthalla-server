#!/bin/bash
# Builds a configured Meson build directory and fails if the build prints anything but progress (AGENTS.md: code on
# GitHub compiles with zero output other than the file progression).
#
#   tools/dev/quiet-build.sh BUILDDIR [SETUP_LOG]
#
# Runs ninja directly (`meson compile` adds its own INFO lines) and passes its output through as it happens. Allowed:
# "[n/N] ..." progress lines and ninja's "Entering directory" / "no work to do". Anything else (a compiler or linker
# warning, a note, a script's chatter) fails the build after it finishes, listed once more at the end. With SETUP_LOG
# (the captured `meson setup` output), Meson's WARNING/DEPRECATION lines fail it too. Bash 3.2 compatible.
set -euo pipefail

dir="${1:?usage: quiet-build.sh BUILDDIR [SETUP_LOG]}"
setup_log="${2:-}"
log="$(mktemp "${TMPDIR:-/tmp}/quiet-build.XXXXXX")"
trap 'rm -f "$log"' EXIT

status=0
ninja -C "$dir" 2>&1 | tee "$log" || status=$?
[ "$status" = 0 ] || exit "$status"

noise="$(grep -vE '^\[[0-9]+/[0-9]+\] |^ninja: (Entering directory|no work to do)' "$log" || true)"
if [ -n "$setup_log" ]; then
  noise="${noise}$(grep -E '^(WARNING|DEPRECATION)|: WARNING:' "$setup_log" || true)"
fi
if [ -n "$noise" ]; then
  echo "::error::the build printed something other than progress (warnings are bugs; see AGENTS.md):" >&2
  printf '%s\n' "$noise" | head -50 >&2
  exit 1
fi
