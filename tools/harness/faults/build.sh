#!/usr/bin/env bash
# Build a scratch daemon with one controlled fault applied, for the engine's acceptance runs.
#
#   tools/harness/faults/build.sh <fault> [--sanitize address,undefined|thread|none] [--ref HEAD]
#
# The fault patch is applied to a throwaway git worktree of <ref> (default HEAD) under
# ${VHH_FAULT_ROOT:-$HOME/.cache/vhh-faults}/<fault>-<sha>, never to your checkout, and built in its own build dir.
# Prints the build dir on the last line: pass it to `vhh run --launch --build <dir>`.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
fault="${1:-}"; shift || true
sanitize="address,undefined"; ref="HEAD"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sanitize) sanitize="$2"; shift 2 ;;
        --ref) ref="$2"; shift 2 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done
patch="$HERE/$fault.patch"
[[ -n "$fault" && -f "$patch" ]] || { echo "usage: $0 <fault>; faults: $(cd "$HERE" && ls *.patch | sed 's/\.patch$//' | tr '\n' ' ')" >&2; exit 2; }

sha="$(git -C "$REPO" rev-parse --short "$ref")"
root="${VHH_FAULT_ROOT:-$HOME/.cache/vhh-faults}"
src="$root/$fault-$sha"
build="$src/build-${sanitize//,/-}"
mkdir -p "$root"

if [[ ! -d "$src" ]]; then
    git -C "$REPO" worktree add -q --detach "$src" "$ref"
    git -C "$src" apply --index "$patch"
    git -C "$src" -c user.name=vhh -c user.email=vhh@invalid commit -qm "FAULT FIXTURE: $fault (do not merge)"
fi
git -C "$src" log -1 --format='%s' | grep -q "FAULT FIXTURE: $fault" || { echo "$src is not the $fault fixture" >&2; exit 1; }

opts=(-Dbuildtype=debug -Dbuild_unit_tests=true -Dintegration_tests=true)
[[ "$sanitize" != "none" ]] && opts+=(-Db_sanitize="$sanitize")
[[ "$sanitize" == "thread" ]] && opts+=(-Db_lundef=false)
[[ -f "$build/build.ninja" ]] || meson setup "$build" "$src" "${opts[@]}" >/dev/null
targets=(core/vaulthalla-server core/vaulthalla-cli)
ninja -C "$build" -t targets all 2>/dev/null | grep -q '^core/vh_fs_actor:' && targets+=(core/vh_fs_actor)
ninja -C "$build" "${targets[@]}" >/dev/null
echo "$build"
