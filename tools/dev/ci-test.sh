#!/bin/bash
# Runs the meson tests of an already built BUILDDIR the way CI does: vh_unit_tests split into N gtest shards that run
# at the same time (GTEST_TOTAL_SHARDS / GTEST_SHARD_INDEX: every test case runs in exactly one shard), beside the
# other meson tests. Fails if any shard or test fails; a failing shard's full output is printed. Nothing is skipped
# or filtered: the shards together run the same cases as one `meson test -C BUILDDIR`. Bash 3.2 compatible.
#
#   tools/dev/ci-test.sh [BUILDDIR] [SHARDS]       (defaults: build, $VH_TEST_SHARDS or 4)
set -euo pipefail

dir="${1:-build}"
shards="${2:-${VH_TEST_SHARDS:-4}}"
logs="$(mktemp -d "${TMPDIR:-/tmp}/ci-test.XXXXXX")"
trap 'rm -rf "$logs"' EXIT

others="$(meson test -C "$dir" --list 2>/dev/null | sed 's/^.* \/ //' | grep -vx vh_unit_tests || true)"

pids=()
names=()
if [ -n "$others" ]; then
  # shellcheck disable=SC2086 # test names are single words
  meson test -C "$dir" --no-rebuild --print-errorlogs --logbase testlog-others $others >"$logs/others.log" 2>&1 &
  pids+=("$!")
  names+=(others)
fi
i=0
while [ "$i" -lt "$shards" ]; do
  GTEST_TOTAL_SHARDS="$shards" GTEST_SHARD_INDEX="$i" \
    meson test -C "$dir" --no-rebuild --print-errorlogs --logbase "testlog-shard$i" vh_unit_tests >"$logs/shard$i.log" 2>&1 &
  pids+=("$!")
  names+=("shard$i")
  i=$((i + 1))
done

status=0
n=0
while [ "$n" -lt "${#pids[@]}" ]; do
  if wait "${pids[$n]}"; then
    grep -E '^ *[0-9]+/[0-9]+ ' "$logs/${names[$n]}.log" || true
  else
    status=1
    echo "=== ${names[$n]} FAILED ===" >&2
    cat "$logs/${names[$n]}.log" >&2
  fi
  n=$((n + 1))
done
exit "$status"
