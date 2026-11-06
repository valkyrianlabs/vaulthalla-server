#!/bin/bash
# Builds and runs the WebAuthn verifier's libFuzzer targets for a bounded time (#355; design section 11, decision D5).
#
#   tools/dev/fuzz-webauthn.sh [--seconds N] [--build-dir DIR] [--merge]
#
# Configures DIR (default build-fuzz) with clang, -Dfuzz=true and ASan/UBSan, which builds only
# core/src/auth/webauthn and its three targets, then runs each target for N seconds (default 60) in parallel over a
# scratch copy of its committed corpus (core/src/auth/webauthn/fuzz/corpus/<target>/). Any crash, leak, timeout or
# sanitizer report fails the run; the reproducer is left in DIR/fuzz-artifacts/ and belongs in the target's corpus
# once fixed, so the unit tests replay it from then on (WebAuthnFuzzCorpus). --merge folds new coverage back into
# the committed corpus (libFuzzer -merge=1). CXX selects the compiler (default clang++-18, then clang++).
# Bash 3.2 compatible.
set -euo pipefail

seconds=60
dir=build-fuzz
merge=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --seconds) seconds=$2; shift 2 ;;
    --build-dir) dir=$2; shift 2 ;;
    --merge) merge=true; shift ;;
    *) echo "usage: $0 [--seconds N] [--build-dir DIR] [--merge]" >&2; exit 2 ;;
  esac
done

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$root"
if [ -z "${CXX:-}" ]; then
  if command -v clang++-18 >/dev/null; then CXX=clang++-18; else CXX=clang++; fi
fi
export CXX

if [ ! -f "$dir/build.ninja" ]; then
  setup_log="$(mktemp "${TMPDIR:-/tmp}/fuzz-setup.XXXXXX")"
  trap 'rm -f "$setup_log"' EXIT
  meson setup "$dir" -Dfuzz=true -Db_sanitize=address,undefined -Db_lundef=false -Dwerror=true \
    -Dbuildtype=debugoptimized >"$setup_log" 2>&1 || { cat "$setup_log" >&2; exit 1; }
  bash tools/dev/quiet-build.sh "$dir" "$setup_log"
else
  bash tools/dev/quiet-build.sh "$dir"
fi

corpus_root=core/src/auth/webauthn/fuzz/corpus
artifacts="$dir/fuzz-artifacts"
mkdir -p "$artifacts"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
export ASAN_OPTIONS="detect_leaks=1:abort_on_error=1"

pids=()
names=()
for target in cbor_cose authenticator_data client_data; do
  work="$dir/fuzz-work/$target"
  rm -rf "$work" && mkdir -p "$work"
  "$dir/core/src/auth/webauthn/fuzz/fuzz_webauthn_$target" "$work" "$corpus_root/$target" \
    -max_total_time="$seconds" -timeout=10 -rss_limit_mb=2048 -max_len=65536 -print_final_stats=1 \
    -artifact_prefix="$artifacts/$target-" >"$dir/fuzz-$target.log" 2>&1 &
  pids+=("$!")
  names+=("$target")
done

status=0
for i in "${!pids[@]}"; do
  if wait "${pids[$i]}"; then
    runs=$(grep -E '^stat::number_of_executed_units' "$dir/fuzz-${names[$i]}.log" | awk '{print $2}')
    cov=$(grep -E '^#[0-9]+.*cov:' "$dir/fuzz-${names[$i]}.log" | tail -1 | sed -E 's/.*cov: ([0-9]+).*ft: ([0-9]+).*corp: ([0-9]+).*/cov \1, ft \2, corpus \3/')
    echo "fuzz_webauthn_${names[$i]}: ok, ${runs:-?} executions in ${seconds}s (${cov:-no stats})"
  else
    status=1
    echo "::error::fuzz_webauthn_${names[$i]} failed; log: $dir/fuzz-${names[$i]}.log" >&2
    tail -40 "$dir/fuzz-${names[$i]}.log" >&2
  fi
done
[ "$status" = 0 ] || exit "$status"

if [ "$merge" = true ]; then
  for target in cbor_cose authenticator_data client_data; do
    "$dir/core/src/auth/webauthn/fuzz/fuzz_webauthn_$target" -merge=1 "$corpus_root/$target" "$dir/fuzz-work/$target" \
      >"$dir/fuzz-merge-$target.log" 2>&1
    echo "merged $target: $(ls "$corpus_root/$target" | wc -l | tr -d ' ') inputs"
  done
fi
