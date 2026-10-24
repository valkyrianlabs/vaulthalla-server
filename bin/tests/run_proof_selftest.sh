#!/usr/bin/env bash
# Self-test for the Tier A proof: a harness that can't fail proves nothing. Each case must make the run fail, and
# fail for the reason it was given:
#
#   1. refusal: vh_integration_tests without a private environment exits 78 before touching any state;
#   2. VH_TEST_NEGATIVE_CONTROL=assertion: one impossible stdout expectation; the run must exit non-zero and the
#      only failing tests must be the ones carrying the negative-control needle;
#   3. VH_TEST_NEGATIVE_CONTROL=oracle: one impossible state check; same rule;
#   4. a run whose stage selection runs no test at all exits non-zero.
#
# Usage: bin/tests/run_proof_selftest.sh [--build-dir DIR | --bin PATH]   (same meaning as run_proof.sh)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROOF="$SCRIPT_DIR/run_proof.sh"
ITEST_TAG=selftest
# shellcheck source=bin/tests/lib/itest.sh
. "$SCRIPT_DIR/lib/itest.sh"

PASS_ARGS=()
BUILD_DIR="$REPO_ROOT/build-itest"
BIN=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir) BUILD_DIR="$(itest_abspath "$2")"; PASS_ARGS+=(--build-dir "$BUILD_DIR"); shift 2 ;;
    --bin) BIN="$(itest_abspath "$2")"; PASS_ARGS+=(--bin "$BIN"); shift 2 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
itest_require_linux

if [[ -z "$BIN" ]]; then
  itest_ensure_build "$BUILD_DIR" core/vh_integration_tests core/vh_fs_actor core/vh_migrate
  BIN="$BUILD_DIR/core/vh_integration_tests"
  PASS_ARGS+=(--bin "$BIN")
fi

OUT="$(dirname "$(dirname "$BIN")")/proof-selftest/$(date -u +%Y%m%dt%H%M%S)_$$"
mkdir -p "$OUT"
failures=0
ok() { printf '[selftest] PASS  %s\n' "$*"; }
bad() { printf '[selftest] FAIL  %s\n' "$*"; failures=$((failures + 1)); }

# ---------------------------------------------------------------- 1. refusal

set +e
env -i PATH=/usr/bin:/bin "$BIN" >"$OUT/refusal-empty.log" 2>&1
rc=$?
set -e
if [[ "$rc" -eq 78 ]]; then ok "refusal: empty environment exits 78"; else bad "refusal: empty environment exited $rc (want 78)"; fi

set +e
env -i PATH=/usr/bin:/bin VH_TEST_DB_USER=x VH_TEST_DB_PASS=x VH_TEST_DB_HOST=localhost VH_TEST_DB_PORT=5432 \
  VH_TEST_DB_NAME=vaulthalla VH_TEST_BACKING_PATH=/tmp/vhh_selftest/b VH_TEST_MOUNT_PATH=/tmp/vhh_selftest/m \
  VH_TEST_LOG_PATH=/tmp/vhh_selftest/l VH_PATH_TO_SUPERADMIN_UID=/tmp/vhh_selftest/r \
  VH_PATH_TO_CONFIG=/tmp/vhh_selftest/c.yaml VH_TEST_CLI_SOCKET=/tmp/vhh_selftest/s \
  "$BIN" >"$OUT/refusal-proddb.log" 2>&1
rc=$?
set -e
if [[ "$rc" -eq 78 ]] && grep -q "VH_TEST_DB_NAME" "$OUT/refusal-proddb.log"; then
  ok "refusal: the production database name exits 78"
else
  bad "refusal: the production database name exited $rc (want 78 naming VH_TEST_DB_NAME)"
fi
[[ ! -e /tmp/vhh_selftest ]] || bad "refusal: the refused run created /tmp/vhh_selftest"

# ---------------------------------------------------------------- 2./3. negative controls

check_negative_control() {
  local kind="$1" stages="$2" dir="$OUT/negative-$1" rc
  set +e
  VH_TEST_NEGATIVE_CONTROL="$kind" VH_TEST_STAGES="$stages" "$PROOF" "${PASS_ARGS[@]}" --artifacts "$dir" \
    >"$OUT/negative-$kind.log" 2>&1
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    bad "negative control ($kind): the run passed (exit 0); the harness can't catch a wrong expectation"
    return
  fi
  if [[ ! -f "$dir/report.json" ]]; then
    bad "negative control ($kind): exit $rc but no report.json (it failed for some other reason; see $OUT/negative-$kind.log)"
    return
  fi
  local verdict
  verdict="$(python3 -I - "$dir/report.json" "$kind" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
needle = "VH-NEGATIVE-CONTROL"
failed = [t for s in r["stages"] for t in s["tests"] if t["status"] != "pass"]
control = [t for t in failed if needle in t["message"]]
other = [t for t in failed if needle not in t["message"]]
if r.get("negative_control") != sys.argv[2]:
    print(f"report says negative_control={r.get('negative_control')!r}")
elif not control:
    print("no failing test carries the negative-control needle")
elif other:
    print("other tests failed too: " + "; ".join(f"{t['name']}: {t['message'][:120]}" for t in other))
else:
    print(f"OK {len(control)} control failure(s), {r['summary']['passed']}/{r['summary']['total']} passed otherwise")
PY
)"
  if [[ "$verdict" == OK* ]]; then
    ok "negative control ($kind): exit $rc, ${verdict#OK }"
  else
    bad "negative control ($kind): exit $rc, $verdict"
  fi
}

check_negative_control assertion "seed,read"
check_negative_control oracle "seed,validate"

# ---------------------------------------------------------------- 4. zero tests

set +e
VH_TEST_STAGES="," "$PROOF" "${PASS_ARGS[@]}" --artifacts "$OUT/zero" >"$OUT/zero.log" 2>&1
rc=$?
set -e
zero_total="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["summary"]["total"])' "$OUT/zero/report.json" 2>/dev/null || echo "?")"
if [[ "$rc" -ne 0 && "$zero_total" == "0" ]]; then
  ok "zero tests: a run that ran nothing exits $rc"
else
  bad "zero tests: exit $rc with total=$zero_total (want non-zero with total 0)"
fi

echo "[selftest] logs and reports: $OUT"
if [[ "$failures" -ne 0 ]]; then
  echo "[selftest] $failures check(s) failed"
  exit 1
fi
echo "[selftest] all checks passed"
