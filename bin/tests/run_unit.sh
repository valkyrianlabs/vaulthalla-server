#!/usr/bin/env bash
# DB-backed unit tests (vh_unit_tests) against a per-run database: `make test`.
#
#   bin/tests/run_unit.sh [--build-dir DIR] [--keep-db] [-- <gtest args>]     e.g. -- --gtest_filter='RoleParity*'
#
# The database (vh_harness_unit_<run>, owned by the vh_harness role) is created for this run and always dropped. The
# suites recreate their schema themselves, so it starts empty. The tests run as you, not root (permission tests
# would mean something else as root); the role's settings are read from the root-only file and handed only to the
# test process's environment. Nothing is installed, no role is rotated, no other database is touched.
#
# Live provider tests (UpstreamLive*, never CI) read their test credentials from the environment, which the
# `env -i` below clears. Only with VH_LIVE_UPSTREAM=1 in the caller's environment are exactly the variables in
# LIVE_ENV_VARS handed through: on a pipe (never argv, never a file), to the test process only. E.g.
#   (set -a; . ./.bashrc; set +a; VH_LIVE_UPSTREAM=1 bin/tests/run_unit.sh -- --gtest_filter='UpstreamLive.*')
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ITEST_TAG=unit
# shellcheck source=bin/tests/lib/itest.sh
. "$SCRIPT_DIR/lib/itest.sh"

BUILD_DIR="$REPO_ROOT/build-itest"
KEEP_DB=false
TIMEOUT_SECS="${VH_UNIT_TIMEOUT:-3600}"
GTEST_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir) BUILD_DIR="$(realpath -m "$2")"; shift 2 ;;
    --keep-db) KEEP_DB=true; shift ;;
    --) shift; GTEST_ARGS=("$@"); break ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) itest_die "unknown option: $1 (gtest arguments go after --)" ;;
  esac
done

itest_preflight
itest_log "building vh_unit_tests in $BUILD_DIR"
itest_ensure_build "$BUILD_DIR" core/vh_unit_tests core/vh_fake_derive_helper  # the derive suites spawn the fake helper
BIN="$BUILD_DIR/core/vh_unit_tests"
[[ -x "$BIN" ]] || itest_die "not built: $BIN"

RUN_ID="$(date -u +%Y%m%dt%H%M%S)_$$"
DB_NAME="vh_harness_unit_${RUN_ID}"
DB_CREATED=false
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ "$DB_CREATED" == true ]]; then
    if [[ "$KEEP_DB" == true ]]; then
      itest_log "keeping $DB_NAME (--keep-db); drop it with: sudo -u postgres dropdb --force $DB_NAME"
    elif itest_drop_db "$DB_NAME"; then
      itest_log "database dropped: $DB_NAME"
    else
      itest_log "error: could not drop $DB_NAME"; rc=1
    fi
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

LIVE_ENV_VARS=(VH_LIVE_UPSTREAM VH_AWS_ADMIN_API_KEY VH_AWS_ADMIN_SECRET_KEY VH_R2_ADMIN_ACCESS_KEY
               VH_R2_ADMIN_SECRET_KEY VH_R2_ADMIN_ENDPOINT VH_CF_API_TOKEN)
# Prints `export NAME=<quoted value>` lines for the live variables that are set (nothing unless VH_LIVE_UPSTREAM=1).
live_env_exports() {
  [[ "${VH_LIVE_UPSTREAM:-}" == 1 ]] || return 0
  local v
  for v in "${LIVE_ENV_VARS[@]}"; do
    [[ -n "${!v:-}" ]] && printf 'export %s=%q\n' "$v" "${!v}"
  done
  return 0
}

itest_create_db "$DB_NAME"
DB_CREATED=true
itest_log "database $DB_NAME; running $BIN ${GTEST_ARGS[*]}"

# Root reads the settings file, then drops back to the invoking user with the settings in the environment only.
# stdin carries the live-test exports (usually nothing); the tests themselves get /dev/null.
live_env_exports | sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 bash -c '
  set -a; . "$1"; set +a
  live_exports="$(cat)"; eval "$live_exports"; unset live_exports
  export VH_TEST_DB_NAME="$2" VH_PATH_TO_CONFIG="$3" HOME="$4"
  uid="$5" gid="$6" dir="$7" timeout_s="$8"
  shift 8
  cd "$dir"
  exec setpriv --reuid="$uid" --regid="$gid" --init-groups -- timeout --signal=TERM --kill-after=30 "$timeout_s" "$@" </dev/null
' bash "$ITEST_DB_ENV" "$DB_NAME" "$REPO_ROOT/deploy/config/config.yaml" "$HOME" "$(id -u)" "$(id -g)" \
  "$(dirname "$BIN")" "$TIMEOUT_SECS" "$BIN" "${GTEST_ARGS[@]}"
