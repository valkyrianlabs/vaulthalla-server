#!/usr/bin/env bash
# shellcheck disable=SC2317  # cleanup/release_mount run from the EXIT trap
# Tier A proof: runs vh_integration_tests as a fully private instance.
#
#   - a per-run database (vh_harness_proof_<run>, owned by the vh_harness role) that is always dropped afterwards;
#   - private paths under /tmp/vhh_proof_<run>/ (backing, FUSE mount, runtime, logs, config, CLI socket); the mount is
#     confirmed gone afterwards and the directory removed;
#   - an overall timeout; reports (report.json, junit.xml), the run log and the daemon logs kept in an artifacts dir.
#
# It never touches the dev install (vaulthalla.service, /run/vaulthalla, /mnt/vaulthalla, /var/lib/vaulthalla), the
# vaulthalla / vh_cli_test databases or the vaulthalla_test role, and it never installs anything. It needs
# passwordless sudo (FUSE, root-only RBAC proofs, the harness DB credentials) and a meson build dir configured with
# -Dintegration_tests=true (configured and compiled here if missing).
#
# Knobs passed through to the harness: VH_TEST_SEED, VH_TEST_CONFIG, VH_TEST_STAGES, VH_TEST_NEGATIVE_CONTROL,
# VH_TEST_UID_BASE, VH_TEST_FS_OP_TIMEOUT_MS, ASAN_OPTIONS, UBSAN_OPTIONS.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ITEST_TAG=proof
# shellcheck source=bin/tests/lib/itest.sh
. "$SCRIPT_DIR/lib/itest.sh"

DB_ENV_FILE="$ITEST_DB_ENV"
BUILD_DIR="$REPO_ROOT/build-itest"
BIN=""
ACTOR=""
ARTIFACTS=""
TIMEOUT_SECS=1200
KEEP_DB=false

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --build-dir DIR   meson build dir (default: build-itest; configured with the isolated-run options only when they
                    differ, then just the needed targets compiled; never installed)
  --bin PATH        run this vh_integration_tests binary instead of compiling one
  --actor PATH      vh_fs_actor binary to use (default: the one next to the test binary)
  --artifacts DIR   where reports and logs go (default: <build-dir>/proof-artifacts/<run>)
  --timeout SECS    overall timeout for the test binary (default: $TIMEOUT_SECS)
  --keep-db         keep the per-run database for inspection (it is still listed at the end)
  -h, --help        show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir) BUILD_DIR="$(realpath -m "$2")"; shift 2 ;;
    --bin) BIN="$(realpath -m "$2")"; shift 2 ;;
    --actor) ACTOR="$(realpath -m "$2")"; shift 2 ;;
    --artifacts) ARTIFACTS="$(realpath -m "$2")"; shift 2 ;;
    --timeout) TIMEOUT_SECS="$2"; shift 2 ;;
    --keep-db) KEEP_DB=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$TIMEOUT_SECS" =~ ^[0-9]+$ ]] || { echo "--timeout must be a number of seconds" >&2; exit 2; }

log() { printf '[proof] %s\n' "$*"; }
die() { printf '[proof] error: %s\n' "$*" >&2; exit 1; }

itest_preflight fuse

# ---------------------------------------------------------------- binaries

if [[ -z "$BIN" ]]; then
  log "building vh_integration_tests, vh_fs_actor and vh_migrate in $BUILD_DIR"
  itest_ensure_build "$BUILD_DIR" core/vh_integration_tests core/vh_fs_actor core/vh_migrate
  BIN="$BUILD_DIR/core/vh_integration_tests"
fi
[[ -x "$BIN" ]] || die "test binary not found: $BIN"
[[ -n "$ACTOR" ]] || ACTOR="$(dirname "$BIN")/vh_fs_actor"
[[ -x "$ACTOR" ]] || log "warning: no vh_fs_actor at $ACTOR (FUSE stages will fail)"

# ---------------------------------------------------------------- per-run identity

RUN_ID="$(date -u +%Y%m%dt%H%M%S)_$$"
DB_NAME="vh_harness_proof_${RUN_ID}"
ROOT="/tmp/vhh_proof_${RUN_ID}"
MOUNT="$ROOT/mount"
[[ "$ROOT" =~ ^/tmp/vhh_proof_[a-z0-9_]+$ ]] || die "unexpected run root: $ROOT"
[[ -n "$ARTIFACTS" ]] || ARTIFACTS="$(dirname "$(dirname "$BIN")")/proof-artifacts/$RUN_ID"
mkdir -p "$ARTIFACTS"
INVOKER_UID="$(id -u)"
INVOKER_GID="$(id -g)"

free_port() {
  python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

DB_CREATED=false
CLEANUP_FAILED=false

mount_present() { awk -v m="$MOUNT" '$5 == m { found = 1 } END { exit !found }' /proc/self/mountinfo; }

# Unsticks a wedged FUSE connection without waiting on it: abort it through fusectl, then detach the mount.
release_mount() {
  mount_present || return 0
  local devno major minor conn
  devno="$(awk -v m="$MOUNT" '$5 == m { print $3; exit }' /proc/self/mountinfo)"
  major="${devno%%:*}"; minor="${devno##*:}"
  conn=$(( (major << 20) | minor ))
  if [[ -e "/sys/fs/fuse/connections/$conn/abort" ]]; then
    log "aborting FUSE connection $conn for $MOUNT"
    echo 1 | sudo -n timeout 5 tee "/sys/fs/fuse/connections/$conn/abort" >/dev/null || true
  fi
  sudo -n timeout 10 umount -l "$MOUNT" 2>/dev/null || sudo -n timeout 10 fusermount3 -u -z "$MOUNT" 2>/dev/null || true
}

cleanup() {
  local rc=$?
  set +e
  trap - EXIT INT TERM

  release_mount
  if mount_present; then
    log "error: $MOUNT is still mounted after cleanup"
    CLEANUP_FAILED=true
  else
    log "mount gone: $MOUNT"
  fi

  if [[ -d "$ROOT/log" ]]; then
    sudo -n cp -a "$ROOT/log" "$ARTIFACTS/daemon-log" 2>/dev/null
  fi
  sudo -n chown -R "$INVOKER_UID:$INVOKER_GID" "$ARTIFACTS" 2>/dev/null

  if [[ "$DB_CREATED" == true ]]; then
    if [[ "$KEEP_DB" == true ]]; then
      log "keeping database $DB_NAME (--keep-db); drop it with: sudo -u postgres dropdb --force $DB_NAME"
    else
      itest_drop_db "$DB_NAME" || true
      if [[ -n "$(sudo -n -u postgres psql -Atqc "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" 2>/dev/null)" ]]; then
        log "error: database $DB_NAME still exists"
        CLEANUP_FAILED=true
      else
        log "database dropped: $DB_NAME"
      fi
    fi
  fi

  if ! mount_present && [[ -d "$ROOT" ]]; then
    sudo -n rm -rf --one-file-system "$ROOT"
  fi

  local leftovers
  leftovers="$(ps -C vh_fs_actor -o pid=,ppid=,stat= 2>/dev/null | awk '$2 == 1' | tr '\n' ' ')"
  [[ -z "$leftovers" ]] || log "warning: orphaned vh_fs_actor processes (pid ppid stat): $leftovers"

  if [[ "$CLEANUP_FAILED" == true && "$rc" -eq 0 ]]; then rc=1; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---------------------------------------------------------------- private instance

sudo -n install -d -m 0755 "$ROOT" "$ROOT/runtime" "$ROOT/log"
sudo -n install -d -m 0700 "$ROOT/backing"
sudo -n install -d -m 0755 "$MOUNT"

CONFIG_TMP="$(mktemp)"
cat >"$CONFIG_TMP" <<EOF
# Private Tier A proof instance ($RUN_ID). Written by bin/tests/run_proof.sh.
websocket_server:
  host: 127.0.0.1
  port: $(free_port)
http_preview_server:
  host: 127.0.0.1
  port: $(free_port)
s3_gateway:
  enabled: false
email:
  enabled: false
operator_emails:
  enabled: false
EOF
sudo -n install -m 0644 "$CONFIG_TMP" "$ROOT/config.yaml"
rm -f "$CONFIG_TMP"
cp "$ROOT/config.yaml" "$ARTIFACTS/config.yaml"

# A clone of the migrated template (built once per migration set by the daemon's own SqlDeployer); ITEST_DB_TEMPLATE=0
# starts from an empty database instead, so the migration path itself stays covered.
TEMPLATE=""
if [[ "${ITEST_DB_TEMPLATE:-1}" != 0 ]]; then
  TEMPLATE="$(itest_db_template "$(dirname "$BIN")/vh_migrate")"
fi
itest_create_db "$DB_NAME" "$TEMPLATE"
DB_CREATED=true

log "run $RUN_ID"
log "  database  $DB_NAME${TEMPLATE:+ (from $TEMPLATE)}"
log "  root      $ROOT"
log "  binary    $BIN"
log "  artifacts $ARTIFACTS"
log "  timeout   ${TIMEOUT_SECS}s"

RUN_ENV=(
  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  "HOME=/root"
  "LANG=C.UTF-8"
  "NO_COLOR=1"
  "VH_TEST_DB_NAME=$DB_NAME"
  "VH_TEST_BACKING_PATH=$ROOT/backing"
  "VH_TEST_MOUNT_PATH=$MOUNT"
  "VH_TEST_LOG_PATH=$ROOT/log"
  "VH_PATH_TO_SUPERADMIN_UID=$ROOT/runtime"
  "VH_PATH_TO_CONFIG=$ROOT/config.yaml"
  "VH_TEST_CLI_SOCKET=$ROOT/cli.sock"
  "VH_TEST_REPORT_DIR=$ARTIFACTS"
  "VH_TEST_ADMIN_UID=$INVOKER_UID"
  "VH_FS_ACTOR=$ACTOR"
)
for knob in VH_TEST_SEED VH_TEST_CONFIG VH_TEST_STAGES VH_TEST_NEGATIVE_CONTROL VH_TEST_UID_BASE \
            VH_TEST_FS_OP_TIMEOUT_MS ASAN_OPTIONS UBSAN_OPTIONS; do
  if [[ -n "${!knob:-}" ]]; then RUN_ENV+=("$knob=${!knob}"); fi
done

# The DB credentials are loaded inside the root shell and never pass through this script's environment or output.
set +e
sudo -n env -i "${RUN_ENV[@]}" bash -c '
  set -a; . "$1"; set +a
  export VH_TEST_DB_NAME="$2"
  shift 2
  exec timeout --signal=TERM --kill-after=30 "$@"
' bash "$DB_ENV_FILE" "$DB_NAME" "$TIMEOUT_SECS" "$BIN" 2>&1 | tee "$ARTIFACTS/run.log"
RC=${PIPESTATUS[0]}
set -e

case "$RC" in
  0) log "harness exit 0" ;;
  124) log "error: overall timeout (${TIMEOUT_SECS}s) reached; the harness was stopped" ;;
  78) log "error: the harness refused the environment (exit 78)" ;;
  *) log "harness exit $RC" ;;
esac

REPORT="$ARTIFACTS/report.json"
if [[ -f "$REPORT" ]]; then
  python3 -I - "$REPORT" <<'PY' || true
import json, sys
r = json.load(open(sys.argv[1]))
s = r.get("summary", {})
print(f"[proof] report: seed {r.get('seed')} config {r.get('config', {}).get('name')} "
      f"{s.get('passed')}/{s.get('total')} passed, {s.get('failed')} failed, {s.get('wedges', 0)} wedges")
PY
else
  log "error: no report.json was written"
  [[ "$RC" -ne 0 ]] || RC=1
fi

exit "$RC"
