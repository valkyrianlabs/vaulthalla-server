#!/usr/bin/env bash
# Proves the test pathways are isolated from the dev install: fingerprints everything the retired `make run_test`
# used to touch, runs `make itest`, a DB-backed `make test` subset and a Tier B launched run, then requires every
# fingerprint unchanged and nothing left behind. Secret files and role passwords are compared by hash, never printed.
#
#   bin/tests/prove_isolation.sh [--skip-harness]
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SKIP_HARNESS=false; [[ "${1:-}" == --skip-harness ]] && SKIP_HARNESS=true
cd "$REPO"

h() { sudo -n sh -c 'if [ -e "$1" ]; then sha256sum "$1" | cut -c1-16; else echo absent; fi' sh "$1"; }
q() { sudo -n -u postgres psql -XAtq -d "${2:-postgres}" -c "$1" 2>/dev/null || echo unavailable; }

snapshot() {
  for f in /usr/bin/vaulthalla-server /usr/bin/vaulthalla-cli /usr/lib/vaulthalla/helpers/vaulthalla-preview-cad \
           /usr/lib/vaulthalla/helpers/vaulthalla-preview-media /etc/vaulthalla/vaulthalla.env \
           /etc/vaulthalla/config.yaml "$REPO/deploy/bashrc" "$REPO/deploy/vaulthalla.env"; do
    echo "file $f $(h "$f")"
  done
  echo "service $(systemctl is-active vaulthalla 2>/dev/null) pid=$(systemctl show vaulthalla -p MainPID --value 2>/dev/null)"
  # Role password hashes (from pg_authid), hashed again: changes are detected, nothing is revealed.
  echo "roles $(q "SELECT string_agg(rolname || ':' || coalesce(md5(rolpassword), '-'), ',' ORDER BY rolname)
                    FROM pg_authid WHERE rolname IN ('vaulthalla', 'vaulthalla_test', 'vh_harness')")"
  echo "dbs $(q "SELECT string_agg(datname, ',' ORDER BY datname) FROM pg_database
                 WHERE datname IN ('vaulthalla', 'vh_cli_test') OR datname LIKE 'vh\_harness\_%'")"
  # The dev database's content, row counts plus a digest of the identity tables.
  echo "devdb $(q "SELECT (SELECT count(*) FROM users) || '/' || (SELECT count(*) FROM vault) || '/' ||
                   (SELECT md5(string_agg(id::text || name, ',' ORDER BY id)) FROM users)" vaulthalla)"
  echo "mounts $(grep -cE ' /tmp/vh(h)?_' /proc/self/mountinfo || true)"
  echo "tmp $(ls -d /tmp/vhh_proof_* /tmp/vh_mount /tmp/vh_backing /tmp/vh_runtime 2>/dev/null | tr '\n' ' ')"
  echo "rootowned-build $(sudo -n find "$REPO/build" "$REPO/build-itest" -user root 2>/dev/null | wc -l)"
}

before="$(snapshot)"
echo "== make itest";  make --no-print-directory itest
echo "== make test (DB-backed subset)"
make --no-print-directory test ARGS="--gtest_filter=RoleParityTest.*:TestModeConnection*:TestInstanceGuard*"
if ! $SKIP_HARNESS; then
  echo "== tools/harness launched run"
  sudo tools/harness/vhh.sh run --target launch --build build-itest --seed 0x150 --sessions 4 --ops 15 \
    --surfaces ws,fuse --out "$(mktemp -d /tmp/vhh-isolation-XXXXXX)"
fi
after="$(snapshot)"

if [[ "$before" == "$after" ]]; then
  echo "ISOLATION PROVEN: nothing the old pathway touched changed (binaries, env files, service, roles, databases,"
  echo "dev DB content, mounts, /tmp paths, root-owned build files)"
  printf '%s\n' "$after" | sed 's/^/  /'
else
  echo "ISOLATION BROKEN:"
  diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") | sed 's/^/  /'
  exit 1
fi
