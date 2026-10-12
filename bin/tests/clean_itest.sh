#!/usr/bin/env bash
# Removes leftovers of interrupted isolated test runs (make test / make itest), and nothing else:
#   - per-run databases vh_harness_proof_* / vh_harness_unit_* that have no open connections
#     (never a migrated template vh_harness_tpl_*, never any other database);
#   - /tmp/vhh_proof_* run directories whose FUSE mount is gone (a still-mounted one is reported, not touched).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ITEST_TAG=clean
# shellcheck source=bin/tests/lib/itest.sh
. "$SCRIPT_DIR/lib/itest.sh"

sudo -n true 2>/dev/null || itest_die "needs passwordless sudo"
dbs="$(sudo -n -u postgres psql -XAtq -d postgres -c "
  SELECT d.datname FROM pg_database d
  WHERE (d.datname LIKE 'vh\_harness\_proof\_%' OR d.datname LIKE 'vh\_harness\_unit\_%')
    AND NOT EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.datname = d.datname)")"
for db in $dbs; do itest_drop_db "$db" && itest_log "dropped $db"; done

for dir in /tmp/vhh_proof_*; do
  [[ -d "$dir" && "$dir" =~ ^/tmp/vhh_proof_[a-z0-9_]+$ ]] || continue
  if awk -v d="$dir/" 'index($5, d) == 1 { found = 1 } END { exit !found }' /proc/self/mountinfo; then
    itest_log "skipping $dir: still mounted (abort its FUSE connection first)"
    continue
  fi
  sudo -n rm -rf --one-file-system "$dir" && itest_log "removed $dir"
done
itest_log "done"
