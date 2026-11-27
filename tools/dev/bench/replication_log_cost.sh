#!/usr/bin/env bash
# Trigger cost of the replication log (migration 160) on the seal path, against the change journal's (115).
#
#   sudo -n true   # needs passwordless sudo: it runs psql and pgbench as postgres
#   bash tools/dev/bench/replication_log_cost.sh [transactions per run, default 3000] [runs, default 3]
#
# Builds a scratch database vh_bench_rl_<pid>_test from deploy/psql (dropped at exit), with three local vaults of 200
# files under a folder chain of depth 3: one mirrored (this server its core, the baseline taken as startCore takes it)
# and one not. Each pgbench transaction is one FUSE seal's statements (Filesystem::updateFile: the files row, the
# entry's mtime and modifier, the ancestors' totals and mtimes) on a random file. Reported: the median over the runs
# of pgbench's average latency per seal, for
#   no triggers         115's and 160's triggers dropped
#   journal only        160's triggers dropped (the state before this change)
#   none mirrored       everything installed, no vault mirrored anywhere (every server today)
#   not mirrored        everything installed, a vault that is not mirrored while another one is
#   mirrored            everything installed, the mirrored vault
#   held elsewhere      everything installed, no vault mirrored, a third vault held as another server's copy (the
#                       backstop of migration 165 then looks the row's vault up)
#   without 165         no vault mirrored and 165's triggers dropped (what the backstop costs every server today)
# and the sequencer's cost per row numbered. Touches nothing but its own database.
set -euo pipefail

TX="${1:-3000}"
RUNS="${2:-3}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DB="vh_bench_rl_$$_test"
WORK="$(mktemp -d)"
chmod 755 "$WORK"
cleanup() {
  [[ "${VH_BENCH_KEEP_DB:-}" == 1 ]] && echo "kept database $DB" ||
    sudo -n -u postgres dropdb --if-exists "$DB" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

q() { sudo -n -u postgres psql -XAtq -v ON_ERROR_STOP=1 -d "$DB" "$@"; }

sudo -n -u postgres createdb "$DB"
for f in $(cd "$ROOT/deploy/psql" && LC_ALL=C ls ./*.sql); do
  q -f "$ROOT/deploy/psql/${f#./}" >/dev/null 2>&1
done

q <<'SQL' >/dev/null
INSERT INTO device_node (singleton, node_id) VALUES (TRUE, 'bench-node') ON CONFLICT DO NOTHING;
INSERT INTO users (name, password_hash) VALUES ('bench_owner', 'x');
INSERT INTO peer (node_id, name, spki_sha256, wrap_public_key)
VALUES ('bench-peer', 'bench peer', repeat('a', 64), decode(repeat('07', 32), 'hex'));
DO $$
DECLARE
    owner INTEGER := (SELECT id FROM users WHERE name = 'bench_owner');
    v INTEGER; parent INTEGER; e INTEGER; i INTEGER; d INTEGER;
BEGIN
    FOR v IN 1..3 LOOP
        INSERT INTO vault (name, owner_id, type, mount_point, uid)
        VALUES ('bench_' || v, owner, 'local', 'bench_' || v, gen_random_uuid()) RETURNING id INTO v;
        INSERT INTO fs_entry (vault_id, name, path) VALUES (v, '', '/') RETURNING id INTO parent;
        INSERT INTO directories (fs_entry_id, uid) VALUES (parent, gen_random_uuid());
        FOR d IN 1..3 LOOP
            INSERT INTO fs_entry (vault_id, parent_id, name, path, created_by, last_modified_by)
            VALUES (v, parent, 'd' || d, '/d' || d, owner, owner) RETURNING id INTO parent;
            INSERT INTO directories (fs_entry_id, uid) VALUES (parent, gen_random_uuid());
        END LOOP;
        FOR i IN 1..200 LOOP
            INSERT INTO fs_entry (vault_id, parent_id, name, path, created_by, last_modified_by, mode)
            VALUES (v, parent, 'f' || i, '/d/f' || i, owner, owner, 420) RETURNING id INTO e;
            INSERT INTO files (fs_entry_id, size_bytes, content_hash, encryption_iv, encrypted_with_key_version,
                               object_uid)
            VALUES (e, 4096, md5(i::text), 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 1, gen_random_uuid());
        END LOOP;
    END LOOP;
END $$;
SQL

MIRRORED="$(q -c "SELECT min(id) FROM vault WHERE name LIKE 'bench_%'")"
HELD="$(q -c "SELECT max(id) FROM vault WHERE name LIKE 'bench_%'")"
PLAIN="$(q -c "SELECT id FROM vault WHERE name LIKE 'bench_%' AND id NOT IN ($MIRRORED, $HELD)")"
# startCore's baseline (MirrorVaults::startCore), without its table lock: nothing else writes here.
q >/dev/null <<SQL
INSERT INTO mirror_vault (vault_id, peer_id, role) SELECT $MIRRORED, id, 'core' FROM peer;
INSERT INTO mirror_entry_hash (vault_id, entry_uid, entry_hash) SELECT $MIRRORED, entry_uid, entry_hash FROM vh_mirror_tree($MIRRORED);
UPDATE mirror_vault SET digest = d.g, digest_entries = d.n
FROM (SELECT vh_mirror_digest(entry_hash) AS g, count(*) AS n FROM mirror_entry_hash WHERE vault_id = $MIRRORED) d
WHERE vault_id = $MIRRORED;
SQL

script() {   # script VAULT -> path of a pgbench script sealing a random file of VAULT
  local vault="$1" lo hi ancestors out="$WORK/seal_$1.sql"
  lo="$(q -c "SELECT min(e.id) FROM fs_entry e JOIN files f ON f.fs_entry_id = e.id WHERE e.vault_id = $vault")"
  hi="$(q -c "SELECT max(e.id) FROM fs_entry e JOIN files f ON f.fs_entry_id = e.id WHERE e.vault_id = $vault")"
  ancestors="$(q -c "SELECT string_agg(e.id::text, ',') FROM fs_entry e JOIN directories d ON d.fs_entry_id = e.id WHERE e.vault_id = $vault")"
  cat >"$out" <<SQL
\set id random($lo, $hi)
BEGIN;
UPDATE files SET size_bytes = size_bytes + 1, content_hash = md5(random()::text) WHERE fs_entry_id = :id;
UPDATE fs_entry SET last_modified_by = last_modified_by, updated_at = NOW() WHERE id = :id;
UPDATE directories SET size_bytes = size_bytes + 1 WHERE fs_entry_id IN ($ancestors);
UPDATE fs_entry SET updated_at = NOW() WHERE id IN ($ancestors);
END;
SQL
  chmod 644 "$out"
  printf '%s' "$out"
}

latency() {   # latency SCRIPT -> median over RUNS of pgbench's average latency (ms)
  local s="$1" i out=()
  for ((i = 0; i < RUNS; i++)); do
    out+=("$(sudo -n -u postgres pgbench -n -c 1 -t "$TX" -f "$s" "$DB" 2>/dev/null | awk '/latency average/ {print $4}')")
  done
  printf '%s\n' "${out[@]}" | sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}'
}

drop_triggers() {   # drop_triggers PATTERN
  q >/dev/null <<SQL
DO \$\$ DECLARE t RECORD; BEGIN
  FOR t IN SELECT tgname, tgrelid::regclass AS rel FROM pg_trigger WHERE tgname LIKE '$1' AND NOT tgisinternal LOOP
    EXECUTE format('DROP TRIGGER %I ON %s', t.tgname, t.rel);
  END LOOP; END \$\$;
SQL
}

SEAL_PLAIN="$(script "$PLAIN")"
SEAL_MIRRORED="$(script "$MIRRORED")"
q -c "VACUUM ANALYZE" >/dev/null

# Every server today: no vault mirrored anywhere.
q -c "DELETE FROM mirror_vault" >/dev/null
none_mirrored="$(latency "$SEAL_PLAIN")"
q -c "INSERT INTO mirror_vault (vault_id, peer_id, role) SELECT $HELD, id, 'mirror' FROM peer" >/dev/null
held_elsewhere="$(latency "$SEAL_PLAIN")"
q -c "DELETE FROM mirror_vault" >/dev/null
q -c "INSERT INTO mirror_vault (vault_id, peer_id, role, digest, digest_entries)
      SELECT $MIRRORED, p.id, 'core', d.g, d.n FROM peer p,
             (SELECT vh_mirror_digest(entry_hash) AS g, count(*) AS n FROM mirror_entry_hash WHERE vault_id = $MIRRORED) d" >/dev/null
not_mirrored="$(latency "$SEAL_PLAIN")"
mirrored="$(latency "$SEAL_MIRRORED")"
rows="$(q -c "SELECT count(*) FROM vault_replication_log WHERE seq IS NULL")"
# The sequencer's statements (db::query::mirror::Log::sequence): the pending groups by their last row, then the numbers
# written by id. One pass over the whole backlog here (the daemon goes 10,000 rows at a time).
start="$(date +%s%N)"
q >/dev/null <<SQL
SELECT array_agg(txid ORDER BY last_id)::text AS txids FROM (
  SELECT txid, max(id) AS last_id FROM vault_replication_log WHERE vault_id = $MIRRORED AND seq IS NULL GROUP BY txid) g
\gset
SELECT array_agg(id ORDER BY last_id, id)::text AS ids FROM (
  SELECT id, max(id) OVER (PARTITION BY txid) AS last_id FROM vault_replication_log
  WHERE vault_id = $MIRRORED AND txid = ANY(:'txids'::bigint[]) AND seq IS NULL) x
\gset
UPDATE vault_replication_log l SET seq = n.seq
FROM unnest(:'ids'::bigint[]) WITH ORDINALITY AS n(id, seq)
WHERE l.id = n.id;
SQL
seq_ns=$(( $(date +%s%N) - start ))
mirror_rows="$(q -c "SELECT count(*) FROM vault_replication_log")"

q -c "DELETE FROM mirror_vault" >/dev/null
drop_triggers 'vh\_mirror\_gate%'
without_165="$(latency "$SEAL_PLAIN")"
drop_triggers 'vh\_mirror\_track%'
journal_only="$(latency "$SEAL_PLAIN")"
drop_triggers 'vh\_fs\_change\_track%'
no_triggers="$(latency "$SEAL_PLAIN")"

printf 'seal transactions per run: %s, runs: %s (median of pgbench average latency per seal)\n' "$TX" "$RUNS"
printf '  no triggers     %8s ms\n' "$no_triggers"
printf '  journal only    %8s ms   (journal triggers: %s ms)\n' "$journal_only" \
  "$(awk -v a="$journal_only" -v b="$no_triggers" 'BEGIN {printf "%+.3f", a - b}')"
printf '  none mirrored   %8s ms   (log triggers, no vault mirrored anywhere: %s ms)\n' "$none_mirrored" \
  "$(awk -v a="$none_mirrored" -v b="$journal_only" 'BEGIN {printf "%+.3f", a - b}')"
printf '  not mirrored    %8s ms   (log triggers on a vault not mirrored, another one is: %s ms)\n' "$not_mirrored" \
  "$(awk -v a="$not_mirrored" -v b="$journal_only" 'BEGIN {printf "%+.3f", a - b}')"
printf '  mirrored        %8s ms   (log triggers on a mirrored vault: %s ms)\n' "$mirrored" \
  "$(awk -v a="$mirrored" -v b="$journal_only" 'BEGIN {printf "%+.3f", a - b}')"
printf '  held elsewhere  %8s ms   (no vault mirrored, a copy held elsewhere; the backstop: %s ms over none mirrored)\n' \
  "$held_elsewhere" "$(awk -v a="$held_elsewhere" -v b="$none_mirrored" 'BEGIN {printf "%+.3f", a - b}')"
printf '  without 165     %8s ms   (none mirrored, 165 dropped; the backstop on every server: %s ms)\n' "$without_165" \
  "$(awk -v a="$none_mirrored" -v b="$without_165" 'BEGIN {printf "%+.3f", a - b}')"
printf '  log rows per seal: %s; sequencer: %s rows numbered in %s ms (%s us per row)\n' \
  "$(awk -v r="$mirror_rows" -v t="$((TX * RUNS))" 'BEGIN {printf "%.2f", r / t}')" "$rows" \
  "$(awk -v n="$seq_ns" 'BEGIN {printf "%.1f", n / 1e6}')" \
  "$(awk -v n="$seq_ns" -v r="$rows" 'BEGIN {printf "%.1f", r ? n / 1e3 / r : 0}')"
