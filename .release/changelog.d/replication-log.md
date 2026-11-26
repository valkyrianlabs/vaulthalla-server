- Replication log of a mirrored vault, core side (migration 160_replication_log.sql; design/peers/mirror.md "As
  built: the replication log"): mirror_vault (role, term, sequence, acknowledged position, running digest),
  mirror_entry_hash and vault_replication_log, written by triggers on fs_entry, files, directories, symlinks,
  files_trashed, the vault settings tables and vault_keys in each mutation's transaction, only for a vault whose
  mirror_vault role is core (none yet). Rows are self-contained states named by permanent ids, accounts as (home node,
  id); ops upsert, move, trash, restore, purge, delete, vault, key; vh.mirror_apply silences them.
  - mirror::Sequencer (service MirrorSequencer) numbers whole transactions per vault in commit order, gap-free, and
    keeps the running digest; db::query::mirror::Log::groupsAfter reads whole groups; the Janitor prunes after 30 days
    or 5,000,000 rows, never past the mirror's acknowledgement. Entry hash and digest defined in mirror/Hash.hpp with a
    test vector. Internal API only: no ws, CLI or peer command.
  - tools/contracts/test_replication_log_contract.py; tools/dev/bench/replication_log_cost.sh measures the trigger cost.
