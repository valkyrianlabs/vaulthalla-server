# Filesystem change journal (`fs.changes.*`, #259/#260)

Sync clients ask "what changed in this vault since revision N" instead of re-listing folders. The first consumer is
Vaulthalla Desktop's File Provider (working set and sync anchors, desktop#1 Stage D; its background agent, desktop#5,
polls first and switches to push once a server has #260). Design decided 2026-11-01 (the `needs:review` label on #259
was an agent's, not Cooper's; this records the reviewed scope).

## Journal (migration 115)

- **Triggers write it, in the mutation's own transaction.** Every write path (FUSE seal, the HTTP/ws upload lanes'
  `createFile`, ws mutations, copy, trash, sync, recovery, a symlink, psql by hand) changes `fs_entry` / `files` /
  `directories` / `symlinks`, and row triggers on those tables insert into `fs_change_log`. No C++ write path calls the
  journal, so none can forget it, and the FUSE code is untouched (`fuse/` has no journal hook). The seal pays one
  trigger call and one insert (benchmark below).
- **Kinds.** `create`: a `files`/`directories`/`symlinks` row is inserted (the entry exists as that type; `fs_entry`
  inserts alone are not logged, the type row follows in the same statement). `update`: a file's size, hash or MIME
  type changes, or a new IV under the same key version (a seal); a symlink's target; an entry's `mode` or
  `is_hidden`. `rename`: new name, same parent. `move`: new parent (or vault). Both carry `old_path` and
  `old_parent_id`. `delete`: `BEFORE DELETE` on `fs_entry` (the type rows still exist then; a cascade logs each
  descendant). The trash statement deletes the `files` row first, so a delete with no type row left is a file.
- **Not journaled** (the `WHEN` clauses skip them without calling plpgsql): directory totals, `updated_at`,
  `last_modified_by`, `inode`, `base32_alias`, path-only updates (an ancestor's rename rewrites descendants' paths;
  their id and parent stay), owner uid/gid, key rotation (IV and key version change together), the vault root, and
  deletes of a deleted (soft or purged) vault's entries.
- **Revisions are commit order, without a lock on the write path.** Writers insert with `revision` NULL.
  `ChangeLog::sequence()` takes `fs_change_revision`'s row lock and numbers the committed pending rows in id order
  (batches of 10k). A transaction that commits later is numbered by a later pass, so a reader that has seen R never
  gets a row below R afterwards; two changes to one entry can't commit out of insertion order (the entry's row lock).
  A per-vault counter row (the identity_change_log pattern, migration 108) was rejected: every writer would hold it to
  commit, and `add_to_ancestor_dir_stats` locks directory rows before `fs_entry` in the same statement, so a writer
  doing that first and one inserting first could deadlock.
- **Resets** are `kind = 'reset'` rows with `vault_id`/`user_id` (NULL = every vault / everyone), logged by triggers on
  the authorization rows that decide filesystem Lookup: `vault_role_assignments` (its vault; the user, or everyone
  for a group), `vault_permission_overrides` (the assignment's), `vault_role` updates (every vault using it),
  `user_global_vault_policy`, `group_members`, `admin_role_assignments` (that user, every vault), `admin_role` updates
  (its holders) and `vault.owner_id`. They are the "vault epoch": a cursor older than a reset that concerns the caller
  and vault is expired. Resets are numbered like changes, so the same commit-order argument holds.
- **Retention** (`db::Janitor`, every DB sweep): numbered rows older than 7 days or more than 1,000,000 revisions
  behind are deleted and `pruned_through` raised; pending rows are never pruned. No foreign keys: rows outlive their
  entry and vault until then.

## `fs.changes.list {vault_id, since?, limit?}` (`ops::fs_changes`)

- Needs filesystem List on the vault root (`canFollow`, the browse rule of `storage.vault.accessible.list`); Denied
  otherwise, NotFound without a live engine. Human (web) and Device sessions; not share sessions.
- Sequences first (read-your-writes), then reads `revision > since` for the vault, oldest first, up to `limit`
  (default 1000, max 10000). The answer's `revision` is the cursor: the last row read when `more`, else the watermark
  read before the rows (anything numbered later is above it). Filtering never stalls the cursor: it advances past
  rows the caller doesn't see.
- **Without `since`**: the current revision and no changes, the anchor a client takes before its first enumeration.
- **`expired: true`** (with the watermark as `revision`, no changes) when `since` is below `pruned_through` (checked
  again after the rows are read, so a concurrent prune can't silently skip rows), above the watermark (another
  database, a restore), or older than a reset for this vault and account. The client enumerates again and continues
  from that revision.
- **Visibility.** Each change is judged by `rbac::fs::visibility::canLookup` on a stand-in entry of its type at its
  path (a deleted entry has no other), with the `seesWholeSubtree` fast path on the vault root (owner, super admin, no
  reaching override). A rename/move visible only after reads as `create`; visible only before, as `delete` at the old
  path; neither, it is left out.
- Contract: ws book `fs.changes.list`, model `FsChange` (`ops::fs_changes::toJson`).

## Proof

- `FsChangeJournalDbTest` (`core/tests/unit/test_fs_change_journal.cpp`, db-only): every write path's statements,
  symlinks and out-of-band SQL, commit order with a writer that commits after a later one, paging, Lookup filtering
  across a deny line, cursor expiry (override, role template edit, retention, a future revision), the ws shape.
- `tools/contracts/test_fs_change_journal_contract.py`: triggers on every entry table, every SQL writer of them in
  `core/src` classified (a new one fails until it is), no trigger bypass (`session_replication_role`, `DISABLE
  TRIGGER`, `TRUNCATE` of an entry table) outside the test-only schema wipe, no direct delete of folder/symlink type
  rows.
- Benchmark: `tools/dev/bench/vhbench.py run --only seal` (FUSE create/overwrite of 4 KiB files, each sealed on close),
  origin/main vs this change on the dev VM: see "Seal benchmark" below.

## Seal benchmark

Pending.
