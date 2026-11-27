# Server mirror: one vault on two linked servers

Status: design, phase 0 of the server mirror plan (2026-11-25). Built so far: permanent ids for every entry (phase 1b,
migrations 158/159), the core side of the replication log (phase 2 piece 1, migration 160; "As built: the
replication log" below) and the sealed contents lane with the mirror's receive path (phase 2 wave 2, migration 161;
"As built: sealed contents" below) and following the core (phase 2 wave 3 piece B, migration 164; "As built: following
the core" below), the write gate (phase 2 wave 4 piece A, migration 165; "As built: the gate" below) and changes made
on the mirror without contents (wave 4 piece B, migration 166; "As built: a change made on the mirror" below), resync,
the scrub and the planned switch (wave 5 piece B, migration 168; "As built: resync and the scrub", "As built: the
planned switch" below), and leaving a mirror: detach, deleting a mirrored vault in one step, versions on the mirror
(wave 5 piece A, migration 167; "As built: leaving a mirror" below). The rest is not implemented. It covers how a vault
is kept identical on two linked servers: the core role, the replication log, applying it, changes made on the
mirror, behaviour while the link is down, moving the core, leaving a mirror, and vaults that also have a remote. The
link is in [`link.md`](link.md); accounts, ownership and audits are in [`identity.md`](identity.md). Section "What
the spikes found" records what was checked in the code before this was written.

## Decided and given

All by Cooper, 2026-11-25:

- **A server mirror is a first-class sync between two servers' local copies of a vault,** separate from remote sync.
  Files and database entries go directly between the servers, so mirroring never causes egress from a bucket.
- **Each mirrored vault is owned by one core server.** Remote sync runs only there; a change made on the mirror is
  sent to the core, which handles the remote.
- **Strict first:** while the link is down, the mirror's copy is read-only. Queued offline changes are a later,
  per-vault option.
- **The detach guarantee:** a mirror can detach, or detach a copy, and take ownership of the files on its own node
  without the core's permission, including when the core is gone. It may be its own permission.
- **Keys go over the link;** the compared pairing code is the proof (`link.md`).
- **Not the core's database:** the mirror keeps its own database, files and inodes (plan revision 3, accepted).

## Terms

| Term | Meaning |
|---|---|
| **Core** | The one server where every change to a mirrored vault commits first, in one order |
| **Mirror** | The other server. It holds a full local replica and follows the core's order |
| **Term** | A counter that increases each time the core role moves. With a sequence number it orders every change: `(term, seq)` |
| **Group** | The changes of one database transaction on the core. Applied on the mirror in one transaction |
| **Pending** | A change made on the mirror that the core has not yet confirmed |
| **Held change** | A change the core refused, kept on the mirror outside the vault until a person deals with it |

## What the spikes found

Four code spikes ran before this document was written. Their results shape the design below.

1. **The filesystem change journal cannot be the replication stream.** `fs_change_log` rows carry local integer ids
   and paths, no permanent ids, and no transaction grouping; its revisions come from one counter for the whole
   server; a `delete` row cannot lead back to a permanent id; and it deliberately omits modification time,
   attribution, key rotation, and the difference between trash and purge (`deploy/psql/115_fs_change_log.sql`). It
   stays what it is: each server's feed for its own clients.
2. **Folders and symlinks have no permanent id on local vaults.** `directories.uid` and `symlinks.uid` are nullable
   and are filled only when a manifest is collected for an encrypted bucket vault
   (`deploy/psql/125_manifest_v2.sql:53-56`, `core/src/db/query/sync/Manifest.cpp:65-86`). `files.object_uid` and
   `vault.uid` are NOT NULL everywhere. (Resolved in phase 1b: "Permanent ids for every entry" below.)
3. **Sealed bytes are portable for every vault type.** Every local backing file is ciphertext, including the local
   copies of an S3 vault whose bucket holds plaintext. A VHF1 header binds the vault uid, object uid, key version
   and salt and nothing host-specific. Files still in the older `gcm0` format bind nothing and are not portable
   as they are; attach-remote already refuses them (`core/src/db/query/vault/RemoteAttach.cpp:347-356`).
4. **A file's `content_hash` is BLAKE2b over the sealed bytes** (`core/src/fuse/WorkingCopies.cpp:385`), so a
   receiver can check a transfer before using any key, and `content::verifyFile` authenticates header and chunks
   with the key (`core/include/vault/Content.hpp:142-149`).
5. **Proving a key version across servers already exists.** `vault::recover::prove` checks a key against an
   attestation by another node's pinned key and refuses self-attested versions (`core/include/vault/Recover.hpp:105-135`).
   An attestation signs the originating node id, its numeric vault id, the version and the key check
   (`core/include/vault/KeyAttestation.hpp:17`).
6. **Nothing freezes local writes today.** `vault.allow_fs_write` is loaded and serialised and read by no write
   path. The strongest per-vault gate, `storage::remote_access`, stops bucket requests only. There is no single
   chokepoint: FUSE, ws, HTTP, the CLI, shares and the S3 gateway each authorise for themselves, and FUSE flush and
   release seal with no check at all.
7. **File operations are not in the operation layer.** mkdir, move, rename, copy, delete and upload-commit live in
   the ws handler, the HTTP lanes, the CLI and FUSE (`core/src/protocols/ws/handler/fs/Storage.cpp:370-729`). There
   is no `ops::fs`. Quota is checked by some callers and not by `Filesystem::createFile`.
8. **There is no keep-both conflict copy.** `KEPT_BOTH` is a TODO (`core/src/sync/Planner.cpp:199`), and the conflict
   records are tied to the cloud sync engine (`sync_conflicts.event_id`, `ConflictResolver` taking a `CloudEngine`).
9. **A local vault's engine cannot serve a file whose bytes are not on disk** (`core/src/storage/Engine.cpp:115-121`);
   only `CloudEngine` hydrates.
10. **Rotation re-seals with a fresh random salt per file and reads each file whole into memory**
    (`core/src/sync/rotation/Rotation.cpp:76-129`). Nothing changes a vault's uid today.
11. **The merge rules work on trees read from two databases; the applier does not.** Run on dev at 5aa0b231
    (v1.26.1), in a DB-backed test on a local vault ([`spikes/`](spikes/README.md)):
    - `Manifest::collect` and `vl::vaultfmt::manifest::reconcile` produced the expected plan and conflicts (edit
      beats delete, edit beats trash, name clash renamed, cycle not applied), and a second run produced an empty
      plan. **Passed.**
    - The existing applier, run on the same local vault, reported the peer's delete and edit as "kept" and left
      them unapplied, and created files as rows with an empty generation and no bytes. **Failed.** Its
      compare-and-set reads the generation from `remote_object_index` (`Applier.cpp:93,131-136,270`), which a local
      vault does not have, and its create binds an `o/<uid>` object that does not exist.
12. **`collect` describes a local file by key version, size and content hash only.** Its `generation` comes from the
    bucket index (`core/src/db/query/sync/Manifest.cpp:522-545`). It also emits created and modified times and
    Linux owner ids, which the merge compares by equality, and the applier never writes a created time
    (`ManifestApply.cpp:239-249`), so two servers whose times differ would see the same attribute operation on every
    merge.

## The replication log

A dedicated log, written only for mirrored vaults, on the core.

```sql
vault_replication_log (
  id            bigserial primary key,  -- insertion order (the sequencer's tie-break)
  vault_id      integer not null,
  term          bigint  not null,
  seq           bigint,                 -- assigned in commit order by the sequencer; NULL until then
  txid          bigint  not null,       -- groups the rows of one transaction
  op            text    not null,       -- upsert | move | trash | restore | purge | delete | vault | key | history
  entry_uid     uuid,
  entry_type    text,                   -- file | directory | symlink
  parent_uid    uuid,
  name          text,
  state         jsonb   not null,       -- the entry as this change left it (below)
  entry_hash    bytea,                  -- of the new state; NULL for a removal
  prev_hash     bytea,                  -- of the state it replaced; NULL for a creation
  actor_node    text,                   -- the acting account's home server's node id (this server's for a local one)
  actor_id      integer,                -- and its id there
  origin        text,                   -- a mirror's request id when the change was submitted by it
  logged_at     timestamptz not null,
  unique (vault_id, term, seq) where seq is not null
)
```

- **Written by triggers, in the mutation's own transaction,** like `fs_change_log`, so no write path can skip it,
  including one made by hand in psql. The triggers return at once for a vault that is not mirrored.
- **Copied verbatim, never recomputed.** Every uid, time, owner id, generation and hash on the mirror is the core's
  value. The mirror assigns none of them. This is what makes the digest comparable and a later merge meaningful
  (spike finding 12).
- **Self-contained rows.** `state` is the entry's row as the transaction left it: parent uid, name, type, mode,
  hidden flag, owner uid and gid, created and modified times, creator and last modifier (each named by its home
  server's node id and its id there, `identity.md`), and for a
  file its size, content hash, MIME type, generation (the header salt), key version and content format; for a
  symlink its target; for a trashed file who trashed it, when, and its last path. A consumer never has to read the
  core's current state to apply a row, which is what makes strict in-order replay correct.
- **What gets a row that `fs_change_log` omits:** modification time, attribution, owner, a key-version change, the
  move to trash, the purge, vault settings (`op = vault`: name, description, quota, the sync and recovery
  policies), and key records (`op = key`).
- **Groups.** Rows of one transaction share `txid`. The sequencer numbers whole groups, never part of one, and a
  reader sees a group only when all of it is numbered. `(term, seq)` is per vault and has no gaps, so a missing row
  is detectable by counting.
- **Retention:** 30 days or 5,000,000 rows per vault, whichever is smaller, and never past what the mirror has
  acknowledged while the link is up. A mirror that falls behind retention resynchronises (below).
- **Cost.** One more trigger insert on the seal path, for mirrored vaults only. The budget is the one measured for
  migration 115 (about 0.3 ms per operation). Measured for migration 160: "As built: the replication log", Cost.

### Permanent ids for every entry

A migration assigns `directories.uid` and `symlinks.uid` at insert for every vault, backfills existing rows and
trashed rows, and makes the columns NOT NULL. The lazy assignment in `Manifest::collect` is removed. This is a
prerequisite for everything below, and it also benefits attach-remote and the manifest.

As built (phase 1b, migrations 158/159): every insert of a folder, symlink or snapshot draws its uid from libsodium
(`db::query::fs::Directory`, `::Symlink`, `db::query::recovery::Snapshot`, the applier and vault restore, which already
did); 158's data step backfilled existing rows without touching a uid that was set; 159 made `directories.uid`,
`symlinks.uid` and `recovery_snapshot.uid` (the snapshots' lazy assignment went too) NOT NULL. `Manifest::collect`
runs in a read-only transaction. Trashed files: a row without `object_uid` got one, except on an opaque_v1 vault,
where the bucket names the trashed object by a uid the database no longer holds (rows from before 125); those keep
NULL, stay out of the manifest as before, and are still restored and purged by path. `files_trashed.object_uid` stays
nullable for them (deviation from "NOT NULL" for trash).

### As built: the replication log (phase 2 piece 1, migration 160)

The core side only: the tables, the triggers, the sequencer, the reader, the digest and retention. No wire protocol,
no applier, no command: nothing makes a vault mirrored yet but tests and the internal `db::query::mirror` API.

- **`mirror_vault`**, one row per mirrored vault: the peer, this server's role (`core`, `mirror`, `orphaned`), the
  term, `last_seq` (core: the last row numbered; mirror: the last applied), the position the mirror acknowledged
  (`acked_term`, `acked_seq`), how far retention pruned, the running digest and its entry count, the state (`live`,
  `paused`, `diverged`) and timestamps. A `core` row is what switches the log on. `MirrorVaults::startCore` takes the
  baseline (per vault since 164: "As built: following the core"; as first built:) under a SHARE lock on the entry tables (writers wait for the time it takes to hash the vault; each wait
  for a writer already running is capped at 200 ms and retried, so it never sits in a deadlock with one) it records
  every entry's hash and the tree's digest, so no change is half in the baseline and half missing from the log.
- **Triggers** on `fs_entry` (update, delete), `files`, `directories`, `symlinks` (insert, delete; files and
  symlinks update), `files_trashed` (insert, update, delete), the settings tables (`vault`, `sync`, `fsync`, `rsync`,
  `vault_recovery_policy`) and `vault_keys`. For a vault with no `core` row they return after one lookup; with none
  anywhere (every server today) after a read of the empty `mirror_vault`. `tools/contracts/test_replication_log_contract.py`
  keeps every SQL writer of these tables classified and nothing but `db::query::mirror` writing the log or setting
  `vh.mirror_apply`.
- **Ops.** `upsert` (created, or changed in place), `move` (an existing entry's parent or name), `trash` (one row: the
  live entry's delete in the same transaction is folded into it, whichever of the two statements came first),
  `restore` (a trash row ends while a live file of the vault holds its uid: the transaction's `upsert` of that file
  becomes the restore), `purge`, `delete` (a live entry removed without the trash), `vault`, `key`. A row is written
  only when the entry's replicated state changed, so path-only rewrites, inodes, aliases and totals write nothing.
- **Accounts** are `(home node, id there)` everywhere: `actor_node`/`actor_id`, and `created_by`, `modified_by` and
  `trashed.by` in the state as `{node, id}` (this server's node id and `users.id` for a local account, `home_node`
  and `home_id` for a remote one). The actor is the transaction's `vh.actor` (users.id) when a write path sets it
  (none does yet; `ops::fs` will), else the row's own attribution (creator, last modifier, who trashed it), else
  none (a delete). `origin` is the transaction's `vh.mirror_origin` (set by the submit path, later).
- **State documents** (`vh_mirror_entry_state`, `vh_mirror_trash_state`, `vh_mirror_vault_state`,
  `vh_mirror_key_state`): an entry's uid, type, parent uid, name, mode, hidden flag, owner uid and gid, created time,
  modified time (not for a folder, below), creator, last modifier; a file's size, content hash, MIME type,
  generation (`files.encryption_iv` as stored), key version and content format; a symlink's target; a trashed file's
  size and `trashed: {path, at, by}` (all `files_trashed` holds). Times are microseconds since the epoch. A vault
  row carries name, description, quota, owner, the deleted flag, the sync policy and the recovery policy; a key row
  the version, key check, attestation, the attestation key's public half and the creation time, never key material.
- **The entry hash** is SHA-256 over a canonical encoding of exactly the replicated fields, defined with a test
  vector in `core/include/mirror/Hash.hpp` and computed identically by `vh_mirror_state_hash` (checked against each
  other in `MirrorReplicationLogDbTest`). **The digest** is the per-word sum, modulo 2^64, of the entry hashes read as
  four big-endian 64-bit words, with an entry count; `Log::sequence` moves it by `+entry_hash - prev_hash` as it
  numbers groups, `Digests::recompute` (the scrub) recomputes it from the tables (`vh_mirror_tree`), and
  `Digests::stored` sums the last-recorded entry hashes.
- **`mirror_entry_hash`** keeps every entry's hash as the log last recorded it. It supplies `prev_hash`, and it makes
  a statement that touches two tables of one entry (fs_entry and files in one CTE, whose row triggers fire at the end
  of the statement) log one exact before/after pair. A change to an entry's type row first takes the entry's
  `fs_entry` row lock, so two transactions changing different tables of one entry log in lock order and each sees
  the other's committed half.
- **Sequencer** (`mirror::Sequencer`, service "MirrorSequencer", every 250 ms; one read of the empty pending index
  when nothing is mirrored): per vault under its `mirror_vault` row lock, it numbers whole groups (at most 10,000
  rows a transaction; a larger group alone), ordered by each group's last row. That is commit order wherever order
  matters: a transaction that had to wait for another's row lock wrote its last row after the other committed.
  `(term, seq)` counts rows, consecutive within a group and with no gaps. Rows stamped with an older term, or of a
  vault that is no longer this server's core, are left unnumbered (a term change drains the log first, "Planned
  switch") and swept by the Janitor.
- **Reader** `Log::groupsAfter(vault, (term, seq), limit)`: whole numbered groups after the position, a page never
  ending inside a group (a first group larger than the limit comes whole), `more`, and `expired` for a position below
  retention, above what was numbered, or on a vault that is not this server's core.
- **Retention** (the Janitor): numbered rows older than 30 days or more than 5,000,000 behind the newest go, never one
  the mirror has not acknowledged and never part of a group; pending rows never. Rows and entry hashes of a vault
  with no `core` row are removed.
- **Cost**, measured on the dev VM (`tools/dev/bench/replication_log_cost.sh`: one FUSE seal's statements per
  transaction, pgbench, the median of three runs of 3,000, 2026-11-25, PostgreSQL 16 as Ubuntu 24.04
  packages it):

  | Per seal (files row, the entry's mtime, four ancestors' totals) | ms | of which triggers |
  |---|---|---|
  | No triggers | 0.315 | |
  | The journal (115) only: the state before this change | 0.424 | journal +0.109 |
  | With 160, no vault mirrored anywhere (every server today) | 0.497 | log +0.073 |
  | With 160, this vault not mirrored, another one is | 0.514 | log +0.090 |
  | With 160, this vault mirrored (2 log rows per seal) | 1.017 | log +0.593 |

  The sequencer numbers about 9 us a row (18,000 rows in 168 ms). On the FUSE path a seal is 12 to 15 ms of wall
  time (encryption and fsync, "Seal benchmark" in `.claude/context/change-journal.md`), so a mirrored vault's seal
  costs about 4 % more and every other vault's nothing measurable. The builders are plpgsql and the hash a single
  inlined expression: as SQL functions planned on every call, the mirrored seal cost 1.7 ms of triggers.

Deviations from the sketch above, forced by the code or decided while building it:

1. **Primary key.** `seq` is NULL until numbered and cannot be in a primary key: rows have an `id`, and
   `(vault_id, term, seq)` is unique among numbered rows.
2. **`actor_node` is never NULL for a known account:** a local account is named by this server's node id, so a row
   reads the same on both servers.
3. **A folder's modification time is not replicated** (not in its state or hash): the totals statements stamp every
   ancestor on every change below it, which would write a row per ancestor per seal. The mirror's own totals stamp its
   folders the same way. Directory totals are derived and not replicated either.
4. **Rows are not merged within a group:** an entry changed by several statements of one transaction has several rows
   (each with the state at that point and a chained `prev_hash`). A consumer applies a group as a whole: per uid the
   first row's `prev_hash` is the compare-and-set and the last row's state the result. A cascade logs the folder
   before what is under it.
5. **Vault settings and key records are not in the digest** (it covers entries: live entries and trashed files). A
   `vault` row's `entry_uid` is the vault's uid.
6. **Trashed files without an object uid** (opaque_v1 rows from before 125) are not entries of the log or the digest,
   as they are not of the manifest; starting a mirror will have to refuse or convert them.
7. **Retention never passes the acknowledged position,** link up or down (the sketch allows passing it while the link
   is down). A mirror that never acknowledges holds the log; ending the mirror (later) or `MirrorVaults::remove`
   releases it.
8. **Every folder rename re-stamps what is under it:** `Filesystem::rename` rewrites each descendant with a new
   modification time and last modifier (existing behaviour), so a folder move is one group with a row per entry under
   it, not one row.

**Known limit (fixed in wave 4, "As built: the gate"): FUSE `utimens`, `chmod` and `chown` never reached the database.** `fuse::setattr`
(`core/src/fuse/Bridge.cpp`, the `FUSE_SET_ATTR_ATIME`/`MTIME` branch) sets the backing file's times with
`utimensat` and re-stats it for the reply; mode, uid and gid only log "no-op" (`warnSetattrMetadataNoOpOncePerMinute`).
No row changes, so no trigger fires: neither the journal nor the replication log sees a `touch -d` or a `chmod`
through the mount, and the next getattr after a cache refresh answers from the row again. Recommended fix, for the
`ops::fs` piece: setattr writes `fs_entry.updated_at` (with `vh.keep_mtime`) and mode/owner through the operation
layer, under Write (mode, times) and the owner rules, in one transaction; the log then records it like any other
attribute change.

## Starting a mirror

1. **Preconditions on the core's vault.** Not already mirrored; not bucket-replicated (`vh vault join`); no attach,
   detach, layout migration or key rotation in progress; not pending deletion; no file in `gcm0` or non-empty
   `plain` format (the format conversion runs first); every key version in use attested by this server.
2. **The offer.** A super admin on the core, or a person the access list lets manage the vault, picks a linked
   server (`mirror.add`). The core sends `peer.mirror.offer`: vault uid, name, size, file count, whether history is
   included, and the role it proposes for the mirror server.
3. **Acceptance.** The mirror accepts automatically if its link is set to accept every vault from that peer;
   otherwise a super admin there accepts. It checks free space first.
4. **Keys.** The core delivers every key version the vault's files, versions and trash use: each wrapped in a KEV1
   envelope to the mirror's wrap key, with its key check and the core's attestation. The mirror runs
   `vault::recover::prove` against the attestation key it pinned at pairing, seals the keys under its own master,
   records their origin, and acknowledges. An unprovable version stops the mirror from starting; nothing is written.
5. **The first copy.** The core sends its tree as of `(term, seq)`. The mirror creates the vault with the core's
   vault uid, as a local vault with a mirror record, and inserts every entry with its uid and generation. Every file
   starts with its content **not yet received**.
6. **Contents** are fetched in the background (below), files a person opens first.
7. **From `(term, seq)` on,** the mirror follows the log.

A vault's first copy is resumable at every step and can be cancelled from either side, which removes what was
created on the mirror.

### How much the mirror holds

- **A vault with no remote, or whose strategy keeps everything on disk** (`sync`, `mirror`): the mirror holds every
  file. Nothing to choose.
- **A vault on the `cache` strategy** may have files that exist only in its bucket. The core would have to download
  them to send them, and that is egress. Starting the mirror shows the estimate from the existing price guard and
  asks: **complete copy** (download once, pay the egress) or **what the core holds** (free).
- The mirror's status always says which it is, because a detach from an incomplete mirror is incomplete
  ("Leaving a mirror").

## Following the core

- **Notice.** The core tells the mirror over the link's websocket whenever a group is numbered
  (`peer.mirror.notify {vault_uid, term, seq}`).
- **Pull.** The mirror asks for groups after the last one it applied (`peer.mirror.log`), in pages cut only at group
  boundaries.
- **Apply.** Each group is applied in one database transaction, with a session flag (`SET LOCAL vh.mirror_apply`)
  that tells the replication-log trigger these are not local changes. `fs_change_log` still fires, so the mirror's
  own clients see the change.
  - Entries are found by uid, never by path.
  - Each row is a compare-and-set against the mirror's row for that uid. A mismatch means the mirror's copy differs
    from what the core believed; the vault stops with `mirror_diverged` and reports the entry. It never guesses.
  - Renames that swap or chain names inside one group go through temporary names, because the unique
    `(parent_id, name)` constraint is not deferrable (`deploy/psql/040_files.sql:24`).
  - A file a person has open on the mirror is deferred, the way the manifest applier defers
    (`manifest_apply_deferred`, migration 146), and finished when it closes.
  - The backing file, the FUSE view and the cache are updated after the commit through the same calls a local write
    uses.
- **Acknowledge.** After applying a group the mirror reports `(term, seq)` and its digest (below).
- **Shared executors.** The manifest applier's operation executors (`core/src/sync/vault_manifest/Applier.cpp:296-326`)
  are moved into one tree-apply module that both appliers call. They lose their dependence on `remote_object_index`
  for the compare-and-set and gain uid lookups for local vaults.

### Contents

- **A sealed lane on the device listener,** for peer sessions only:
  `GET /peer/object/<vault_uid>/<object_uid>/<generation>` serves the backing file's bytes as they are, with the
  sealed length, the generation as the entity tag, and byte ranges over sealed offsets so a transfer resumes. `PUT`
  on the same address is the mirror sending a file to the core.
- **Receiving:** write to an unnamed temporary file, check the size and the BLAKE2b content hash from the log row,
  authenticate header and chunks with the key (`content::verifyFile`), compare-and-set the row to "received", then
  link the file into place. A file that fails any check is discarded and fetched again; three failures stop the
  vault and report the file.
- **"Not yet received."** The local engine gains a content state per file. Opening such a file on the mirror fetches
  it from the core ahead of the queue. With the link down the open fails with a reason, not with a generic I/O
  error.
- **Slots and pressure.** A fixed number of transfers per peer, shared between the two directions, with a person's
  open ahead of background work.
- **Never sent:** FUSE working copies, upload staging and other scratch files. They are sealed under a key that
  exists only in one process's memory.
- **Derived artifacts** (thumbnails, renders) are regenerated on the mirror; their encryption binds local ids.
- **History.** File versions, snapshot records and their blobs are the same sealed bytes and travel the same way.
  They are phase 3; until then the mirror's status says history is not mirrored.

### As built: sealed contents (phase 2 wave 2, migration 161)

The lane, the fetching client, receive-verify-link and the "not yet received" state. Not the mirror protocol: nothing
marks a file as expected in production yet (the log applier will), no `PUT`, no hydrating from a bucket, no ws
command. Decided while building (owner's instruction to build without waiting for review):

- **The address.** `GET|HEAD /peer/object/<vault uid>/<object uid>/<generation>`: the uids in their text form
  (vl-keykit base32, as object keys), the generation as the unpadded base64url of its bytes (`files.encryption_iv` is
  standard base64, with `/` and `+`), one spelling only. The entity tag is that string, quoted. No query.
- **Who gets it.** The listener hands the lane to a linked key alone, as an HTTP session with no user that serves
  nothing else; to a device, a pairing-only key, the relay or anything else the path does not exist (404). Per request,
  before a byte is read: the switch (off: 404), the row still live with the key of the handshake (else 403
  `peer_revoked`), the vault's `mirror_vault` row naming this peer whichever role this server has, core or mirror (an
  orphaned copy serves nobody; another server, no such vault or no such file: the same 404 `not_found`, so a peer
  learns nothing about vaults it is not the linked server of), the file's current generation (else 410
  `generation_not_current`), VHF1 (gcm0 or plain with bytes: 422 `format_not_portable`; an empty plain file is 0
  bytes), and the bytes on this disk at that generation's sealed length (else 404 `not_held`: a bucket-only file's
  hydration is the next piece's decision). The row is read again after the file is opened: every content replacement
  writes the row before it renames the new bytes in, so the descriptor holds the generation asked for. Unlinking
  closes the peer's lane connections with its websocket.
- **The client** (`peer::object::fetch`) dials the row's endpoints with the link's TLS context and the same pin check
  as the websocket dial (`peer::pinnedKeyOf`, now shared), asks `Range: bytes=<held>-` with `If-Range` on the tag, and
  streams the body into its sink at the sink's pace (TCP back-pressure). Every wait is bounded: a 200 ms slice for
  cancellation, a deadline for the whole call, 30 s of inactivity per step.
- **Slots.** 4 transfers per peer, both directions (only fetching exists yet); background work never takes the last
  one, and a person's open is granted before any waiting background transfer. A transfer runs on a thread the link
  service joins when it stops.
- **"Contents not yet received"** is `mirror_content_pending` (161), a side table: generation, key version, plaintext
  size, BLAKE2b content hash and modification time expected, a priority, attempts and the last error, waiting or
  failed. No column on `files`, and no foreign key to it (that would add a trigger to its delete path): a row whose
  file is gone or names another generation is dropped as superseded when next looked at. Only a vault whose role here
  is `mirror` gets rows. `MirrorVaults::remove` keeps them: they are exactly the list of missing files a detach shows.
- **Receiving** (invariant 8): an unnamed temporary file (O_TMPFILE) in the backing file's directory (a private O_EXCL
  sibling where there is none, macOS), interrupted transfers resumed by range (at most 5 per attempt), then the size,
  the BLAKE2b content hash, `content::verifyFd` with the vault key, then under the file's content lock
  (`Filesystem::contentWriteMutex`, the one overwrites, seals and rotation take) and in one transaction the
  compare-and-set (the pending row FOR UPDATE: exactly this generation, key version, size and hash, still waiting; the
  file's row FOR SHARE: still this generation), the modification time set, the bytes flushed, linked at the content
  sidecar and renamed over the backing path, the pending row deleted. A crash after the link leaves either the
  sidecar (startup recovery promotes it: it authenticates under the row) or the bytes in place with the row still
  pending (the next attempt finds them, checks them the same way and settles the row).
  **Deviation:** the binding checks the vault, the generation and the key version, not the object uid. A local vault's
  copy keeps its source's sealed bytes (`Filesystem::copy`), whose header names the source's uid under the same
  generation; binding the object would refuse every copy for good. Bytes sealed for another object carry another
  generation (a random 32-byte salt), which is refused.
- **Failures.** Counted: a refusal from the serving side, a transfer that broke off more than 5 times, and a size, hash
  or authentication failure. Not counted: the link down, cancellation, the row or the file moving on meanwhile. Three
  mark the file `failed` with the reason; it is not fetched again (by an open either) until
  `PendingContents::retry`. **Deviation from "three failures stop the vault":** they stop the file. Stopping the vault
  is the applier's decision, with the vault's state (`mirror_vault.state`), in the next piece.
- **Opening such a file** through the mount, the download and preview lanes and the ws (share) download, which all
  read through `Engine::openPlaintextReader` or the working copies' materialize hook: fetched ahead of the queue on an
  interactive slot (one transfer per file however many wait; it goes on after a waiter gives up), waiting at most
  **15 s**. With the link down (or the switch off) it fails at once, without a transfer. The reasons and the errnos
  the mount answers: link down `mirror_link_down` **ENOLINK** ("Link has been severed": exactly the case); still
  coming after 15 s `mirror_fetch_timeout` **ETIMEDOUT**; failed `mirror_fetch_failed` **ENODATA** ("No data
  available": the file is there, its contents are not). The HTTP lanes answer 503 with the code and `Retry-After`. A
  file pending for another generation than the row a reader holds is read as that row describes (the newer row comes
  with the log).
- **The mount waits for few files at once.** The mount serves every vault from one FUSE worker pool
  (`ThreadPoolManager::fusePool`, fixed at max(3 × cores, 8) / 6 workers: 2 on a host of up to 4 cores, 9 on 18), so
  a recursive reader on a freshly mirrored vault (an indexer, `grep -r`, a backup) could otherwise park every worker on
  a fetch and stall the whole mount for 15 s at a time. At most a quarter of the pool (at least 1, at most 4:
  `mirror::contents::mountWaitCap`) of mount opens wait at once; that leaves three quarters (half on the smallest hosts)
  serving every other request. An open over the cap still starts or joins its file's fetch ahead of the queue, so
  opening it again soon succeeds, and answers ETIMEDOUT at once. The place is held only while waiting and given back
  on every way out. The HTTP, ws, CLI and S3 paths run on threads of their own and keep the full 15 s wait.
- **Proof split.** Two daemons over a real link (`vhh drill peers`, step 6): one serves a real sealed file of a vault
  it holds (its `mirror_vault` row written by hand: no command makes a vault mirrored yet), the other fetches it with
  the real client, broken off and resumed by range, byte for byte; refusals of a stale generation and of a vault the
  fetcher is not the linked server of. The fetching daemon cannot hold the same vault yet (key delivery and vault
  creation are the next piece), so receiving into a vault is proven in process with a test source of bytes
  (`MirrorContentsDbTest`).

### As built: starting a mirror (phase 2 wave 3, piece A, migration 163)

Steps 1 to 4 of "Starting a mirror", the vault-creation half of step 5, the grant, cancelling, the rotation refusal and
the background contents worker. The tree, its first copy and following the log are piece B (same wave). Decided while
building (owner's instruction to build without waiting for review):

- **The protocol** (`mirror/start/Start.hpp`). Each side keeps one `mirror_offer` row per start (migration 163; the two
  rows share `offer_uid`). Core: `offered` → `accepted` → `keys_acked` → `started`; mirror: `pending` → `accepted` →
  `installed` → `started`; either: `declined`, `cancelled`, `expired`, `failed`. A `notify` flag marks a state the
  other server has not been told; the `MirrorStarter` service (1 s, woken by every operation) tells it while the link
  is up and again after a restart, waits 5 s after a request that got no answer, and never holds a lock while it waits
  (the wire handlers run on the link's two io threads and only change rows). Messages: `peer.mirror.offer` (vault uid,
  its numeric id on the core, its root folder's uid, term, name, description, quota, size, file count, `history`
  false, owner as home node and id with a display name, the proposed role), `peer.mirror.answer`, `peer.mirror.keys`,
  `peer.mirror.begin` (term, grant), `peer.mirror.grant`, `peer.mirror.cancel`. `LinkService::request` (new) sends a
  request over the kept connection and waits.
- **Where the core row comes from.** The mirror writes its vault and its `mirror` row in the transaction that installs
  the keys; its answer to `peer.mirror.keys` is the acknowledgement. Only then does the core call
  `MirrorVaults::startCore`, and it sends `peer.mirror.begin` until it is answered. So the core never has a `core`
  row whose mirror does not already hold the vault, its keys and its own row; a crash after `startCore` resends the
  begin (startCore is not repeated), a crash before it repeats it. A crash on the mirror after the commit and before the
  answer: the core sends the keys again and gets the same answer.
- **Preconditions**, each an `ops::Refused` code: `mirror_already` (mirrored, or held here as another's copy),
  `mirror_start_running`, `vault_replicated`, `vault_attach_running`, `vault_detach_running`,
  `layout_migration_running`, `key_rotation_running`, `key_salvage_running`, `vault_pending_deletion`,
  `vault_unavailable`, `legacy_content` (gcm0, or plain with bytes), `key_version_missing`, `key_version_unattested`,
  `trashed_without_uid` (as-built note 6 for migration 160: refused, not converted), `contents_not_held` (a file whose
  bytes are not on this disk at its generation's sealed length: "download them first"; the "complete copy or what the
  core holds" choice is not built), and on the link `peer_not_linked`, `peer_link_down`. An S3 vault is accepted when
  every file is on disk (remote sync stays on the core).
- **Which key versions go:** every version live files are sealed under, the current one, and every retired version this
  server still holds (trashed files record no key version, so all retained ones go). History is not mirrored, but a
  retained version a snapshot needs goes with the rest. Each is wrapped in a KEV1 envelope (suite X25519) to the
  peer row's `wrap_public_key`, with this node's key check over its own vault id and a fresh attestation by this node
  (`attestation::provenanceOf`), and the attestation key's public half.
- **The proof** on the mirror: `vault::recover::prove` with the evidence's node id taken from the peer row (never from
  the payload), the core's vault id from the offer, and the pins = the peer row's `attest_public_keys` (what pairing
  bound into the code); this server's own attestation keys are passed as self keys, so a self-attested version is
  refused. An envelope for another recipient or vault, a version mismatch, a wrong key check, an attestation by
  another key, or no (or more than one) current version refuses the **whole** start: the mirror's offer becomes
  `failed` (`mirror_keys_unproven`, the reason kept), the core's too (`mirror_keys_refused`), nothing of the vault is
  written. Pairing pins what this needs: no weakening.
- **The mirror's vault**, one transaction (`MirrorStart::createMirrorVault`): a local vault with the core's uid, name,
  description and quota; its root folder carries **the core's root uid** (so piece B's tree starts from the same root);
  no other entries; the owner is the remote account for (home node, id) (`users.remote`, created when missing), or the
  local account itself when the owner's home is this server; each key version sealed under this host's vault master,
  with this node's provenance over the new vault id (`vault_keys`, retired ones in `vault_keys_trashed`) and its origin
  (`vault_key_origin`, anchor `peer`: migration 163 widens the CHECK); the `mirror` row with no grant (rbac::mirrored:
  nobody has access); the offer `installed`. Then the engine starts (`reinstateVault`).
- **A name clash is refused, not renamed** (`mirror_name_taken`: any live vault here with that name, case and spaces
  aside), so nobody can mistake one for the other in the mount or a list; rename this server's vault and accept again.
  Also refused: a uid this server holds (`mirror_vault_exists`), `history: true` (`history_not_supported`), and a
  volume (the backing path) with less free than the vault's size plus max(256 MiB, a tenth of it) (`mirror_no_space`).
  Checked at the offer (declined at once, the core told), again at accept (the offer stays pending) and again at the
  keys.
- **Accept every vault** from a linked server: `peer.accept_vaults` (163, default off, who and when), set by a super
  admin here (`vh mirror accept-all <server> on|off`, ws `mirror.accept_all.set`), audited `mirror.accept_all.set`.
- **Lifetime.** An offer nobody answered (core `offered` or `accepted`, mirror `pending` or `accepted`) expires 7 days
  after it was made, on each server by its own clock (`offer_expired`; the other server is told). Once the keys are
  installed nothing expires: cancel ends it. Finished rows are swept 30 days after they ended, except a `started` row
  whose vault is still mirrored (a later cancel tells the other server through it).
- **The grant.** The core sends `PeerVault::role(peer, vault)` (role name and its four permission masks, or null for
  nothing or `implicit_deny`) at begin, then whenever it differs from what it last sent over the current connection:
  the service compares on every pass, so every source of change is covered without a hook in each (the link's default,
  a per-vault assignment or its removal, the role's permissions edited, the role deleted), and a link-up resends it.
  The mirror records it with `granted_by_node` = the sending server's node id from its session, never a field, and
  only for a vault whose `mirror` row names that server (`not_found` otherwise).
- **Cancel** (`mirror.cancel`, `peer.mirror.cancel`; the ending rule, owner's decision of 2026-11-26, "Ending a mirror
  from the core, and deleting" above). On the core, at any step: the `core` row and the log go at once
  (`MirrorVaults::remove`), the offer becomes `cancelled` with `remove_copy` recorded, and `peer.mirror.cancel` carries
  it to the mirror, queued while the link is down. The mirror's answer carries `copy` (removed | kept | none), which the
  core stores on its offer (`copy_outcome`, shown by `vh mirror info`) and audits (`mirror.cancel.copy`). On the
  mirror: unfinished (`firstCopyFinished` false) is removed (`storage::Manager::removeVault`: rows, keys, origins,
  pending contents and the mirror row cascade, the backing directory goes, then the remote owner account when nothing
  else names it); finished with `remove_copy` and `peer.keep_vaults` off is removed; otherwise `MirrorVaults::orphan`
  and the offer ends `orphaned`. A cancel told again after that answers `kept` and changes nothing. On the mirror's
  own side, a start that has not completed (`pending`, `accepted`, `installed`) is removed and the core told; a
  completed one is refused (`mirror_detach_required`); an orphaned copy is removed (`removeOrphaned`, data-destroy
  step-up, audited `mirror.remove`). `firstCopyFinished(vault)` is the one place "finished" is decided: on this branch,
  true once the mirror's offer is `started` (or orphaned, or gone); **the lead rewires it to piece B's first-copy
  column at the merge** (erring towards "finished" errs towards keeping).
- **Keep setting:** `peer.keep_vaults` (163, who and when), `vh mirror keep-removed <server> on|off`, ws
  `mirror.keep_removed.set`; super admins; audited `mirror.keep_removed.set`.
- **Deletion refused** (`mirror/start/Guard.hpp` `refuseDeletionIfMirrored`): `ops::vaults::remove` (a live vault and
  an already deleted one; a super admin is told why even where the mirror's rule leaves no Remove permission) and the S3
  gateway's DeleteBucket (both overloads; 409 `InvalidBucketState`). Codes `vault_mirrored` (core, a start running, or
  a mirror) and `vault_orphaned_copy` (removed through `vh mirror cancel` only: one way, one step-up, one audit line).
  The retention pass only purges what `ops::vaults::remove` scheduled, and a vault pending deletion can't be mirrored.
- **Unlinked meanwhile** (`reconcileUnlinked`, every MirrorStarter pass, so every revocation path counts: `vh peer
  unlink`, `peer.unlinked`, a rotation that dropped the link): the queued notices for that server are dropped (a
  removal never delivered), its copies here become orphaned (`mirror.orphan` audited), and the mirrors this server is
  the core of with it end here (core row and log dropped, so the log is not held for a server that can't acknowledge).
  A mirror that never learns of the unlink (it was down and the notice was lost) keeps its `mirror` row until it is
  unlinked there too, then orphans it.
- **Rotation refused** (`vault_mirrored`) on both servers while the vault has any `mirror_vault` row or a core-side
  start runs: `EncryptionManager::prepare_key_rotation` (so `vh vault keys rotate`, an attach's rotation and an
  import's salvage) and `EncryptionManager::mintSalvageKey`; `vh vault keys rotate` reports it per vault. No scheduled
  rotation exists. (`mirror/start/Guard.hpp`; a test-only switch lets the replication log's own test rotate.)
- **Who may** (`ops::mirrors`): the switch, then a person (`ops::peer_policy::requirePerson`: never an agent, a scoped
  or relayed device, a linked server; `peer_forbidden`). `mirror.add` and the core's cancel: a super admin, or a person
  with the vault's admin Edit and `vault.roles.assign` on it (design decision for "a person the access list lets
  manage the vault": the rights that already decide who may hold a vault), plus the keys step-up in the console
  (target `mirror.add:<vault>`). Everything on the mirror's side and `mirror.list`: super admins. `mirror.get`: super
  admins, or on the core the vault's admin View. The MCP catalog leaves `mirror` out; the router refuses `mirror.` to
  scoped devices. Audited: `mirror.offer` (both sides), `mirror.accept`, `mirror.decline`, `mirror.keys` (versions,
  never material), `mirror.start`, `mirror.cancel`, `mirror.accept_all.set`.
- **Background contents** (`MirrorContents` service, `mirror/start/BackgroundContents.hpp`): wave 2 left no worker,
  only `fetchOutstanding`. Every 2 s, for each `mirror` vault whose link is up and that has outstanding rows, one batch
  of up to 16 files on a transfer thread (`Transfers::spawn`, joined when the link service stops) through
  `fetchOutstanding` (background slots; a person's open always goes first). A batch that received nothing backs that
  vault off with jitter from 5 s to 10 min; a file fails for good after three attempts, so failed rows never keep it
  busy. It runs nothing with the link down or the switch off.

**What still treated the mirror's vault as an ordinary local vault** (found while building; all of it closed in wave 4,
"As built: the gate"): a super admin with a granted role that writes can write through every
surface (no gate yet; a reader grant is refused writes by RBAC, `vhh drill peers` 7f); local versioning and its
retention (`recovery/local/Versions.cpp`) run on its writes; the format conversion service would visit it (a mirror
holds only VHF1, so it finds nothing). The local sync task (FSTask) now runs none of its content-changing jobs (the
at-rest repair, the trash purge, rotation) on a vault held as another server's copy, mirror or orphaned (wave 3 join,
`MirrorStartDbTest.TheLocalSyncPassLeavesTheTrashOfAMirrorAndOfAnOrphanedCopyAlone`). `storage::Manager::removeVault` itself (the trusted primitive behind rollbacks and the
removals above) has no mirror check.

### As built: following the core (phase 2 wave 3 piece B, migration 164)

The data plane: the baseline, the first copy, serving and following the log, applying it, acknowledging with the
digest. The control plane (the offer, keys, creating the mirror's vault, the grant, cancelling) is piece A; the two meet
only at `MirrorVaults::startCore` (A calls it once the mirror has the keys) and at the `mirror` row A writes with
`startMirror` (the follower finds every such row by itself). Decided while building (owner's instruction to build
without waiting for review); each is listed for confirmation in the hand-off:

- **The baseline is per vault.** `startCore` no longer locks the entry tables server-wide. It commits the vault's
  `mirror_vault` row in a new state `starting` first; from then on a writer of that vault takes a share of the row's
  lock in its trigger (`vh_mirror_core_term`) and so waits while the baseline runs, and is logged once it has committed.
  The writers of the entry tables already running when the row committed (every holder of a RowExclusiveLock on
  fs_entry, files, directories, symlinks or files_trashed, read from pg_locks) may have changed the vault without
  seeing the row: the start waits for each to end (bounded: 200 ms x 50, then ops::Conflict "try again"). Then, under
  the row's exclusive lock, it reads the tree. A writer of another vault never waits; a writer of this one waits as long
  as the baseline takes; no change is half in the baseline and half missing from the log
  (`MirrorFollowDbTest.AWriterOfTheVaultDuringTheBaselineIsInItOrLoggedNeverBoth`). A start that crashed leaves a
  `starting` row that costs the vault's writers a share lock and is replaced by the next start. The start waits for a
  long-running writer of any vault (it cannot tell which vault an open transaction changed); it never blocks one.
- **A readable baseline: the states are kept** (`mirror_baseline`), recommended by the brief and taken as it is: in
  the same transaction that records the entry hashes, every entry's state document and hash, numbered so that a folder
  comes before everything under it (by depth) and trashed files after every live entry. The first copy pages through
  it however long it takes while the core keeps writing; the log from the baseline's position (`(term, 0)`) is held by
  retention (nothing is acknowledged yet). Dropped by the first matching acknowledgement (`baseline_rows` NULL; its
  position and digest stay for a repeated acknowledgement there) and by `MirrorVaults::remove`. A fuzzy copy plus replay
  was not taken: the log's rows chain `prev_hash` from the baseline's hashes, so a copy read at another moment would need
  a second compare-and-set rule. Cost, measured (`MirrorFollowDbTest.DISABLED_BaselineOfAHundredThousandEntries`, dev VM, PostgreSQL 16, 2026-11-26:
  100,000 entries, 100 folders of 999 files): the state documents 2.1 s, the scrub (hashing them) 11.5 s, `startCore`
  with its baseline 11.5 s. Keeping the states adds next to nothing; hashing is the whole cost (about 93 us an entry in
  SQL). As first built (a function call per entry, under the server-wide lock) the same vault took 22.7 s to hash:
  164 builds the tree's documents in one join (`vh_mirror_tree_states`), which halved it. The vault's writers wait
  those 11.5 s; no other writer waits. Recommended next (not done): hash in C++ (`mirror::entryHash`, a few us) in the
  same transaction.
- **The root folder is named by the vault's uid.** Each server gives its own vault root a uid of its own, so an entry
  directly under the root names the vault's uid (the one both servers share) as its parent in its state (164 replaces
  `vh_mirror_entry_state`). Without this no top-level entry's hash could ever agree.
- **The digest at every group's end** is written by the sequencer on the group's last log row (`digest_after`,
  `entries_after`); `MirrorVaults::digestAt` answers it, or the baseline's for its position. An acknowledgement
  (`peer.mirror.ack`) is compared there: equal, it is recorded (retention may pass it) and the baseline goes; different,
  the core stops the vault as `diverged` (`mirror_digest_mismatch`, both digests in `stop_detail`), records nothing, and
  answers `match: false`, and the mirror stops too. A position pruned since it was acknowledged answers as matching
  without comparing (a repeat).
- **The wire.** `peer.mirror.tree {vault_uid, after}`, `peer.mirror.log {vault_uid, term, seq, part?}`,
  `peer.mirror.ack {vault_uid, term, seq, digest, entries}` (the core answers) and `peer.mirror.notify {vault_uid, term,
  seq}` (the mirror wakes), on the link's websocket (`peer::LinkService::request|notify`), peer sessions only (the peer
  wire set), `peers_experimental` while the switch is off. A caller that is not the vault's linked server with the other
  role, a vault not mirrored here or no such vault: `not_found` "Not found", the sealed lane's answer. Every answer
  carries the core's state; `diverged` there stops the mirror. **Bounds:** the link takes messages of at most 1 MiB
  (`protocols::ws::Session`, `kWebSocketReadBufferMaxBytes`), so an answer stays under 768 KiB and 1,000 tree entries
  or 2,000 log rows. A log page holds whole groups only. **Deviation:** one group larger than an answer (a folder move
  re-stamps every entry under it, as-built deviation 8 of the log) comes in parts (`part {term, txid, first_seq,
  last_seq, rows, complete}`, asked again with `{txid, after_seq}`); the mirror collects them in memory and applies the
  group whole. A group of 100,000 rows holds about 60 MB in the follower while it arrives (known limit).
- **The notice** is coalesced per vault in the follower and sent from its thread (`Follower::numbered`, called by the
  sequencer after each pass), never blocking the sequencer. A lost notice costs at most the slow poll.
- **The follower** ("MirrorFollower", started after PeerLinks) visits every `mirror` row (never an `orphaned` one: while
  a vault is mirrored the mirror applies everything the core's log says, deletions included, with no safety copies;
  only an explicit act, the row ending or becoming orphaned, or an unlink, stops it matching): every second while the first
  copy is unfinished, at once on a notice or when its link comes up, every 30 s otherwise; an error backs off from 1 s
  to 60 s; a visit applies for at most 3 s; a vault that is not `live` or whose row is gone is not asked anything.
  Requests are bounded by the link's request timeout (15 s). It runs on its own thread, never on a FUSE worker or the
  link's read thread; contents are not fetched here: the MirrorContents service is the one drainer of the pending queue (the follower's own
  fetch thread was removed at the merge, so no file is fetched twice). For a drill:
  the mirror's `mirror_vault` row (`last_seq`, `copy_finished`, `copy_cursor`, `digest`, `state`, `stop_reason`) and the
  log lines "first copy finished at (t, s), digest D, N entries" and "applied through (t, s), digest D".
- **The applier** (`mirror::apply`): one transaction per page or group, under the apply switch and `vh.keep_mtime`
  (`ApplyRows::begin`). The mirror's entry hashes are kept in `mirror_entry_hash` on the mirror too (the Janitor's sweep
  of vaults that are not a core now spares `mirror` and `orphaned` rows): per uid the group's first `prev_hash` must be
  the hash recorded here, the last row's state is the result. Work: removals (a folder once it is empty), then
  placements (a creation or a move whose parent exists here and whose name is free), repeated until done; when nothing
  can proceed, an entry in the way that itself moves or goes in the group steps aside to `.vh-mirror-<uid>` (a swap or
  a cycle); anything else that cannot be placed is a divergence. Then every replicated field, the paths of what moved
  (folders first), the contents expected, and each entry's hash computed from this server's own tables
  (`vh_mirror_entry_state`): it must equal the core's, else `diverged` (`mirror_apply_mismatch` with both hashes and both
  states). A first copy whose digest at its last page is not the baseline's is `mirror_copy_mismatch`. Exactly once: a
  page or group at or below the vault's position is `AlreadyApplied`, one that does not start right after it is
  `NotNext`; both apply nothing.
- **Accounts** arrive as `{node, id}`: this server's own node id names a local account (none: the field is empty and the
  hash will not agree, a divergence); any other node a remote account (migration 158: `remote`, `home_node`, `home_id`,
  no password, named `#<id>@<node>`), created in the group's transaction the first time it is named. Never matched by
  name, never a local account for another server's. Written as SQL in the applier's transaction, not through
  identities::Manager (remote accounts never authorize, so no canonical object goes stale that matters; the watcher
  catches up).
- **Contents:** every live file whose generation is new here gets its `mirror_content_pending` row in the group's
  transaction (wave 2's rules: a new generation replaces an older row); a file trashed, deleted or purged drops it. The
  applier locks the group's pending rows before any entry row, the receive path's order (pending row, then the file's).
  Bytes of the old generation stay on disk until the new ones are linked over them (every open waits for a pending file;
  the lane refuses bytes that are not the asked generation). Nothing is fetched by the applier.
- **A file open on the mirror's mount: the whole group waits** (deviation from "deferred the way the manifest applier
  defers"): a group that replaces, trashes or removes a file with an open working copy applies nothing and is tried
  again on the next visit until the file is closed. The group stays atomic for the digest and for the files on disk, and
  no deferral table is needed. Known limit: a file held open for hours holds that vault's log behind it (reads go on).
- **Keys:** a `key` row, or a file sealed under a key version this server does not hold, stops the vault as `stopped`
  (`mirror_key_missing`, the version). Only presence is checked (a key check is over each server's own vault id;
  piece A proves delivered keys). Unknown ops (`history`) stop it as `mirror_unknown_op`.
- **Vault settings** (`op = vault`, and the baseline's vault document on the first page): name (unless another vault
  here holds it), description, quota and owner (mapped) applied, the whole document recorded in
  `mirror_vault.vault_state`; its sync and recovery policies are never acted on (remote sync runs on the core only).
  After the commit the engine is rebuilt (`storage::Manager::updateVault`).
- **Expired:** `{expired: true}` (below retention, the baseline gone before the copy finished) or `not_found` (the core
  no longer mirrors the vault with this server) stops the vault as `expired` (`mirror_log_expired`,
  `mirror_baseline_gone`, `mirror_core_gone`); it is not asked again. Resynchronising is a later piece.
- **After the commit**, through the calls a local write uses: the bytes of a removed file (under its content lock), its
  derived artifacts, a removed folder's backing directory, a moved entry's backing path (through a staging directory, so
  a folder and an entry that left it can both move), a new folder's backing directory, the FUSE cache
  (`fs::tree_apply::cacheFresh`, evictions, totals). `fs_change_log` fires from the table writes.
- **The shared tree-apply module** (`fs/tree_apply`): the uid lookup for local vaults (no `remote_object_index`) and the
  after-commit cache and folder effects, which the manifest applier's executors now call. Deviation: its row writers
  stay with each applier (`db::query::sync::ManifestApply` and `db::query::mirror::ApplyRows`): the compare-and-sets
  differ (the bucket index's generation; the log's entry hashes) and so do the transactions (one per operation; one per
  group). The manifest applier's behaviour and suites are unchanged.
- **The trigger deadlock (wave 1's risk), fixed with one lock order:** a writer of a type row locks the entry's fs_entry
  row first. Every writer already did (it updates fs_entry first in the same statement) except key rotation's
  `set_file_encryption_iv_and_version` and its compare-and-set and `ManifestApply::replaceContent`, which now lock the
  entry first; the type trigger's own lock then never waits while holding the files row. Reproduced with the old
  statement shape and shown gone with the product's (`TypeRowWritersLockTheEntryFirstSoNoDeadlock`). Cost re-measured
  (`tools/dev/bench/replication_log_cost.sh`, the base e0b1201a and this change back to back, twice, 2026-11-26, on a
  dev VM busy with another build): the mirrored seal 1.30 and 1.15 ms on the base, 1.31 and 2.10 ms with 164 (the
  second run disturbed: its unmirrored seal doubled too); the other cases within the same noise. Nothing measurable on a
  loaded VM. 164 adds one read of the vault's state in `vh_mirror_core_term` on a core vault's writes and nothing on
  any other vault's; the seal path's statements do not change (the lock order touched rotation and the manifest
  applier only). The cost table above (160) stands as measured then.
- **Retention** moves once the mirror acknowledges and never past it; a mirror that stops acknowledging holds the log
  (known limit, as before) (`AcknowledgementsCompareDigestsAndRetentionFollowsThem`).

Not built here: resynchronising a diverged or expired vault, the strict-mode gate (wave 4, "As built: the gate"),
submitting the mirror's changes, history.

**At the join with piece A** (wave 3 merge, 2026-11-26):

- **The follower waits for the core's begin.** The mirror's row exists from the keys step on; the core's `core` row
  only after the keys are answered and `startCore` took its baseline (seconds for a large vault). A tree request in
  between got `not_found`, which the follower reads as "the core is gone" and stops the vault for good
  (`mirror_core_gone`). It now asks nothing while piece A's offer for the vault is still `installed`
  (`mirror::start::awaitingBegin`), and the begin wakes it (`MirrorStartDbTest.TheFollowerAsksForTheTreeOnlyOnceTheCoresBeginArrived`).
- **`firstCopyFinished`** (piece A's ending rule) answers from `copy_finished`: no row or `orphaned`, true.
- **Test instances only** (`paths::testMode`, `VH_TEST_FAULT_DIR`): `mirror-copy-hold` holds every first copy back
  (`Follower::step` answers Waiting) and `mirror-contents-hold` holds background fetching (`contents::fetchOutstanding`
  fetches nothing; a person's open is not held), so `vhh drill peers` can see an empty vault after the begin, an open
  fetched ahead of the queue, and an unfinished copy ended. Never in a packaged daemon.
- **The two-daemon proof** is `vhh drill peers` steps 7 and 8 (above): a whole mirror and its ending, nothing written
  by hand. Restore and purge have no person's command on a local vault (the purge is a bucket vault's pass, a restore
  the manifest applier's), so the drill does not do them; `MirrorFollowDbTest` applies both from a real core's log.
  A single-group swap needs a rename exchange, which the mount does not offer: the drill swaps with three renames.

### As built: a change made on the mirror (phase 2 wave 4, piece B, migration 166)

Steps 1 to 5 of "A change made on the mirror", "When the core refuses" and "What strict mode cannot refuse" (a file
open for writing when the link drops). Piece A's gate (`mirror::access`, `acceptsLocalChanges()` now true) decides
whether a write may happen at all; everything here is behind it, entered only while the vault is `Live` here (and for
a seal, also while the link is down). Decided while building (owner's instruction to build without waiting for
review); each is listed for confirmation in the hand-off:

- **Local apply** (`mirror::submit::Local`): `mkdir`, `move`, `rename`, `remove` (a file to the trash, a folder or
  symlink deleted), `write` (a file's contents: a create or a replacement) and `setattr` (mode and modification time)
  are applied here at once, through the same `vh::fs` calls a local change uses, so the journal fires and this server's
  clients see the change. **Every surface takes this path**: `ops::fs` builds a `Local` right after the gate's line
  (the ws commands), and `vh::fs::Filesystem`'s mutators (`mkdir`, `rename`, `remove`, `copy`, both `createFile`s)
  and FUSE `unlink` and `rmdir` build one around their bodies, so the mount, the HTTP lanes, `vh fs put`, share uploads
  and the S3 gateway do too (a `Local` is inert when one of the same vault already runs on the thread: the outer one
  describes the change). FUSE seals build one in `WorkingCopies::seal` (below). Under the vault's local-change lock (`submit::vaultMutex`, also held by the applier around
  every page, group and settle, so a change here and a group from the core never interleave) it first records the
  change (`mirror_pending`, state `local`) with every entry it touches as the tables hold it now (the entry and, for a
  folder, everything under it: a rename re-stamps them), then runs the mutation with `vh.mirror_local = on` (piece A's
  backstop) and `vh.mirror_request` in every transaction it begins (`db::SessionSettings`, applied by
  `Transactions::exec`), then marks it `pending` and wakes the follower. A mutation that fails having changed nothing
  leaves nothing; one that changed something is submitted all the same.
- **A created entry's uid is chosen by the mirror** (`db::query::fs::AssignedUid`, consulted by the folder, file and
  symlink inserts for that one path on that thread) and the core creates it under the same uid, so the entry never
  changes id and the confirmation finds it by uid. The core refuses a uid it already holds (`invalid`).
- **Copy is submitted only** (deviation): its new entries need new uids for a whole tree, so the mirror does not copy
  locally; the core copies and the entries arrive in the log with the core's uids.
- **What "dirty" means.** A pending change never moves `mirror_entry_hash` or the digest: they stay what the core last
  confirmed, so every acknowledgement is of the core's tree. `mirror_dirty` holds, per entry a pending change touched,
  the state the core last confirmed for it (captured from the tables while the entry was clean; kind `none` for an
  entry the mirror created). The compare-and-set of every group is against the recorded hash, which is the last one the
  core confirmed, never the pending one.
- **Submit** (`peer.mirror.submit`, from the follower's visit before it pulls the log; never on a FUSE worker or the
  link's thread): `{vault_uid, request_id, person: {node, id}, at: {term, seq}, op, entry_uid, args: {uid, parent_uid,
  name}}`, every entry by uid (the vault's uid names its root). One change at a time per vault, oldest first; the next
  goes once the core has answered the previous one (executed or refused), so a refusal that renames and resubmits keeps
  its place (the same row, a new request id).
- **The core answers at once and executes on the sync pool** (deviation from executing in the handler: the link's two
  io threads would block for a large folder). `mirror_submission` keeps each request id with what the core did the first
  time: `queued`, `running`, `executed` with the number of groups it logged, `refused` with the code. A repeated submit
  is answered from it and never executed twice; a `running` row a stop interrupted is executed again only if nothing of
  it reached the log (else it counts as executed). Kept 30 days after it finished (the log's own retention; swept
  when the vault's submissions are next drained).
- **Who authorizes a change made on the mirror:** today a mirror's change is authorized by the linked server's role on
  the vault alone; the person named in it is recorded (the log's actor, the audit event), not checked.
- **Executing** (`mirror::submit::drain`): as the remote account for (the mirror's node id, the person's id there),
  created the first time it is named; the person must be one of the submitting server's own accounts (`invalid`
  otherwise). Through `ops::fs` inside an `ops::fs::PeerSubmission`: the linked server's vault role
  (`rbac::resolver::PeerVault::may`) is the ceiling and, **with no per-account rules yet, the only check** (the
  person's own role on the core is a later piece; a remote account never authorizes on its own); then the op's own
  checks: a taken name is `conflict` (never replaced), a missing entry or folder `not_found`, the ceiling `denied`.
  Every transaction carries `vh.mirror_origin` (the request id: the log's `origin`) and `vh.actor` (the person: the
  log's actor). The audit event is the op's own (`fs.mkdir`, `fs.move`, ...) with the person as actor and `peer_id`,
  `peer_node` and `origin` in its details. Something logged before a failure counts as executed (its groups confirm
  what happened).
- **Confirm** (the applier): log rows carry `origin` on the wire. A group whose origin is one of this server's pending
  requests counts towards it (`groups_applied`); once the core's answer (`groups_expected`) and the groups agree, the
  change is confirmed in the same transaction: its row goes and its entries settle. **It is not applied a second time:**
  the group is applied to the entries where they stand here (a dirty entry may be created, moved, trashed or removed
  here already; the existence checks tolerate it), which for the person's own change moves nothing (the same row, the
  same inode, no backing file touched) and writes only the core's values (times, owner, attribution); each entry's hash
  from the tables must then be the core's, and the digest moves exactly as on the core. Bytes already on this disk at
  the generation the core names are not fetched again (the comparison is with the entry as it was before the
  transaction).
- **An unrelated core change to a pending entry arrives first:** the compare-and-set passes (it is against what the
  core confirmed), the group applies the core's state to the entry (so the person's pending view of that entry gives
  way to the core's until their change comes back: known limit, no rebase), and `mirror_dirty` takes the core's new
  state as the one to come back to. The person's change then goes to the core, which executes it on top.
- **A pending entry in the way of the core's change** is brought into line in the same transaction, nothing else:
  one that holds the name the core's entry needs steps aside to its conflict name (`name (conflict <first 8 hex of its
  uid>)`, before the extension of a file) and stays pending; a folder a pending change removed that the core's entry
  needs comes back as the core has it; an entry a pending change made in a folder the core removed goes back to where
  the core has it (or, made here, is removed: its change will be refused and held).
- **Settling** (`apply::settle`, and at confirmation): every entry of the settled change that no other pending change
  holds is brought back to its confirmed state where its tables differ (a revert, in the applier's work loop, verified
  against the recorded hash; the digest must not move), then is clean.
- **When the core refuses** (the design's table, as built): `conflict` for mkdir, move or rename becomes a conflict
  copy: the same entry takes its conflict name here (unless the applier set it aside already) and the change is
  resubmitted under that name with a new request id, recorded in `mirror_held` as kind `conflict` (copy name, reason);
  a conflict copy refused again for its name, and every other refusal (`denied`, `not_found`, `invalid`, a fault) is a
  **held change**: the entries settle back to the core's state and `mirror_held` keeps the operation, its arguments,
  where it was, the person and the core's code and text (kind `held`). Held changes of these operations carry no
  bytes, so there is nothing to seal or download. Listed, discarded and retried by super admins of the mirror
  (`ops::mirrors::held|discardHeld|retryHeld`; ws `mirror.held.list|discard|retry`; `vh mirror held [--vault N]
  [--all]`, `vh mirror discard|retry <n>`; audited `mirror.held.discard|retry`): a retry submits the change again as it
  was, as its person, at the end of the queue and without applying it here first (its result comes back in the log; a
  new refusal is held again). **Deviation:** they are their own listing, not Sync Conflicts (that record stays the cloud
  engine's: generalising it is not needed for these). No `mirror.held.get` and no download (no bytes yet); the console
  and Desktop do not show them yet.
- **Restart:** rows survive; a `local` row a stop left is submitted (the core decides; its answer settles the entries),
  a `submitted` row is asked again under its request id. Waits are bounded: the link's request timeout, the follower's
  3 s visit, 100 ms between asking again about a queued change.

- **Contents** (step 2; `mirror/submit/Contents`, `peer::object::put`, `protocols::device::peer_object::beginPut|
  finishPut`): a `write` keeps its sealed bytes in the **pending store** (`.vh-mirror-pending/<vault>/<row>` under the
  backing root, a hard link, a copy where linking fails) the moment it is applied here, so nothing that later replaces
  the file here (the core's state coming back) takes them before the core has them. Before its submit the follower
  sends them: `PUT /peer/object/<vault uid>/<object uid>/<generation>` on the sealed lane, the facts as `X-VH-Size`,
  `X-VH-Content-Hash`, `X-VH-Key-Version`. The core decides from the header (the switch, the link, this server the
  vault's core and live, the caller its mirror, a `Content-Length` that is that generation's sealed length), streams
  the body to a private file, then verifies (invariant 6: the size, the BLAKE2b, the header and every chunk
  authenticated with the vault's key as that generation; the object is not bound, wave 2's rule) and keeps it
  **staged** by generation (`.vh-mirror-staged/<vault>/<object uuid>.<generation>`) with the facts it verified beside
  it (`<staged>.facts`, written first): 201, else 422 `invalid_contents`, 409 `key_version_missing`, 404. Before a
  byte is kept it refuses a mirror whose role on the vault creates and replaces no file (403 `denied`) and bytes the
  vault has no room for (413 `over_quota`, or `no_space` without a quota): neither is sent again, the mirror holds the
  change. A submit of a write whose bytes are not staged is refused `contents_missing` before it is queued (not kept
  for the request), and the mirror sends them again; a write's `generation` must be a VHF1 salt (none for an empty
  file), else `invalid`. The core commits the file from the staged bytes (`ops::fs::commitSealed`, a writer that links
  them) with the mirror's uid and MIME type and **the facts it verified** (generation, key version, size, BLAKE2b),
  never what the submit claims of them: a submit whose facts are not those of its bytes is refused `invalid_contents`
  (held, never retried). So both servers hold the same bytes and the confirmation fetches nothing; a create never
  replaces what is there (a conflict), a replacement is the compare-and-swap on the generation it was based on
  (`content_conflict`). **Housekeeping** (`contents::housekeeping`, from the follower's loop at its first pass and
  every hour, the switch on or off): partial receptions a stop left (`.receiving-*`, at the first pass), staged bytes
  never committed after a day, staged bytes of a vault that is not this server's core, pending bytes no change names,
  held bytes of a held change no longer open, and the directories of a vault that is gone.
  The pending store's link goes when the change is confirmed; a held change keeps it as `.vh-mirror-held/<vault>/<id>`.
  Bytes are sent without a transfer slot (a known limit, below).
- **When a vault's copy or mirror ends**, deliberately: a held change discarded takes its bytes; a retried one moves
  them to its new pending change (and back to a held change if it is refused again). A **removed copy** (the core
  asked, its first copy never finished, or the vault deleted: `storage::Manager::removeVault`) takes its rows with the
  vault and its three directories (`.vh-mirror-pending|held|staged/<vault>`) with them; nothing is left on disk for a
  vault that is gone. An **orphaned copy** (the core ended the mirror and it is kept: `cancelReceived`,
  `reconcileUnlinked`; housekeeping catches any it missed) keeps what was applied here as content, and each change
  still pending becomes a held change with its bytes (`mirror_orphaned`), listed until a super admin discards it;
  nothing is dirty any more. On the core, ending the mirror (`cancelOnCore`) forgets what the mirror submitted
  (`mirror_submission`) and drops `.vh-mirror-staged/<vault>`.
- **An HTTP upload's staging file** (`.upload-http-*.part`, staged through the mount on Linux: CLAUDE.md) is never
  content, in either direction. Migration 166 (chosen over a new migration: 166 is unreleased, and replacing
  functions of 160 and 164 with `CREATE OR REPLACE` is safe on installs that ran them; its upgrade test proves it)
  leaves such a file out of the state documents (`vh_mirror_entry_state`, `vh_mirror_tree_states`: so out of the log,
  the hashes, the digest, the baseline and the scrub, and never fetched), out of the trash (`vh_mirror_track_trash`),
  and logs a file renamed to such a name as a delete (`vh_mirror_log_state`); one rule, `vh_mirror_upload_staging`, the
  same as `vh::fs::isUploadStagingName`. On a mirror the staging file is this server's scratch
  (`mirror::submit::Scratch`): created, sealed, its attributes set and removed past the backstop with no pending or
  dirty row, never submitted. The upload's commit is the one change: one pending write, one PUT.
- **The person of a change** is a local account, always: the caller of the surface, or for a seal the one who wrote
  to the file or opened it for writing (`WorkingCopies::open` now records the opener; never the file's last modifier,
  which on a mirror is often the core's person, a remote account here). A `Local` refuses a remote account (inert, so
  the gate's backstop refuses the write), and a seal with no local writer is kept unsaved. Found by the drill: a
  truncating open sealed under the core's person was attributed on the core to this server's account of that id.
- **A file open for writing when the link drops** is sealed and kept as pending (`Local::Mode::Seal`: taken while the
  link is down, never in another read-only state, where piece A's rule stands: the seal is refused and the copy kept
  unsaved), and submitted when the link returns. A new write while the link is down is refused by the gate; an upload
  that began while `Live` is refused at its commit (piece A's line in each lane) and its staged bytes discarded.
- **Set attributes:** a mode or a modification time is a `setattr` change (the core runs `ops::fs::setAttributes`
  under the ceiling); **an owner change is refused on a mirror** (`Denied`: an owner is a Linux account of the host
  holding the copy, the core's). **Symlinks made on a mirror are refused** (`EROFS`; no operation on the core makes
  one from a submit yet). Copy stays submitted only.
- **A replacement the core outran** (`content_conflict`): the file comes back to the core's state, and the person's
  version becomes a new file beside it, `name (conflict <8 hex of its new uid>).ext`, made here from the pending store
  (same bytes, generation and key version) and resubmitted as a create; recorded as a conflict. A refused creation
  holds the later changes of the entry it would have made (its contents written afterwards) with it.
- **A file whose contents have not arrived here** renames and moves as metadata (`Filesystem::handleRename`: with a
  `mirror_content_pending` row and no bytes on disk, nothing is moved; the receive path links the bytes wherever the
  file is when they come); trashing one was never refused.

Not built here: restore (no surface on a local vault has it), per-account rules on the core, downloading a held
change's bytes, the held changes in the console and Desktop.

Known limits: **one writer at a time per mirrored vault**: the vault's local-change lock (`submit::vaultMutex`) is
held across a seal or an upload's commit, so that vault's other writers and its applier wait for it (a large file
sealed through the mount holds them for as long as the seal takes); **sends take no transfer slot** (the sealed
lane's PUTs run outside the four slots per peer of wave 2, which are for fetches). A folder change captures every
entry under the folder into the pending row (a very large folder makes a large row); an
unrelated core change to a pending entry shows the core's version of that entry until the person's change comes back;
a change left pending when a vault stops (diverged, expired) stays pending until the vault is live again or detached
(wave 5: pending changes become ordinary changes); one left pending when the copy is orphaned is held (above).

### Key rotation

Run by the core.

1. The core mints the next key version, delivers it to the mirror as in "Starting a mirror", and waits for the
   acknowledgement.
2. The core re-seals. For each file the log carries the old generation, the new generation and the new key version.
3. **The mirror re-seals its own copy with the generation the core chose,** and checks that its result has the
   content hash in the log row. The sealing is deterministic given the key, the salt and the plaintext, so both
   servers end with identical bytes and no file is sent again. Where the check fails, the file is fetched.
4. The old version retires on each server only when no entry there references it.

This needs `content::resealFile` to take the salt as a parameter, and the rotation to stream instead of reading
each file into memory. A mirror that is unreachable blocks step 2; the core's admin can end the mirror to proceed.

## A change made on the mirror

1. **Local.** The mirror checks that the person is allowed by the link's policy (a super admin of the mirror by
   default, or an account the core added; `identity.md`) and within the server's role, applies the change locally,
   and records it in `mirror_pending` (vault, entry uid, operation, the generation it was based on, the new
   generation, the acting account (the mirror's node id and the account's id there), the origin). People on the
   mirror see it at once.
2. **Contents first.** For a new or changed file the mirror sends the sealed bytes to the core's lane. The core
   verifies them and keeps them staged by generation.
3. **Submit.** `peer.mirror.submit` names the person (the mirror's node id and the account's id there), the origin on
   the mirror, the `(term, seq)` the mirror
   had applied, and the operations by uid with the generation each was based on.
4. **The core executes it** through the operation layer as that person:
   - the peer's vault role is checked first, as a ceiling;
   - then, when the acting account is one the core added to the policy, that account's role;
   - then quota, a name clash (`RenameMode::NoReplace`) and the base generation (`expected_source_id`);
   - a file is committed from the staged bytes (`NewFileContext::sealed`), so the core never has a row for a
     mirror's file without its contents;
   - the audit event names the person and the peer (`identity.md`).
5. **Confirm.** The change returns in the log with the mirror's request id in `origin`. The mirror marks it confirmed
   and drops the pending row. It does not apply it a second time.

**The operation layer.** This needs `ops::fs`: mkdir, move, rename, copy, trash, restore, delete, set attributes and
commit-from-sealed, with permission, quota, name-clash handling, audit and the operations record inside. The ws
handler, the HTTP lanes, the CLI, shares and the S3 gateway call it too, so a submitted change and a local one run
the same code.

### When the core refuses

| Refusal | What the mirror does |
|---|---|
| The entry changed on the core meanwhile, or the name was taken | Reverts the entry to the core's state and resubmits the person's version as a new file beside it, named `name (conflict <short uid>)`. Recorded as a conflict |
| No permission, over quota, or any refusal that would also refuse the copy | Reverts the entry to the core's state and keeps the person's version as a **held change** |

**Held changes** live outside the vault's tree, sealed under the vault's key, listed under Sync Conflicts with the
reason. The person can download or discard them; someone with the right can retry. Nothing a person wrote is ever
dropped without their action. The conflict record and its listing are generalised away from the cloud sync engine
so that a local vault can have them.

## Strict mode: read-only while the link is down

### The gate

A per-vault state on the mirror, held in memory behind a shared lock so that it never waits on the database, built
on the pattern of `storage::remote_access` (`core/include/storage/RemoteAccess.hpp`):

| State | When | Writes |
|---|---|---|
| `live` | The link is up and the core is following | Accepted as pending |
| `read_only` | The link is down, the peers' protocol versions differ, the vault is paused, or the apply stopped | Refused, with the reason |

`mirror_access::requireWritable(vault, operation)` throws `MirrorReadOnly{reason}`. It is called at every write
surface, and each surface reports it in its own terms:

| Surface | Where | Reported as |
|---|---|---|
| FUSE | `fuse::Resolver::resolve`, after the engine is resolved, for every mutating action | `EROFS`; `statfs` reports the filesystem read-only |
| ws `fs.*` | `enforcePermission` in the fs handler, and the upload commit | Code `read_only`, with the reason |
| HTTP uploads, text save | `http::access`, and each commit | 503 with `Retry-After` and the reason |
| `vh fs put` and other CLI writes | Before staging and again at commit | The reason, and a distinct exit code |
| Share uploads and overwrites | `share::Manager` | The share's own refusal, with the reason |
| S3 gateway | `requireS3Permission`, which super admins do not bypass for this check | 503 `ServiceUnavailable`, so clients back off and retry |
| Recovery restore | `ops::recovery` | The op's refusal |

The gate moves into `ops::fs` as each surface is lifted onto it, and the per-surface calls go away.

**A database backstop.** A trigger on the entry tables refuses a change to a mirrored vault on the mirror unless the
transaction set `vh.mirror_apply` (a change from the core) or `vh.mirror_local` (a pending change accepted while
`live`). It catches a path the gate missed. It surfaces as a generic error, so it is the backstop and never the
interface.

### What strict mode cannot refuse

A file that was open for writing when the link dropped. Flush and release must seal it or lose it, and a working
copy does not survive a restart. **Such a file is sealed and kept as pending,** and submitted when the link returns.
Losing a person's data is never the price of strictness. The exposure is bounded to handles that were already open;
no new write is accepted.

A long upload that began while `live` is refused at its commit if the link has dropped by then, and its staged bytes
are discarded, as an interrupted upload's are today.

### Background work on the mirror

For a mirrored vault the mirror runs none of the jobs that change vault content: trash purge, key rotation, the
at-rest repair, format conversion, version retention. Their results arrive from the core. The working-copy retry
loop holds its files while the vault is read-only.

### As built: the gate (phase 2 wave 4, piece A, migration 165)

The mirror is read-only: every write surface, the database backstop and the background jobs. On this piece's branch a
mirror is **strictly** read-only, link up or down: piece B (the mirror's own changes, pending and submitted to the
core) lets writes through while the state is `live`. Decided while building (owner's instruction to build without
waiting for review; each is listed for confirmation in the hand-off):

- **`vh::mirror::access`** (`core/include/mirror/access/Access.hpp`, the interface piece B builds on): `state(vault)`
  is `NotMirrored` (no row here, or this server is the core), `Live` (role `mirror`, `copy_finished`, state `live`,
  `peers.experimental` on, the link up) or `ReadOnly`; `reason(vault)` is the code `requireWritable` refuses with
  (`""` when it lets the write through); `requireWritable(vault, operation)` throws `MirrorReadOnly` (an
  `ops::ReadOnly`, itself an `ops::Refused` with code `read_only` and a `reason` member); `acceptsLocalChanges()` is
  false. Reasons, in the order they are judged: `mirror_orphaned`, `mirror_diverged`, `mirror_expired`,
  `mirror_paused`, `mirror_stopped` (any other state, with `stop_reason` kept in `facts()`), `mirror_first_copy`,
  `mirror_peers_off` (the switch off here: the follower does not run), `mirror_link_down`, and for a `Live` vault
  `mirror_writes_not_built` while `acceptsLocalChanges()` is false. Each has a sentence (`sentence()`), with no path,
  name or key material. **`mirror_core_owned`** (added): what is never a local change on a held vault, `Live` or not:
  its name, description, quota, owner, sync and recovery settings and a remote (`refuseIfHeld`).
- **In memory, never waiting on the database:** a map of the held rows (peer, role, state, `copy_finished`,
  `stop_reason`) and of each peer's link, behind a shared lock; one atomic load while nothing is held. Published
  by `reload()` at startup in `wireStorage()` before any engine serves (a failure stops startup, as for
  `rbac::mirrored`), by every `MirrorVaults` write that changes a held row (`startMirror`, `recordGrant`, `clearGrant`,
  `remove`, `orphan`, `setState`, `stop`) and `createMirrorVault` before they return, by the applier when a first copy
  finishes, and by `peer::LinkService` when a link is kept (`adopt`) or closes. **The periodic reconcile rides on the
  existing watcher** (`rbac::mirrored::Watcher`, 1 s; no second worker): the rows, and each held peer's link from
  `LinkService::connected`. An unreadable database keeps what memory held.
- **The surfaces**, each after its own permission check (so a caller without access learns nothing about the vault):
  - FUSE: `fuse::Resolver::enforceMirrorGate`, after `enforcePermissions`, for every mutating action (Write, Touch,
    Overwrite, Rename, Delete, Move, Copy, Link; so create, mkdir, symlink, rename, unlink, rmdir, write, setattr,
    fsync, `open` for writing and `access(W_OK)`): `EROFS`. **`statfs` cannot say read-only per vault:** the kernel
    takes a mount's read-only flag from the mount, not from the statfs reply, and one mount serves every vault. A
    vault's subtree answers `EROFS` to every write instead.
  - `ops::fs`: one line after the permission check of each mutating operation (`mkdir`, `move`, `rename`, `copy`,
    `remove`, `authorizeUpload` (so the ws upload start and finish), `commitSealed`, `setAttributes`), marked
    `// mirror gate`; piece B's hand-over goes after it. ws answers `{code: "read_only", reason}`
    (`protocols/ws/core/Refusal.hpp`).
  - `vh::fs::Filesystem`'s mutating calls (the layer under every surface: `mkdir` when something is to be created,
    `copy`, `rename`, `remove`, both `createFile`s, `createSymlink`): `-EROFS`, or `MirrorReadOnly` for the throwing
    ones. Nothing of the follower or the receive path goes through them.
  - The HTTP lanes: `http::access::requireUserAction` for Write and Overwrite (upload content, text save, the resumable
    sessions, the upload sessions' human lane, and `vh fs put`'s checks), plus the share lanes of the upload sessions
    and the resumable commit; `handler::errorFor`, the resumable lane's `errorFor` and the upload router answer
    **503** `{code: "read_only", reason}` with `Retry-After: 30`. A resumable file refused at its commit fails with
    `read_only` and its spool is discarded, as an interrupted upload's is.
  - `vh fs put`: refused before staging (through `http::access`) and again after the transfer, before the commit,
    with **exit code 69** (`EX_UNAVAILABLE`, `transfer::exitcode::kReadOnly`) and `read-only (<reason>): <sentence>`.
  - Share uploads (ws `share.upload.start`, the upload sessions' share lane): refused after the share's own scope
    check; the commit refuses through `Filesystem`. Shares cannot overwrite (no share lane edits a file).
  - The S3 gateway: `ObjectStore::requireS3Writable` after every permission check of PutObject, DeleteObject(s),
    CopyObject's destination, CreateMultipartUpload, UploadPart, CompleteMultipartUpload: **503
    `ServiceUnavailable`**, super admins included (the open question "503 over 403" taken as proposed).
  - Recovery restore (`ops::recovery::restore`): refused before the plan starts. Vault settings (`ops::vaults::update`,
    `updateSync`), the recovery policy (`ops::recovery::update`) and `vault.remote.attach`: `mirror_core_owned`.
  - Trash restore and purge have no person's command on a local vault (the purge is the sync pass's, skipped; a
    restore is the manifest applier's, which a local mirror never runs). Snapshot creation is **not** refused: it reads
    the copy and changes nothing in it (history of a copy is phase 3; decision recorded).
- **The backstop (migration 165)**: BEFORE triggers on `fs_entry` (insert, delete, and an update of a replicated
  column: 160's list), `files` (insert, delete, a content update), `directories` (insert, delete), `symlinks`
  (insert, delete, a target update) and `files_trashed` (insert, delete, any update) raise `mirror_read_only` for a
  vault whose role here is `mirror` or `orphaned`, unless the transaction set `vh.mirror_apply` (the follower,
  `Log::markMirrorApply`) or `vh.mirror_local` (piece B, `Log::markMirrorLocal`, added; nothing calls it on this
  branch but tests). Never refused: the vault root (created with the vault, re-parented on a soft delete; not
  replicated), a folder's modification time alone (the totals, the follower's after its commit too), totals, inodes,
  aliases and paths, and **the rows of a vault removed as a whole** (its `vault` row is already gone when the cascade
  reaches them). So **creating the mirror's vault sets no flag** (its root is exempt; the row comes last) and **removing
  a copy sets no flag** (`storage::Manager::removeVault`, which the ending rule, `removeOrphaned` and every rollback
  use; deleting a held vault is refused above it, `refuseDeletionIfMirrored`). The contract
  (`test_replication_log_contract.py`) now also keeps `vh.mirror_local` to `db::query::mirror` and checks the triggers'
  table set.
- **Background work** on a held vault changes nothing: the local sync task (wave 3: at-rest repair, trash purge,
  rotation), format conversion (`convertVault` reports `blocked`; the service skips the vault), local versioning
  (`versions::retain` captures nothing, `versions::maintain`'s retention skips it), key rotation and salvage
  (`refuseIfMirrored` refuses on a mirror or orphaned copy even where a test lets a core rotate), deletion and its
  retention (refused, wave 3), the working-copy retry (below). No scheduled job writes into a vault otherwise.
- **What strict mode cannot refuse, on this branch:** a handle already open for writing when the vault became
  read-only. On this branch a mirror is read-only from its creation, so no such handle can exist; the seal is gated
  anyway (`WorkingCopies::seal`): the seal is refused (`EROFS` from flush and fsync), **nothing is sealed over the
  core's content and no byte of the vault changes**, and the copy is kept unsaved as a failed seal is (the bytes stay
  in this process, encrypted under its key; reopening the file shows them; the background retry holds them while the
  vault is read-only; a daemon stop logs them as lost). Known limit: an unsaved copy counts as open, so the follower's
  group that would change that file waits for it (the deferral rule of wave 3). **Piece B takes over at that line:**
  such a copy is sealed and kept as pending.
- **The mount's own shortcut is gone:** a held vault's root is shown and listed through `rbac::mirrored` like every
  other surface (no super-admin, owner or admin-view shortcut in `canExposeVaultRoot`; a super admin's listing of the
  mount root leaves out a copy whose grant shows nothing).
- **Cost** (`tools/dev/bench/replication_log_cost.sh`, which now also measures "held elsewhere" and "without 165").
  On a server that holds no copy the triggers read one empty partial index (`mirror_vault_held_idx`) per row; with a
  copy held elsewhere one more indexed lookup of the row's vault. Measured on the dev VM, 2026-11-26, PostgreSQL 16,
  3,000 seals per run, while the other wave 4 piece built on the same VM (load about 2.7), two runs back to back:

  | Per seal | run 1 (3 runs, median) | run 2 (5 runs, median) |
  |---|---|---|
  | No vault mirrored, 165 dropped | 0.536 ms | 0.832 ms |
  | No vault mirrored, with 165 (every server today) | 0.826 ms | 0.736 ms |
  | No vault mirrored, a copy held elsewhere | 0.821 ms | 0.817 ms |
  | This vault mirrored (core, 2 log rows per seal) | 1.400 ms | 1.375 ms |

  The backstop's difference is +0.29 ms in one run and -0.10 ms in the other: inside this VM's noise (in run 1 "no
  triggers" even measured slower than "journal only"). Nothing measurable on a loaded VM; a quiet host would give a
  sharper figure (not run).

Carried fixes (each with a test that failed before it):

- **FUSE `setattr` reaches the row** (the known limit of 160): `chmod`, `chown` and a new modification time go
  through `ops::fs::setAttributes`, one transaction (`db::query::fs::Entry::setAttributes`, with `vh.keep_mtime` so
  a mode change never moves the time, and `vh.actor` for the log), Write at the path; an owner or group that differs
  needs a super admin (as chown needs root; decision), audited `fs.chown`; mode and times are not audited (`cp -p`
  sets them on every file). The journal records the mode (it never journals times or owners); the replication log
  records all of them. `touch` (UTIME_NOW) is honoured. The access time stays the backing file's only.
- **A create never returns what is there:** `Filesystem::createFile` with `overwrite = false` refuses an existing
  file with `EEXIST` (it returned it silently), so `vh fs put` reports "created by someone else meanwhile" instead of
  "stored"; the provider restore and share uploads map it to their conflict.
- **Missing is told from no permission:** `ops::fs::check(actor, vault, path, action)` answers `Allowed`, `Denied` or
  `Missing`; `Missing` only for an action on an existing entry (a create's Write, Touch or Link is judged where the
  entry would go, as before), when nothing is at the path and the actor may List the nearest folder that exists (they
  could see it is missing there anyway), `Denied` otherwise (no existence oracle; the HTTP lanes' rule). Every
  `ops::fs` operation refuses the same way: `NotFound` for a missing entry the caller may know is missing (a sealed
  commit's replacement: `ContentConflict`, its base is gone, as a super admin already got), `Denied` otherwise. Piece
  B's "changed meanwhile" uses it.
- **`ShellServerTest`'s race:** the CLI socket's path appeared at `bind()`, before `listen()` and before the server
  recorded the inode it owns: a connect in that window was refused, and a stop in it left the path behind. The socket
  now listens under a private name and is renamed onto the path once its inode is recorded, and the run loop closes
  the listener and removes its own path whenever it ends.

Proven: `MirrorGateDbTest` (`test_mirror_gate_db.cpp`), `ShellServerTest.ThePathAppearsOnlyListening...`, the
contracts, and `vhh drill peers` step 7h (B's mount refuses create, overwrite, mkdir, rename, delete, chmod and touch
with `EROFS`; `vh fs put` exits 69 with the reason; A's writes still arrive; B reads within the grant). The ws reply is
proven in process (the handlers call `ops::fs`; the drill has no console session).

## Parity

- **A running digest.** Each log row carries the hash of the entry's new state and of the state it replaced. Each
  server keeps, per vault, the sum of its entries' hashes, updated as rows are written (core) or applied (mirror).
  The mirror computes its side from its own rows after applying, not from the log, so the comparison is a real
  check.
- **Every acknowledgement carries the mirror's digest at `(term, seq)`.** The core compares it with its own at that
  point. Equal: the UI says "identical as of" that moment. Different: the vault stops with `mirror_diverged` and both
  sides are told.
- **A scrub** recomputes the digest from the tables and re-hashes file contents on a schedule, on both servers, and
  compares. It catches what the running digest cannot: a file damaged on disk.
- The digest detects accidents and bugs. It is not a defence against a peer that lies; that is what the audit
  exchange is for (`identity.md`).

**Resynchronising.** When a vault stops as diverged, or the mirror fell behind the log's retention, the mirror asks
for the core's tree, compares it with its own by uid and generation, and takes the core's state for every
difference. Contents are fetched only for files whose generation differs. Whatever the mirror had that the core did
not becomes held changes.

### As built: resync and the scrub (phase 2 wave 5, piece B, migration 168)

Decided while building (owner's instruction to build without waiting for review); each is listed for confirmation in
the hand-off:

- **Resync** (`mirror.resync`, `vh mirror resync <vault>`, on the mirror; super admins, never an agent, a scoped or a
  relayed device; audited `mirror.resync` on both sides): for a copy that is `diverged`, `expired` or `stopped`, with
  the link up. **Through the first-copy path.** The mirror asks its core first (`peer.mirror.resync {vault_uid}`): the
  core takes its baseline again **in the next term** (its row becomes `starting`, the vault's log, entry hashes,
  baseline and submissions go, then `MirrorVaults::startCore(term + 1)`; a start that cannot finish (the writers'
  bound) leaves the row `diverged`, `mirror_resync_failed`, so the mirror can ask again; a paused vault is refused).
  Then the mirror holds every pending change (`mirror_resync`, its bytes with it: `submit::holdAllPending`, which the
  orphaned rule now shares), forgets its entry hashes and dirty rows, and resets its row (live, first copy at cursor 0,
  no baseline, zero digest; `resync_at`, `resync_by`, `resync_count`); pending-contents rows stay. The follower then
  runs the first copy as usual.
- **The copy takes this server's entries as they are.** A copy page's entry that is here by uid is brought to the
  core's state in place (moved, renamed, its fields written): the same entry row, and **the bytes it holds are reused
  when the generation is the core's** (the comparison is with the entry before the transaction, as for a confirmed
  change: nothing identical is fetched). An entry of this server's that holds a name the core's entry needs, and that
  no page has named yet, steps aside to its conflict name (a later page takes it into place, or the end keeps it).
- **Nothing a person wrote here is dropped.** A file whose generation differs keeps this server's version as a held
  change (`mirror_resync_replaced`, op `write`, its facts and its bytes linked into the held store before the core's
  bytes are fetched over them), unless a change of its held at the start keeps it already. When the copy is complete,
  every live entry and trash row whose uid the core's tree does not hold leaves the tree as a held change
  (`mirror_resync_extra`: a file with its bytes, a folder as `mkdir`, a symlink as `symlink` with its target, a trash
  row with its bytes), kept once; so the digests agree and the evidence of the divergence is listed (`vh mirror held`)
  until a super admin discards it. Metadata that differed (a name, a mode) is the core's afterwards and is in neither
  list: the copy's adoption is the report (known limit). The held changes name the person who started the resync.
- **The scrub** (`mirror::resync::scrub`, `Resync::scrub`): one statement compares every entry's hash from the tables
  (`vh_mirror_tree`) with the recorded one (an entry a change made here holds dirty is skipped), and on the mirror the
  running digest with the recorded hashes' sum. Run from the follower's hourly pass for every live vault (a core, or a
  mirror whose first copy is complete) not scrubbed for `kScrubEvery` (24 h; `scrubbed_at`); never on a server that
  mirrors nothing. A difference stops the vault as `diverged` (`mirror_scrub_mismatch`, the count and the first 20
  uids with both hashes), audited `mirror.scrub`; the mirror learns of a core's divergence from its next answer.
  Contents are not re-hashed (the design's scrub also re-hashes file contents: not built). Cost: the scrub of 100,000
  entries is the hashing measured for the baseline (about 11.5 s on the dev VM), on the follower's thread once a day.
  Test instances only (`paths::testMode`, `VH_TEST_FAULT_DIR/mirror-scrub-now`): every vault is due at every pass, so
  `vhh drill peers` (step 7o) sees a planted difference caught, then resyncs.

Known limits: a vault whose baseline takes longer than the link's request timeout (15 s) to take again answers the
mirror's resync too late: the core has started over, the mirror has not; asking again works (the core takes it again).

## Moving the core

Each server keeps a `mirror_vault` row per mirrored vault: the peer, its own role, the term, the last `(term, seq)`
applied or acknowledged, and the state.

### Planned switch

1. Either side asks (`mirror.switch`, by someone who may manage the vault).
2. The core stops accepting changes for the vault (both sides are briefly read-only), finishes numbering, and waits
   for the mirror to acknowledge the last group with an equal digest and no pending changes.
3. Both record `term + 1` with the roles swapped. The new core starts its log at `(term + 1, 1)`.
4. If the vault has a remote, remote sync moves with the role ("A mirrored vault with a remote").

There is no divergence, by construction. If step 2 does not complete within a timeout the switch is abandoned and
nothing changes.

### As built: the planned switch (phase 2 wave 5, piece B, migration 168)

Decided while building (owner's instruction to build without waiting for review); each is listed for confirmation in
the hand-off:

- **The core coordinates, whichever server was asked** (`mirror.switch`, `vh mirror switch <vault>`, super admins of
  the server it is asked on; never an agent, a scoped or a relayed device; no step-up: nothing is destroyed and no key
  moves). Asked on the mirror, it checks its own obstacles first (pending changes, contents not yet here) and asks its
  core with **`peer.mirror.switch.request`** (a wire command the list below did not have), which begins the switch and
  answers its id at once. The mirror only ever prepares and is told: a prepared mirror never decides, so the core (the
  one that accepted changes) is never held by its mirror; the mirror's way out of a switch whose core vanished is the
  take-over (step 3) or a detach. Both sides keep a `mirror_switch` row (the protocol's state, then its record:
  phase, the term it leaves, the core's last position and digest, who asked and where, why it was abandoned).
- **The freeze** (core): one transaction under the core row's lock (FOR UPDATE; enqueuing and claiming a submission
  now take a key share of it, so none is queued or starts after it) sets the row `switching` (a new state) unless a
  submission of the mirror is queued or running (`mirror_submissions_queued`) or a switch is open
  (`mirror_switch_running`). From then on every write surface refuses with **`mirror_switching`** (`mirror::access`
  gates a switching core; `held()` stays false for it, so no background job treats it as a copy; vault settings refuse
  through `refuseIfHeld`) and the database refuses what a surface missed: `vh_mirror_core_term` (every entry trigger)
  and `vh_mirror_track_vault` (the settings) raise for a switching core. The writers of the vault tables running when
  it committed (pg_locks, as `startCore` does, now including the settings tables) are recorded and waited for, then
  the sequencer numbers what they logged and the switch takes the row's `(term, last_seq)` and digest: final.
- **Prepare** (`peer.mirror.switch.prepare`, asked again from the core's pass until ready or the deadline): the mirror
  freezes too (its row `switching`, its switch `preparing`) under the vault's local-change lock, taken without waiting
  (a busy vault answers "busy"); `submit::Local` judges the gate again once it holds that lock, so no change made
  here starts after the count. While preparing, the follower goes on applying the core's log (the core still serves
  it) up to the position. Ready when it is there with the core's digest, nothing pending or dirty and no file whose
  contents have not arrived (`mirror_pending_changes`, `mirror_contents_missing` refuse, which abandons the switch:
  switch again once they confirm or arrive). Ready is durable (`prepared`) before it is answered.
- **The decision** is the core's, durable before anything is told. `switched` (`Switches::commitCore`, one transaction
  that checks the row is still this switch's switching core at the drained position, nothing unnumbered, nothing
  queued): the core's row becomes the vault's `mirror` in term + 1 at `(term + 1, 0)`, its entry hashes and digest
  kept, first copy complete, still `switching` (read-only, the follower asks nothing) until the new core confirms; its
  log, baseline and submissions go. `abandoned`: the deadline (**30 s** from the freeze, `mirror_switch_timeout`, with
  what the mirror last answered), a refusal by the mirror (its code), the vault's row changing meanwhile
  (`mirror_switch_interrupted`; a stop as diverged stands), or a vault that moved since it was drained: the row goes
  live again in the same term.
- **Telling** (`peer.mirror.switch.commit {outcome}`, every 5 s until answered): `switched`, the prepared mirror becomes
  the core in term + 1 (`becomeCore`: live, its log from `(term + 1, 1)`, its baseline position `(term + 1, 0)` at the
  digest both hold so the new mirror's first acknowledgement compares, the grant cleared); told again it answers the
  same. Then the old core goes live as a mirror and follows. `abandoned`: a mirror that froze goes live again; one
  that never heard of the switch has nothing to undo.
- **Invariant 12, by construction:** the old core stops accepting at the freeze; it accepts again only by its own
  `abandoned` (taken only before it decided), and the new core accepts only after the core's `switched` was durable.
  A stop, a timeout or a dropped link at any point ends in nothing changed or switched on both, after the core's next
  pass and the telling (`MirrorSwitchDbTest`, every interruption point). Every step runs from the follower's pass
  (`switching::tick`, on both servers, nothing when no switch is active); the wire handlers only change rows.
- **What moves with the role:** the log and the sequencer (by the row's role and term); the access list, remote
  accounts, owner and attribution need no rewriting (all `(home node, id)`: the new core's log names the old core's
  people by its node id, which the old core maps to its own accounts); the keep and accept settings are per link and
  stay; the start's offer changes side on both servers (so a later cancel is told from the new core). **The old core's
  role on the new core** is whatever the new core's own policy gives that linked server (its per-vault assignment or
  the link's default, `PeerVault::role`): nothing is carried across, since roles are never matched between servers.
  The mirror's prepare answers it (`peer_role`, the document `grantFor` builds; null for none or "no access"), the
  core keeps it with the switch, and the new core's start service sends it to the old core as its grant. **A switch
  never silently takes the old core's access away** (lead's review): with no role the core abandons the switch before
  it decides (`mirror_switch_no_role`, with what to do: set the linked server's role on the other server first, `vh
  peer policy set`, or switch with `--accept-no-access`); asked on the mirror, the mirror refuses it itself before
  asking. `accept_no_access` (ws, `--accept-no-access`, carried in `peer.mirror.switch.request` and kept on the switch)
  lets it go ahead, and the answer and the audit say the old core holds no role. The answer of every switch names the
  role and what it allows in a word (`peer_role`, `peer_access`: read-only, read-write or none) and `vh mirror switch`
  prints it.
  Pending contents: none can exist on the new core (refused). Piece A's versioning setting: not on this branch.
- **Held changes** stay with the server that holds them: still listed (and discardable) on a server that became the
  core; a retry there is refused (it is retried from a mirror).
- **Local vaults only:** a vault whose type is not local (an S3 vault can be mirrored today when every file is on
  disk) is refused (`mirror_has_remote`): its remote sync would have to move with the role (phase 3).

Known limits: a mirror whose core decided `switched` but which can no longer take the role (it detached meanwhile)
leaves the old core read-only as the mirror of nobody, told again every 5 s; ending the mirror there (later pieces) is
the way out. A long-running writer of any vault holds the freeze until the deadline (it cannot tell which vault an open
transaction changed), which abandons the switch.

### Forced promotion ("take over")

The core is gone or cannot be reached, and someone holding **Take over as core** on the mirror promotes it.

1. The mirror records `term + 1`, itself as core, the last `(term, seq)` it applied as the **fork point**, and a
   copy of its tree at that moment as the **fork base**.
2. It lifts the read-only gate. Pending changes become ordinary local changes.
3. It audits the promotion with the fork point and warns that the old core may hold changes this server never
   received.

### The old core returns

It learns of the higher term on reconnecting, stops accepting changes, and becomes the mirror.

- **If it committed nothing after the fork point,** it simply follows the new core's log.
- **If it did,** its tree, the new core's tree and the fork base are reconciled by the three-way merge the server
  has (`vl::vaultfmt::manifest::reconcile`, the rules of issue #442: an edit beats a delete, a name clash gets a
  deterministic rename, a move that would close a loop is not applied). The new core's side is applied. The old
  core's own changes are submitted to the new core like any mirror's changes, and those it refuses become conflict
  copies or held changes.

**Why the fork base is a true common ancestor.** In strict mode the mirror committed nothing of its own while the
link was down, so its tree at the moment of promotion is a state the old core also passed through. That is the
tree the new core stores and hands to the old core.

**What this needs** (spike finding 11): the rules run as they are. The applier needs a second entry point that takes
three trees (base, theirs, ours) with no sealed root, no bucket and no manifest state; a compare-and-set on the
file's own generation in place of the bucket index; `collect` giving a local file its generation from
`files.encryption_iv`; creates and replacements that fetch the sealed bytes over the link before they commit; the
created time either written or left out of the attribute comparison; and snapshot operations skipped. These land
with the shared tree-apply module, and the spike's test becomes its first regression test.

## Leaving a mirror

**The guarantee:** a mirror can always leave with its files, with the link up or down, without an answer from the
core, and the core cannot refuse. The mirror holds the bytes and the keys; refusing in software would protect
nothing.

What makes it true: the mirror holds the whole tree, every key version its files use, and every file's contents
(or it knows and says exactly which are missing). Nothing about reading its own copy depends on the core.

| | Take over | Detach | Detach a copy |
|---|---|---|---|
| Result here | This server is the core of the same vault | This copy is a separate, standalone vault | A new, separate vault; the mirrored one stays |
| Remote | Continues from here | Stays with the old core; none here | None |
| If the old core returns | It becomes the mirror; changes are merged | It is told; the vaults are unrelated | Nothing changes |
| Cost | Immediate | Immediate | A full copy in time and disk |
| Vault uid and keys | Same | Same, until re-keyed | New |

### Detach

1. The person chooses the new owner, a sign-in account on this server (by default themselves).
2. The dialog shows the last `(term, seq)` confirmed, the digest state there, and every file that would be missing.
   The list can be exported before anything happens.
3. In one transaction: the mirror record goes, the gate is lifted, pending changes become ordinary local changes,
   the owner is set, the peer's vault role and its local denials go. Access-list entries for remote accounts stay
   listed and do nothing.
4. The engine is reloaded as a plain local vault (`Manager::updateVault`, `reloadEngine`).
5. Nothing is deleted on either server and no bucket is touched.
6. `mirror.detach` is audited here at once: who, when, the fork point, the missing count.
7. The core is **told, not asked,** when it is next reachable (the pattern `vh vault leave` uses with the cloud). It
   records the detach and ends the mirror on its side. Its own vault is unaffected.

**Why the detached vault takes no remote.** The core may be alive and writing to that bucket. To carry the remote
on, take over. A different bucket can be attached afterwards; attaching the original's bucket is refused, as a
bucket holding another server's vault is today.

**After a detach** the vault shares its uid and keys with the original. It behaves as any local vault, with one
restriction: it cannot be mirrored with a server that holds the original. The console keeps recommending the
re-key pass until it has run.

### The re-key pass

A rewrite that gives a detached vault a new uid and a new key, after which it shares nothing with the original. It
is harder than a rotation and is its own work item: the re-seal takes a target vault uid; readers accept the old uid
per generation while the pass runs; versions and snapshot blobs are covered; the rewrite streams; then the old key
versions and the old uid are dropped.

### Detach a copy

A new vault is written from the mirrored one: new uid, new entry uids, new key, a chosen owner. The mirrored vault
stays read-only and resumes when the core returns. It needs a vault-to-vault copy, which does not exist today
(`Filesystem::copy` and rename answer `EXDEV` across vaults). It runs as a background job with progress and needs
free space for a second copy.

### Who may do it

Admin permissions on the mirror server, outside the shared access list (`identity.md`): **Detach mirrored vaults**
(detach, detach a copy) and **Take over as core**. Super admins hold both. A super admin on the host's control
socket can always do it. The console asks for the vault's name to be typed. A full-access Desktop follows RBAC
alone. Never an agent, a scoped device or a relayed browser.

### Ending a mirror from the core, and deleting

> "Assume the trust boundary is valid until either party acts to make it invalidated." (Cooper, 2026-11-26)

While two servers are linked and a vault is mirrored, each side does what the other asks, without second-guessing or
defensive extra steps. What invalidates the trust is an explicit act: the core ending the mirror, the mirror turning on
its keep setting or detaching (wave 5), either side unlinking. The rule (Cooper, 2026-11-26: the core may choose to
try to remove the mirror's copy, the mirror may keep what its core removes, and mirrors should not accumulate junk):

- **The core chooses.** `mirror.cancel` on the core (`vh mirror cancel <vault> [--remove-copy]`) ends the mirror on
  the core at once (its `core` row and log go) and tells the mirror, with `remove_copy` (default false). Asking for
  removal of a mirror that has begun needs the data-destroy step-up. The audit says which was asked.
- **The mirror applies the rule, with no confirmation of its own:**
  - a copy whose first copy is not finished is removed, whatever was asked or set: the mirror holds nothing complete;
  - a finished copy is removed when the core asked for it and the mirror's keep setting for that link is off;
  - otherwise it is kept as an **orphaned** copy: `mirror_vault.role = 'orphaned'`, read-only, its last grant and its
    pending-contents rows kept (rbac::mirrored resolves it as it did).
  It answers what it did (removed or kept), and the core records and shows it (audit `mirror.cancel.copy`,
  `vh mirror info`).
- **The keep setting** ("keep the vaults this server's core removes", per link, on the mirror, default off; a super
  admin there): turning it on is the mirror's act that limits what the core may remove.
- **Orphaned copies do not pile up:** a super admin on the server holding one removes it (`vh mirror cancel <vault>`,
  with the data-destroy step-up; audited `mirror.remove`). A live mirror is not removed from the mirror's side (detach,
  wave 5).
- **Deleting a mirrored vault** (wave 5): on the core it is one step that takes the choice for the mirror's copy
  (`vh vault delete <id> --mirror-copy remove|leave`, `mirror_copy` on `storage.vault.remove`; no default) and follows the
  vault's retention window (decisions log 601-602; Cooper: the mirror matches the core until the core actually deletes the
  vault): the choice is recorded with the deletion and the mirror is read-only for the window; a restore keeps it; the
  purge ends it with that choice exactly as `mirror.cancel [--remove-copy]` does. On the mirror a held copy is never deleted as a vault: detach it, or remove an orphaned one through
  `vh mirror cancel`. (Until wave 5 the core's delete was refused until the mirror was ended.)
- **The mirror unreachable:** the core ends its side at once and the request waits (`notify`) until the link is back.
- **Unlinking the servers** invalidates the trust: a request still queued is dropped, never delivered; the mirror's
  copies of that core become orphaned (kept), and the core's mirrors with that server end on the core.
- **After any of these** the server that left still holds the keys. The core is offered a key rotation.

### As built: leaving a mirror (phase 2 wave 5, piece A, migration 167)

"Detach", "Who may do it", the core's side of "Ending a mirror from the core, and deleting", invariants 10 and 11, and
opt-in versions on the mirror. Detach a copy and the re-key pass are piece C. Decided while building (owner's
instruction to build without waiting for review); each is listed for confirmation in the hand-off:

- **The permission** "Detach mirrored vaults" is the admin module `mirror` (`admin.mirror.detach`, bit 0 of
  `admin_role.mirror_permissions`, migration 167; `rbac/permission/admin/Mirror.hpp`; the next bit is piece B's "Take
  over as core"). Super admins hold it, no other built-in role; an admin role grants it like any admin permission
  (`--allow-mirror-detach`, the console's snapshot) under the escalation ceiling. `ops::mirrors::requireDetacher`: the
  switch, a person (`peer_policy::requirePerson`: never an agent, a scoped or relayed device, a linked server:
  `peer_forbidden`), then a super admin or a holder. A super admin on the host's socket always holds it.
- **Detach** (`mirror.detach`, `vh mirror detach <vault> [--owner <user>]`; `mirror/leave/Leave.hpp`): every held copy,
  role `mirror` in any state (live with the link up or down, first copy unfinished, stopped, diverged, expired) or
  `orphaned`, with the peer unreachable or unlinked; it asks the core nothing. **The preview** is `mirror.detach.preview` /
  `vh mirror detach --dry-run [--json]` (decision: a separate read command, so a console can show it before the typed
  confirmation): the last `(term, seq)` applied (the fork point) and the last the core confirmed, whether the digest
  matched there (false once diverged; null when nothing was compared), the first copy's progress, the pending and held
  changes, and every file whose current contents are not here, by path (shown to someone who may detach, never logged or
  audited; `--json` is the export). **One transaction** (`db::query::mirror::MirrorDetach::detach`, the mirror row locked
  first, under the start's step lock and the vault's local-change lock, so no page, group or person's change interleaves):
  the files whose contents never arrived become `mirror_content_pending` rows in state `missing` (every other content row
  goes); each pending change becomes an ordinary local change (its row and its pending bytes go), except a write whose
  bytes the file no longer holds (the core's state came back over it while it waited), which is kept as a held change
  (`mirror_detached`) with its bytes, so nothing a person wrote is lost; dirty rows, the linked server's role and any
  `peer` assignment go; the owner is set (a local, active account: the caller by default); the mirror's offer ends
  `detached` (to be told); the detach is recorded (`mirror_detached`, side `mirror`: fork point, digest, state it was in,
  missing count, owner, who); then `MirrorVaults::remove` (log, entry hashes, baseline, submissions). Remote accounts on the
  access list stay listed and do nothing; there is no local-denial table yet. After the commit `rbac::mirrored` and
  `mirror::access` republish (no gate, no backstop), the pending bytes move or go, the engine is rebuilt
  (`Manager::reloadEngine`), and it is audited `mirror.detach` (who, role, state, fork, confirmed, digest, missing, pending
  kept and held, owners). **No step-up** (decision: nothing is destroyed and no key leaves; the console asks for the vault's
  name, `confirm_name`, which the server checks when given).
- **Files whose contents never arrived** stay in the tree as they are (decision: nothing is deleted, the entries and
  their sizes are the person's record of what the core holds), each with its `missing` row at the file's generation. An
  open fails with `mirror_contents_missing` (`mirror::contents::Reason::Missing`, `ENODATA` on the mount, HTTP 410), never
  empty and never another generation's bytes (an older generation's bytes left on disk are not read); nothing ever fetches
  them (`outstanding` takes waiting rows, failed ones only when asked). A new version written here supersedes the row (it
  names the old generation). `MirrorDetach::missing` lists them exactly, before and after. **This is the rule** (owner
  decision 1 of the wave 5 hand-off, confirmed by the lead's review): and listings say so without opening anything,
  `fs.dir.list` entries carry `contents_missing: true` (`PendingContents::missingFileIds`, no query for a vault that
  never had a content row), `vh fs ls` shows their type as `missing`, and the console shows "Contents missing" in place
  of the size.
- **The core is told, not asked** (`peer.mirror.detached {offer_uid, vault_uid, at, missing}`, sent by the start service
  for the mirror's `detached` offer while `notify`, dropped by `dropNotices` on unlink like every notice; an orphaned copy's
  core ended the mirror already and is not told). The core (`leave::detachedReceived`) takes it only from the server it
  mirrored the vault with: it ends the mirror as `cancelOnCore` does (core row, log, submissions, staged bytes), records the
  outcome on its offer (`copy_outcome` `detached`), records the detach (side `core`, once) and audits `mirror.detached`. Its
  own vault is unaffected. `vh mirror info|list` show both records.
- **The same uid afterwards**: until the re-key pass sets `rekeyed_at`, `mirror_detached` makes both servers refuse to
  mirror that uid with each other: the core's `mirror.add` and the receiving end's offer check (`mirrorRefusal`, so at the
  offer, the accept and the keys) answer `mirror_detached_copy`. `vh mirror info|list` show the detached vault as
  `detached` with `rekey_recommended`. Known limit: a record stays when the other server deleted its vault (nothing tells
  this one); the re-key pass clears it.
- **Orphaned copies**: a super admin (or a holder of the permission) detaches one like any copy; `vh mirror cancel` still
  removes it. `vh mirror list|info` say what it is and the two things that can be done with it.
- **Deleting a mirrored vault in one step**, on the core (`ops::vaults::remove`, `Remove::mirror_copy`, `vh vault delete
  --mirror-copy remove|leave`, `storage.vault.remove {mirror_copy}`): a vault with a `core` row or a start running needs the
  choice (`mirror_copy_choice_required`, no default); then every check of the delete runs (the key-loss and "now"
  confirmations, the data-destroy step-up at the request, its target bound to `:mirror-copy` for remove), a person is
  required (deciding a mirror's end is never an agent's), and the vault is scheduled through the existing retention path.
  **The mirror follows the retention window** (lead's review of c42e1d09): the schedule only records the choice
  (`mirror_vault.deleting_copy`, migration 167) and the core's row, log and offer stay. The start service tells the mirror
  (`peer.mirror.deleting {vault_uid, deleting, purge_after, copy}`, `leave::syncDeletionNotices`: once per connection and
  whenever it changes, so a mirror down at the schedule learns it on reconnect; the core keeps the grant it sent). The
  mirror pauses a live copy with reason `mirror_core_deleting` (`MirrorDetach::pauseForCore`; `mirror::access` judges it
  before `mirror_paused`): read-only on every surface with a sentence saying what happens and when, and naming detach;
  `vh mirror info` shows the date, the core's choice and what this server's keep setting makes of it. The follower asks
  nothing of a paused copy, so nothing is submitted and changes pending stay pending (submitted if the vault is restored,
  held when the mirror ends). Detach works throughout. **A restore** (`vault::retention::restore` → `leave::restored`)
  clears the choice and the mirror is told: it is live again where it was, nothing copied again. **The purge** (the
  window's end, or `--now`/expedite; `vault::retention::purgeOne` → `leave::endForPurge`, before anything is removed) ends
  the mirror with the recorded choice (`leave` when none was recorded: erring towards keeping) through `cancelOnCore`, so
  the keep setting, the queue while the mirror is down and the drop on unlink are the cancel's. Changing the choice during
  the window: `vh vault delete <id> --mirror-copy remove|leave` (or `storage.vault.remove {mirror_copy}`) on the deleted
  vault, by whoever may delete it, with the same step-up rule; it is told again. This rides on the existing retention
  scheduler and restore (no second scheduler): the retention service's pass is the only thing that ends the mirror.
  Fixed on the way (found by the drill): the deletion's and the restore's bookkeeping (`inode = NULL`, the root off and
  back on the mount) ran without `vh.keep_mtime`, so every entry's modification time was stamped with the deletion's
  time (any vault: users saw every file modified) and a mirrored vault's entries changed under its log; both keep the
  times now. The round trip logs only the vault's own document (its soft deletion, 160's rule), which the applier
  records and does not act on. On the mirror a held copy is refused with a sentence naming detach (`vault_mirrored`), an orphaned one
  naming `vh mirror cancel` and detach (`vault_orphaned_copy`); the S3 gateway's DeleteBucket keeps refusing a mirrored
  vault (409: no field for the choice there).
- **Versions on the mirror** (`mirror.versions.set`, `vh mirror versions <vault> on|off [--keep-last N] [--max-age-days
  D] [--quota-bytes B]`; `mirror/versions/Versions.hpp`): `mirror_vault.keep_versions`, the local versioning policy's
  shape, default off, super admins of the mirror, audited `mirror.versions.set`. Turning it on with no limits gives 10
  versions per file for 30 days (decision: never unbounded; a 0 is "no limit of that kind", at least one stays). The
  applier, before a group's transaction, stages the prior generation of each live file the core replaces (a new
  generation), trashes or deletes, through `versions::retain` with the mirror's policy (`RetainOptions::held_copy_policy`,
  past the held-copy skip; not for this server's own entries brought back into line, not for a first copy, not for a
  generation whose contents never arrived), attaches it in the group's transaction (recovery tables only: past the
  backstop, never logged, hashed, submitted or in the digest) and finishes it after the commit. `versions::maintain` applies
  the mirror's policy to held vaults that keep versions. Read them with `recovery.list|inspect` (rbac::mirrored decides who
  may read the file); a restore is a change made on the mirror (the restore writes through `Filesystem::createFile`, a
  pending write while Live; `read_only` with the gate's reason otherwise). After a detach they are the local vault's like
  any others (its own policy from then on); a removed copy takes them with its recovery store. **Cost**: with it off, one
  atomic load per group: nothing beyond the applier's own work. Measured
  (`MirrorSubmitDbTest.DISABLED_VersionsOnTheMirrorCostPerGroup`, dev VM, ASan build, PostgreSQL 16, 2026-11-27, load
  about 2: 100 groups each replacing one file): 12.1 ms a group off, 16.7 ms on (+4.6 ms: the hard link of the prior
  bytes, the version and blob rows under a savepoint, the per-file prune).
- **A held change's bytes** (`mirror.held.get`, `vh mirror save <id> <dest|->`, a leaf beside `discard` and `retry`, so
  `vh mirror held` stays the listing leaf): the person's version of a held write,
  decrypted with the vault's key at that generation, for super admins (who may list held changes); inline base64 up to
  8 MiB on ws (`too_large` beyond), streamed with `vh fs get`'s transfer frames on the CLI (the client writes `<dest>`).
  Nothing in the vault changes; a detached vault's held changes stay listed.

Proven: `MirrorLeaveDbTest` (`test_mirror_leave_db.cpp`), `MirrorSubmitDbTest.VersionsOnTheMirror...`,
`RoleParityTest.MirrorDetach...`, `SqlDeployerHistoryDb.MirrorLeaveMigration167...`, and `vhh drill peers` step 9.

## A mirrored vault with a remote

- **Remote sync runs on the core only,** with the existing engine, under the vault's own strategy. The mirror never
  contacts the bucket and is given no bucket credentials while the link's sharing is `identities`.
- **On the mirror the vault is a local vault** with a mirror record. Its remotes are shown, read-only, from the
  shared vault settings.
- **A file kept only in the bucket** (`cache`): the mirror asks the core, which serves it from disk or fetches it
  from the bucket under its price guard.
- **Planned switch:** the old core finishes or abandons its pass and releases the bucket; the new core takes the
  remote's state (index, baselines, manifest position) over the link and continues. The credentials go with it,
  wrapped to its wrap key.
- **Forced promotion:** the new core needs the bucket credentials (already there with `full` sharing; asked for
  otherwise), reads the bucket's current state, compares it with its local copy and continues. For an encrypted
  layout this is a new path: today a server refuses to rejoin a bucket that holds its own vault
  (`bucket_holds_this_vault`). On Backblaze B2 the admin is warned that the old core must be stopped, because B2
  cannot make two publishers safe.
- **The one-way `mirror` sync strategy works** on a server-mirrored vault, since one server writes to the bucket.

## Commands

For a person: `mirror.add` · `mirror.accept` · `mirror.remove` · `mirror.list` · `mirror.status` · `mirror.pause` ·
`mirror.resume` · `mirror.switch` · `mirror.takeover` · `mirror.detach` · `mirror.detach.copy` · `mirror.resync` ·
`mirror.held.list` · `mirror.held.get` · `mirror.held.retry` · `mirror.held.discard`

On a peer session: `peer.mirror.offer` · `peer.mirror.accept` · `peer.mirror.key.deliver` · `peer.mirror.key.ack` ·
`peer.mirror.tree` · `peer.mirror.notify` · `peer.mirror.log` · `peer.mirror.ack` · `peer.mirror.submit` ·
`peer.mirror.switch.request` (as built: the mirror asks its core to begin) · `peer.mirror.switch.prepare` ·
`peer.mirror.switch.commit` · `peer.mirror.promoted` · `peer.mirror.detached` ·
`peer.mirror.removed` · `peer.mirror.fork_base`

CLI: `vh mirror add <vault> --to <peer>`, `vh mirror status [<vault>]`, `vh mirror pause|resume`, `vh mirror switch`,
`vh mirror takeover`, `vh mirror detach [--copy] [--owner <user>]`, `vh mirror remove`, `vh mirror held …`.

## Limits in the first version

- One mirror per vault.
- A vault is server-mirrored or bucket-replicated (`vh vault join`), never both.
- No files in `gcm0` or non-empty `plain` format.
- No writes on the mirror while the link is down.

## Invariants (each gets a test)

1. The mirror's tree at `(term, seq)` equals the core's at `(term, seq)`, by digest, at every acknowledgement.
2. A group is applied whole or not at all.
3. No change to a mirrored vault commits on the mirror outside `vh.mirror_apply` or `vh.mirror_local`.
4. While `read_only`, every write surface refuses with a reason, and no surface reports a generic error.
5. A file open for writing when the link drops is never lost.
6. The core never commits a mirror's file without holding its verified contents.
7. A change the core refuses is never dropped: it becomes a conflict copy or a held change.
8. No file is linked into place before its size, hash and authentication checks pass.
9. A key version is installed on the mirror only after `prove` accepts it against a pinned attestation key.
10. Detach completes with the peer unreachable, deletes nothing, and touches no bucket.
    (`MirrorLeaveDbTest.Invariant10_DetachCompletesWithThePeerUnreachableDeletesNothingAndTouchesNoBucket`)
11. When a mirror ends, the mirror's copy is removed only by the rule above: unfinished, or removal asked by the core
    with the mirror's keep setting off; otherwise it is kept, orphaned. Nothing else on either side removes it.
    (`MirrorLeaveDbTest.Invariant11_TheCopyIsRemovedOnlyByTheRuleWhenItsCoreDeletesTheVaultAndNeverByADeleteHere`)
12. Two servers never both accept changes as core of one vault in the same term.

**The drill** (exit criterion for phase 2): two private daemons; mirror a vault; write on both sides; kill the core
mid-transfer; check strict mode on every surface; detach the mirror; check that every confirmed file opens and the
missing list is exact; restart the core and check that it accepts the news.

## Work items

Phase 2 (local vaults):

1. Permanent ids for folders and symlinks; the replication log, its triggers and sequencer.
2. `ops::fs`, with every write surface moved onto it.
3. The tree-apply module, shared with the manifest applier.
4. The sealed lane; the receive-verify-link path; the content state on the local engine.
5. Key delivery and proof; the bucketless vault writer for the first copy.
6. `mirror_pending`, submit, confirm, conflict copies, held changes, the generalised conflict record.
7. The gate at every surface, the backstop trigger, the background-job skips.
8. The digest, acknowledgements, the scrub, resynchronising.
9. The planned switch.
10. Detach; the two admin permissions; orphaned copies.
11. Commands, CLI, console and Desktop; the drill.

Phase 3: remotes on the core and the role move with a remote; forced promotion and the old core's return; history
(versions and snapshots); key rotation across the mirror; detach a copy; the re-key pass.

Phase 5 (optional): queued offline changes on the mirror.

## Open

- **The S3 gateway's refusal:** 503 `ServiceUnavailable` (clients retry) is proposed over 403.
- **Log retention figures** (30 days, 5,000,000 rows) are starting values.
- **Whether a planned switch should be offered automatically** at a clean shutdown of the core.
