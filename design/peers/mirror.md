# Server mirror: one vault on two linked servers

Status: design, phase 0 of the server mirror plan (2026-11-25). Built so far: permanent ids for every entry (phase 1b,
migrations 158/159), the core side of the replication log (phase 2 piece 1, migration 160; "As built: the
replication log" below) and the sealed contents lane with the mirror's receive path (phase 2 wave 2, migration 161;
"As built: sealed contents" below) and following the core (phase 2 wave 3 piece B, migration 164; "As built: following
the core" below). The rest is not implemented. It covers how a vault
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

**Known limit (not fixed here): FUSE `utimens`, `chmod` and `chown` never reach the database.** `fuse::setattr`
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
  link's read thread; wave 2's `contents::fetchOutstanding` runs on a second thread of it (4 files a pass). For a drill:
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

Not built here: resynchronising a diverged or expired vault, the strict-mode gate (a local write on the mirror is not
refused yet), submitting the mirror's changes, history. The two-daemon proof needs piece A and is the lead's.

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

- **The core ends the mirror** (`mirror.remove`): the mirror is told and its copy becomes **orphaned**: read-only,
  kept, waiting for an admin there to delete it or detach it. The core never deletes another server's copy.
- **The core's vault is deleted:** the same. The mirror's copy is orphaned, not deleted.
- **Unlinking the servers** is refused on a mirror while it holds mirrored vaults, until each is detached or
  deleted there. On the core it orphans the mirrors.
- **After any of these** the server that left still holds the keys. The core is offered a key rotation.

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
`peer.mirror.switch.prepare` · `peer.mirror.switch.commit` · `peer.mirror.promoted` · `peer.mirror.detached` ·
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
11. The core never deletes or alters the mirror's copy when a mirror ends.
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
