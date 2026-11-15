# Applying another writer's manifest to the local database

Status: design for review (managed storage plan of 2026-11-12, workstream I, "a manifest applier that merges another
server's changes into the local database"); work items 1 to 5 and 7 are built (see the "As built" sections), item 6
in part. The applier takes in heads naming several writers; replicated vaults are still not offered (no join,
`mirrors.md`). It covers how a running server takes a
canonical `opaque_v1` root that another writer published into its database, FUSE view, cache and change journal, and
how that closes the restart gap of [spec 06](../encryption/06-publish-without-preconditions.md) §5.5. It does not cover
the publish protocol (spec 03 §3.4, spec 06 §5), joining a node to `writers`, key hand-over or rotation between
servers ([`mirrors.md`](../cloud/mirrors.md)), `path_v0` vaults, or anything in vaulthalla-cloud.

## Decided and given

- **Decided (Cooper, 2026-11-12, plan §3.1):** item 6, mirrored deployments are optional, per vault, solo by default,
  "start simple", with the existing conflict resolution; item 1, one bucket per vault; item 7, Desktop-only vaults
  with several Macs (wave 4). Everything else is this design's, decided under the compatibility policy's rule 5
  (`docs/contributors/compatibility-policy.md`: no customer dependency, durable data stays recoverable, testable);
  the one choice that changes key custody was put to the maintainer and is under "Decided by the maintainer".
- **Given by the code:** a solo vault never needs the applier (every head it reads is its own), so wave 1 ships
  without it, and a solo pass keeps its cost: one HEAD of the root when nothing moved (spec 06 §5.7).

## What exists today (branch of #441)

**The publisher's merge.** `manifest::publish` (`core/src/sync/manifest/Publisher.cpp`) builds on a base root, and
when another writer's root won (a 412 on the conditional path, `:400-404`; a lost C1 round on `version_log`,
`:342-345`, `:360-371`) it reloads the head and retries. Each attempt merges in memory with `mergePending(theirs,
before, ours)` (`Content.cpp:93-104`): per entry uid, key version and snapshot id, ours wins if we changed it since
`before`, theirs is kept otherwise, an entry we no longer have but had in `before` is dropped; producer, `vault` and
`recovery_policy` are always ours. `before` is `PublisherCache::last_produced` (what this server collected for its
previous publish, `:188`, `:208`) and falls back to `theirs`. **The merged result goes only into the published root
and the in-memory cache** (`cache.base`, `:392`). The database, `remote_object_index`, the FUSE cache and
`fs_change_log` never see it.

**Reading other writers' roots.** `Service::verifyRemote` (`Service.cpp:120-214`), called at the start of every
regular pass (`Cloud::initBins`, `Cloud.cpp:373`, through `CloudEngine::refreshRemoteIndexFromManifestIfChanged`,
`CloudEngine.cpp:527-537`), costs one HEAD while the root's ETag is the recorded one. Otherwise it loads the head with
its segments, applies the chain, mode and `writers` checks, **records it as `known`** (`recordRoot`, `own = false`)
and discards the content. After a restart (`cache_` empty) the next publish has `before = theirs`, so every entry the
database lacks is "deleted by us". The interleaving suite counts exactly this: `reverted_by_restart`
(`core/tests/unit/test_manifest_interleavings.cpp:683-688`, asserted `> 0` at `:812-813`).

**Building a database from a manifest.** `db::query::vault::Recover::apply` (`core/src/db/query/vault/Recover.cpp`)
is the only code that turns `Content` into rows: one transaction into a freshly reserved vault id, insert-only. It
writes the tree parents first (`fs_entry`, `directories.uid`, `files.object_uid` with the generation as
`encryption_iv`, `symlinks.uid`), inodes through `fsCache->assignInode` (`ops/VaultRecover.cpp:249-253`),
`files_trashed`, `remote_object_index` rows with `source = 'manifest'` (`:231-238`), provider versions
(`ON CONFLICT DO NOTHING`), snapshot records as `recovery_snapshot` + `file_versions`, re-sealed keys, grants and
envelope rows, and the chain position. Nothing is downloaded: the vault runs `cache` and hydrates on open.
`vault::recover::plan` (`core/src/vault/Recover.cpp:768-812`) repairs a tree first: entries whose folder is gone or
that form a cycle go under `/Recovered`, and a duplicate name in one folder gets `" (" + uid[0..8] + ")"` appended.
The row shapes and the tree repair are reusable; the insert-only, empty-vault, one-transaction apply is not.

**The sync pass.** `initBins` lists or reads `remote_object_index`, binds `o/<uid>` rows to local files by uid
(`Cloud::keyByObjectUid`, `Cloud.cpp:471-512`) and counts objects no file names as orphans, "left alone, never
downloaded". The planner (`Planner.cpp`) then decides per file: local only → upload under `cache` and `sync`
(`:51-71`); remote only → never reached for opaque vaults (orphans are dropped before); both → in sync when the
generation matches (`sameOpaqueGeneration`, `:118`), else classified against the per-file `Baseline` (`:138-143`).
Under `ask` a one-sided change syncs in its direction and a two-sided one becomes an open `sync_conflict` row
(`:147-172`); `keep_local`, `keep_remote` and `keep_newest` decide it (`RemotePolicy::resolve_conflict`,
`RemotePolicy.cpp:209-223`). An open conflict is decided with `ConflictResolver::resolve` (keep_local uploads,
keep_remote downloads; stale decisions refused; ws `sync.conflicts.*`, `vh sync resolve`). There is no conflict
model for names, folders or attributes: only content.

**What clients get.** Row triggers on `fs_entry`, `files`, `directories` and `symlinks` write `fs_change_log`
(migration 115) in the writer's own transaction, so any write path is journaled (create, update, rename, move,
delete). `FsChangeNotifier` pushes `fs.changed {vault_id, revision}` to subscribed sessions and clients read
`fs.changes.list` from their cursor (`.claude/context/change-journal.md`). A contract test classifies every SQL
writer of those tables (`tools/contracts/test_fs_change_journal_contract.py`). FUSE asks the kernel to cache nothing
(`kKernelMetadataTimeout = 0.0`, `fuse/Bridge.cpp:61`), so a committed row and a refreshed `fs::cache::Registry`
entry are what the next lookup sees.

## The design in one rule

**The database is always at a root.** `remote_manifest_state` (`epoch`, `root_sha256`, `root_version_id`) names the
last root whose content the database has fully taken in; the database equals that root's content plus local changes
made since. Today `known` advances on a read without applying (`verifyRemote`) and on a publish that merged in memory,
so the rule fails exactly when another writer exists. The applier makes `known` advance only (a) in the transaction
that finishes applying a root, or (b) when this server's own publish settles, whose content it collected from a
database already at the base. Then `mergePending` with `before = theirs` is correct at every cold start, and the
three-way work moves to one place: the applier.

## When it runs

| Signal | Today | With the applier |
|---|---|---|
| A pass starts and the root's ETag moved | `verifyRemote` loads, records, discards | `verifyRemote` returns the loaded head (no extra request: segments are already fetched); the applier runs before `keyByObjectUid` and planning |
| A publish loses a round (412, or C1 names another successor) | merge in memory, retry | the publisher returns the head it loaded; the pass applies it, collects again and publishes; still at most `max(3, writers + 1)` rounds (spec 06 I7), then `PublishConflict` as today |
| The head is this server's own root, recorded | nothing | nothing (the solo case) |
| The head is this server's own root, unrecorded (a crash after the PUT) | recorded as another writer's | applied: every change compares equal, so nothing is written but the record |

Events never signal a root (`.vaulthalla/` keys are outside events and listings). A head refused by the chain rules,
the mode check or `writers` (`checkHeadForWriter`) is never applied; the vault stalls and alerts as today.

## What it applies, in order

The applier computes `reconcile(base, theirs, ours)`: `base` the content of `known` (see "The merge base"), `theirs`
the head, `ours` a fresh `Manifest::collect` (which also gives uids to directories and symlinks that lack one). It is
a pure function over three `Content` values returning an ordered plan and a list of decided or open conflicts; no DB,
no I/O. Each entry is compared in groups: **placement** (`parent`, `name`), **content** (`generation`, `key_version`,
`size`, `content_hash`, `object`, `mime`; `mtime` follows content), **attributes** (`mode`, `owner`, symlink
`target`), **state** (live, `trashed`, purged). A group changed on one side takes that side; changed on both to the
same value is in sync; changed on both differently is a conflict (next section). **History** (`versions`, `names`,
tombstones) is a union, never a conflict.

| Step | What | Rows (same shapes as `Recover::apply`) |
|---|---|---|
| 1 | Vault settings per field (`name`, `quota_bytes`, `sync_strategy`, file-recovery mode) | `vault`, `rsync`, `vault_recovery_policy`; a name taken by another vault on this server is not applied (noted) |
| 2 | Recovery grants are not taken from another replica's root: the account's signed recovery policy carried in the root is verified against this server's pin and applied by the cloud service (decision below). Envelope kids per version: union | `vault_recovery_grant`, `vault_key_envelope` |
| 3 | Key records: only checked, never applied. A version this server doesn't hold, or a held version whose `key_check` differs, stops the apply (`manifest_key_missing` / `manifest_key_mismatch`, stall, alert once) | none |
| 4 | Directories created, parents first | `fs_entry`, `directories`; inode from `assignInode` |
| 5 | Moves and renames (dirs, then files and symlinks), each checked against cycles | `fs_entry.parent_id`, `name`, `path` (descendants' paths follow, as for a local rename) |
| 6 | Files and symlinks created: remote-only, bound to `o/<uid>`, hydrated on open | `fs_entry`, `files`, `symlinks`, `remote_object_index` (`source = 'manifest'`) |
| 7 | Content replaced: the row takes the new generation, the index row the new object; the local cached bytes are removed | `files`, `remote_object_index`, the backing file |
| 8 | Trash, then deletes (children first) and purges | through the same calls as local trash and `Engine::removeLocally` (local versioning keeps the last generation, `Engine.cpp:318-346`) |
| 9 | Provider versions, prior names, tombstones: union | `upstream_object_version` (`ON CONFLICT DO NOTHING`) |
| 10 | Snapshot records, once they carry a uid (below) | `recovery_snapshot`, `file_versions` |
| 11 | `known` := head, the head's base copy stored, `applying` cleared | `remote_manifest_state`, `remote_manifest_root`, base copy |

**Snapshot records are not applied until the format changes.** `SnapshotRecord::id` is `recovery_snapshot.id`, a
per-server sequence (`Content.cpp:72`, merged by id at `:100`), so two servers' snapshot 7 are different snapshots.
Design: a random `uid` per snapshot record in the snapshot segment (spec 03 §3.3), merged by uid (work item 1);
until then the applier leaves snapshot records alone.

**Batches and transactions.** All network work (root, segments) happens before the first transaction. Rows are
written in short transactions of at most 500 entries in the step order above, each through `db::Transactions::exec`,
followed by the cache work for that batch after commit (`Registry::cacheEntry`/`updateEntry`/`evictId`,
`refreshDirStats`, removing backing files under `Filesystem::contentWriteMutex`). Every row update is a
compare-and-set on what `ours` held (the row's id, parent, name and generation): a row a local write changed since
`collect` is skipped and becomes a local change for the next apply. Step 11 is its own last transaction.

## Identity and local state

- **Mapping.** A manifest entry is matched by uid only: `files.object_uid`, `directories.uid`, `symlinks.uid`
  (migration 125), `files_trashed.object_uid` (`db::query::sync::ObjectIdentity`). Local ids, inodes, `base32_alias`,
  backing paths, owners of local rows and `fs_entry.created_by` are per server and never compared. New rows are
  attributed to the vault owner, as a restore attributes them to the restoring admin; the audit event names the
  producing node.
- **Moves keep identity:** the `fs_entry` id and inode stay, so open handles (FUSE is keyed by inode,
  `WorkingCopies` too), share links (`share_link.root_entry_id`) and conflict rows follow the entry. Permission
  overrides are glob paths (`vault_permission_overrides.glob_path`) and re-match at the new path, exactly as after a
  local rename.
- **Deletes and trash** end the `fs_entry` row as a local one does: its share links go (`ON DELETE CASCADE`,
  `070_link_shares.sql:14`) and share uploads lose their target (`SET NULL`, migration 101), as after a local delete.
- **Open files.** A content replacement or delete of a file with a working copy (`WorkingCopies::isOpen`, the check
  `recovery/provider/Restore.cpp:331` uses) is deferred for that entry only: its incoming value is kept in a
  `manifest_apply_deferred` row, the collector reports that value for the uid so a publish never reverts it, and the
  first pass after the last `release` applies it, or, if the close sealed new bytes, treats it as edit/edit.
- **Cached bytes under `cache`.** A replaced generation removes the backing file; the next open hydrates the new
  object with one GET (`openOpaqueObject`). Derived artifacts follow the file id (`purgeDerivedArtifacts`).
- **Content conflicts reuse the planner.** The applier writes the incoming object into the uid's
  `remote_object_index` row but leaves a locally changed `files` row alone; `keyByObjectUid` then binds it and the
  planner's existing L+R path classifies it against the `Baseline` (two-sided → policy or open conflict).

## Conflict rules

| Case | Rule |
|---|---|
| Content edit / edit | the existing conflict path, under the vault's policy (`keep_local` by default; `mirrors.md` proposes `ask` for replicated vaults). The losing generation stays a provider version |
| Edit / delete (either direction) | **the edit wins.** Ours edited, theirs purged: the entry stays, its index row goes, and the planner re-uploads (`uploadLocalOnly`). Theirs edited, ours trashed: the entry is restored from our trash to its incoming place |
| Delete / delete, trash / trash | converged |
| Placement: rename / rename, move / move, rename / move | **the head wins** (it is published; ours is not), and our undone placement is reported in the apply's audit event and status. Deterministic, no clock |
| Attributes changed on both sides | the head wins, reported the same way |
| A move that would close a directory cycle | not applied: the entry keeps its local parent and the next publish carries ours. The other writer then applies that root (its side unchanged since), so both converge on one tree |
| Two uids with the same name in one folder (`UNIQUE (parent_id, name)`, `040_files.sql:24`) | the entry with the greater uid is renamed `name (<uid[0..8]>)`, the rule `vault::recover::plan` uses; every server computes the same, so the rename converges instead of ping-ponging |
| A folder deleted on one side, with children added or edited on the other | the folder is kept (an edit beats a delete); children deleted with it on the deleting side are deleted |
| Names that differ only by case | not a clash: the server compares names byte for byte, as it does for local creates |
| A head whose own tree is broken (an orphaned entry, a cycle) | `plan`'s step 6 repair: under `/Recovered`, reported |

What the user sees: applied changes appear in FUSE, the web UI and Desktop at once (journal + push); content
conflicts in the existing conflicts list; decided placement and attribute conflicts, deferred entries and the applied
epoch and node in the vault's sync status and audit trail (`manifest.applied`, new). Nothing is silently lost:
content survives as a provider version or a local version, and an undone rename loses no data.

## The merge base, and closing the §5.5 gap

`base` must be the content of `known`, available after a restart and after any time offline. Neither existing
candidate is safe:

- **The cached base** (`PublisherCache`) is memory only.
- **The last settled root, read from the bucket** holds entries the database lacks today (fixed by the rule above), and
  may be gone: the root janitor keeps the head and two predecessors and deletes older canonical roots after 7 days
  (`collectRootVersions`); segments go 24 h after the last three canonical roots stop naming them
  (`collectGarbageVersionLog`, `collectGarbage`); conditional buckets expire noncurrent roots after a day (spec 03
  §3.5). A server offline for a day while another writer publishes three times has no base left in the bucket.

**Design:** keep a local copy of `known`: the root's bytes and its segments' sealed bytes
(`remote_manifest_base`, by vault and sid, in the next free migration), written in the transaction that records
`known` (step 11, or an own publish's `recordRoot`), with segments no longer named deleted. It is read with the
existing `Reader` code and checked against the root's pins, so it needs no new merge semantics, and a cold-start
publish no longer GETs segments. Cost: about the manifest's size per vault (one segment per 8,192 entries, at most
4 MiB of plaintext each). `remote_manifest_state` also gains `applying_epoch` and `applying_root_sha256`.

A writer restarted from its database alone then has its base on disk, applies any newer head before it publishes
and drops nothing. A restore stays as spec 06 §5.5 has it (it takes the vault over, at the loaded root).

## Crash safety, idempotency, concurrency

- **The same head twice:** step 11 recorded it, so `verifyRemote`'s HEAD matches and nothing runs; a second run
  before step 11 finds every applied change equal on both sides (in sync), writes nothing for them and finishes.
- **A crash mid-apply:** committed batches stay, `known` is still the old root, `applying_*` is set. Publishing is
  refused while `applying_*` is set (a partial state is never published), and the next pass applies the newest head
  from the same local base, converging as above.
- **A head that arrives while applying:** the applier finishes the head it loaded (a consistent snapshot) and the
  publish's listing or the next pass sees the newer one. A lost publish round applies again, bounded by I7.
- **Local writes during an apply** are skipped by the compare-and-set and become local changes. Two applies of one
  vault can't overlap: both run under the pass lease (`sync::Controller::tryAcquirePass`).

## Off the hot paths

The applier runs on the sync pass's thread under the pass lease, never in a FUSE callback or a ws handler. No
transaction spans a network request; batches are bounded, so a large incoming change never holds a pool connection
for long (the DB pool's restart wedge, `production-hardening.md`, is why). The only lock it shares with FUSE is the
per-file `contentWriteMutex`, held for one backing-file removal as `Engine::removeLocally` does.

## What it does not do

Add a node to `writers` (the join), hand vault keys to a server, rotate keys across replicas, or decide who may write
(`mirrors.md`); talk to vaulthalla-cloud; open a server-to-server channel; apply `path_v0` index manifests (they are
path-keyed and already reloaded into the index); run on vaults with the `mirror` strategy, which replicas refuse.

## Testing

**Given by #441:** the versioned fake bucket (`tests/helpers/versioned_bucket.hpp`: `Reject501`, `listingLag`,
`orderBy(Start)` + `holdPut`, `expireNoncurrent`), the `HookedStore` scheduler and its exhaustive and seeded
interleavings with crash, lost-reply and failed-DELETE faults (`test_manifest_interleavings.cpp`), `ManifestPublish*`
and `ManifestChain*` in both modes, DB-backed `test_manifest_db.cpp`, `VaultRecoverDb`, the sync conflict harness and
`FsChangeJournalDbTest`. **To add:**

1. `ManifestReconcile*` (pure): every row of "Conflict rules", plus property tests over random concurrent operations:
   convergence, idempotence, and no broken tree from the cycle and name rules.
2. The interleaving suite's writers get a model database (a `Content`) the pure applier updates and a crash keeps;
   at quiescence every model equals the head, and `reverted_by_restart` is asserted to be zero.
3. `ManifestApplyDb*`: each step's rows and journal kinds, a crash at every batch boundary then re-apply, the
   compare-and-set skip, an open working copy deferred then applied or turned into a conflict, a share link on a
   moved and on a deleted folder, cached bytes dropped and rehydrated, the journal contract classifying the writers,
   and a solo vault's pass still costing one HEAD.
4. Two daemons on one fake bucket in the Tier B harness (a `vhh drill mirror`), then on Backblaze (spec 06 §8.3
   item 8) once A3 and A4 are confirmed.

## Work items, in landing order

| # | Item | Size | Unblocks |
|---|---|---|---|
| 1 | Format: snapshot record `uid`, `mergePending` by uid; spec 03 §3.3 amendment | S | snapshots across replicas |
| 2 | Pure `reconcile(base, theirs, ours)` with the rules above and test 1; no DB, no server includes | M | mirrors; the wave 4 Desktop engine (several Macs) through the shared format library (plan J, L) |
| 3 | Local base copy (`remote_manifest_base`, `applying_*`), written wherever `known` advances; cold-start publish reads it | M | the §5.5 fix |
| 4 | DB executor (`db::query::sync::ManifestApply`) and the per-vault applier: batches, compare-and-set, cache and backing-file work, deferral, audit | L | mirrors |
| 5 | Wiring: `verifyRemote` returns the head, apply before planning, a lost round applies and republishes, `known` advances only by apply or own publish | M | mirrors; closes §5.5 |
| 6 | Tests 2-4 | M | enabling replicated vaults (mirrors.md item 1) |
| 7 | Status: applied epoch and node, deferred entries, decided conflicts (mirrors.md item 6) | S | Desktop and portal mirror screens |

Together about XL, the core of plan workstream I. The portal (wave 2 browser, wave 4 reader) needs none of it; the
Desktop engine needs item 2 and its own executor into File Provider state.

## Decisions made in this design (compatibility policy, rule 5)

No customer depends on any of these, none loses durable data, and each is fixed by the tests above.

1. **The base lives locally** (known root and segments): the bucket collects it, and per-entry hashes would add new
   comparison semantics without the values a field-level merge needs.
2. **Placement and attribute conflicts: the head wins, reported.** No data is lost, no clock decides, and content
   keeps the existing conflict resolution, as decided.
3. **A lost publish round applies, then republishes:** one merge implementation and the database always at a root;
   an extra apply only in a rare lost round.
4. **Edit beats delete** in both directions: the other order loses an edit.
5. **Bounded batches with idempotent re-apply:** one transaction per head would pin a pool connection for a big head.
6. **Case-only name differences stay distinct,** as for local creates.
7. **Snapshot records get a uid,** a format change with no transition: no replicated vault exists yet.

## Decided by the maintainer (2026-11-14)

**Recovery grants added by another replica.** The risk put to the maintainer: if grants in another replica's root
were applied, this server would wrap every future key version to a recipient it never enrolled, so one compromised
replica (it holds the vault keys) could enroll an attacker's public key and the others would keep honouring it after
that replica is rotated out. The recommendation was to hold added grants as pending until confirmed on each server.

**Decision (Cooper):** "one account-authorized signed recovery policy, independently verified by every server. Don't
make the customer approve identical grants across every deployment." So grants are never merged between replicas.
The account holder signs one recovery policy with the account key; the root carries it; each replica verifies the
signature against the account key it pinned when it was linked, refuses a lower sequence, and makes its
account-managed grants equal to the policy. Additions and revocations both come only from that policy, which also
stops a compromised replica from stripping recovery. The design is `design/cloud/key-manager.md`, "The account's
recovery policy"; the applier's part is to carry `recovery_policy.account_policy` through the merge (the higher valid
sequence wins) and hand it to the cloud service, never to write grants itself.

**Also decided (Cooper, 2026-11-14):** the applier is built as the first piece of the mirrors wave, not before.

## As built: items 1 to 3 (branch `feat/manifest-applier`)

**Item 1, snapshot uids** (migration 145). `SnapshotRecord` is named by `uid` (`recovery_snapshot.uid`, a UUID
column given by the collector the first time it lists a ready snapshot, like `directories.uid`; immutable through
`vh_uid_immutable`; unique per vault, not globally, so a restore beside the original on one server keeps its uids;
`Recover::apply` writes the manifest's uid). Every collection keys snapshots by `snapshotKey` (the uid, or `id:<n>`),
so `mergePending`, `normalize`, the publisher's and reader's snapshot maps merge by uid. Spec 03 §3.3 is amended
accordingly (the snapshot member list there is the as-built form).

- *A manifest written before this change:* its snapshot documents carry `id` and no `uid`. They still read (a
  document needs a uid or an id, never neither), re-encode to their bytes, and a restore from such a root restores
  them (uid NULL, given at the first publish). On the first publish after the upgrade (a cold cache) those records are
  "ours deleted" against the head and ours, the same snapshots under their new uids, replace them; nothing else in the
  root changes (`ManifestContent.APreUidRootsSnapshotsAreReplacedByTheSameSnapshotsWithUids`).
- *Not written any more:* `id`. A per-server id written by every replica would make each server's publish rewrite the
  other's snapshot segments. An older package restoring a newer root reports its snapshot segments as unreadable
  (`bad_snapshot`, a segment issue) and restores the tree and files.
- *Vectors:* unchanged (`--check` passes). No vector holds a snapshot document, and `vectors.json` must stay byte
  for byte vl-keykit's copy (`KeykitVectors.TheLibrarysCopyIsThisRepositorysVectors`); a snapshot vector belongs to the
  format library's extraction, with a vl-keykit release first. The C++ tests pin both forms.

**Item 2, `reconcile`** (`sync/manifest/Reconcile.hpp`, includes only the manifest format code). It returns the
resulting `Content`, an ordered plan of `Op`s (each with `ours`, the entry as collected, for the executor's
compare-and-set, and `target`), the conflicts, key problems that stop it, and an incoming account recovery policy to
hand on. `applyPlan` is the model executor; `treeProblems` the soundness check. Choices the rules left open, each the
simplest that loses no data:

1. *"Edit"* in edit/delete and edit/trash is a content change since base (or a restore from the trash); a rename,
   move or attribute change is not, so a delete or trash on the other side wins over it.
2. *Trash against purge* converges on gone (both sides deleted, nothing was edited; local versioning keeps the last
   generation). Undo: keep the trashed side in `decide`.
3. *Content edit/edit* keeps ours in the result (the files row stays) and opens a conflict carrying theirs for the
   index row; the planner decides it, as designed.
4. *Symlink `target`* is an attribute (head wins), not content.
5. *`mtime`* travels with the content; `ctime` is always ours (a per-server time).
6. *Cycle rule:* the least uid among the cycle's entries whose placement came from the head is put back to ours; a
   cycle the head made alone (no such entry) and an entry whose folder is gone on every side go under `/Recovered`, a
   directory whose uid is the first 16 bytes of SHA-256(`vh.manifest.recovered/` + the root's uid), so every writer
   makes the same one and the repair converges.
7. *Name clash:* every live entry of one name in one folder but the least uid is renamed `name (<uid[0..8]>)`,
   repeated until none clash.
8. *Trashed entries* name their folder only while it is live in the result (the collector's form).
9. *Snapshots:* created where theirs added one, deleted where theirs deleted one base had; ours otherwise (records are
   immutable; per-server fields such as `restorable_from_bucket` stay ours); records without a uid are left alone.
10. *Two sides holding a uid base lacks* (only a re-apply, or an own unrecorded root): groups compare without a base,
    so a difference is a conflict decided by the head's rule.

Tests (DB-free): `ManifestReconcile.*`, one per rule row; `ManifestReconcileProperty.*`, 300 seeds each of two
replicas doing random local operations (create, mkdir, rename, move, edit, chmod, trash, restore, purge, recursive
delete; names from a pool of four, so clashes are common) for 6 rounds in a random publish order, then quiescence:
both replicas end on the head; changes that don't overlap end on the same tree in either order; at every apply the
plan takes ours to the result, the result is a sound tree, and the same head again (before and after its record) plans
nothing. The run asserts that each of content edit/edit, placement, attributes, edit/delete, edit/trash, folder kept,
name clash and cycle was reached (2026-11-15: 84, 21, 11, 115, 102, 217, 87, 4).

**Item 3, the local base copy** (migration 145). The root's sealed bytes are `remote_manifest_state.base_root`, the
named segments' and snapshot segments' sealed bytes are `remote_manifest_base` rows by sid; `Manifest::recordRoot`
writes both in its transaction from `RootRecord::base` (nullopt drops the copy), keeps a named sid's stored bytes
when the record lacks them, and drops sids no longer named. The publisher and the reader keep each object's sealed
bytes (`LoadedSegment::sealed`, `Loaded::root_bytes`, `OpenedRoot::bytes`); the session drops them from its cache once
recorded. `openBaseCopy` checks the copy as a load would (root hash = known, authenticity, every pin) and returns the
content of `known`, or nothing with a reason. A cold `Session::publish` (no `last_produced`) passes that content as
`PublishOptions::pending_base`, the base of its pending changes, instead of the head. `applying_epoch` /
`applying_root_sha256` (`Manifest::markApplying`) make `publish` throw `ApplyIncomplete` before any request; recording
that same root clears them, recording another leaves them.

- *Written wherever `known` advances today:* by a publish and by `verifyRemote` (both modes). Until item 5 stops the
  read from advancing `known`, the copy can be of a root the database never applied, so the cold start is fixed for
  "another writer published after our known root" (`ManifestDbTest.AColdStartPublishKeepsWhatAnotherWriterAdded*`,
  `ManifestPublish.AColdStartOnTheLocalBaseCopy*`) and no worse than before otherwise; the interleaving suite's
  `reverted_by_restart` is unchanged (it drives `manifest::publish` directly) until item 6 gives its writers model
  databases.
- *Not written:* by attach-remote's cutover and by a restore (both record the chain position in their own
  transaction). A cold start after them merges on the head as before, which is right for both (a solo vault; a
  restore takes the vault over); the next recorded root writes the copy. Existing vaults get it at their next record.
- *Not done:* the cold start still GETs the head and its segments; seeding the cache from the copy when the head's
  ETag is the recorded one would save them (spec 06 §5.7) and is left for item 5.

**What item 4 needs from this:** run `reconcile(openBaseCopy(state.base()), loaded head, collect())`; stall when the
copy is missing or refused (pre-145 states, attach, restore: decide then whether to apply against the head as base or
to wait for an own publish to write the copy); call `markApplying` before the first batch; execute the plan's `Op`s
in order with `ours` as the compare-and-set; for each open `ContentEditEdit` write `theirs.object` into the uid's
`remote_object_index` row and leave the files row; hand `incoming_account_policy` to the cloud service; finish with
`recordRoot` of the head with `.base = baseCopyOf(loaded...)` in the last transaction. Deferral of open files needs
its own table (`manifest_apply_deferred`, the next migration).

## As built: items 4 and 5 (branch `feat/manifest-applier-apply`)

**Item 5, wiring.** `Session::verifyRemote` returns a `RemoteHead` (the `Acceptance` plus, when the head is not the
recorded root, the loaded head with its sealed bytes) and no longer records another writer's root: `known` advances
only by an apply or by this server's own publish (closes decision 5 of items 1-3). The server's session publishes with
`PublishOptions::apply_on_lost`: a head other than `known`, at the start or after a lost round (412, or C1 naming
another successor), throws `HeadMoved` instead of merging in memory. `vault_manifest::Service::publish` /
`publishIfChanged` catch it, apply (`applyRemote`) and publish again, at most `kPublishRounds` = 4 times, then
`PublishConflict`. A pass applies before planning: `CloudEngine::refreshRemoteIndexFromManifestIfChanged` calls
`applyRemote` (deferred entries first, then the verify: one HEAD while nothing moved). `ApplyStopped` and
`ApplyIncomplete` stall the pass (`SyncStalled`). The tests' and the interleaving suite's own writers keep the
in-memory merge (`apply_on_lost` false) unless they model a database.

**Item 4, the executor.** `db::query::sync::ManifestApply` (rows, by uid) and `sync::vault_manifest::Applier`
(`apply`, `finishDeferred`). Per operation, a compare-and-set on `op.ours` (row found by uid; parent uid and name for
placement, the index row's generation for content, mode and owner for attributes), one short transaction, then the
cache work. Choices, each the simplest that loses nothing:

1. *No usable base copy* (a state from before migration 145, one an attach-remote cutover or a restore recorded, a
   copy of another root): the merge runs with an empty base, a union. Nothing is deleted on either side; additions
   and the head's placement and attributes apply. Undo: stall instead (`apply` throws `ApplyStopped` when
   `union_base` would be set).
2. *A skipped operation* (a local write since collect, a name taken, a parent gone) leaves the head unrecorded and
   `applying_*` set: nothing is published from the partial state and the next pass applies the head again from a
   fresh collect. A skip that would otherwise be recorded could let the next publish drop the other writer's entry.
   Livelock is possible only under constant local writes to the same entries. Undo: record anyway after skips (change
   the `report.skipped` branch).
3. *One transaction per operation*, not batches of 500: each is short, and the moves, trash and deletes go through
   `Filesystem::rename` / `remove` and `Engine::removeLocally` (their own transactions, cache and backing-file work,
   local versioning). Creates, content and attributes are rows in `ManifestApply` (the shapes of `Recover::apply`).
   Undo: batch the row-only operations in `Applier.cpp`. A file with no local bytes (remote-only under `cache`)
   moves in the rows (`ManifestApply::moveRow`): `Filesystem::rename` refuses a source without backing bytes; a folder
   created by an apply or a restore gets its backing directory before a move.
4. *A local copy whose generation isn't the index's* (a change waiting for its upload): a content replacement writes
   only the index row (the planner's two-sided path decides it, under the vault's policy), a delete or trash is not
   applied (edit beats delete; the next publish carries the entry). Counted as `kept`, not skipped.
5. *Open working copies* (`fuse::WorkingCopies::isOpen`): a content replacement, delete or trash is deferred
   (`manifest_apply_deferred`, migration 146) and the collector reports the deferred target for the uid, so the head
   is recorded and no publish reverts it. `finishDeferred`, at the start of every `applyRemote`, finishes each once
   closed: unchanged → applied; sealed new bytes → the incoming object into the index (two-sided change) for a
   replacement, kept for a delete or trash.
6. *Restore from our trash* (theirs edited what ours trashed): a live entry is created, our trash row ends
   (`deleted_at`) and its local bytes go as a purge would remove them: left in the trash, the next pass's purge would
   delete the object the live file now names.
7. *Not executed:* envelope kids (`AddEnvelopes`: envelope rows belong to this server's grants, which come only from
   the account's policy), the file-recovery policy (set per server through `vh vault recovery`), a `mirror` sync
   strategy (refused for replicas), a vault name another vault here holds. Each is a note in the report.
8. *A head that didn't load completely* (a segment from an older root, a blind range) is not applied (`ApplyStopped`):
   reconcile would read what it lost as deleted.
9. *reconcile, refined on real data:* provider versions compare as a set (the database lists them in its own
   order), and an entry no operation touches stays exactly as ours holds it (prior names and a tombstone's last place
   are not the database's; the publisher carries them from the root it builds on). Before, both made an
   `AddHistory` the database could never satisfy, so a re-apply never converged.
10. *Audit:* `manifest.applied` (epoch, producing node, counts, union base), after the record. The undone placements and
   the decided conflicts are in `ApplyReport::conflicts`; their status output is item 7.

**Tests.** DB-backed `ManifestApplyDb.*` (test_manifest_apply_db.cpp, a real opaque_v1 cloud vault on the versioned
fake bucket, the other writer a publish under another node id): every kind of change with rows, index, journal kinds
and cache; the same head twice and a solo pass costing one HEAD; a local write skipping the record then converging; a
crash before every operation then re-apply; open files deferred then applied or kept; real collector output with the
real trash form (an edit beating our trash) and reconcile on the result planning nothing; a lost round applying and
republishing; no base copy as a union; share links following a moved folder and going with a deleted one.
`VaultRecoverDb.ARestoreKeepsEachSnapshotsUid`. The interleaving suite's writers optionally keep a model database
(`Scenario::model_db`): `ManifestVersionLogFaults.WithTheApplierACrashAtEveryStepRevertsNothing` asserts
`reverted_by_restart` zero and every model equal to the head at quiescence; the original crash test keeps the
in-memory merge and its `> 0`, as the record of what the applier fixed.

**Own roots (review of items 4-5).** A solo vault meets a head that is not `known` whenever its own root was PUT and
not recorded (a crash between the PUT and `recordRoot`, or a failed `recordRoot`). Its database is at or past that
root, so reconciling it as another writer's would misread every change made since (a rename undone by "the head
wins", an edit against itself, an entry deleted since re-created). `originOf` (Publisher.hpp) classifies a moved head
before anything is applied:

- *OwnPast*: producer node id = this node **and** producer vault id = this vault, built directly on `known` (epoch + 1,
  `prev` = known's hash, and on version_log the version below it = known's version id when recorded; epoch 1 with no
  `prev` when nothing is known), and its hash is among the roots this server PUT since its last record
  (`remote_manifest_state.publishing_roots`, migration 146: each root's hash is added before its PUT through
  `PublishOptions::before_root_put`; each record resets the set to the recorded root, so it is empty only before any
  publish or record since the migration). `Session::verifyRemote` records it as own with its base copy and nothing is
  reconciled. A set, not the last hash: a lost reply leaves the PUT's outcome unknown (conditional mode: the store
  throws and the publish records nothing; version_log: `PutOutcomeUnknown`, the publish lists and looks for its version
  by hash, and records nothing when it isn't listed yet), so the root may land after the next publish sealed and noted
  another one; that publish then meets it (412, or C1 naming it) and adopts it. At 256 the oldest hash goes: that takes
  256 root PUTs without one record, and a dropped hash that matters (its root lands later still) stalls the vault
  (`ApplyStopped`), never misapplies it. Undo: the last hash alone (the first fix), which stalled this case.
- *OwnUnexplained*: names this node and vault but fails the rest. No publish of this server leaves one (every publish
  builds on `known`, and a moved head is applied or adopted before the next), so another installation is publishing
  under this identity: `ApplyStopped`, never guessed.
- *Foreign*: anything else, including this node's root for another vault id (a restore beside the original on one
  server).

How the identity behaves: the node id is `device_node.node_id`, one per installation's database. `vh vault recover`
on another server publishes under that server's node id; on the same server it restores into a new vault id
(`Recover::reserveVaultId`, a sequence that never reuses an id), so neither looks own. A database restored from a backup
onto a second machine while the first still runs is the one way two installations share a node id and vault id; the
noted hashes then tell them apart (each server's own PUTs only). The set is empty only in a state that has neither
published nor recorded since migration 146; there the producer and the direct-on-known check decide, which a clone
could pass (an accepted gap of that one-time window). Undo: drop the set check in `originOf` (the producer rule
alone).

**One apply at a time.** `Service::applyRemote` holds `applyMutex_` for the whole remote step (deferred entries, verify,
apply, `applied`). Lock order is apply mutex, then the session's: the session releases its mutex before `HeadMoved`
reaches `publishRounds`, and nothing takes the apply mutex while holding the session's or `Filesystem`'s. The pass
lease is never waited on under it, and no FUSE callback or ws handler takes it (only the sync pass and the publish
paths call `applyRemote`). `ManifestApplyDb.TwoAppliesOfOneVaultRunOneAfterTheOther` overlaps two applies without it.

**Item 6 prerequisites, named where replicated vaults are refused** (`Applier.hpp`, `kCarriesForeignEnvelopes`; the
applier refuses a head naming more than one writer, `ManifestApplyDb.AReplicatedHeadIsRefusedWhileForeignEnvelopes*`):

1. Another writer's recovery envelope kids are dropped from this server's roots (decision 7 of items 4-5): carry them
   forward (or have each replica's envelopes for the account grants named) before replicas run.
2. When another writer built on this server's own unrecorded root before this server adopted it, the apply's base is
   `known`, not that root, so local changes made since can lose to it (the interleaving suite measures it:
   `own_root_built_on`, 24 of 646 crash runs, 2026-11-15). Store the pending root's base copy before its PUT (its root
   and new segments' bytes, by sid) and use it as the base when the head's chain contains it.

**What items 6 and 7 need:** item 6 (the two-daemon drill, `vhh drill mirror`, then Backblaze) can drive two vaults
with one uid on one bucket now; it needs the join (writers naming both nodes, `mirrors.md`) or a test-only writers
seed, and it should assert the journal and FUSE views on both. Item 7 (status) has `ApplyReport` (epoch, producer,
counts, conflicts, union base, notes) and `manifest_apply_deferred` to show; nothing persists the last report yet.

## As built: replica prerequisites and status (branch `feat/replica-prerequisites`; migration 147)

**Foreign envelopes.** Under the decided model every replica holds the same account-managed grants (one signed
policy, verified by each server), and each replica wraps every key version for each of them itself: the kids differ
per server. So a root has to name every writer's kids, and no writer may drop another's.

- *Kept as:* a reference in `manifest_foreign_envelope` (kid, key version, recipient id), read once per new kid before
  the apply's first transaction: the envelope `.vaulthalla/key/<kid>` is fetched, its kid must be its bytes' hash, and
  its header must name this vault and the key version the root lists it under (customer class). A kid that fails, or
  whose object is missing, is not kept (a note in the report). Never a grant or `vault_key_envelope` row.
- *Named when:* one of this vault's grants (revoked or not) has the envelope's recipient, the same rule by which a
  server names its own envelopes (every kid it wrote, a revoked grant's too); the key version must be in the vault's
  key history (the collector attaches envelopes only to listed versions, retired ones included).
- *Policy removes a recipient:* the cloud service revokes the grant (it stays as revoked), so both writers keep naming
  both writers' kids for it, as each names its own: the root stays the same. A grant deleted outright (only with the
  vault) takes its references out of the root.
- *Same recipient and version on both writers:* both kids, the union, sorted (the collector orders by version and kid),
  so a publish with nothing changed produces the same list whoever publishes.
- A grant that exists on one replica only (not from the account's policy) would make the roots alternate between
  writers: a join prerequisite is that replicated vaults hold account-managed grants only.

`kCarriesForeignEnvelopes` is now true and a head naming several writers is applied. It is refused on a vault syncing
with the `mirror` strategy (`manifest_mirror_shared`: mirror deletes remote objects its database doesn't hold).

**The pending root's base copy.** Before each root PUT the publisher hands the server the sealed root and the
segments it wrote (`PublishOptions::before_root_put`); `notePublishing` keeps them (`remote_manifest_pending`, and
the segments by sid in `remote_manifest_base`) beside the hash in `publishing_roots`; every record clears them. When
a foreign head arrives, `Session::adoptBuiltOn` checks each pending own root P that is directly on `known`: when the
head continues P (its `prev` is P, or the chain rules from P accept the head without a gap) and P's copy opens, P is
recorded as own first, so the apply's base is P. The interleaving suite's crashed writers now keep their rename in
every run, the 24 runs of 646 where another writer built on the unrecorded root included (asserted; the model takes
the descent from the true chain). Undo: drop `adoptBuiltOn`.

**Trash with another writer.** On a cloud vault a trashed file is purged at the next pass, remote object included.
With another writer that DELETE can remove an object the other writer names live again (it restored the file; or,
for a trash applied from its root, it still names it). Rule: while the recorded root names a writer other than this
server (`remote_manifest_state.writers`), a trash is purged locally only, no remote DELETE (`Local::removeTrashedFiles`,
`CloudEngine::manifestNamesOtherWriters`). Cost: the trashed objects stay in the bucket (`o/<uid>` no root names, an
orphan "left alone"), so storage is not freed until an orphan collection exists (a join prerequisite). A vault this
server writes alone keeps the remote purge: its own restore ends the trash row before any purge, so it has no such
hazard. Undo: drop the `shared` branch.

**Status (item 7).** The last apply is persisted (`manifest_apply_report`: epoch, producing node, recorded, union
base, applied/skipped/deferred/kept, conflicts decided and open, notes, time) and shown by `storage.vault.get` of an
opaque_v1 vault (`manifest`: `VaultManifestStatus` with `last_apply`, `ManifestApplyReport`) and `vh vault sync info`
(a "Manifest" section). A stopped apply (`manifest_key_missing`, `manifest_key_mismatch`, `manifest_head_incomplete`,
`manifest_mirror_shared`) is recorded with its root and alerts the operator once per root and reason
(`manifest_apply_stopped`); the next successful apply clears it. No console UI.

**Tests.** `ManifestApplyDb.AnotherWritersEnvelopeKidsAreCarriedForTheGrantsThisServerHolds` (carried, stable across
publishes, no grant or envelope rows; not carried: a recipient without a grant here, a missing object, another
vault's or key version's envelope, a kid that isn't its bytes' hash), `.AMirrorVaultRefusesASharedHeadAndAlertsOnce`,
`.AnUnrecordedOwnRootAnotherWriterBuiltOnIsTheBaseOfTheApply`, `.WithAnotherWriterATrashIsPurgedWithoutARemoteDelete`,
`.RemoteOnlyFilesHydrateAfterAnAppliedMoveAndReplacement`; the interleaving crash test as above; the ws model checks.

**What the join and the two-daemon drill (item 6) still need:**

1. The join itself: writers naming both nodes, the other server's keys (`mirrors.md` "Join"), and the account-managed
   grants on both before the first publish; refusing local-only grants, `mirror`, layout migration, key salvage and
   `vh vault recover --into` on a replicated vault.
2. Key rotation by one replica: the other can't open roots sealed under the new key (`manifest_key_missing`, a stall,
   no loss); the rotation owner and the key hand-over are `mirrors.md`'s.
3. Content edit/edit across replicas resolves through the planner under the vault's policy (`keep_local` by default:
   the losing generation survives only as a provider version, so replicated vaults need bucket versioning, or `ask`).
4. An orphan collection for the objects shared vaults' trash leaves in the bucket.
5. The drill: two daemons on one fake bucket in the Tier B harness, asserting journals and FUSE views on both, then
   Backblaze once spec 06's A3 and A4 are confirmed.

