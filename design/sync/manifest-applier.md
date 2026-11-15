# Applying another writer's manifest to the local database

Status: design for review (managed storage plan of 2026-11-12, workstream I, "a manifest applier that merges another
server's changes into the local database"); nothing here is implemented. It covers how a running server takes a
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
