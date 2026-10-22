# File recovery: local snapshots, local versioning, provider versioning

Branch `feat/recovery` (2026-10-16). Migration 111. Contracts: `core/include/recovery/Model.hpp` (shared model),
`core/include/ops/Recovery.hpp` (the only authorizing boundary). This file is the design of record; keep it true.

## Philosophy

The infrastructure best suited to retaining history does the work. Vaulthalla decides, indexes, secures, prices and
orchestrates. It never keeps a long-term local duplicate of history the provider already holds, and cost is a
first-class, unmissable part of turning provider versioning on.

## Three backends, one model

| Backend | What | Created | Lives |
|---|---|---|---|
| Local snapshot (`snap-<id>`, members `lv-<id>`) | explicit named recovery point of a file or directory tree | only by a person (`vh snapshot create`) — never on writes, truncation, rename, delete, sync or key rotation | `recovery_snapshot` + `file_versions` (origin `snapshot`) → `recovery_blob` |
| Local version (`lv-<id>`) | opt-in harness (`vault_recovery_policy.local_versioning`): the prior sealed generation of a file is kept on every content change (overwrite, truncate, delete, a sync download over local content, restore, conflict resolution); never on rename/move (no content change) or key rotation (same plaintext) | automatically, when enabled | `file_versions` (origin `version`) → `recovery_blob` |
| Provider version (`pv-<id>`) | native object versions + delete markers in an AWS S3 bucket with versioning enabled | by the provider on every PUT/COPY/DELETE | the bucket; Vaulthalla keeps metadata only in `upstream_object_version` |

Vault preference `vault_recovery_policy.mode`: `off | local_snapshots | provider_versioning` (no row = off). Local
versioning is orthogonal to it. Existing snapshots and versions stay recoverable whatever the mode; the mode gates
*creation* (snapshots need `local_snapshots`) and the provider activation flow. The preference never misrepresents the
bucket: choosing `off`/`local_snapshots` does not suspend a bucket that is versioned (status says so).

## Local storage (recovery store)

- Blobs: `<backing>/.vh-recovery/<vault mount_point>/<aa>/<storage_name>` (storage_name = 32 `[a-z0-9]`, `aa` its first
  two chars). Outside `backingVaultRoot`, so the rotation sidecar walk (`*.vh-rotate`), `repairAtRest` and size walks
  never see it. A blob is the file's sealed bytes exactly as they were (AES-256-GCM body‖tag, no header); IV + key
  version live in `recovery_blob`. Never plaintext.
- Capturing a generation is zero-copy where possible: every content write in Vaulthalla is sidecar → fsync → row →
  `rename` over the backing path (FUSE seal, `createFile` overwrite, rotation, copy), so the old inode is never written
  again. Retaining = `link(backing, blob)` *before* the rename (fsync blob dir). Deletes link the backing file in too
  and unlink the origin only after the transaction commits (`Capture::committed()`), so a crash before commit never
  loses the live file. Every delete path (FUSE unlink, `Filesystem::remove`, `Engine::removeLocally`,
  `CloudEngine::indexAndDeleteFile`, `ObjectStore::purgeLocalObjectState`) retains under `Filesystem::contentWriteMutex`
  with the row re-read, so a concurrent seal can't be linked under the old IV. Fallbacks: reflink (FICLONE / macOS `clonefile`), then copy. A blob is immutable once linked.
- **Invariant this rests on: nothing writes a backing file in place.** A linked blob shares the live file's inode until
  the next rename-replace; an in-place writer would silently rewrite history. Every backing-file writer must replace
  by rename (or the capture must use `captureCopy`). Guard: `tools/contracts/test_backing_writers_contract.py` scans
  `core/src` for in-place-capable write primitives (ofstream, `O_TRUNC`, `open`/`openat` that may write — flags
  spelled `O_WRONLY|O_RDWR`, or not spelled out at all — without `O_EXCL`/`O_TMPFILE`, `creat`, `pwrite`,
  `ftruncate`/`resize_file`, `fopen`/`fdopen`/`freopen`, `copy_file_range`, `copy_file`/`copy` with
  `overwrite_existing`, `mmap` with `PROT_WRITE`, `writeFile(`), matched per statement across lines, against a
  per-file, counted allowlist with the reason each never touches vault bytes. Audit (2026-10-16): new files are created with `writeFileExclusive` (FUSE create, empty
  `createFile`) or `writeFileAtomic`/`replaceFileAtomic` (buffer and source-path `createFile`, the slow rename path);
  `fs::ops::writeFile` (ofstream + truncate) is gone; seals, overwrites and rotation already rename a sidecar; the
  remaining primitives write sidecars/temps (`encryptFileToFile`, `resealFile*`, `decrypt_aes256_gcm_file`), working
  copies, staging/temp files, logs, caches or secrets.
- Dedupe: unique `(vault_id, encryption_iv, key_version)` for non-empty IVs: the same generation captured twice
  (two snapshots of an unchanged file) is one blob. Physical accounting = sum of distinct blobs' `cipher_bytes`.
- Crash safety: blob first (temp name + rename + dir fsync), then the DB rows in the same transaction as the files-row
  update; an orphan blob (no row, older than 1 h) is swept at startup; a row whose blob is missing is reported
  `restorable=false` ("blob missing"), never silently dropped (a later capture of the same generation recreates the
  file under the existing name). Removal deletes the row first, then the file: a crash leaves an orphan file for the
  sweep, never a row without its file.
- Quota: blob bytes count against the vault quota only where they are not a live file's bytes already:
  `Engine::freeSpace` adds `store::chargedBytes` (`recovery_blob_charged_bytes`: blobs that are NOT the current
  generation — same IV + key version — of a live file they were captured from, via `file_versions.file_id`; no walk,
  no stat; cached 5 s). A blob linked from a live backing file shares its inode, which `getVaultSize` already counts;
  once that file is replaced or deleted the blob is charged. Known approximations (under-count until the live file
  next changes): a capture that fell back to copy/reflink while the generation is still live, and a `local_copy`
  restore that reused a blob's IV with copied bytes. Also against `snapshot_quota_bytes` / `version_quota_bytes`
  (those count the blobs' bytes). Vault purge removes `.vh-recovery/<alias>` with
  the backing dirs.
- Retention: snapshots are kept until deleted. Local versions: `version_keep_last` per file, `version_max_age_days`,
  `version_quota_bytes` (oldest first); keep_last and max age never prune a generation still `pending` upstream, the
  quota does as a last resort (oldest first, marked `skipped` with `upstream_error = 'quota'`, logged, reported as
  `pending_dropped`); a blob still referenced
  by a snapshot is never deleted (refcount = referencing `file_versions` rows). `db::Janitor` runs
  `recovery::local::versions::maintain` every 15 min (retention for vaults with local versioning on; the orphaned
  backlog is settled, below; the rest of the pending backlog of upstream vaults whose bucket status isn't `enabled` is
  marked `skipped`) and, at startup and then daily,
  `store::sweep` for every vault with a store directory (orphans of crashed captures, unreferenced rows). keep_last is
  also applied right after a capture, in its transaction (bounded: only once the file's version number exceeds it, at
  most 64 rows); the freed blobs go after commit, and after the content lock is released where one is held (FUSE
  seal, createFile overwrite: `versions::DeferBlobFrees` scope declared before the lock).

### Local versioning: capture (`recovery/local/Versions.*`)

- One helper for every writer: `versions::retain(engine, priorRow, Reason, {actor, upstream}) -> Pending` stages the
  blob (`captureLink` of the prior backing file) BEFORE the transaction; `Pending::attach(txn)` inserts the blob and
  the `file_versions` row (origin `version`) in the same transaction that updates/trashes the files row;
  `committed()` after commit; `abort()`/the destructor on failure. Callers rename the new bytes over (or unlink) the
  backing file only after `committed()`.
- Off path: the per-vault policy is cached in memory (`recovery::local::versioningPolicy`, 60 s TTL as a safety net);
  whoever writes `vault_recovery_policy` calls `recovery::local::invalidatePolicy(vaultId)` after the commit. With
  versioning off a write costs no query, and an upload no backlog query either: `local::mayHaveBacklog` checks the
  vault once (EXISTS pending) and remembers "none" until the policy changes (`invalidatePolicy`, also each
  maintenance run). The usage ledger's first-put/overwrite classification is one `(vault_id, object_key)` index
  lookup per PUT/DELETE; the provider version hook does nothing for a PUT without a version id. A staging failure is logged/counted and never fails the write;
  neither does an attach failure: `Pending::attach` inserts its rows under a savepoint (`vh_recovery_version`), and a
  failure (a reused blob removed since `retain`, a constraint) rolls back only them (counted `failed`, version skipped).
- Skipped (counted, no row): an empty generation, legacy plaintext (blobs are never plaintext), a cloud file without
  local bytes (the provider holds it).
- Call sites (reason): `Filesystem::createFile` overwrite branch (`NewFileContext::version_reason`, default
  `overwrite`; callers pass `restore`, `conflict`, `download`); the FUSE seal (`WorkingCopyHooks::commit` gets the
  prior entry; `truncate` when the copy was emptied (O_TRUNC, truncate to 0) or the result is empty, else
  `overwrite`); `Filesystem::remove` (file, and every file of a folder), FUSE `unlink`, S3 gateway DeleteObject (via
  `Engine::remove`) and `ObjectStore::purgeLocalObjectState`, sync DeleteLocal (`Engine::removeLocally`) → `delete`;
  cache-strategy index-only downloads over a different local copy (`CloudEngine::indexAndDeleteFile`) → `download`.
  The S3 gateway PutObject, sync downloads (`downloadFile`) and conflict keep_remote (`replaceLocalContent`) reach the
  createFile overwrite branch. Never: rename/move, copy, rotation, hydrate, `repairAtRest`; the HTTP upload temp part
  unlink.
- Upstream state at capture: `pending` with `upstream_key` = the vault path without its leading slash in an upstream
  vault; `none` for local vaults, for `download`/`conflict` (content that lost to the remote side: replaying it would
  reorder the provider's history) and for deletes the vault's sync policy doesn't propagate (only mirror + keep_local
  deletes remote leftovers) or that came from upstream (sync DeleteLocal).

## Keys (historical key compatibility)

- `EncryptionManager::keySnapshot(v)` keeps its strict meaning (current, or current−1 mid-rotation) for live reads.
  Recovery reads use `historicalKeySnapshot(v)`: any version this vault ever had, unsealing `vault_keys_trashed[v]`
  under the TPM-sealed vault master on demand, cached briefly (mlocked `SecretKey`, wiped on release).
- Live rotation never re-encrypts retained generations (they are immutable); they keep their key version.
- Trigger `recovery_guard_retired_vault_key` refuses to delete a retired key while a `recovery_blob` or a live
  `upstream_object_version` references it (vault deletion still cascades). Key export includes the retained historical
  versions recovery data needs.
- Restoring a generation sealed under the current key may reuse its sealed bytes (same IV for the same plaintext, as
  copy does). Under an older key it is re-sealed: streaming GCM decrypt (old key) → encrypt (current key, fresh IV)
  into the sidecar; committed only after the old tag verifies. No plaintext touches disk.
- API (`vault/EncryptionManager.hpp`): `historicalKeySnapshot(v)` (current / rotation-old from memory, else
  `vault_keys_trashed[v]` unsealed and cached: ≤ 8 versions, LRU, dropped after 10 min unused, checked on access
  and by `evictIdleHistoricalKeys(now)` for every engine from `VaultRetentionService`'s 30 s loop, so an idle key
  leaves memory without a later access; outstanding snapshots stay valid until released) throws `vault::KeyVersionUnavailable` for a version the vault
  doesn't hold (incl. 0). `retainedKeyVersions()`, `hasKeyVersion(v)`, `referencedHistoricalKeys()` (export).
  `resealFileToCurrent(src, iv, v, dst, f)` / `resealToCurrent(buf, …)` over `crypto::util::resealFile` /
  `resealBuffer` (`crypto/util/reseal.hpp`, 64 KiB chunks, `GcmStreamDecryptor` → `GcmStreamEncryptor`): a source
  that fails authentication throws `storage::IntegrityError` and dst is removed (whatever it held). The plaintext
  buffer (unauthenticated until the tag verifies) is wiped on every path, success or failure (`WipeOnExit`; tests
  observe it through `setPlaintextWipeObserverForTesting`). An empty
  generation (empty IV, version 0, zero bytes) re-seals to an empty dst with empty IV/version 0 (how every empty file
  is stored); a non-empty source with an empty IV is plaintext and refused (`std::invalid_argument`). Same-version
  re-seal still draws a fresh IV (reuse the bytes instead if that is wanted).
- Key export (`vh vault keys export`, ws `vault.keys.export`; `ops::vault_keys`, `key-backup.md`) adds, per vault,
  `historical_keys: [{key_version, key (base64), key_check, reason, created_at, retired_at}]` for every other needed
  version: the retired versions `recovery_blob` / live `upstream_object_version` rows reference (`recovery`) and an
  unfinished rotation's outgoing key (`rotation`), never the current one; and `missing_key_versions` when a needed
  version is gone. Both are omitted when empty. Every export carries the current key's `key_check`. Export tracking
  (`exported_version`) records the current version only. A deleted vault's export (from `vault_deletion_key`) carries
  its needed versions too.
- `get_rotation_old_vault_key` used to `SELECT *` from `vault_keys_trashed`, which has no `updated_at` column, so
  `vault::model::Key(row)` threw and a restart mid-rotation could not load the vault key. Retired-key reads now alias
  `trashed_at AS updated_at` (pinned by `RecoveryKeysDbTest`).

## Local snapshots and restore (`recovery/local/{Snapshots,Restore,Points}`)

- Trusted primitives (no RBAC): `snapshots::create(engine, actor, path, name, authorize)`,
  `snapshots::cleanupInterrupted(minAge)` (`db::Janitor`: first run min age 0, then with the daily store sweep, 1 h), `snapshots::remove(id)`, `local::removeVersion(id)`,
  `local::planFor(id, subPath, destination)`, `local::restore(engine, actor, item)`, `local::missingParents`,
  `points::{list,get,detail,fromSnapshot,fromGeneration}`. `ops::recovery::createSnapshot`
  (`ops/RecoverySnapshots.cpp`) authorizes List/Read on the root, then every entry (Read + Copy per file, List per
  directory; symlinks are not captured) before anything is written; one denial refuses the whole snapshot.
- Create: mode must be `local_snapshots` (`Invalid` names the mode). Plan = cache root + `Entry::listSubtree` (DB);
  quota first: `snapshot_quota_bytes` against the new blob bytes (generations without a blob yet), `Engine::freeSpace()`
  against only what the capture newly allocates (the hydrate copy of an index-only cloud file; a copy when the backing
  file is on another device than the store; a link costs nothing) (`Conflict` with needed/left bytes). Per file under
  `Filesystem::contentWriteMutex`: re-read the row, `captureLink` the backing file (empty file → empty blob),
  members inserted with their blob `attach` 64 per transaction. Captures the last **sealed** generation: an open FUSE
  working copy's unsealed changes are not in it. Skipped with a reason in `skipped_json`: `symlink`,
  `upload_staging`, `content_unavailable` (cloud file with no local copy whose hydrate the remote-read gate refused or
  that failed; never an unbounded fetch), `integrity_error`, `unsealed` (legacy plaintext), `vanished`, `moved`.
  Directories without a captured file under them go to `empty_directories`. Any failure after the row exists: state
  `failed` + error, members and now-unreferenced blobs released (the row stays as a record). A crash leaves
  `creating`: `cleanupInterrupted` does the same at startup. Deleting a `creating` snapshot is refused.
- Restore destinations: original paths (the path at capture; a renamed/moved file is left alone and the old path is
  recreated), or an alternate directory D: the chosen point P goes INTO D under its own name (P/x → D/name(P)/x).
  Plan items per member + empty directory (directory items: source `snap-<id>`, method `none`, note
  `empty directory`): Create / Overwrite (`destination_source_id` = the destination's current `sourceId`) / Skip (same
  IV + key version, or both empty) / Conflict (directory vs file, a file in the parent chain) / Unavailable (blob
  missing, body only upstream, key version gone). Method `local_copy` (current key: sealed bytes reused with their
  IV after `gcmVerifyFd`) or `local_reseal` (`resealFileToCurrent`). Blocker when the bytes exceed `freeSpace()`.
- Commit: `NewFileContext::sealed` (`fs::SealedWriter`) commits pre-sealed bytes through createFile's own overwrite
  and new-file branches (content lock, CAS, open-working-copy refusal, rows, parent stats, thumbnails), so the local
  versioning capture on the overwrite branch also retains what a restore replaces. Create uses
  `expected_source_id = ""` (no generation has it): a file that appeared since the plan is a `ContentConflict`.
- Points: snapshot points carry `encryption.key_version = 0` (members differ) and `key_available` = every key version
  the vault's blobs use is still held; members/versions carry their exact key. `restorable=false` with a reason for
  a missing blob, a body released upstream, a missing key, or a snapshot that isn't `ready`.
- Fixed on the way: `Filesystem::remove` of a folder left its subfolders/symlinks in the FS cache (a restore or mkdir
  at the same path then hung new rows off deleted parents; FK violation).

## Provider versioning (AWS S3 first; capability contract per provider)

- Capability: `AdminClient` reports `versioning` support (AWS: yes; R2: no — refused with the documented reason,
  local snapshots/versions keep working). Activation needs an admin-enabled key and a managed/adopted, unprotected
  bucket; an existing vault's unmanaged bucket can be adopted in the same flow (`accept_adoption`, admission preflight).
- Enable flow: inspect (versioning, object lock, MFA delete, lifecycle incl. foreign noncurrent expiration) → cost
  disclosure (`versioningDisclosure`, token bound to vault + bucket identity + retention + actor + estimate, 10 min) →
  `update{mode=provider_versioning, disclosure_token[, accept_unpriced]}` → PutBucketVersioning Enabled only if not
  already enabled → re-read until Enabled (bounded) → `versioning_settles_at = now + 15 min` (AWS documents up to 15
  minutes before versioning applies to all writes; until then status says `propagating` and version-aware writes are
  not relied on) → retention lifecycle (owned `vaulthalla-managed` rule `NoncurrentDays`, foreign rules preserved byte
  for byte) → audit.
- Never: enable on bucket creation; suspend on mode change; delete versions on vault removal (retention purge deletes
  current keys only → delete markers); mutate protected/unmanaged buckets; expose versions through the S3 gateway.
- Shortening retention (indefinite→N, N→M<N) needs `accept_retention_shortening` from every caller. Suspension is
  its own explicit, confirmed op and deletes nothing.
- Local versioning limits that delete retained versions sooner need the same acceptance (`RETENTION_SHORTEN`,
  `polLocalShortening`): a limit added where none applied (or turning versioning back on, since retention only runs
  while it is on, so limits apply to everything kept meanwhile) or lowered, and only when the vault has local
  versions. The message counts what the next retention run deletes now (versions + plaintext bytes; one
  `listPrunable` per side, minus what the previous limits delete anyway). Turning local versioning off deletes nothing
  and asks nothing. With a provider change in the same update, the provider's shortening question carries this text
  too (asked before anything is sent), so one acceptance never covers an unseen consequence.
- Version index `upstream_object_version`: rows from our own PUT/COPY responses (`x-amz-version-id`, origin
  `vaulthalla`, with IV/key version/hash/sizes) and from on-demand `ListObjectVersions` for a path (metadata only, no
  bodies, request-budgeted; origin `observed`). `became_noncurrent_at` when superseded; `gone_at` when no longer listed.
- Restore of `pv-<id>` (takes the vault's pass lease; never concurrent with a sync pass):
  1. HEAD `?versionId` (metadata: vh-iv, vh-key-version, content-hash, size, storage class). Archive tiers → unavailable.
     Not origin `vaulthalla` → `recovery_unverified_version` acknowledgement.
  2. Same-key (or plaintext-upstream) and ≤ 5 GiB → **provider copy**: CopyObject `?versionId` onto the key with
     directive COPY (metadata preserved: IV, key version, hash) → new current version id + ETag recorded.
     Older key, or > 5 GiB → **bounded transfer**: price preflight + per-restore request cap → streaming GET
     `?versionId` (If-Match) → verify + re-seal under the current key → PUT.
  3. Local state reconciled before releasing the lease: cache vaults adopt the new generation index-only (files row =
     remote metadata under CAS on the planned generation; backing copy dropped; derived artifacts purged; hydrated on
     read); other strategies hydrate it. `applyRemoteIndexMutation`, baseline agreed, write intent with the new ETag
     (the Copy event settles as our own write). The next pass sees L == R: **no second upload**.
- Directory point-in-time restore = per object the latest version with `last_modified ≤ at` (a delete marker or no
  version = absent). Always labelled a timestamp-based reconstruction, never an atomic snapshot (`Plan.atomic=false`).

### Provider recovery as built (`recovery/provider/*`, `storage/CloudEngineRestore.cpp`)

- **Own writes** (`provider::noteOwnWrite`, fired by `CloudEngine::OwnWrite::done()` through `hooks::afterUpstreamWrite`):
  a PUT/COPY response with `x-amz-version-id` upserts an origin `vaulthalla` row (etag, object size, last_modified =
  now, IV/key version/hash/plaintext size from the written generation; sealed iff the generation says so, else
  object size = plaintext + 16) and supersedes the key's previous latest. No version id (unversioned) → no row.
  Our own DELETE supersedes the key's latest (it is hidden by a marker now) but records no marker: DeleteObject's
  response id isn't surfaced, so the next listing learns the marker. `.vaulthalla/` keys are never indexed.
- **Write intents carry the ETag**: `OwnWrite::done()` completes the event intent with the stored object's unquoted
  ETag (PUT, multipart and CopyObject alike), so a restore's `ObjectCreated:Copy` settles as ours and an external
  same-size write cannot claim the intent. The decoder/inbox keep `versionId`; the applier stores it on the index row.
  `ObjectRemoved:DeleteMarkerCreated` and a permanent version delete both decode as removals and are HEAD-confirmed
  against the *current* object: a permanent delete of a noncurrent version finds the object present and is skipped
  (local data safe); the version index learns such deletions only from the next complete listing (gone_at).
- **Listing** (`versions::refresh(engine, prefix, {max_requests, page_size, price_preflight})`): ListObjectVersions
  pages only (a nested capture caps HEAD/GET/PUT/COPY/DELETE at 0), price preflight (`recovery_version_list`) and the
  vault's request budget; rows are observed (never downgrading ours), `became_noncurrent_at` = the next newer
  version's LastModified when the listing shows it; `markGoneUnder` only after a complete listing. Usage source
  `recovery_version_list` is reported in the result (the ledger feed is the cost slice's).
- **Points** (`points::fromRow/forPath/byId`): not restorable = gone, delete marker ("absent at this time"), current
  version ("nothing to restore"), GLACIER/DEEP_ARCHIVE, a key version the vault no longer holds. Retention comes from
  `RetentionInfo::from(ProviderVersioningState)` (effective noncurrent days, else indefinite only when Vaulthalla set
  it and no foreign rule expires noncurrent versions, else `unknown`); expires_at = became_noncurrent_at + days.
- **Plans** (`planFor`, `planOne`, `planAt`): Skip when the destination already is the version (current, same ETag
  or same IV + key version); Conflict for a directory, an open sync conflict or local changes not uploaded yet
  (baseline); `provider_copy` only for the same object key, ≤ 5 GiB, and sealed under the current key (or plaintext in
  a plaintext-upstream vault); otherwise `provider_transfer`. Prune removals are `local_remove` (trash; the next sync
  deletes upstream → delete marker).
- **Restore** (`restore(engine, item, expectedSourceId, {accept_unverified, user_id, hooks})`): order is CAS precheck
  (stale → `conflict`, already that generation → `skipped`) → origin check (`UnverifiedVersion`) → pass lease
  (`PassBusy`) → price preflight (`recovery_restore`, worst case) → HEAD `?versionId` → verification → copy or
  transfer. Verification: an origin `vaulthalla` row must match the HEAD (IV + key version when the row is sealed,
  object size) or the item is `unavailable` ("the bucket's copy differs from what Vaulthalla wrote"); a plaintext
  version (no `vh-encrypted`, or `false`) in an `encrypt_upstream` vault is `unavailable` unless it is our own recorded
  plaintext write or the vault's active subscription has `foreign_objects=import` (`subscriptions::importsForeignObjects`,
  the sync engine's rule) — `accept_unverified` does not override it (a bucket writer could inject content). Every
  request runs under the vault's request budget plus a per-step cap (HEAD 1, COPY 1, GET 1 + object bytes).
  Copy: `CloudEngine::copyObjectVersionAsOwnWrite` (intent + hook with the restored generation); an earlier attempt's
  copy that is already current is reused, never copied twice. Then `adoptIndexOnly` (files row = version metadata,
  backing copy dropped, derived artifacts purged, under the content lock CAS); a local change meanwhile → `conflict`,
  the copy is kept and the index learns it so the next pass sees a two-sided change. Index + manifest
  (`applyRemoteIndexMutation` Upload with the new ETag/version id) and `Baseline::agreed`. Non-cache strategies
  hydrate immediately. Transfer: GET into a 0600 `.vh-restore-*` temp next to the destination (plaintext objects are
  sealed while streaming), verify (current key) or `resealFileToCurrent` (retired key), commit with createFile's
  sidecar protocol under the CAS (`.vh-rotate` sidecar, so startup recovery settles a crash), then one `upload` +
  index + `Baseline::afterUpload`; an upload failure leaves the local restore and the next pass uploads it once.
  Outcomes carry `retryable` and the request usage (source `recovery_restore`).
- Tests: `RecoveryProviderTest*`, `RecoverySmartCacheTest*` (the acceptance scenario), harness
  `tests/helpers/recovery_provider_harness.hpp`.
- **Live acceptance on real AWS S3** (the since-removed `test_recovery_live.cpp`, consolidated away with the other
  live suites on 2026-10-22; passed 2026-10-16, us-east-2, fresh test buckets; the same steps stay covered by
  `RecoverySmartCacheTest` / `RecoveryProviderTest`): the same scenario through ops (disclosure → `update` with
  `accept_adoption` on a new bucket → list → plan → restore → costs), real `CloudEngine`, prices from the signed
  fixture catalog. Measured: each upload pass PUT 2 (object + manifest; the vault's first pass PUT the manifest
  twice, PUT 3, until #248: now PUT 2 too); listing 4 versions = LIST 1, 0 HEAD/GET; restore by copy = COPY 1, HEAD 2, PUT 1 (manifest), GET 0;
  hydrate read = HEAD 1 + GET 1; next pass = HEAD 1 (manifest), 0 PUT; noncurrent 4 versions / 185 B exact; costs
  `active`, priced, month-to-date non-null. Across a key rotation: `provider_transfer`, GET 1 + PUT 2 (object +
  manifest), COPY 0, current object carries the new key version. Disclosure = 6 admin requests, enable (adoption +
  versioning + retention) = 29 (HEAD 12: `AwsAdmin::headBucket` probed the global endpoint then the region on every
  call; since #247 a known region (cache, `upstream_bucket.region`, else the key's region) is one HEAD, so the
  enable should drop to ~23; not re-measured live). R2: refused with `kR2VersioningUnsupported`, 0 requests of any
  kind, local snapshot + restore on the same vault works. Nothing failed on real AWS that passed on the fake.

## Local versions as the upstream backlog

For upstream vaults with local versioning on, retained generations are also the ordered upstream backlog:
`file_versions.upstream_state` `pending` → `sent` (provider version id recorded) | `skipped`.

- When the provider doesn't respond, writes keep working locally and generations queue up in `version_number` order.
  The backlog of one key is bounded: `Pending::attach` keeps at most keep_last (else `versions::kDefaultPendingCap` =
  32) pending versions per `upstream_key`; older ones become `skipped` with `upstream_error = 'coalesced'` (not
  replayed; still local versions under the normal retention, so with keep_last they are pruned in the same
  transaction and their blobs freed). Counted in `versions::counters().coalesced` and logged.
- When it responds again and the bucket has provider versioning enabled+settled, the upload of a file first replays
  its pending generations oldest-first (each PUT carries the generation's own IV/key-version metadata), then the
  current content, so the provider's history matches local history. Price preflight and request budgets cover the
  replays. A bucket without versioning: intermediate generations are `skipped` (only the latest content matters).
- Smart cache: in a `cache` vault (or gateway `remote_cache`) with provider versioning, a generation's local blob is
  released once the provider holds it (`sent`) unless a snapshot references it. Local history bodies exist only as an
  unacknowledged backlog, never as a duplicate of provider history.

Implementation (`recovery/local/Backlog.*`, `storage/CloudEngineBacklog.cpp`, `recovery/provider/State.*`):

- Triggers: `sync::tasks::Upload` calls `backlog::replayBeforeUpload(engine, file)` before `CloudEngine::upload`, and so
  does every other writer of a key's current content: conflict keep_local (`ConflictResolver`; its price preflight
  already counts the replays through `Planner::estimateS3Cost`), key rotation's re-publish (`sync::rotation`
  `runtimeDeps` remote.upload; a blocked replay fails that file's rotation, retried next pass) and the provider
  restore's transfer upload (a blocked replay is reported like a failed upload; the next sync uploads);
  `sync::tasks::Delete` calls `replayBeforeRemoteDelete(engine, path)` before a REMOTE/PURGE delete. A replay that
  fails (`blocked`) fails that task: the current content (or the delete marker) waits for its predecessors; the next
  pass retries. Nothing runs on a FUSE/HTTP write path.
- The key's backlog: pending rows of the file (any with another `upstream_key` were retained before a rename and are
  `skipped`) plus pending rows retained at the same path by earlier incarnations, in capture (`id`) order.
- `provider::bucketVersioningForVault(vaultId)` (newest `upstream_bucket` row of the vault): `keepsHistory()` =
  status `enabled` and past `versioning_settles_at` (none recorded: settled). Anything else → every pending row of the
  key is `skipped`.
- Already upstream (no PUT): a known version of the key (`upstream_object_version`, same IV + key version or content
  hash) → `sent` with its version id; the content both sides last agreed on (`sync_file_baseline.content_hash`, so
  uploaded before Vaulthalla knew a version id) → `skipped`.
- Replay PUT: `CloudEngine::uploadGeneration(key, blob, row)`: the generation's own `vh-iv` / `vh-key-version` /
  `content-hash` / `vh-encrypted`, through `noteOwnWrite(...)`/`done()` (the recovery hook sees it); plaintext-upstream
  vaults get the blob decrypted in memory with `historicalKeySnapshot` (buffers wiped). Version id from
  `lastPutOutcome` → `markSent`; none (or `null`) → `skipped`. Every replay PUT also updates the key's
  `remote_object_index` row to that generation (its hash, the PUT's ETag and version id) and, for the live file, writes
  `Baseline::afterReplay` (remote side = what we put; local hash = the `vh-replay` marker, which never matches). An
  interrupted replay (g1 sent, g2 failed) therefore leaves "remote = our own write, local = unpublished history":
  the Planner's `publishing()` rule plans an Upload under every conflict policy while the remote side is unchanged
  since (hash, else ETag compared unquoted), so the next pass finishes the publication instead of a spurious `ask`
  conflict or a keep_remote/keep_newest download of the stale generation over the live file. Local failures (blob or key version gone,
  authentication fails: `ContentUnavailable`/`IntegrityError`) → `recordFailure` + `skipped` (never block the file
  forever); any other failure → `recordFailure`, stop, `blocked`.
- Smart-cache release after `sent` (incl. "already upstream" matches): `Generation::releaseBlob` + `store::removeBlobs`
  (a snapshot-held blob stays). Rows `skipped` keep their blob (no version id to point at).
- Price preflight: `sync::Planner::estimateS3Cost` adds one PUT and the blob bytes per pending row under the keys of
  the plan's uploads and remote deletes, only while the bucket keeps history (`backlog::addPlannedReplays`).
  Request budgets apply to replay PUTs like any other request.
- `backlog::summary(vaultId)` → `recovery::Backlog` (status).
- Orphaned backlog (#249, `backlog::settleOrphaned`, from `versions::maintain` only, ≤ 256 rows per vault per run):
  pending rows whose key has no `fs_entry` at its path, no unpurged `files_trashed` entry, and no
  `remote_object_index` row (the trash purge deletes upstream without replaying, or the key is never written again).
  Rows of any other key stay a pass's. Bucket keeps history → under the vault's pass lease (busy: next run),
  price-preflighted (`metering::PriceReservation`, operation `backlog_settle`), a strict HEAD confirms absence (present:
  left alone), replay oldest first, then a DELETE (delete marker) so the key stays deleted and the index row the replay
  added is removed; a key whose content the bucket never had (no non-delete-marker version known, nothing `sent`) is
  skipped `'orphaned'` without a request. No history (status not `enabled`) → `'orphaned'`, no request. Propagating →
  wait. A DELETE failing after a replay PUT leaves the replayed generation current and indexed (logged; a pass would
  offer it as remote-only). The trash purge itself (`Local::removeTrashedFiles`) still deletes without replaying first.

## Costs (computed locally; nothing leaves the host)

- Inputs: signed price-bot catalog profile for (provider, region, storage class) incl. its `versioning` block
  (`supported`, `noncurrent_storage_billing`, minimum duration/size, `delete_marker_billing`); per-vault daily
  counters `vault_upstream_usage_daily` (requests by class, bytes, first-put vs overwrite objects and the replaced
  object bytes, deletes, version list/restore requests) fed by `Controller::recordRequest` + `CloudEngine` upload/delete
  instrumentation (in-memory, flushed every 60 s and at shutdown; ≤ 60 s lossy on a crash, documented); the version
  index; the remote object index for current bytes.
- Model: noncurrent bytes grow by overwritten + deleted bytes per day; steady state under retention R ≈ rate × R;
  indefinite grows linearly (12-month accumulation). Priced at the class storage rate (+ minimum duration/size rules),
  delete markers at key-name bytes, recovery as COPY or GET+PUT+bytes. Decimal arithmetic (`cpp_dec_float_50`) end to
  end; money is a string.
- Separated: versioning surcharge (the figures) vs current object storage (context only) vs recovery operations vs
  unmodeled account-level costs (free tier, taxes, discounts, transitions/early deletion where not modelled).
- Honesty: < 7 measured days → low confidence with a range; no measurements → illustrative scenarios (stated
  assumptions, e.g. 1/5/20 % of current bytes overwritten per month) labelled `illustrative`; no profile → `priced=false`
  + reason, never `$0.00`; versions predating monitoring → `unaccounted_history`; catalog unverified/stale shown as such.
- Alerts: `cost_alert_monthly` exceeded → `operator_notification` (type `recovery_versioning_cost`). Alerts never
  block writes or disable versioning.

### Policy, usage and costs as built (`recovery/{provider/Policy,usage,cost}`, `ops/RecoveryPolicy.cpp`)

- **Who.** status: vault sync.config.view (refresh: + admin.upstream.view + key View). costs and versioningDisclosure:
  sync.config.view + stats.vault.pricing (`ops::stats::canViewVault`). The disclosure's one inspect, and the bucket
  configuration it reveals (object lock, MFA delete, foreign lifecycle rule ids, the foreign-rule cap in the figures),
  need what refresh needs (`polMayReadBucketConfig`); without it the disclosure is the cost report from the recorded
  versioning state plus generic consequences and a line saying the configuration was not read, and no provider request
  is made (the enable re-checks everything and the token names the person). update: sync.config.edit; a provider change (entering
  provider_versioning or a retention) + admin.upstream.configure + key Consume; adoption + admin.upstream.provision
  (through `ops::upstream::adoptPreflight`). suspend: like a provider change.
- **Order of a provider change** (nothing is sent before the first five): vault/bucket → configure + key Consume →
  provider capability (identity `cloudflare-r2` or `supportsVersioning()==false` → Invalid, R2 text
  `kR2VersioningUnsupported`) → admin-enabled key → protection (Denied + audit `refused`) → unmanaged without
  `accept_adoption` → `upstream_adoption` → retention required (no hidden default) → one GetBucketVersioning → token →
  unpriced → shortening → adoption (`adoptPreflight`, other bindings / another vault's manifest = Conflict, then
  `ops::upstream::detail::adoptBoundBucket`, audited `bucket.adopt`) → PutBucketVersioning Enabled only when not
  Enabled (`policy::putAndConfirm`: ≤ 6 reads, 250 ms doubling; unconfirmed = warning, still recorded enabled since the
  PUT succeeded) → `versioning_settles_at = now + 15 min` (only ever moved later; also for a bucket found Enabled,
  `enabled_by_vaulthalla` false) → retention → `Policy::upsert` → `recovery::local::invalidatePolicy`. Audit actions
  (`upstream_audit`, bucket-affecting): `recovery.disclosure`, `recovery.versioning.enable`, `recovery.retention.set`,
  `recovery.versioning.suspend`. Every `update` also logs its changes field by field to the audit log
  (`log::Registry::audit()`, like the other ops): mode, snapshot quota, cost alert, local versioning on/off and its
  limits, provider retention; `warn` when a local retention cut was accepted.
- **Retention on the bucket.** The owned rule `vaulthalla-managed` gets `NoncurrentDays` (indefinite: removed, the
  rule's other fields kept) plus `vaulthalla-manifest-versions` (prefix `.vaulthalla/`, NoncurrentDays 1, rebuilt from
  fields, `lifecycle::mergeManifestRule`). GET-merge-PUT-GET; every non-Vaulthalla rule id must come back, ours must say
  what was asked. "Current" history for shortening: the recorded retention, else indefinite when the bucket already
  versions. Status/disclosure list foreign NoncurrentVersionExpiration rules (`policy::describeRetention`) and the
  effective (shortest whole-vault) days. `ops::upstream::detach` removes every `vaulthalla-*` rule (owned + manifest-versions; foreign rules re-verified) and resets
  the recorded retention to `unset`. `vh upstream lifecycle --expire-noncurrent-days` on a bucket with a recorded
  retention IS that retention: shortening it (vs. the recorded value) needs `accept_destructive`, `0`/`--clear` record
  `indefinite`, N records `days N`, and a non-empty prefix on a `days` retention is refused (Invalid).
- **Disclosure token.** `v1.<expires>.<hex HMAC-SHA256>` under a per-process random key over (vault, provider,
  account, bucket, retention or `unset`, actor id, `cost::pricingDigest`, expiry), length-prefixed fields; 10 minutes;
  stateless (a restart invalidates tokens). The pricing digest covers currency, catalog version, provider/region/class,
  the unpriced reason and the provider-rule assumptions (rates, minimums) — never usage, which moves every minute.
- **Usage ledger.** `usage::noteRequest/noteDownloadedBytes/noteUploadedBytes` from `s3::Controller::recordRequest` /
  `recordUploadBytes` of controllers whose `setUsageVault` was called (`CloudEngine` constructors and
  `setS3ControllerForTesting`). Thread-local `usage::ScopedRequestTag`: multipart.cpp tags CreateMultipartUpload
  (`MultipartInitiate`) and UploadPart (`MultipartPart`); version.cpp tags ListObjectVersions (`VersionList`) and
  `copyObjectVersion` (`VersionRestore`); stream.cpp tags a GET with `version_id` (`VersionRestore`, bytes too).
  `noteUpstreamWrite` reads the key's `remote_object_index` row (one SELECT): absent = first put; present = overwrite
  of its `size_bytes` (skipped when the row's ETag is already this write's); delete = a delete marker (+ the row's
  bytes); the manifest key is ignored. Flushed by `usage::tick` from `VaultRetentionService`'s 30 s loop (every 60 s;
  cost alerts at most hourly) and by `runtime::Manager::stopAll` after every service stopped. A failed flush keeps its
  deltas (capped at 20 000 (vault, day) keys); rows of a deleted vault are dropped. Days are UTC strings computed in C++
  (`usage::utcDay`), never `CURRENT_DATE`.
- **Cost formulas** (`cost::estimate`, pure; `cost::gather` builds the inputs; `cpp_dec_float_50`, money 8 decimals).
  r = first-tier storage rate per byte-month (gb_month / 1e9, gib, tb, tib). Over N measured days (≤ 30, rows of
  `vault_upstream_usage_daily`): g = (overwritten + deleted bytes)/N + rewrites/N × avg current object size (rewrites =
  copy − version-restore requests: metadata rewrites keep full noncurrent copies); v = (overwrite + deleted objects +
  rewrites)/N; m = deleted objects/N; P = max(0, put − first_put − overwrite − multipart_parts − multipart_uploads)/N
  (manifest publishes). N = 0: illustrative g = current bytes × {1, 5, 20} %/month ÷ (365/12) (low/expected/high), P = 24.
  1 ≤ N < 7: low/high from the smallest/largest day (one day: ½× / 2×). D = max(R, D_min) billed days (R = chosen
  retention, capped by a shorter foreign whole-vault rule; indefinite = 365-day horizon). Monthly at elapsed t days =
  r × [max(g, v × S_min) × min(t, D) + m × t × keyBytes + P × max(M, S_min) × min(t, max(2, D_min))], M = max(1024,
  256 × current objects). Steady state t = max(R, D_min, 2) (indefinite 365); accumulation t = 365k/12, k = 1..12.
  Active: month-to-date = byteHours/730 × r; projected = (byteHours + B × H + g × H²/48)/730 × r (H = hours left in the
  UTC month, B = known noncurrent bytes; no growth term when suspended). Recovery per GB = egress + retrieval + GET +
  PUT; per object = COPY + HEAD (+ IA retrieval of an average version). Phase `active` = bucket Enabled and mode
  provider_versioning. Unpriced (no profile, pricing disabled, versioning block unsupported, unknown billing rule, no
  versioning block on a non-AWS profile) → every money field null. Catalog: one shared `PriceCatalogStore`
  (`cost::lookupProfile`), refreshed only as the configuration allows.
- **Alerts.** `cost::noteAlert`: one `operator_notification` per vault per UTC day (`run_uuid` =
  `recovery_versioning_cost:<vault>:<day>`, refreshed in place, expires after 2 days), when `projected_monthly` exceeds
  the threshold; evaluated by costs(), the disclosure and the hourly tick (`evaluateAlerts`: vaults with a threshold).
- Tests: `RecoveryCost*` (golden decimals from the signed fixture `core/test-assets/pricing/versioning`, all 24
  profiles because the signed manifest lists them), `RecoveryDisclosureToken*`, `RecoveryManifestRule*`,
  `RecoveryUsageLedger*` (DB-free); `RecoveryPolicyTest*`, `RecoveryUsageDbTest*` (DB).

## Surfaces (CLI, ws)

Both call `ops::recovery` and nothing else; payloads and `--json` use `ops/RecoveryJson.hpp` (the CLI builds the ws
payload shape from its options and reads it with the same readers, so validation is one code path).

- CLI (`protocols/shell/commands/{recovery,snapshot}.cpp`, `vault/recovery.cpp`; books `core/usage/src/usages/recovery.cpp`):
  `vh snapshot create|list|delete`, `vh recovery list|inspect|plan|restore|delete|costs`,
  `vh vault recovery status|set|suspend|disclosure` (`vh vault restore` stays vault undelete). Human output prints
  unknown money as "cannot be estimated (reason)", never 0. `set --mode provider-versioning` always fetches and prints
  the disclosure, then needs `ENABLE VERSIONING` typed (or `--yes` without a terminal) and, when unpriced, a separate
  `ACCEPT UNPRICED` (`--accept-unpriced`); retention shortening / adoption are asked the same way
  (`--accept-retention-shortening`, `--adopt-bucket`), also when the op raises them. `restore <recovery-id>` plans,
  previews, asks (type `RESTORE` when anything is overwritten or removed; y/N otherwise) and restores with the plan's
  token; `restore <plan-id> --token` is the scripted path; non-TTY without `--yes`/`--token` refuses. Exit 1 on a
  partial/failed result or conflicts. `set` sends local-versioning flags as a `LocalVersioningPatch` (absent =
  unchanged; `--keep-last 0` / `--max-age-days 0` / `--version-quota 0` = no limit), no status read first.
- ws (`protocols/ws/handler/Recovery.cpp`, book `core/usage/src/contract/ws/recovery.cpp`): `recovery.list` (120 s),
  `recovery.inspect` (30 s), `recovery.plan` (180 s), `recovery.plan.get`, `recovery.restore` (1800 s),
  `recovery.snapshot.create` (300 s), `recovery.point.delete` (60 s, `confirm`), `recovery.costs` (60 s),
  `vault.recovery.status` (60 s), `vault.recovery.update` (180 s), `vault.recovery.disclosure` (60 s),
  `vault.recovery.suspend` (60 s, `confirm`). Refusal codes = the `NeedsConfirmation` codes in `ops/Recovery.hpp`.
  Web types: `web/src/models/recovery.ts`. Parity: `test_ops_parity_recovery.cpp`.

## Module ownership (who edits what)

| Area | Files |
|---|---|
| Schema | `deploy/psql/111_file_recovery.sql` + `core/seed/shipped_migrations.lock` — integrator only |
| Contracts | `core/include/recovery/Model.hpp`, `core/include/ops/Recovery.hpp` — integrator only (agents propose changes) |
| Keys/crypto | `vault/EncryptionManager`, `crypto/util` reseal, key export |
| Data plane | `storage/s3/Controller` versioned ops (`storage/s3/version.cpp`), sigv4 query encoding, test fakes |
| Admin | `storage/s3/provider/admin/*` versioning get/put/probe, admin fakes, transport-seam adapter tests |
| DB + store | `db/query/recovery/*`, `db/preparedStatements/recovery/*`, `recovery/Model.cpp`, `recovery/Store.*` |
| Local versioning | `recovery/local/Versions.*` + capture hooks in fs/fuse/sync, backlog replay |
| Local recovery | `recovery/local/{Snapshots,Restore}.*` |
| Provider policy + cost | `recovery/provider/Policy.*`, `recovery/cost/*`, `recovery/usage/*`, `ops/RecoveryPolicy.cpp` |
| Provider recovery | `recovery/provider/{Versions,Restore}.*` |
| Dispatch | `ops/RecoveryPoints.cpp` (list/inspect/plan/restore/deletePoint) — integrator |
| Surfaces | `protocols/shell/commands/{snapshot,recovery}.cpp`, `vault/recovery.cpp`, usage books, ws handler + book |

## Status / open items (2026-10-16)

Built on `feat/recovery`: the three backends, the dispatcher, CLI/ws/web surfaces, operator docs
(`docs/vaults/recovery.md`, `docs/web-console/recovery.md`, `docs/cli/command-reference.md#file-recovery`).

Dispatcher as built (`ops/RecoveryPoints.cpp`): points are filtered by filesystem Read (+ List for directories; a path
that is gone is judged on its nearest existing folder), a file's history drops the snapshots whose `lv-` members it
already lists, plans keep only readable sources and show destination refusals as blockers. Plans are personal (someone
else's = NotFound), live 30 min, and their token is returned only when the plan is made (`getPlan` clears it).
`restore` saves each outcome as it goes and resumes a `running`/`partial` plan even after its 30 minutes; finished items
are kept. `db::Janitor` expires plans and purges finished/expired ones after 30 days.

Open, consolidated from the slices (the sections above keep the detail):

- **Backlog:** pending rows of a deleted file are settled by maintenance since #249 (replayed + re-deleted, or
  `'orphaned'`), up to 15 min late; the trash purge deletes upstream without replaying first; conflict keep_local
  uploads without replaying first (and its preflight doesn't price replays).
- **Version index:** permanent deletes of noncurrent versions and our own delete markers are learned only from the next
  complete listing. Live event delivery on a versioned bucket is unproven.
- **History retention shown per point** (`rpRetention`) uses the recorded state only: `days` shows Vaulthalla's days
  even when a foreign rule is shorter, `indefinite` shows `unknown`. Status and the disclosure do report foreign rules.
- **Lifecycle overlap:** `vh upstream lifecycle --expire-noncurrent-days` writes the same `vaulthalla-managed`
  `NoncurrentDays` as recovery retention, without `recovery_retention_shorten` and without updating the recorded
  retention. `ops::upstream::detach` clears only `vaulthalla-managed` (the manifest-versions rule stays) and its
  foreign-rule check counts `vaulthalla-manifest-versions` as foreign.
- **Keys:** a deleted vault's export (`vault_deletion_key`) carries no `historical_keys`.
- **Lossy by design:** usage ledger deltas ≤ 60 s on a crash; disclosure tokens die with the process key on restart.
- **CLI bug:** `vh recovery restore <plan-id>` without `--token` can never succeed (`getPlan` cleared the token, so
  `rcRunPlan` sends "" → `recovery_restore`), although the usage book says `--yes` works there. Docs tell operators to
  pass `--token`; fix by refusing early or re-planning.
- **Web:** the point-in-time form is shown for folders of local vaults too; ops refuses it (Invalid).
- **Proof gaps:** no Tier A/B harness scenario for recovery yet; no live provider-versioning run since the
  live suites were consolidated (2026-10-22: the live R2 tests cover the data plane only; R2 has no versions); no lab
  install of a recovery build.
