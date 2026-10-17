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
  loses the live file. Fallbacks: reflink (FICLONE / macOS `clonefile`), then copy. A blob is immutable once linked.
- **Invariant this rests on: nothing writes a backing file in place.** A linked blob shares the live file's inode until
  the next rename-replace; an in-place writer would silently rewrite history. Every backing-file writer must replace
  by rename (or the capture must use `captureCopy`). Guard: a contract test listing the writers (local versioning
  slice).
- Dedupe: unique `(vault_id, encryption_iv, key_version)` for non-empty IVs: the same generation captured twice
  (two snapshots of an unchanged file) is one blob. Physical accounting = sum of distinct blobs' `cipher_bytes`.
- Crash safety: blob first (temp name + rename + dir fsync), then the DB rows in the same transaction as the files-row
  update; an orphan blob (no row, older than 1 h) is swept at startup; a row whose blob is missing is reported
  `restorable=false` ("blob missing"), never silently dropped (a later capture of the same generation recreates the
  file under the existing name). Removal deletes the row first, then the file: a crash leaves an orphan file for the
  sweep, never a row without its file.
- Quota: blob bytes count against the vault quota (`Engine::freeSpace` adds `recovery_blob` bytes from the DB, no
  walk) and against `snapshot_quota_bytes` / `version_quota_bytes`. Vault purge removes `.vh-recovery/<alias>` with
  the backing dirs.
- Retention: snapshots are kept until deleted. Local versions: `version_keep_last` per file, `version_max_age_days`,
  `version_quota_bytes` (oldest first); a generation still `pending` upstream is never pruned; a blob still referenced
  by a snapshot is never deleted (refcount = referencing `file_versions` rows).

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
  `vault_keys_trashed[v]` unsealed and cached: ≤ 8 versions, LRU, dropped after 10 min unused, checked on access;
  outstanding snapshots stay valid until released) throws `vault::KeyVersionUnavailable` for a version the vault
  doesn't hold (incl. 0). `retainedKeyVersions()`, `hasKeyVersion(v)`, `referencedHistoricalKeys()` (export).
  `resealFileToCurrent(src, iv, v, dst, f)` / `resealToCurrent(buf, …)` over `crypto::util::resealFile` /
  `resealBuffer` (`crypto/util/reseal.hpp`, 64 KiB chunks, `GcmStreamDecryptor` → `GcmStreamEncryptor`): a source
  that fails authentication throws `storage::IntegrityError` and dst is removed (whatever it held). An empty
  generation (empty IV, version 0, zero bytes) re-seals to an empty dst with empty IV/version 0 (how every empty file
  is stored); a non-empty source with an empty IV is plaintext and refused (`std::invalid_argument`). Same-version
  re-seal still draws a fresh IV (reuse the bytes instead if that is wanted).
- Key export (`vh vault keys export`) adds, per vault, `historical_keys: [{key_version, key (base64), created_at,
  retired_at}]` for the retired versions `recovery_blob` / live `upstream_object_version` rows reference (never the
  current one), and `missing_key_versions` when a referenced version is gone. Both fields are omitted when empty, so
  exports without recovery data are byte-identical to before. Export tracking (`exported_version`) still records the
  current version only. A deleted vault's export (from `vault_deletion_key`) does not add historical keys yet.
- `get_rotation_old_vault_key` used to `SELECT *` from `vault_keys_trashed`, which has no `updated_at` column, so
  `vault::model::Key(row)` threw and a restart mid-rotation could not load the vault key. Retired-key reads now alias
  `trashed_at AS updated_at` (pinned by `RecoveryKeysDbTest`).

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

## Local versions as the upstream backlog

For upstream vaults with local versioning on, retained generations are also the ordered upstream backlog:
`file_versions.upstream_state` `pending` → `sent` (provider version id recorded) | `skipped`.

- When the provider doesn't respond, writes keep working locally and generations queue up in `version_number` order.
- When it responds again and the bucket has provider versioning enabled+settled, the upload of a file first replays
  its pending generations oldest-first (each PUT carries the generation's own IV/key-version metadata), then the
  current content, so the provider's history matches local history. Price preflight and request budgets cover the
  replays. A bucket without versioning: intermediate generations are `skipped` (only the latest content matters).
- Smart cache: in a `cache` vault (or gateway `remote_cache`) with provider versioning, a generation's local blob is
  released once the provider holds it (`sent`) unless a snapshot references it. Local history bodies exist only as an
  unacknowledged backlog, never as a duplicate of provider history.

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
  partial/failed result or conflicts. `set` with only some local-versioning flags merges them into the stored policy
  (reads `status` first; `--keep-last 0` / `--max-age-days 0` = no limit).
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
| Admin | `storage/s3/provider/admin/*` versioning get/put/probe, admin fakes, live tests |
| DB + store | `db/query/recovery/*`, `db/preparedStatements/recovery/*`, `recovery/Model.cpp`, `recovery/Store.*` |
| Local versioning | `recovery/local/Versions.*` + capture hooks in fs/fuse/sync, backlog replay |
| Local recovery | `recovery/local/{Snapshots,Restore}.*` |
| Provider policy + cost | `recovery/provider/Policy.*`, `recovery/cost/*`, `recovery/usage/*`, `ops/RecoveryPolicy.cpp` |
| Provider recovery | `recovery/provider/{Versions,Restore}.*` |
| Dispatch | `ops/RecoveryPoints.cpp` (list/inspect/plan/restore/deletePoint) — integrator |
| Surfaces | `protocols/shell/commands/{snapshot,recovery}.cpp`, `vault/recovery.cpp`, usage books, ws handler + book |
