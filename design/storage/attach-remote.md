# Attaching a remote to a local vault

How an existing local vault becomes an encrypted, `opaque_v1`, bucket-backed vault without leaving service: the
preconditions, a resumable state machine, the cutover transaction and engine swap, and the surfaces. It serves BYOS
and Vaulthalla Cloud managed storage alike (`design/cloud/managed-remotes.md` calls it with a provisioned bucket). It
does not design the reverse in full, moving a vault between buckets, or the manifest publish path for buckets without
conditional PUT (`design/encryption/06-publish-without-preconditions.md`).

## Decided (Cooper, 2026-11-12)

- Existing local vaults must be upgradable to a synced remote, for BYOS and for managed storage. It is a launch
  requirement. BYOS is built first, because it needs nothing from the cloud.

Everything else here is a proposal.

## Today

- **The type is fixed at creation.** `ops::vaults::update` refuses an API key, bucket, tier or encryption field on a
  local vault (`core/src/ops/Vaults.cpp:416`); the ws handler refuses a type change (`protocols/ws/handler/vault/
  Vaults.cpp:190`); the console says "fixed when the vault was created" (`web/src/features/vaults/settings/
  VaultSettings.tsx:169`). The schema allows the change: `vault.type` is a CHECKed column, `s3` a row keyed by vault
  (`deploy/psql/020_vaults.sql`), the sync policy a `sync` row with an `fsync` or `rsync` child (`050_sync.sql`).
- **Engines follow the row.** `storage::Manager::{addVault,updateVault,reloadEngine,reinstateVault}` build an `Engine`
  for `local` and a `CloudEngine` for `s3`; `sync::Controller::processTask` replaces a vault's task when its engine
  object changes (`Local` or `Cloud` by type). The vault root, FUSE name and backing paths come from the vault row,
  not the engine type.
- **The bytes are already the object.** Every vault has a `vault.uid` and every file an `object_uid` (migrations
  122, 123). VHF1 makes the local backing file, the recovery blob and the upstream object the same bytes (spec 02
  §3.1); the generation id is the header salt in `files.encryption_iv`, and `files.content_format` says `plain`,
  `gcm0` or `vhf1` (migration 126). Uploading a converted local vault is a byte copy, never a re-seal.
- **A new S3 vault** is created `opaque_v1` when it encrypts (`db/query/vault/Vault.cpp:70`); its first manifest
  publish writes the layout hint, segments and root (`sync/manifest/Publisher.cpp`), and its KEV1 envelopes are PUT
  before a key version is committed and at the start of each pass (`CloudEngine::ensureRecoveryEnvelopes`).
  Recipients are refused on local vaults: "recovery recipients are for S3 vaults" (`ops/RecoveryRecipients.cpp:163`).
- **The closest conversion** is the layout migration (spec 01 §6 as built, `vault/LayoutMigration.hpp`, migration
  133): operator-started, run by `LayoutMigrationService`, item rows, resume by HEAD and header generation, a
  verification gate, one cutover transaction, nothing deleted on failure.
- **History.** Local versions of a local vault are captured with `upstream_state = 'none'`; in an upstream vault
  they are the ordered backlog (`pending` → `sent`), and smart cache releases a blob once the provider holds it
  (`.claude/context/recovery.md`). `vh vault recover` rebuilds a vault from its bucket, keys and manifest alone (spec
  03 §6.4) and starts it in `cache`.
- **No reverse exists.** `upstream.bucket.detach` relinquishes management (lifecycle and event rules) of a bucket no
  live vault uses; it never converts a vault (`ops/Upstream.cpp:918`).

## Preconditions (checked at start and again before cutover)

1. **A local vault**, live, its engine loaded with its keys, no attach running, no key rotation or salvage running.
2. **No legacy content.** No live file or recovery blob in `gcm0`, and no non-empty `plain` file
   (`vh vault format status`). The format conversion service finishes first; an attach never converts.
3. **Every key version** the live files, blobs and snapshots use is held and attested (`vault.keys.status`).
4. **The bucket is empty or this vault's own.** A complete `ListObjectVersions` (every page; a truncated or refused
   listing fails) shows no version or delete marker, or only objects a previous attempt of this attach recorded.
   No other vault or attach holds `(api_key_id, bucket)` (`Vault::bucketOwner` and the attach table); the bucket
   has no protection lock. A bucket the upstream control plane provisions for the purpose (`BucketProvisionFields`,
   AWS and R2 admin keys) is empty by construction.
5. **Encrypted, `opaque_v1` only.** There is no `transparent` or `path_v0` attach: a new attachment never writes
   names the provider can read, and nothing needs the legacy writer.
6. **Recovery material** per spec 03 §5.5 as amended: managed storage needs the account key `pinned`; the server adds
   it as a grant on conversion (`design/cloud/key-manager.md`; refused as `account_key_unconfirmed` without a pin).
   BYOS needs a recipient or a verified export covering every needed version. `key-manager.md` ("Local vaults") lets
   a local vault hold grants, with their envelopes in `vault_key_envelope.envelope`; the attach copies those into the
   bucket and wraps any version still missing one (open question 2).
7. **The bucket can publish the manifest.** `preparing` runs spec 06's capability probe (§7, on
   `.vaulthalla/probe/<uid>`) and stores its result on the attach row: publish mode `conditional` or `version_log`
   and the probe JSON. `bucket_capability_insufficient` (neither conditional PUT nor versioning) refuses. In
   `version_log` mode every manifest write follows spec 06, not only the root: envelopes, segments and the layout hint
   are plain PUTs (§5.2 step 1, §7), and the root is published and settled by rule C1 with `writers = [this node]`
   (§5.5). On Backblaze, which very likely needs `version_log`, attach depends on spec 06's work items 2-5.
8. **Preflight.** BYOS: the price budget (`pricing`, operation `remote_attach`): per file one PUT or a multipart
   upload of its VHF1 size, the envelopes, the manifest, two listings and the read-back sample; worst case every
   object read back when the provider's ETags are not MD5s. Unpriced needs `accept_unpriced`. Managed: the vault's
   bytes against the quota left in the cached entitlement, refused as `over_quota` before anything is written (the
   cloud enforces; this is only the courtesy check).

## Data model (the next free migration)

Landing order set for the series: spec 06's probe columns, then this, then `key-manager.md`'s pin tables, then
`managed-remotes.md`. Numbers are taken when each lands.

`vault_remote_attach (vault_id PK, origin [byos|cloud], api_key_id, bucket, storage_tier_id, manifest_publish,
bucket_probe JSONB, state, started_by,
started_at, accept_unpriced, passes, verified_at, cutover_at, done_at, aborted_at, estimate JSONB, usage JSONB,
last_error)`, unique `(api_key_id, bucket)` while not `aborted`. `vault_remote_attach_item (vault_id, kind
[content|envelope|metadata|orphan], file_id, object_key, generation, key_version, size, etag, version_id, state
[pending|sent|verified|stale|deleted|failed], error)`. The item rows are the only list abort and orphan cleanup may
delete from, always by version id.

## States

| State | Work | Writes locally | Writes to the bucket |
|---|---|---|---|
| `preparing` | preconditions, spec 06's probe; item per live file with content (file id, object uid, generation, size); estimate and preflight | attach row, items; for managed storage the account-key grant | every grant's envelopes, copied from the database or wrapped now (`.vaulthalla/key/<kid>`), the layout hint |
| `uploading` | per item: open the backing file, read the generation from the header actually read, PUT the bytes to `o/<uid>`, record ETag, version id and size, compare the ETag with the MD5 computed while sending | item state | content objects |
| `catching_up` | items whose file changed generation are re-sent; new files get items; a file deleted since its upload gets its versions deleted; repeated until a pass finds nothing or `vaults.remote_attach.max_passes` (default 3) | items | objects; DELETE by version id |
| `verifying` | a second complete listing equals the items plus metadata, nothing foreign; a read-back sample (1 %, at least 100) authenticated end to end, or every object when ETags are not MD5s; publish manifest v2 (epoch 1, in the probed mode; `version_log` settles it per spec 06 §5.2) and load it back from the bucket with only the key material, compared with the database (`layout::verifyManifestAgainstDatabase`); every envelope passes `kev1::inspect` for its grant and version | `verified_at` | root and segments |
| `cutover` | one transaction (below), then the engine swap, then orphan cleanup | the vault becomes `s3` | orphan deletes |
| `done` | nothing; the vault syncs as any S3 vault | `done_at` | normal sync |
| `failed` | any error before the cutover: the vault is still local and untouched; run attach again to resume | `last_error` | none |
| `aborted` | abort ran (below) | `aborted_at` | deletes of what the items list |

**Writes during the attach** go on as before: FUSE, the web console, shares and the gateway use the local `Engine`
throughout. The attach reads backing files without a lock: a FUSE commit replaces a backing file atomically, and the
item records the generation of the bytes actually sent, so a racing write is just a newer generation. Catch-up only
keeps the first pass after the cutover small; correctness does not depend on it, because the cutover baselines name
exactly what the bucket holds and anything newer locally is an ordinary pending upload.

**Rotation waits.** A key rotation requested during an attach stays queued until `done` or `failed`; otherwise a new
version could seal content before its envelopes reach the bucket.

## Cutover

One transaction, under the vault's pass lease and its row lock:

1. Re-check preconditions 1, 3 and 4 (the reservation) and that the attach is `verifying` with `verified_at` set.
2. `vault.type = 's3'`; insert `s3 (api_key_id, bucket, storage_tier_id, encrypt_upstream = true, storage_layout =
   'opaque_v1', manifest_publish, bucket_probe)`, the last two copied from the attach row (spec 06 §7's columns).
3. Replace the `fsync` row with an `rsync` row from `freshPolicy(S3)`: the operator's `vaults.s3` defaults, which ship
   as strategy `cache` and conflict policy `ask` (`deploy/config/config.yaml:223`), keeping `interval` and `enabled`.
4. `remote_object_index` rows for every verified item (source `manifest`), sync baselines at the sent generation,
   `remote_manifest_state` and `remote_manifest_root` at the published root (with `root_version_id` and
   `settle_window` in `version_log` mode, spec 06 §7), `vault_key_envelope` rows.
5. Items whose file no longer exists become `orphan`; live files without an item (created after the last catch-up)
   get no index row and upload on the first pass.
6. An `upstream_bucket` binding for the vault (ownership as the control plane already records it; `unmanaged` for a
   plain BYOS bucket). A gateway binding in mode `local` becomes `remote_cache`, the mode `ops::s3_gateway` uses for
   S3-backed vaults (open question 4).
7. Existing local versions keep `upstream_state = 'none'`: pre-attach history stays local (open question 1).
8. The attach row `cutover`, and the audit event `vault.remote.cutover`.

After commit: `storage::Manager::reloadEngine(vault)` builds the `CloudEngine` from the row and swaps both indexes
under the manager lock, then `sync::Controller::refreshEngines()` replaces the `Local` task with a `Cloud` task. FUSE
calls in flight hold the old `Engine`, which writes the same backing files and `files` rows the `CloudEngine` reads,
so nothing is lost. Orphans are then deleted by version id, a first pass runs, and the row becomes `done`. Key
retention follows the type from then on (`vaults.s3.tpm_retention_window`).

## Crash recovery and abort

| Crash in | On restart |
|---|---|
| `preparing` | redo it: envelopes and the hint are idempotent (same kid, same content); items are rebuilt |
| `uploading`, `catching_up` | a `pending` item HEADs its key and reads the 120-byte header: the recorded generation means the PUT landed (record it); any other leaves a stray version, deleted by version id after the right one is recorded |
| `verifying` | rerun the verification from the start; a root published by the lost attempt is loaded and republished as the next epoch (in `version_log` mode an unsettled one is found and repaired by spec 06 §5.4) |
| `cutover`, before commit | nothing changed; rerun |
| `cutover`, after commit | the row says `cutover`: redo the engine swap (idempotent), orphan cleanup and the first pass |

`LayoutMigrationService`'s pattern, as a `RemoteAttachService` started after `LayoutMigrationService`: its own thread,
polling attach rows, never a FUSE, sync or request thread. Nothing runs without an attach row.

**Abort** is allowed before `cutover` only. It deletes, by version id, every object, envelope, hint, segment and
root the items list, removes the grant rows the attach created, and releases the reservation; a delete the provider
refuses is retried and listed, never reported done. The vault was never changed. It deletes nothing it did not
record, so a bucket shared with anything else is never emptied. Managed storage aborts through its per-vault switch.

## Status and health

`vault.remote.status`: state, origin, bucket, publish mode, the estimate and usage, `last_error`, after `done` the
first pass's result, and a `progress` object that Desktop and the console render as is: `phase` (the state, or
`hydrating` for a detach), `files_total`, `files_done`, `bytes_total`, `bytes_done`, `bytes_per_second` over the
last minute, `eta_seconds` (null while unknown), `passes`, `updated_at`. `storage.vault.get` adds a `remote` summary
(`none`, `attaching:<state>`, `attached`). Health: `remote_attach_failed` (degraded, per vault) and
`remote_attaches_unfinished` (info), beside `layout_migrations_unfinished` (`stats/model/SystemHealth.cpp`).

## After the cutover

The vault is an ordinary `opaque_v1` S3 vault in `cache`: files stay local, so nothing is downloaded; new
generations follow the backlog rules; snapshots taken before the attach list members whose generation the bucket
holds as restorable from it and the rest as local only. `cache` never evicts current bodies, so local disk is not
reduced (plan section 7). Provider history follows the vault's recovery policy as for any S3 vault
(`vault_recovery_policy.mode`, `upstream_bucket.noncurrent_retention_*`); a BYOS B2 bucket versions always and gets no
rule from the server (spec 06 §5.4); managed storage sends the retention to the cloud (`managed-remotes.md`).

**The reverse.** No S3 → local conversion exists, and BYOS doesn't need one at launch. Managed storage does: its
per-vault switch hydrates and detaches (`managed-storage.md`, "The per-vault switch"). The contract proposed here:
`vault.remote.detach` hydrates every remote-only file, verifies every live file has a local copy at its current
generation, then in one transaction makes the vault `local` (the `s3` row and remote index go, `rsync` becomes
`fsync`, a `remote_cache` gateway binding returns to `local`) and swaps the engine; the bucket is untouched. Its own
work item; full design with it. **Moving to another bucket** is out of scope: `update` can repoint an S3 vault's key
and bucket today without moving data, which is only right when the new bucket already holds the same objects.

## Surfaces

| Surface | Contract |
|---|---|
| `ops::vault_remote` | `attach(actor, {vault_id, api_key_id, bucket, storage_tier?, origin, accept_unpriced})`, `status`, `abort`; `origin = cloud` only from `ops::cloud_storage` |
| CLI | `vh vault remote attach <vault> --api-key <key> --bucket <name> [--storage-tier] [--accept-unpriced]`, `vh vault remote status [<vault>\|all]`, `vh vault remote abort <vault> --confirm <name>` (the `vh vault format status` and `vh vault keys` subcommand style) |
| ws | `vault.remote.attach`, `vault.remote.status`, `vault.remote.abort`; models `VaultRemoteStatus`, `VaultRemoteEstimate` in `usage/src/contract/models/vaults.cpp` |
| Catalog | `core/usage/src/usages/vault.cpp` (`attach` Destructive, `abort` Destructive), ws book `usage/src/contract/ws/vaults.cpp`, an `OperationSpec` per op in `usage/src/contract/operations.cpp`, the step-up table (`ws/stepup.cpp`): `vault.remote.attach` and `.abort` `keys`, bound to the vault |
| RBAC | attach: vault Edit, sync config Edit and the key's Consume (what `create` and `update` ask for an S3 binding), plus the encryption-key Rotate permission (as the layout migration, which also decides where every object of the vault goes). Status: the vault's View. Abort: as attach |
| MCP | `vault remote attach` excluded: where a vault's data goes is decided by a human, as for `cloud recovery enroll`. Status available; abort available with its confirmation |
| Web | vault settings: "Storage: local" gains "Add remote storage" → credential (keys the user may consume), bucket (an empty one, or created with `BucketProvisionFields`), recovery material check with the next step when missing (Desktop or `vh` adds the recipient), the estimate, step-up and confirm; then a progress panel with abort. The "fixed when the vault was created" line goes |
| Desktop | the vendored contract gains the three commands, both models, `progress` and the `remote` summary. From a paired device the `keys` step-up is answered as for any device session today: the device's approval key (Secure Enclave, `keys` and `device.trust` only) or a console approval with a passkey (#361, `auth/approval/Approvals.hpp`, `auth/stepup/StepUp.cpp:214-237`). Only the step-up ceremony itself is web-only (`Ceremony.cpp:41`) |

The type-change refusals stay: `storage.vault.update` still never changes a type. Attach is the one path.

## Tests

- `RemoteAttach.*` (DB, versioned fake S3 with fault injection): every precondition refuses with nothing written;
  a crash after each named step resumes (the layout migration's `afterStep` seam); writes, renames and deletes during
  `uploading` and between verification and cutover end consistent after the first pass; a stray version is removed;
  verification failures (listing mismatch, foreign object, wrong ETag, tampered object, manifest difference) keep the
  vault local; abort deletes exactly the recorded versions; cutover is one transaction (a fault inside leaves it
  local); trash restore and purge of files never uploaded; rotation waits.
- `RemoteAttachRequestAudit`: every request is on the `opaque_v1` allowlist (spec 01 §8); `RemoteAttachCost` matches
  the estimate.
- `RemoteAttachRecover`: after `done`, `vh vault recover` on a fresh instance rebuilds the vault from the bucket with
  the recipient's kit (spec 03 §7's drill, extended).
- Harness Tier B: attach while FUSE and the web console write; gateway binding flips to `remote_cache`.
- Live: one `vh-test-*` R2 bucket; B2 once spec 06 and a key exist (ETag form, version listing).

## Work items

Prerequisites: spec 06 work items 2-4 (Store seam, capability probe and columns, plain PUTs) for every bucket, and 5
(the `version_log` publish with `writers`) for Backblaze.

1. Local-vault grants and database-held envelopes (`key-manager.md`, "Local vaults"), if that proposal is taken.
2. The migration, `vault::remote::attach` engine and `RemoteAttachService`, BYOS only, behind no capability: it is
   ordinary BYOS behaviour.
3. `ops::vault_remote`, CLI, ws, catalog, step-up, MCP exclusion, health.
4. Web flow and progress panel; Desktop contract bump.
5. `vault.remote.detach`, designed and built before managed storage's switch ships.
6. Drill additions (`managed-remotes.md`, work item 9).

## Open questions

1. **Pre-attach history.** Upload local versions as provider history? *Recommendation: no. They stay local recovery
   points with their retention; provider history starts at the attach, and the cost stays one PUT per file.*
2. **Recipients on local vaults** (`key-manager.md` proposes database-held envelopes). Without them, a BYOS attach
   of a vault with no verified export has no recipient path, and attach would have to take a recipient itself and
   repeat the D4 rules for who may add one. *Recommendation: take the key-manager proposal; attach takes none.*
3. **Agents.** *Recommendation: attach excluded from MCP, status and abort allowed, as above.*
4. **Gateway buckets in `local` mode.** Flip to `remote_cache` at cutover, or refuse the attach. *Recommendation:
   flip; it is what a gateway bucket on an S3 vault already is.*
5. **Catch-up bound.** *Recommendation: three passes, then cut over; the rest is the first pass's work.*
6. **Re-attaching the vault's own earlier bucket** (managed switch on again before the cloud deleted it).
   *Recommendation: allowed when the hint and root carry this vault's uid and open with its keys; objects at the
   same generation are kept, the rest deleted by version id after the cutover.*
7. **Detach for BYOS users.** *Recommendation: CLI and ws only at first; the console offers it with managed storage.*
