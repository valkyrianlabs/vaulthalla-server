# Upstream control plane and event-driven sync (#237, #96)

Built 2026-10-15 on `feat/upstream-control-plane`. Operator docs: `docs/vaults/upstream-buckets.md`,
`docs/vaults/event-sync.md`. Migration 110.

## What it is

An upstream API key (AWS S3 or Cloudflare R2) can be marked an administrative credential (`api_keys.admin_enabled`).
Then Vaulthalla lists the account's buckets, creates/adopts buckets for vaults, owns one lifecycle rule
(`vaulthalla-managed`), runs event subscriptions (S3 → SQS Standard, R2 → Cloudflare Queues HTTP pull) and cleans up
buckets it created. Other providers: plain storage, but protection locks still apply.

## Code map

| Layer | Where |
|---|---|
| Provider adapters (trusted, no RBAC) | `storage/s3/provider/admin/` — `Admin.hpp` interfaces (`AdminClient`, `EventsClient`), `AwsAdmin`, `AwsEvents` (SQS JSON protocol, queue policy, notification GET-merge-PUT), `R2Admin`, `R2Events` (Cloudflare REST), `S3Api`/`Xml`/`Internal` (merges, redaction), `Registry` (`adminFor`/`eventsFor`, `setFactoryForTesting` test-mode only) |
| Signing/HTTP | `storage/s3/sigv4/Signer` (any service/region), `storage/s3/curl/Http` (timeouts, size cap, `ScopedCancellation`, transport seam) |
| Identity + lock | `storage/upstream/{Identity,Guard}` — identity = (providerIdentity, account_ref, bucket); `guard::require` in `s3::Controller::recordRequest` and every bucket-scoped adapter call; set loaded at startup (`main.cpp wireStorage`, fail closed) |
| Control plane primitives | `storage/upstream/{Inventory,Lifecycle,Provisioner,Cleanup}`, models `storage/upstream/model/*`, queries `db/query/upstream/{Bucket,Audit,Binding,Channel,Subscription,Inbox,WriteIntent}` |
| Events | `sync/events/{Event (normalized + decoders), Ingest (message → inbox), Applier (inbox → index → scoped pass), Service (UpstreamEventService: pollers, sweeps), Subscriptions (state machine)}` |
| Sync | `sync::Controller::{runScoped, tryAcquirePass, releasePass}`, `sync/model/Scope.hpp`, `Cloud::{initScopedBins, loadRemovedKeys, setPendingRemovalsProvider, setEventHooks}`, Planner removal rule |
| Ops (only authorizing boundary) | `ops/Upstream{,Events,Json}.cpp`; `ops::vaults::create` `S3Spec::provision` |
| Surfaces | CLI `protocols/shell/commands/upstream.cpp` + `usage/src/usages/upstream.cpp`; ws `protocols/ws/handler/Upstream.cpp` + book `usage/src/contract/ws/upstream.cpp`; web `features/credentials/*` (admin panel, `/credentials/[id]/buckets`), `NewVaultPage`, `VaultSettings` events panel |
| RBAC | `rbac/permission/admin/Upstream.hpp`, `admin_role.upstream_permissions` BIT(8): view 0, configure 1, provision 2, protect 3, unprotect 4, destroy 5 |

## Invariants (keep them)

- Protection belongs to the bucket identity, never the key; unknown account ⇒ any lock on (provider, bucket) applies.
  Identity follows the endpoint host, not the key's provider label (`*.r2.cloudflarestorage.com` ⇒ cloudflare-r2,
  `*.amazonaws.com` ⇒ aws-s3; `providerIdentity(const APIKey&)`); keys whose label contradicts the endpoint are refused.
  Bucket names/regions are validated (`storage/upstream/Names`) before any request; Cloudflare REST segments are
  percent-encoded (no signature covers those paths).
  Every protect/unprotect: `guard::reload()` + `subscriptions::invalidateCache()` + `onBucketProtected/Unprotected`.
- Create-new never takes over: HeadBucket 404 → CreateBucket (collision = Conflict) → must list empty; compensation
  deletes only an empty bucket created by the same operation token. No rollback deletes a pre-existing bucket.
  The claim row is `unmanaged` + `provision_attempted` until `confirmCreated` (token-guarded) after a 2xx create and an
  empty listing; all ownership/state writes are token-guarded.
- Vault delete/detach never deletes upstream data; cleanup only for `managed` + `created_by_vaulthalla`, unbound, not
  protected, no live subscription; preflight token bound to identity + counts + actor (10 min), all checks repeated
  right before deleting; object lock enabled = blocker, unreadable = warning (provider refusals → `partial`).
  Cleanup holds its own lease (`deleting`, fresh token; busy for adoption/provision/detach), re-checked per round;
  a mid-run provider error leaves the row failed + resumable. `delete_upstream` is refused for adopted buckets.
- Lifecycle: only `vaulthalla-managed` is rebuilt from fields; every other rule round-trips raw and is re-verified;
  an owned rule with unmodeled elements is refused rather than rewritten.
- Only `vaulthalla-*` rules/statements/queues are ours. AWS notification config is replaced wholesale on PUT: always
  GET-merge-PUT and re-read. R2 DELETE always carries `ruleIds` (a bodyless DELETE removes every rule for the queue).
- Inbox insert commits **before** the queue ack; undecodable messages are never acked (→ DLQ). Manifest keys are
  ingested as skipped/self (they fed a republish loop). Order is `event_time_ms` (R2 has no sequencer); S3 sequencers
  compare left-padded (= numeric), as AWS documents.
- The index is fresh from events only while the stream is contiguous: a DLQ backlog, a poll gap over retention or an
  ingest failure on a last delivery sets `continuity_broken_at` and the baseline back to pending (full LIST).
- One pass per vault (pass lease). The applier holds the lease while it changes `remote_object_index` and republishes
  the manifest: a regular pass reloads the index from the manifest when it is empty or the manifest ETag moved, and a
  stale manifest resurrects deleted objects.
- Removal events delete a local copy only if unchanged since the baseline and a HEAD confirms 404 (a present object is
  re-indexed; a failed HEAD retries); mirror+keep_local re-uploads. The applier takes the lease before claiming rows
  and yields to a waiting regular pass. Write intents are removed on failure and match on ETag.
- An object without Vaulthalla metadata over an encrypted file is plaintext only if the vault doesn't encrypt
  upstream, or its active subscription has `foreign_objects=import`; otherwise it stays an authentication failure.
  `vh-encrypted=false` over a sealed file follows the same rule. Encrypting vaults default to `foreign_objects=ignore`
  (adopted buckets: `import`). Manual `vault sync events --file` needs configure + sync.config.edit + key Consume.
- `s3` bindings are upserted per vault (`ON CONFLICT (vault_id)`); a key+bucket pair of another vault is refused.

## Provider facts (verified live 2026-10-15)

- AWS test identity `vaulthalla-test-admin`: S3 admin works; **no SQS permissions** and no
  `s3:GetBucketObjectLockConfiguration` → AWS event delivery untested live. Needed statement: docs/vaults/upstream-buckets.md.
- R2: both `VH_R2_*` pairs in the repo `.bashrc` are S3 token pairs (same account); neither authenticates the Cloudflare
  REST API (6003 / 1000). Events need one CF API token (Queues: Edit, Workers R2 Storage: Edit) stored as the key's
  provider token. R2 accepts any SigV4 region (`auto`, `wnam`, `us-east-1`). New R2 buckets carry a default
  "Default Multipart Abort Rule" (foreign). Collisions: 409 `BucketAlreadyOwnedByYou` on both providers.
- Live tests: `VH_LIVE_UPSTREAM=1 … --gtest_filter='UpstreamLive*'` (only `vaulthalla-test-<ts>-*` names; cleans up).
- Provider versioning (file recovery, `AdminClient::{supportsVersioning,versioning,putVersioning}`; verified live
  2026-10-16, `UpstreamLive.AwsVersioning`): PutBucketVersioning carries Content-MD5 (AWS requires an integrity
  header) and `x-amz-expected-bucket-owner` when the account is known, Status only — never MfaDelete/`x-amz-mfa`.
  The test identity has Get/PutBucketVersioning + ListBucketVersions; Enabled and Suspended read back on the first
  GET (~130 ms), but AWS still asks for 15 min before relying on versioned writes. R2 has no versioning:
  `versioning()` = Unversioned without a request, `putVersioning` = `CapabilityMissing("versioning")`, nothing sent.
  Existing noncurrent retention (ours + foreign, incl. NewerNoncurrentVersions): `storage/upstream/Lifecycle`
  `noncurrentExpirations` / `coverage` / `effectiveNoncurrentDays`.

## Tests

DB-free: `UpstreamSigV4*`, `UpstreamProvider*`, `UpstreamEventDecode*`, `UpstreamPassLease*`, `ShellLogRedaction*`.
DB-backed (`bin/tests/run_unit.sh`): `UpstreamStore*`, `UpstreamOps*`, `UpstreamEventOps*`, `UpstreamEvents*`,
`UpstreamSubscriptions*`, `UpstreamScopedSync*`, `UpstreamParity*`, `SqlDeployerHistoryDb.*` (migration 110),
`RoleParity*` (upstream bits). Fakes: `tests/helpers/upstream_admin_fakes.hpp`, `upstream_event_fakes.hpp`.

## Open items

- Live AWS SQS and R2 Queues delivery: blocked on the IAM policy and a Cloudflare token (see above).
- A shared channel is polled with the key of the most recent subscriber; that key can't be removed/demoted while any
  subscription on the channel is live.
- Cleanup of very large buckets runs in rounds (60 s / 50k objects per call); no background job yet.
- R2 queue retention isn't set (Cloudflare's default applies).
