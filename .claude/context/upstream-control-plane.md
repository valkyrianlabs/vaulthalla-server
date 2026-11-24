# Upstream control plane and event-driven sync (#237, #96)

Built 2026-10-15 on `feat/upstream-control-plane`; Backblaze B2 bucket administration added 2026-11-23
(`feat/b2-provider-admin`, migration 153). Operator docs: `docs/vaults/upstream-buckets.md`,
`docs/vaults/event-sync.md`. Migration 110.

## What it is

An upstream API key (AWS S3, Cloudflare R2 or Backblaze B2) can be marked an administrative credential
(`api_keys.admin_enabled`). Then Vaulthalla lists the account's buckets, creates/adopts buckets for vaults, owns one
lifecycle rule (`vaulthalla-managed`), runs event subscriptions (S3 → SQS Standard, R2 → Cloudflare Queues HTTP pull)
and cleans up buckets it created. Backblaze B2 gets the bucket half only (see "Backblaze B2" below). Other providers:
plain storage, but protection locks still apply.

## Code map

| Layer | Where |
|---|---|
| Provider adapters (trusted, no RBAC) | `storage/s3/provider/admin/` — `Admin.hpp` interfaces (`AdminClient`, `EventsClient`), `AwsAdmin`, `AwsEvents` (SQS JSON protocol, queue policy, notification GET-merge-PUT), `R2Admin`, `R2Events` (Cloudflare REST), `B2Admin` (no events adapter), `S3Api`/`Xml`/`Internal` (merges, redaction), `Registry` (`adminFor`/`eventsFor`, `setFactoryForTesting` test-mode only) |
| Signing/HTTP | `vl::sigv4::sign` from vl-sigv4 (`subprojects/vl-sigv4.wrap`, any service/region; called in `provider/admin/Internal.cpp` `detail::send` and `Controller::signObjectRequest`; the in-tree `storage/s3/sigv4/Signer` is kept only as the goldens' reference until a verified release),  `storage/s3/curl/Http` (timeouts, size cap, `ScopedCancellation`, transport seam) |
| Identity + lock | `storage/upstream/{Identity,Guard}` — identity = (providerIdentity, account_ref, bucket); `guard::require` in `s3::Controller::recordRequest` and every bucket-scoped adapter call; set loaded at startup (`main.cpp wireStorage`, fail closed) |
| Control plane primitives | `storage/upstream/{Inventory,Lifecycle,Provisioner,Cleanup}`, models `storage/upstream/model/*`, queries `db/query/upstream/{Bucket,Audit,Binding,Channel,Subscription,Inbox,WriteIntent}` |
| Events | `sync/events/{Event (normalized + decoders), Ingest (message → inbox), Applier (inbox → index → scoped pass), Service (UpstreamEventService: pollers, sweeps), Subscriptions (state machine)}` |
| Sync | `sync::Controller::{runScoped, tryAcquirePass, releasePass}`, `sync/model/Scope.hpp`, `Cloud::{initScopedBins, loadRemovedKeys, setPendingRemovalsProvider, setEventHooks}`, Planner removal rule |
| Ops (only authorizing boundary) | `ops/Upstream{,Events,Json}.cpp`; `ops::vaults::create` `S3Spec::provision` |
| Surfaces | CLI `protocols/shell/commands/upstream.cpp` + `usage/src/usages/upstream.cpp`; ws `protocols/ws/handler/Upstream.cpp` + book `usage/src/contract/ws/upstream.cpp`; web `features/credentials/*` (admin panel, `/credentials/[id]/buckets`), `NewVaultPage`, `VaultSettings` events panel |
| RBAC | `rbac/permission/admin/Upstream.hpp`, `admin_role.upstream_permissions` BIT(8): view 0, configure 1, provision 2, protect 3, unprotect 4, destroy 5 |

## Invariants (keep them)

- opaque_v1 (#369): event keys are object keys. `.vaulthalla/` keys are skipped as before; a foreign key (neither
  `o/<uid>` nor `.vaulthalla/`) is never HEADed or indexed: skipped under `foreign_objects = ignore`, handed to a scoped
  pass that imports it once as `/Imported/<key>` under `import`; an `o/<uid>` object no file of the vault has is
  skipped as an orphan. Scoped passes resolve `/o/<uid>` to the file with that uid.

- Protection belongs to the bucket identity, never the key; unknown account ⇒ any lock on (provider, bucket) applies.
  Identity follows the endpoint host, not the key's provider label (`*.r2.cloudflarestorage.com` ⇒ cloudflare-r2,
  `*.amazonaws.com` ⇒ aws-s3, `s3.<region>.backblazeb2.com` ⇒ backblaze-b2; `providerIdentity(const APIKey&)`); keys
  whose label contradicts the endpoint are refused.
  Bucket names/regions are validated (`storage/upstream/Names`) before any request; Cloudflare REST segments are
  percent-encoded (no signature covers those paths).
  AWS HeadBucket (#247) goes straight to a known region: the adapter's cache, `AdminClient::setKnownRegion`
  (ops pass `upstream_bucket.region`: `ops::upstream` via `adminClient(key, id)`, `ops::recovery` policy), else the
  key's region; the global endpoint only when none is known (key region empty/`auto`) or a redirect names no region;
  an `x-amz-bucket-region` hint costs one more HEAD (≤ 3). Name validation and the guard still come first; a
  malformed hint or header is ignored, never routed to.
  Every protect/unprotect: `guard::reload()` + `subscriptions::invalidateCache()` + `onBucketProtected/Unprotected`.
- Create-new never takes over: HeadBucket 404 → CreateBucket (collision = Conflict) → must list empty by
  `listObjectVersions` (old versions and delete/hide markers count; R2 falls back to ListObjectsV2); compensation
  deletes only an empty bucket created by the same operation token. No rollback deletes a pre-existing bucket.
  The claim row is `unmanaged` + `provision_attempted` until `confirmCreated` (token-guarded) after a 2xx create and an
  empty listing; all ownership/state writes are token-guarded.
- Vault delete/detach never deletes upstream data; cleanup only for `managed` + `created_by_vaulthalla`, unbound, not
  protected, no live subscription; preflight token bound to identity + counts + actor (10 min), all checks repeated
  right before deleting; object lock enabled = blocker, unreadable = warning (provider refusals → `partial`).
  Cleanup holds its own lease (`deleting`, fresh token; busy for adoption/provision/detach), re-checked per round;
  a mid-run provider error leaves the row failed + resumable. `delete_upstream` is refused for adopted buckets.
- Lifecycle: only `vaulthalla-managed` is rebuilt from fields (detach removes every `vaulthalla-*` rule); every other rule round-trips raw and is re-verified;
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
- A pass publishes the manifest at most once (#248): a full LIST in `Cloud::initBins` only marks the index rebuilt
  (`CloudEngine::markRemoteIndexRebuilt`); the pass's `applyRemoteIndexMutation` then publishes it with the plan's
  changes (even with none), resolving a conflict by refreshing the ETag and overwriting, never by reloading the
  manifest over the listed index. A pass that stops first (failed ops, error, stall) publishes it in
  `Cloud::operator()` under the lease (`publishPendingRemoteIndexManifest`). A manifest reload or any publish clears
  the mark. A missing manifest is an expected HEAD 404 (debug log; `getHeadObject` logs only real failures as errors).
- Removal events delete a local copy only if unchanged since the baseline and a HEAD confirms 404 (a present object is
  re-indexed; a failed HEAD retries); mirror+keep_local re-uploads. The applier takes the lease before claiming rows
  and yields to a waiting regular pass. Write intents are removed on failure and match on ETag.
- An object without Vaulthalla metadata over an encrypted file is plaintext only if the vault doesn't encrypt
  upstream, or its active subscription has `foreign_objects=import`; otherwise it stays an authentication failure.
  `vh-encrypted=false` over a sealed file follows the same rule. Encrypting vaults default to `foreign_objects=ignore`
  (adopted buckets: `import`). Manual `vault sync events --file` needs configure + sync.config.edit + key Consume.
- `s3` bindings are upserted per vault (`ON CONFLICT (vault_id)`); a key+bucket pair of another vault is refused.
- `s3.storage_layout` (migration 122, #366; design/encryption/01 §4.6) is internal: `transparent` ⇔
  `encrypt_upstream=false`, `path_v0`/`opaque_v1` ⇔ `true` (`s3_storage_layout_check`). `Vault::upsertVault` resolves
  it (`resolveStorageLayout`), never a request; `opaque_v1` for every new encrypting vault since #371; an `opaque_v1`
  vault's encryption can't be turned off, and `encrypt_upstream` can't change while a layout migration copies.
  Existing path_v0 vaults move with `vh vault migrate-layout` (#373, architecture.md). `vault.uid` and
  `files.object_uid` are 16 libsodium bytes (`crypto::id::ObjectUid` = `vl::keykit::Uid`; base32 text by `vl::keykit::toBase32`), assigned once (immutable by trigger): new rows
  in `upsertVault`/`File::upsertFile` (a rewritten inode keeps its uid; copies clear it first), existing rows by the
  deployer data step for 122 (`SqlDeployer` `kMigrationDataSteps`). Nothing in the data plane reads them yet (#369).

## Bucket write capability (design/encryption/06-publish-without-preconditions.md §7, migration 136)

- **What:** `storage::s3::probeBucket` (`storage/s3/Capability.hpp`, `capability.cpp`) answers, on one key
  `.vaulthalla/probe/<uid>` (allowlisted under opaque_v1, `ObjectKeys`): PUT If-None-Match absent/present, If-Match
  wrong/right; versions newest first and readable by id; GET If-Match wrong/right; then deletes every version it wrote
  by id (`leftover_versions` counts refusals). Verdict (`vl::vaultfmt::manifest::WriteCapability`, `<vl/vaultfmt/manifest/WriteCapability.hpp>`:
  the enum, `to_string`, `publishModeFromString` and `sendsPreconditions` live with the manifest, which the probe includes): `Conditional` (conditions honoured; versions
  not needed: R2 has none), `VersionLog` (rejected with 501/400 NotImplemented, or silently ignored, and versions
  kept), `Insufficient` (neither, or GET If-Match not honoured), `Unknown` (never probed: behaves as Conditional).
- **Where it's stored:** `s3.manifest_publish` (`conditional|version_log`, NULL) + `s3.bucket_probe` JSONB (the
  result; `changed_at`/`changed_detail` once a conditional bucket refuses a condition). `db::query::vault::
  BucketCapability`. The `upsert_s3_vault` statement nulls both when the bucket or key changes; `ops::api_keys::update`
  clears them for every vault of a key whose provider or endpoint changed.
- **When it's probed** (`storage::bucket_capability`, `storage/BucketCapability.hpp`): `ops::vaults::create` (before
  `addVault`: an encrypting = opaque_v1 vault is refused with `ops::Refused` `bucket_capability_insufficient` on an
  Insufficient bucket only), `ops::vaults::update` on a bucket/key change (same refusal), `ops::vault_recover` after
  the write (never refuses: a rescue path), `ops::vault_layout::start` (fresh probe; refuses an Insufficient bucket,
  spec 01 §6.1 step 5), `ops::vault_remote::attach` (a local vault attaching the bucket: `s3::probeBucket` through the
  attach's own controller, the verdict kept on `vault_remote_attach` and copied to the `s3` row by the cutover; refuses
  an Insufficient bucket; `vault.remote.detach` reverses it and only unbinds the `upstream_bucket` row, never touching
  the bucket), `vh vault storage probe`, and lazily on first use for rows from
  before 136 (`resolve`, at most one failed attempt per vault an hour). **Test mode never probes on its own**
  (`setLazyProbingForTesting`, `setControllerFactoryForTesting`): existing suites see Unknown and unchanged requests.
- **What it changes:** `vl::vaultfmt::manifest::ObjectStore::mode()` / `putOnce` (If-None-Match only where
  `sendsPreconditions`), `storage::s3::ManifestStore(controller, mode)`; segments, snapshots, the layout hint and KEV1 envelopes go through
  `putOnce`; the `path_v0` index-v1 is PUT plainly on a non-conditional bucket. On VersionLog the manifest root is
  published as provider versions (spec 06 §5; architecture.md "version_log publish"). `manifest::publish` throws
  `PublishUnsupported` **before any request** on Insufficient only, which `CloudEngine::publishManifestV2` turns into
  `SyncStalled("manifest_publish_unsupported: …")`; health lists those opaque_v1 vaults and any with a changed
  conditional bucket (`vaults_manifest_unpublishable`, reasons `bucket_capability_insufficient` /
  `bucket_capability_changed`, degraded; `vh status`).
- **Never silently downgraded:** a 501/400 NotImplemented on a conditional PUT is `s3::PreconditionsUnsupported`
  (`buffer.cpp`; manifest-level `ConditionsUnsupported`), never retried without the condition. Stored Conditional:
  `noteChanged` marks `changed_at`, alerts once (`bucket_capability_changed`, operator notification), and
  `CloudEngine::writeCapability()` stalls every later use until a re-probe. Unknown: logged, the next use probes.

## Backblaze B2 (bucket administration only)

- **Adapter:** `B2Admin` (`provider/admin/B2Admin.cpp`) over B2's S3-compatible API, for a key labelled
  `S3Provider::BackblazeB2` whose endpoint is `https://s3.<region>.backblazeb2.com` (`admin::b2EndpointRegion`; the
  request host is rebuilt from that region, SigV4 is signed for it). `admin::supportsAdmin` /
  `adminUnsupportedReason` are the gate (a B2 label over another endpoint, or another label over a B2 endpoint, is
  not administrative; neither is any key managed storage issued, `origin = 'cloud'`).
- **What it calls** (Backblaze's documented "supported calls"): ListBuckets (no paging: `pagedListBuckets() == false`),
  HeadBucket, CreateBucket (`x-amz-acl: private`, `LocationConstraint` = the endpoint's region), DeleteBucket,
  GetBucketVersioning, Get Object Lock Configuration, ListObjectsV2, ListObjectVersions, DeleteObjects.
- **What it never calls**, because that API has no such operation (lifecycle rules: "available only through the
  Backblaze web console and the Native API"; event notifications: native only): `supportsLifecycle() == false`,
  `inspect` answers `lifecycle_readable = notifications_readable = false` with one warning, `putLifecycle` and
  `putVersioning(Suspended)` throw `CapabilityMissing` after the name and guard checks with nothing sent,
  `putVersioning(Enabled)` only reads (B2 buckets are always versioned), and `probe()` lists `lifecycle`,
  `versioning`, `events.queues` and `events.notifications` as `ok = false, probed = true`
  (`kB2LifecycleUnsupported` / `kB2VersioningFixed` / `kB2EventsUnsupported`). `admin::supportsEvents` (AWS, R2)
  gates event-driven sync in `ops::upstream` (`supportGap`, `beginProvision`) and `sync::events::subscriptions`.
  Provider versioning as a recovery mode stays AWS only (`polProviderGap` in `ops/RecoveryPolicy.cpp`).
- **Ops** (`ops/Upstream.cpp`): `lifecycleGap(key)` refuses `setLifecycle` and a provisioning `lifecycle` before any
  request, skips the lifecycle step of `detach`, and empties `supported_lifecycle_fields`; `requireValidRegion` /
  `defaultRegion` allow only the key's own region (an account lives in one); `identityOf` applies B2's name rules.
- **Names** (`storage/upstream/Names`): `validB2BucketName` = the S3 rules + at least 6 characters + no `b2-`
  prefix; `validBucketNameFor(providerIdentity, …)` picks the rules, used by `S3ApiAdmin::requireBucket`,
  `provision::createManaged` and `identityOf`. B2 names are unique across every B2 account.
- **Identity:** `(backblaze-b2, s3.<region>.backblazeb2.com, bucket)`. The account part is the region endpoint host,
  which is what plain B2 vaults and managed (cloud) buckets were already recorded with: names are global on B2, so
  the host is enough, and no network call or re-keying is needed. Two B2 accounts in one region therefore share an
  inventory scope (`listForAccount`): a bucket Vaulthalla knows from one shows as "not listed" under the other's key.
  Migration 153 renames `upstream_bucket.provider` from `s3:backblaze-b2` (and other `s3:*` labels over a B2 host),
  one row per bucket (`s3:backblaze-b2` first, else `DISTINCT ON`: vault-bound, then managed/adopted, then lowest id;
  the rest stay under their old label), carrying a lock over from any row left behind; `upstream_audit` keeps what it
  recorded.
- **A taken name:** `provision::createManaged` reports a HeadBucket 403 without a region, and a CreateBucket
  `BucketAlreadyExists`, as "already taken … choose another name" (`ops::Conflict`); `BucketAlreadyOwnedByYou` still
  says "adopt it instead". Applies to AWS too.
- **Web:** `models/upstream.ts` `supportsAdmin` / `adminFeatures(provider)`; `BucketProvisionFields` hides region,
  lifecycle and events for B2 and applies the 6-character / `b2-` rule; `provisionPayload(values, accepted,
  provider)` never sends what core would refuse; the buckets page hides the lifecycle action.

## S3 gateway upstream profiles (migration 154, built 2026-11-23)

What a gateway `CreateBucket` creates. Decided with Cooper 2026-11-23: per gateway credential; an existing bucket is
adopted only while empty; an optional name prefix, a taken name fails (409); a server default credentials opt into;
per-request selection by region; re-apply of sync settings optional (server setting, per-credential override);
setter-and-principal permissions; a per-credential allowlist of the profiles a request may select (approved the same
day through the Sentinel session: "Yes I like your idea of an allowlist"). Operator docs: `docs/s3-gateway/buckets.md` "Upstream Profiles".

- **Model:** `s3_gateway_upstream_profile` (name, api_key_id ON DELETE RESTRICT, encrypt_upstream, sync_strategy,
  conflict_policy, bucket_prefix). `s3_gateway_credentials.upstream_profile_id` / `upstream_server_default` (CHECK:
  never both) / `upstream_reapply` (NULL = server). `s3_gateway_bucket.created_by_credential_id` /
  `upstream_profile_id` (set only by a profile CreateBucket; a bucket follows the profile it was created from).
  `s3_gateway_credential_upstream_profile` (credential_id, profile_id; profile ON DELETE RESTRICT): the allowlist.
  Config: `s3_gateway.default_upstream_profile` (validated in `ops::config::validateSettings`),
  `s3_gateway.reapply_upstream_profile_changes` (default true).
- **Names:** a profile name is region-shaped (1-32 `[a-z0-9-]`), immutable, never `local`, `server-default` or
  anything `validAwsRegion` / `validB2Region` / `validR2LocationHint` accepts: clients send it as
  `LocationConstraint` or sign with it, and a real region must never select a profile.
- **Selection** (`ops::s3_gateway::profileForCreate`, trusted): `LocationConstraint` naming a profile (`local` forces a
  local vault, anything else is ignored) → the SigV4 scope region (`AuthContext::signing_region`) → the credential's
  profile → the server default if the credential opted in → local. A profile the request names must be the
  credential's effective profile or on its allowlist (`CredentialUpstream::allowed`), else Denied (403), never local;
  an unsigned dev-mode request (credential id 0) is not bounded. A credential that asks for a profile that isn't
  there (deleted default) throws Invalid: never silently local.
- **Create** (`createProfileBucket`, actor = the credential's principal): `ops::vaults::create` with
  `upstream::BucketMode::CreateOrAdoptEmpty` (no surface spells it; `bucketModeFromString` doesn't accept it).
  `beginProvision` runs `provision::createManaged`; on `provision::BucketExists` (this account's bucket, or a row
  Vaulthalla already knows; a name another account holds stays a plain `ProvisionConflict`) it adopts only if
  `provision::listsEmpty`, else Conflict. `ops::vaults::create` refuses again if the data plane sees objects
  (`bucketHoldsData`; skipped in test mode). The ticket's `mode` is what happened (Create or Adopt). Vault name =
  gateway bucket, upstream bucket = `<prefix><name>`, bound `remote_cache`, `api_exclusive` =
  `s3_gateway.default_api_exclusive`, `max_remote_index_age` 24 h and budget preset `balanced` as create-remote-cache.
- **Why "only while empty":** `mirror` + `keep_local` deletes remote objects the vault doesn't hold
  (`RemotePolicy::deleteRemoteLeftovers`). Residual race: objects written between the emptiness check and the vault's
  first pass; nothing closes it.
- **S3 errors** (`ObjectStore::createBucket`): Conflict → 409 `BucketAlreadyExists`, Denied → 403 `AccessDenied`,
  NeedsConfirmation → 409 `OperationAborted`, other `ops::Error` → 400 `InvalidArgument`, `padmin::ProviderError` →
  503 `ServiceUnavailable`. `Router` parses the body only for a plain `PUT /bucket` (no query): spooled
  (`payload.file`) or buffered, ≤ 64 KiB, malformed → 400 `MalformedXML`.
- **Permissions:** profile CRUD = `manage_buckets` + `upstream::requireProvisioner` (provision + key Consume + the key
  can administer). `setCredentialUpstream` = credential visibility + `requireActFor` + `requireProvisioner` for the
  actor and (as Invalid) for the principal, for its own profile and for every profile newly added to the allowlist
  (keeping or dropping one is no grant); `local`, `reapply` and shortening the allowlist need only the credential. Step-up family secrets.
  At request time the principal passes the existing gateway checks (admin, not vault_allowlist, manage_buckets) and
  everything `ops::vaults::create` checks (vault Create, key Consume, provision).
- **Re-apply:** `updateUpstreamProfile`, when strategy or conflict policy changed: every `listBucketsOfProfile` row
  whose credential's `upstream_reapply` (else the server setting; also for a credential that is gone) is on gets
  `ops::vaults::updateSync` as the actor; refusals are per bucket (`ReappliedBucket`), never an abort. Key,
  encryption and prefix are never re-applied.
- **Deletes:** a profile is refused while a credential or the server default names it; `ops::api_keys::remove` refuses
  a key a profile uses.
- **Surfaces:** CLI `vh s3-gateway upstream list|show|create|update|delete`, `creds scope <c> set --upstream
  <profile>|server-default|local --reapply on|off|inherit --allow-upstream <profile>|none`; ws `s3.gateway.upstreamProfiles.*`,
  `s3.gateway.credentials.upstream.set`; JSON shapes `S3GatewayJson::{upstreamProfile,credentialUpstream}` used by
  both; web `features/gateway/{UpstreamProfilesTab,UpstreamProfileDialog}.tsx` and `UpstreamEditor` in
  `CredentialSheet.tsx`.
- **Tests:** `GatewayUpstreamTest.*` (`test_s3_gateway_upstream.cpp`, db-only, fake provider account),
  `SqlDeployerHistoryDb.S3GatewayUpstreamProfilesMigration154…`, `ContractModels` (profile + credential upstream).
- **Not built:** a hostname per profile (`vl-b2.s3.example.com`), and a live Backblaze run of the gateway flow (the adapter itself is live-tested, see below).

## Provider facts (verified live 2026-10-15)

- Backblaze B2 bucket administration over the S3-compatible API (2026-11-23, us-west-004, account-wide test key,
  `LiveB2.TheAdminAdapterAdministersTheRunBucket` on the Mac): CreateBucket with `x-amz-acl: private` and
  `<LocationConstraint>us-west-004</LocationConstraint>` → 200 and the bucket shows in `b2_list_buckets`; the same
  name again → `409 BucketAlreadyOwnedByYou`; ListBuckets (no paging parameters) lists it; HeadBucket 200 for it and
  404 for a free name; GetBucketVersioning → `Enabled` on a fresh bucket; Get Object Lock Configuration is readable
  and says not enabled (`object_lock = false`, no warning); ListObjectVersions returns both versions of a key PUT
  twice, one `IsLatest`, each with a version id. Not exercised live: a name held by ANOTHER account (HeadBucket
  403/404 and CreateBucket `BucketAlreadyExists` are handled, from the docs and the fake), DeleteBucket through the
  adapter (the helper deletes natively), a bucket-restricted key.
- Backblaze B2 (2026-11-12, `s3.us-west-004.backblazeb2.com`, coordinator's probe): PutObject with `If-None-Match: *`
  or `If-Match` → `501 NotImplemented`, nothing written. Versions always on: every PUT returns `x-amz-version-id`;
  ListObjectVersions newest first with id/ETag/IsLatest, pages with max-keys; GET/DELETE by version id; deleting the
  newest makes the previous current; delete by name = a delete marker; single-PUT ETag = MD5; GET If-Match and
  `x-amz-copy-source-if-match` honoured (412/200). Listings read-after-write and concurrent ordering held in the
  trials of spec 06 §4; a stalled-body PUT got 500 (the publisher treats a 5xx on the root PUT as an unknown
  outcome and looks for its version by hash), lifecycle prefix rules unverified. Live suite `LiveB2.*`
  (testing.md): passes live, 2026-11-14.

- AWS test identity `vaulthalla-test-admin`: S3 admin works; **no SQS permissions** and no
  `s3:GetBucketObjectLockConfiguration` → AWS event delivery untested live. Needed statement: docs/vaults/upstream-buckets.md.
- R2 credentials (2026-10-22): the repo `.bashrc` holds one R2 admin S3 pair (`VH_R2_ADMIN_*`) and a Cloudflare API
  token (`VH_CF_API_TOKEN`, Queues: Edit + Workers R2 Storage: Edit) stored as the key's provider token for events; the
  account id comes from the endpoint host.
- R2 events, verified live 2026-10-22 (`LiveR2.EventNotificationsOnTheRunBucket`, Mac and dev), and fixed where they
  broke Vaulthalla: the bucket's notification configuration names the queue by an id spelled unlike the Queues API's
  `queue_id`, so `R2Events` matches our rules by that id with dashes/case ignored or by queue name (before the fix,
  every subscribe failed with "R2 accepted the event rule … but does not list it"); a just-created queue can answer
  404 on its consumers lookup for a few seconds (`ensureChannel` waits for a queue it created); a pull right after
  the http_pull consumer is added can answer 405 "http_pull mode not enabled", and Cloudflare answers the odd 504
  7009 (the poller retries both); a new rule takes effect a little after it is listed (the first upload may produce
  no event); R2 refuses DeleteBucket while the bucket has notification rules (409) and deleting a queue a rule
  targets (400 11017); the Queues listing lags behind creates and deletes. R2 accepts any SigV4 region (`auto`, `wnam`, `us-east-1`). New R2 buckets carry a default
  "Default Multipart Abort Rule" (foreign). Collisions: 409 `BucketAlreadyOwnedByYou` on both providers.
- Live tests (2026-10-22, testing.md "Live provider tests"): opt-in (`VH_LIVE_TESTS=1`), R2 only, through
  `tests/helpers/live_bucket.hpp`. Two rules: every bucket a test creates is `vh-test-<host>-<pid>-<run start>` and the
  helper refuses every other bucket/queue name; every such bucket is emptied, deleted and checked gone after the run
  (orphans of that pattern older than 6 h are swept). One bucket per run: the real `R2Admin` create/collision/delete
  path plus a small data-plane suite and an R2 event-notification test (needs `VH_CF_API_TOKEN`). The facts above from
  2026-10-15/16 came from the earlier, since-consolidated `UpstreamLive.*` / `test_recovery_live.cpp` suites and stay
  covered by the transport-seam and fake suites.
- Provider versioning (file recovery, `AdminClient::{supportsVersioning,versioning,putVersioning}`; verified live
  2026-10-16 by the since-removed `UpstreamLive.AwsVersioning`): PutBucketVersioning carries Content-MD5 (AWS requires an integrity
  header) and `x-amz-expected-bucket-owner` when the account is known, Status only — never MfaDelete/`x-amz-mfa`.
  The test identity has Get/PutBucketVersioning + ListBucketVersions; Enabled and Suspended read back on the first
  GET (~130 ms), but AWS still asks for 15 min before relying on versioned writes. R2 has no versioning:
  `versioning()` = Unversioned without a request, `putVersioning` = `CapabilityMissing("versioning")`, nothing sent.
  Existing noncurrent retention (ours + foreign, incl. NewerNoncurrentVersions): `storage/upstream/Lifecycle`
  `noncurrentExpirations` / `coverage` / `effectiveNoncurrentDays`.

## Tests

DB-free: `SigV4Goldens.*` (incl. `VlSigv4*`: vl-sigv4 against the upstream, SES, gateway and legacy data-path goldens), `S3DataPathWire.*`, `UpstreamProvider*` (`UpstreamProviderTest.B2*`: the B2 adapter over the transport seam), `UpstreamEventDecode*`, `UpstreamPassLease*`, `ShellLogRedaction*`.
Live (opt-in, one `vh-test-*` bucket per run): `LiveR2.*`, `LiveB2.*` (`TheAdminAdapterAdministersTheRunBucket`: the
real `B2Admin`, which also creates the run bucket); guard self-tests `LiveBucketGuard.*`, `LiveB2Guard.*` (testing.md).
B2 ops (DB-backed, fake account): `UpstreamOpsTest.ABackblazeB2*`, `OnlyABackblazeEndpoint…`,
`ANameAnotherAccountHolds…`; migration: `SqlDeployerHistoryDb.BackblazeIdentityMigration153…`.
DB-backed (`bin/tests/run_unit.sh`): `UpstreamStore*`, `UpstreamOps*`, `UpstreamEventOps*`, `UpstreamEvents*`,
`UpstreamSubscriptions*`, `UpstreamScopedSync*`, `UpstreamParity*`, `SqlDeployerHistoryDb.*` (migration 110),
`RoleParity*` (upstream bits). Fakes: `tests/helpers/upstream_admin_fakes.hpp`, `upstream_event_fakes.hpp`.

## Open items

- Live AWS SQS and R2 Queues delivery: blocked on the IAM policy and a Cloudflare token (see above).
- A shared channel is polled with the key of the most recent subscriber; that key can't be removed/demoted while any
  subscription on the channel is live.
- Cleanup of very large buckets runs in rounds (60 s / 50k objects per call); no background job yet.
- R2 queue retention isn't set (Cloudflare's default applies).
