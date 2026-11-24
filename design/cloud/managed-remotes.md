# Vaulthalla Cloud managed remotes: the server's side (wave 1)

How a linked server gets Backblaze storage from vaulthalla.cloud for its vaults, keeps it working through billing
states, and leaves it in place on ejection: the local data model, the provisioning flow and its hook, a background
cloud service, the per-vault switch, credentials, retention, restores, ejection, unlinking and the surfaces. The
cloud's side is `managed-storage.md` and `billing.md` (vaulthalla-cloud `docs/design/`); the account key is
`design/cloud/key-manager.md`; converting a vault is `design/storage/attach-remote.md`; buckets without conditional
PUT are `design/encryption/06-publish-without-preconditions.md`; Desktop is its `docs/cloud-storage.md`. Nothing here
is built.

## Decided

**Cooper, 2026-11-12 (plan section 3.1):** one bucket per vault (one member account per cloud account and region, one
key per server and bucket); the server is the hub, holds the vault keys and encrypts; vaulthalla.cloud is the
preferred key manager, included and automatic for managed storage; existing local vaults must be upgradable to a
synced remote.

**Given as decided in the brief, and in the plan's target design (sections 4.2, 4.4, 4.8) rather than section 3.1:**
remotes provisioned automatically for every vault of a linked server whose account has a storage entitlement, on by
default, with a per-vault switch; `cache` as the default strategy; a simpler storage pane than BYOS; ejection converts
managed vaults to plain BYOS in place with no data movement; the server talks to Backblaze directly and the cloud is
never in the data path. Everything else is a proposal.

## Today

- **Link.** `cloud_link` is one row (`pending` or `linked`, installation and account ids; migration 134); the
  identity key is sealed to the host (slot `cloud_identity`). `cloud::Client::signedCall` signs VHC1-Ed25519 requests.
  `ops::cloud` (link, status, unlink) is super admin only and refuses agents (`ops/Cloud.cpp:27-29`);
  `ops::cloud_recovery` also admits the encryption-key View and Export permissions (`ops/CloudRecovery.cpp:35-42`).
  No ws command, web surface, RBAC module or background poller exists for the cloud.
- **Keys.** `api_keys` rows (the secret sealed under `ak_master`; migrations 020, 110, 124) belong to a user;
  `ops::api_keys::update` edits one in place, re-probes it, asks a `secrets` step-up and rebuilds bound engines.
- **Backblaze** is `S3Provider::BackblazeB2`, a `GenericProfile` (`storage/s3/provider/Registry.cpp:15`). When this
  was written it had no admin adapter; since 2026-11-23 customer B2 keys have one for bucket administration
  (`provider/admin/B2Admin`), which a key issued by managed storage (`origin = 'cloud'`) never gets
  (`admin::supportsAdmin`). **The probe** (`storage/s3/validate.cpp`) checks the key's format (20-128 of `[A-Za-z0-9/+=]`,
  which B2 ids and secrets satisfy) and calls ListBuckets; success, or `AccessDenied` without a signature error,
  passes, so a bucket-limited key should pass either way (Phase 2 confirms). `isBucketEmpty` lists the bucket.
- **Creation paths:** `ops::vaults::create` (CLI, ws, gateway remote-cache buckets), `Manager::initUserStorage`, the
  gateway's CreateBucket (`protocols/s3/ObjectStore.cpp:333`), the seed's admin vault (`seed/src/seed_db.cpp:482`,
  a direct `upsertVault`), and `vh vault recover` (`Recover::apply`, then `reinstateVault`).
- **Retention.** Provider history is governed by `vault_recovery_policy.mode = 'provider_versioning'` and
  `upstream_bucket.noncurrent_retention_mode|days` (migration 111), set through the disclosure flow and applied on AWS
  as the owned `vaulthalla-managed` rule (`NoncurrentDays`). B2 has no adapter, so no rule is set there today.
- **Naming.** `upstream_bucket.ownership = 'managed'` already means a bucket Vaulthalla created; the marker here is
  `cloud`. **Metering:** `vault_upstream_usage_daily`, `remote_object_index.size_bytes`.

## Data model (the next free migration)

Landing order set for the series: spec 06's probe columns, `attach-remote.md`, `key-manager.md`'s pin tables, then
this. Numbers are taken when each lands.

| Change | Holds |
|---|---|
| `api_keys.origin` `customer` \| `cloud`, default `customer`; `api_keys.cloud_access` `full` \| `read_delete`, set exactly when `origin = 'cloud'` | which keys the cloud issued and what they may do |
| `vault_cloud_storage` (`vault_id` PK, `vault_uid`) | `switch` (`on`, `off`, `offered`, `declined`), `switch_by`, `switch_at`, `state` (below), `bucket`, `s3_endpoint`, `region`, `api_key_id`, `key_state` (`none`, `issued`, `active`, `superseded`), `access` (`full`, `read_only`, `none`), `retention_sent` (the value last acknowledged), `attempts`, `next_attempt_at`, `last_error`, `registered_at`, `ready_at`, `ejected_at` |
| `cloud_storage_account` (singleton, deleted with the link) | the cached entitlement: `state`, `quota_bytes`, `used_bytes`, `usage_day`, `state_since`, `next_transition_at`, `fetched_at`, `fetch_error`; `new_vaults` (on by default), `enabled_at` (storage first seen entitled on this link), `offer_open` |
| `admin_role.cloud_permissions` BIT(8) | the RBAC module below |

Per-vault `state`: `unregistered` → `registered` → `waiting` (bucket not ready, payment required,
`account_key_unconfirmed`) → `keyed` → `attaching` → `active`; and `detaching` → `off`, `moved`, `ejected`,
`failed`. BYOS S3 vaults get no row; the pane lists them as using their own storage.

## The cloud storage service

`CloudStorageService`, a runtime service (after `LayoutMigrationService` in `runtime/Manager.cpp`, its own thread),
idle while unlinked. Every `cloud.storage.poll_minutes` (default 15), when woken, and every 15 s for five minutes
after a billing handoff, it calls `GET /v1/storage` and `GET /v1/billing`, writes `cloud_storage_account`, then
advances each vault's row one step. It also hosts `key-manager.md`'s account-key check and enrollment retries. No
FUSE, sync or ws path calls the cloud: handlers read the cached rows and record intents the service carries out. A
`403` from Backblaze on a cloud key makes the sync pass wake the service instead of retrying.

## Provisioning a new vault

Proposed (open questions 2 and 3, because they change what "default on" means in practice): a new vault is created
as today and attached once its bucket exists, and an empty vault is registered only once it holds its first file.
Creation never waits on the cloud: provisioning is asynchronous there (`409` until ready), and a vault must work with
the cloud down.

1. **Row.** The sweep finds a vault without a row: local and created after `enabled_at` with `new_vaults` on →
   switch `on`; created before → `offered`.
2. **Register.** `POST /v1/vaults {vault_uid, origin_vault_id}` (`account-model.md`); `409` (another deployment holds
   it) → `failed`. Registration starts provisioning at the cloud, so only switched-on vaults are registered.
3. **Wait** on `GET /v1/storage` for the bucket; `402 payment_required` or `account_key_unconfirmed` keep it
   `waiting` with the reason shown.
4. **Credential.** An X25519 pair in memory; `POST /v1/storage/vaults/{uid}/credentials {public_key}`; open
   `sealed_secret` as `managed-storage.md` ("Credentials") specifies; `APIKeyManager::addAPIKey` (provider
   `BackblazeB2`, the returned endpoint and region, access key = `key_id`, `origin = 'cloud'`, owned by the vault's
   owner); wipe secret and private key; probe (`validateAPICredentials`, a bucket listing); `POST
   /v1/storage/credentials/{key_id}/ack`.
5. **Attach.** `ops::vault_remote::attach` with origin `cloud`. Its `preparing` runs spec 06's capability probe and
   records the publish mode (`version_log` expected on B2), which the cutover writes to `s3.manifest_publish`; the
   account-key grant is added (`key-manager.md`). Result: an `opaque_v1` vault in `cache`, encrypted on the host.
6. **Retention and enrollment.** Send the retention (below); then `ops::cloud_recovery::enrollAutomatic`.

Each step reads the recorded state first, so a retry resumes. A lost credential response is never replayed: a new
key pair is used, and the cloud revokes the unacknowledged key. A crash between `addAPIKey` and the ack acknowledges
on restart or, if the cloud already revoked the key, deletes the row and asks again.

**Backblaze depends on spec 06:** its work items 2 (Store seam), 3 (probe and columns), 4 (plain PUTs for envelopes,
hint and segments) and 5 (`version_log` with `writers`). Until 5 lands, no managed vault can publish on B2.

**The hook is a sweep, not a call site.** Every creation path, the seed and `Recover::apply` included, produces a
`vault` row, and the sweep over `vault` is the guarantee; `Manager::addVault` and `reinstateVault` only call a
non-blocking `wake()`. A recovered vault on a cloud key gets its row as `active`.

**Existing local vaults** take the same path from step 2. When storage first becomes entitled on a link, every local
vault is `offered`; the console, Desktop and `vh cloud storage status` show one confirmation listing them with sizes.
Nothing is uploaded until a person accepts (all or some) (open question 1).

## The per-vault switch

- **Off:** before a bucket exists, `PUT /v1/storage/vaults/{uid} {enabled:false}`. With one, `vault.remote.detach`
  (`attach-remote.md`, "The reverse") hydrates, verifies and makes the vault local; then `POST .../{uid}/detached`,
  the `PUT`, and the key row is deleted. Deleting the bucket stays the account holder's step in the portal.
- **On:** the `PUT` with `enabled: true`, then step 3; a kept bucket is re-attached (attach-remote, question 6).
- **No step-up.** It adds no decryption path (the account key's pin was the one confirmation) and the bucket is the
  account's, so a person on a paired device's session can use it with the RBAC below.

## Noncurrent retention (the lifecycle rule)

The cloud no longer sets "current versions only" and never expires anything under `.vaulthalla/` (spec 06 §5.4, A6).
Retention of noncurrent content versions is the vault's own setting, applied by the cloud as a rule on `o/` only.
For a managed vault the server records `vault_recovery_policy.mode = 'provider_versioning'` and
`upstream_bucket.versioning_status = 'enabled'` at cutover (B2 always versions), and the retention in
`upstream_bucket.noncurrent_retention_mode|days` as for AWS. It sends `PUT /v1/storage/vaults/{uid}/retention
{noncurrent_days | "indefinite"}` (a route for the cloud to add) after the attach and on every change through the
existing recovery-policy operations, which keep their shortening confirmation (`accept_retention_shortening`).
`retention_sent` makes it idempotent; status shows "retention pending" until the cloud acknowledges. The default for a
new managed vault is a configuration value (open question 11). Quota counts every stored version.

## Credentials and restores

- **Rotation** (`vh cloud storage rotate`, or `superseded`): a new key as in step 4, probed, written into the same
  `api_keys` row (the `ops::api_keys::update` path without its user-facing checks), `reloadEngine`, then the ack.
- **Revocation** (installation revoked, `suspended`) shows as `key_state: none`: `access = none`, status says why.
- **A restore moves the vault.** Approving a restore onto another deployment removes this deployment's replica and
  revokes its credential (the cloud's account model, wave 1; two writers on one bucket wait for mirrors). The old
  server sees the vault leave `GET /v1/storage` or Backblaze refuse its key: the row becomes `moved`, `access =
  none`, the vault's sync stops, its local data stays untouched and readable, and the admin is told (health
  `vault_cloud_moved`, audit, the pane: "moved to *server*; this copy no longer syncs") with two ways on: keep it as
  a local vault (detach without hydration, listing remote-only files) or delete it. **Spec 06's `writers` rule is the
  second line of defence:** the restored root names only the new node (§5.5), so an old node whose key still works
  stops publishing (`manifest_superseded`) instead of merging.
- **Users can't edit or remove cloud keys:** `ops::api_keys::{update,remove}` refuse `origin = 'cloud'` (Conflict).

## Entitlement states and the `access` gate

**New server work:** there is no read-only remote mode today. The gate is `vault_cloud_storage.access`, set by the
service and read by the sync pass, the upload and delete paths, the manifest publisher and hydrate (work item 4).
*Built (work item 4):* the gate lives in its own table `vault_remote_access` (migration 140), not in
`vault_cloud_storage`, so BYOS vaults have it too and the cloud migration needn't own it; the service sets it with
`storage::remote_access::set(vault, mode, cause, "system:cloud")` (`storage/RemoteAccess.hpp`); values `full`,
`read_only`, `none`; operators also have `vh vault remote access`.

| State (`billing.md`) | Key | Server does | Shows |
|---|---|---|---|
| `active` | `full` | everything | usage against quota |
| `past_due` | `full` | everything | payment overdue, full access until `next_transition_at`; billing |
| `restricted` (or over quota) | `read_delete` | `read_only`: no PUT, DELETE or manifest publish; reads and hydrate work; local writes kept, uploaded on return to `active`; rotations wait | read-only and why, local changes kept, the next date, ejection |
| `suspended` | revoked | `none`: no remote requests; local copies work; a remote-only file fails with `remote_unavailable` | suspended, data kept until a date, ejection |
| `ended` | buckets deleted | converts to local in place, remote-only files listed as lost (open question 5) | ended |

The gate prevents failures instead of retrying them: the pass records `skipped: remote read-only` in `sync_event`;
health reports `vault_remote_restricted` or `vault_remote_unavailable` (degraded). Deletes pause too, because the
manifest that would drop them cannot be published. **An unreachable cloud** changes nothing: cached state and keys
stay, intents wait, status says "last confirmed at". **Quota:** the pane shows the cloud's figure (as of a day)
against the quota and this server's own (`remote_object_index`), labelled; the cloud enforces through the key.

## Ejection and unlinking

The customer asks in the portal; the console's "Leave managed storage" opens the portal page at an address `GET
/v1/storage` returns. Seeing it there, per cloud vault in one transaction: `api_keys.origin = 'customer'`,
`cloud_access = NULL`, the row `ejected`, `access = full`, audit. Credentials and engine stay, so no reload and no data
movement; then `POST .../{uid}/ejected`. The key is then ordinary BYOS: `ops::api_keys::update` replaces it with one
from the customer's own account. **Unlink** (`ops::cloud::unlink`) refuses while any vault is registered and not
`off`, `moved` or `ejected`, naming the ways out; `--force` unlinks and says the cloud revokes this installation's
keys. A server linked again to the same deployment requests fresh keys: keys belong to an installation.

## Surfaces

| Surface | Contract |
|---|---|
| `ops::cloud_storage` | `status`, `setSwitch`, `acceptOffer`, `declineOffer`, `rotate`, `setNewVaultsDefault`, `billingHandoff(kind)`, `linkStatus` |
| CLI | `vh cloud storage status [--json]`, `enable <vault>`, `disable <vault> --confirm <name>`, `accept [<vault>…\|--all]`, `decline`, `rotate <vault>`, `new-vaults on\|off`, `billing [checkout\|portal]` (prints the URL) |
| ws | `cloud.storage.status`, `.switch`, `.offer.accept`, `.offer.decline`, `.rotate`, `.new_vaults`, `.billing.handoff`; `cloud.link.status`; models `CloudStorageStatus`, `CloudStorageVault`, `CloudLinkStatus` |
| RBAC | admin module `cloud` (`rbac/permission/admin/Cloud.hpp`): `view` 0, `storage` 1 (switches, offers, rotation, the default), `billing` 2. A switch also needs the vault's Edit. Link and unlink stay super admin; recovery keeps its rules |
| MCP | excluded: `cloud storage enable`, `disable`, `accept`, `decline`, `rotate`, `new-vaults`, `billing` (a person decides where a vault is stored and what the account pays; `billing` opens a browser). `status` is available |

**Billing** opens in a browser: `POST /v1/billing/handoffs {kind}` returns the portal URL, printed or opened, then the
service polls fast. Nothing of it is stored; the call runs on the handler's worker with a 10 s bound.

## What Desktop needs from the server

- **`vault_uid` on `Vault`** (`storage.vault.list`, `storage.vault.accessible.list`, `storage.vault.get`), for any
  user who can see the vault. Today it is only in key-status and recovery models. Acceptable: an identifier, not a
  secret, already in recovery kits, the bucket's cleartext layout hint and every VHF1 header, and giving no access.
- **`cloud.link.status`:** linked or not, installation id, deployment id, account public id, the pinned account-key
  fingerprint and generation (`key-manager.md`), relay state later (null now). Identifiers and public values only:
  `admin.cloud.view` or super admin; any other session sees `linked` alone.
- **Paired-device use.** The switch needs no step-up. Attach (BYOS) and "add the account key"
  (`vault.keys.recipients.add {account_key: true}`) need `keys`, which a device session answers today with its
  approval key or a console approval (#361; `attach-remote.md`, Surfaces). Bucket deletion stays in the portal.
- **Progress:** `vault.remote.status` `progress` for attach and detach; `CloudStorageVault` adds `pending_upload_bytes`
  and `pending_files` (the backlog and files newer than their baseline) and the running pass's throughput.
- **Read-only credentials:** the `APIKey` model gains `origin` (`customer` | `cloud`) and `editable` (false while
  `cloud`), so Desktop's Credentials view and the console show them read-only from the contract.
- **Capabilities, one list:** `cloud.account_key` (`key-manager.md`) and `cloud.storage.managed_remotes` (here: new
  vaults may be attached to managed storage automatically). Whether storage is on is runtime state in
  `cloud.storage.status` (`available`). Attach-remote adds commands, not a capability (`WsProtocol.hpp`: presence
  is in `commands`).

## The console page

Under "Storage & cost", a nav item with a new `NavSignal` (`cloudStorage`), shown with the capability, `view` and
`available`: the plan state as a sentence, usage against quota with its date, one offer banner, each vault with its
switch and state in words (backed up, uploading 40 %, waiting and why, off, read-only, moved, uses its own storage),
"Manage billing" and "Leave managed storage". It hides keys, endpoints, bucket names, provider and tier, lifecycle and
protection, events, request budgets and price estimates. `NewVaultPage` shows the vault's switch, on by default.

**Claims lint.** `tools/contracts/encryption_claims.py` scans `web/src` and fails on "Vaulthalla Cloud" or
"vaulthalla.cloud" outside a "planned" sentence, and on "managed storage … includes … key recovery". Until launch the
page says "Managed storage" and never ties it to recovery; its copy sits in one module so the launch change (spec 05
§6 and the lint) edits one file (open question 8).

## Audit events

`audit::record`, actor the user or `system:cloud`: `cloud.storage.offer.accept`, `.offer.decline`, `.switch`,
`.new_vaults`, `.vault.register`, `.bucket.ready`, `.credential.issue`, `.ack`, `.rotate`, `.revoked`, `.retention`,
`.access` (with the cause), `.entitlement`, `.moved`, `.eject`, `.detach`, `.failed`, `.billing.handoff` (the kind,
never the URL). Never a secret. The attach records its own `vault.remote.*`.

## Tests

- **A fake cloud** behind the HTTP transport seam (`storage/s3/curl/Http`): vaults, storage, credentials sealed for
  the versioned fake S3, retention, billing, handoffs; injected `402`, `409`, `429`, lost responses, revocations, a
  restore elsewhere. The fake S3 refuses PUT and DELETE for `read_delete` keys and runs in spec 06's `Reject501` mode.
- **Sealed credentials:** vectors shared with the cloud; a wrong installation, vault or key id fails.
- **The hook:** each creation path gets a row; offered vaults are never registered or uploaded before acceptance.
- **States:** each table row by request audit; writes during `restricted` upload after `active`; cloud down changes
  nothing; `moved` stops sync and keeps data, and a stale key is stopped by `writers`.
- A crash at each provisioning step; rotation with the vault busy; user edits refused; retention resent until
  acknowledged; ejection flips without reload, then `ops::api_keys::update` swaps the key; unlink refuses.
- **Drill** (`vhh drill`, dev): provision through a local cloud with `FakeProvider` and a real S3 data path; write;
  attach an existing vault; lose the server and restore from the key manager (the old one reports `moved`);
  restriction; suspension; simulated ejection; the switch off and on.

## Work items, in landing order

1. Prerequisites: spec 06 items 2-5, attach-remote (BYOS), key-manager's pin and local-vault envelopes.
2. Migration and models; `APIKey.origin`/`editable`; `ops::api_keys` refusals; `vault_uid` on `Vault`.
3. `cloud::Client` calls for `/v1/vaults`, `/v1/storage`, `/v1/billing`; the sealed credential; the fake cloud.
4. **The `access` gate** (new: no read-only remote mode exists) in the sync pass, upload, delete, publish and hydrate
   paths, with health.
5. `CloudStorageService`: cache, sweep, provisioning, rotation, revocation, retention, `moved`, states.
6. `ops::cloud_storage`, RBAC module, CLI, ws (`cloud.link.status` included), catalog, MCP exclusions, capability.
7. `vault.remote.detach` and the switch off; ejection in place; unlink refusal.
8. Console page and `NewVaultPage` switch behind the capability; Desktop contract bump.
9. Drill. Then, in Phase 2, the launch change: lint, spec 05 §6, `docs/admin/cloud.md`, release notes.

## Open questions (recommendations first)

1. **Vaults that exist at first link.** Offer them in one confirmation, never upload silently.
2. **New vaults local first.** Create, then attach, rather than block creation on a bucket. "Default on" then means
   "attached shortly after creation", not "born in the bucket".
3. **Empty vaults.** Register and provision only once a vault holds its first file, so unused per-user default
   vaults don't spend buckets (100 per member account). An empty vault then shows "not stored yet".
4. **Gateway buckets in `local` mode.** Offered, not automatic: an S3 client sees remote-cache behaviour afterwards.
5. **Restricted and ended.** At `restricted`, offer "keep a full local copy" (the detach), never automatic; at
   `ended`, convert to local in place and list what was lost.
6. **Unlink with managed vaults.** Refuse without `--force`.
7. **Who owns a cloud key.** The vault's owner, read-only while `origin = 'cloud'`.
8. **Copy before launch.** Neutral "Managed storage" copy in one module, changed with the lint at launch.
9. **The sealed-credential code.** Built: vl-keykit 0.2.0 has it (`storage_credential.hpp`, with vectors), which this
   server pins, so wave 1 uses it; it is no longer deferred to wave 4 as `managed-storage.md` open question 8 had it.
10. **The server-wide default.** Keep `new_vaults` as an admin setting, on by default.
11. **Default retention for managed vaults.** A configured number of days, shown at acceptance like the existing
    versioning disclosure, rather than indefinite (which bills every overwritten version for ever).
12. **A moved vault's old copy.** Keep it read-only and say so; never delete it automatically.

## As built (2026-11-14, wave 1 engine)

Work items 2 to 7 are built (migration 142; `cloud/Storage.*`, `cloud/StorageService.*`, `ops/CloudStorage.*`,
`db/query/cloud/Storage.*`, the in-place detach in `vault/RemoteDetach.*`), every open question as its recommendation.
The console page (item 8) and the drill (item 9) are not. What the build settled where this document left a choice,
each small to change:

1. **The contract is the cloud's code** (vaulthalla-cloud `src/storage/ManagedStorage.cpp`, `src/accounts/
   Deployments.cpp`, `src/billing/Billing.cpp`). There is no retention route: retention is
   `PUT /v1/storage/vaults/{uid} {content_retention_days}` (1-36500), so "indefinite" is sent as 36500. `GET /v1/storage`
   carries no ejection portal address, so "Leave managed storage" is the billing portal (`billing --kind portal`).
   `account_key_confirmed` there is the cloud's offline-copy confirmation, not this server's pin; the server's own
   gate is the pin. The cloud's `provider` `b2` maps to `S3Provider::BackblazeB2`, anything else (the development
   provider) to `Other`.
2. **The service** `CloudStorageService` runs a pass every 30 s or when woken: the account key check (it replaced
   `cloud::KeyService`; daily, hourly after a failure, at once for `cloud.key.refresh`), then, only with a MAC-verified
   pin, `GET /v1/storage` and `GET /v1/billing` when due (`cloud.storage.poll_minutes`, every 15 s for five minutes
   after a step or a billing handoff), the sweep, and one step per vault against the last fetched state. A failed
   step backs off (1 min doubling to 6 h); an unreachable cloud changes nothing. `Manager::addVault` doesn't wake it:
   the sweep finds new vaults on the next pass.
3. **States.** `vault_cloud_storage.state` adds `ended` (converted at the end of the plan). An empty vault stays
   `unregistered` with reason `empty`. A vault registered by another deployment is `failed`
   (`registered_elsewhere`). The waiting reason is the cloud's (`payment_required`, `over_quota`,
   `account_key_unconfirmed`, `bucket_limit`), or its bucket state (`pending`, `created`). A rotation request is
   recorded as reason `rotation_requested`.
4. **Keys.** The exchanged key is an ordinary `api_keys` row (named `managed storage <uid>`, owned by the vault's
   owner, `origin = 'cloud'`), sealed like the others; a rotation or re-request writes into the same row and reloads
   the engine. It is acknowledged only after the probe (`validateAPICredentials`) passes; a probe failure or a lost
   response leaves the key unacknowledged (the cloud revokes it) and the next attempt uses a new key pair. `superseded`
   is re-requested at once; `none` closes the gate.
5. **The gate** is `full` for `active`/`past_due`, `read_only` for `restricted` (or a `read_delete` key), `none` for
   `suspended`, a revoked key, a move or an unlink. Only a managed vault's own gate is set; an operator's
   `vh vault remote access` (and attach, detach, abort) on a managed vault is refused `managed_storage`.
6. **The attach** is `ops::vault_remote::attachForCloud` (no actor or step-up), run by `RemoteAttachService` like any
   attach. `vault::remote::setManagedHooks` gives it the account key's system grant
   (`ops::recovery_recipients::addAccountKeyForManagedVault`, audited `system:cloud`, `automatic: true`, refused
   without a pin or a switch that isn't on) before precondition 6, and a quota courtesy check instead of the price
   preflight. Once done, the bucket is bound in `upstream_bucket` (versioning enabled, retention days from
   `cloud.storage.default_retention_days` unless set) and `vault_recovery_policy.mode = 'provider_versioning'`; the
   retention the vault's recovery policy asks for is sent until the cloud's view holds it.
7. **Enrollment** is `ops::cloud_recovery::enrollAutomatic(vault, reason)`: only the account-key grant's envelopes,
   after the attach, after a key rotation (the vault's key version moved past the one enrolled) and while it is
   behind; `enroll_behind_since` drives health `cloud_recovery_behind` after a day.
8. **Switch off** with a bucket is the detach (`hydrate`, no keys step-up), then `/detached`, `enabled: false` and the
   key row removed; while access is `none` it waits (`waiting_for_access`), because files held only in the bucket
   can't be fetched. Before a bucket: `enabled: false`; an attach in flight is aborted.
9. **In place** (`vault_remote_detach.mode = 'in_place'`) is how `ended` and a moved vault kept local convert: no
   request to the bucket; files held there only are listed in `lost` and moved to the trash (no local bytes, so
   nothing local is deleted); every usable grant's envelopes are wrapped again into the database
   (`envelopes::wrapIntoDatabase`, replacing records that pointed into the bucket); a revoked grant's bucket-only
   records are dropped and counted. The bucket is never touched.
10. **Ejection** flips in one transaction (`origin = 'customer'`, `cloud_access = NULL`, row `ejected`), opens the gate
    and reports `/ejected`; the engine and credentials stay.
11. **Unlink** refuses `managed_vaults` while any row is between `registered` and `detaching`; `--force` closes their
    gates (state `moved`, reason `unlinked`) and forgets the cached account state.
12. **The vault's own earlier bucket** (switched off, then on again; an `ended` the cloud reverses): an attach whose
    bucket isn't empty loads the bucket's manifest root with the vault's uid and its own keys; if it authenticates, the
    attach refuses `bucket_holds_this_vault` (the operator restores with `vh vault recover`, or the account holder
    deletes the bucket in the portal) instead of `bucket_not_empty`. Nothing in the bucket is deleted. Rejoining it in
    place (attach-remote question 6, with files only the bucket holds coming back as remote-only entries) is not built.
13. **An ended plan waits** (migration 143): the vault stays attached with access `none` (reason
    `ended_pending_confirmation`, health `cloud_storage_ended_pending`, status `ended {since, converts_at,
    confirmed_by}`) until an admin confirms (`vh cloud storage confirm-ended`, ws `cloud.storage.ended.confirm`) or
    the service has answered `ended` without interruption for `cloud.storage.ended_grace_hours` (24). Any other
    answer clears the run.
14. **The account policy in the root:** `recovery_policy.account_policy {policy, signature}` carries the pinned row's
    policy bytes for a vault with an active account-key grant; `vh vault recover` offers it to
    `ops::cloud_keys::offerPolicy`, which verifies it against this server's own pin and floor like the service's.
15. **The cloud's contract changes** are one place each (`contract::` in `cloud/Storage.cpp`), as the cloud ships
    them (2026-11-15), with no earlier names kept: `account_key_offline_copy_confirmed`, `ejection_portal_url` (https,
    or http only to this host; stored in `ejection.portal_url`, opened by "Leave managed storage"), base64url envelopes
    from `GET /v1/keys/vaults/{uid}/envelopes`, and `moved_to: {deployment_id, name}` on a vault moved off this
    deployment (state `moved` at once, the reason naming the server).
16. **The console** (item 8): `/managed-storage` (`features/managedStorage`, copy in `copy.ts`), a nav item under
    "Storage & cost" with `NavSignal` `cloudStorage` (the view permission and `available` or `linked`, since the page
    also holds the relay switch, `relay.md` "The console"; a server without the
    capability has no `cloud.storage.status`), and the new-vault switch (shown with the `meta.hello` capability;
    a choice that differs from the server's default is sent after the vault is created).
17. **Not built:** the `403`-from-Backblaze wake, `pending_upload_bytes`/`pending_files` and throughput in
    `CloudStorageVault`, rejoining a kept bucket in place. The drill is vaulthalla-cloud's `ci/milestone --only
    managed` (its `tests/milestone/README.md`).
18. **Restoring a managed vault** (the drill's finding, 2026-11-15): `vh vault recover --from-cloud --vault-uid U`
    without `--api-key`. Once the restore is approved the cloud has moved the vault to this deployment, so after the
    keys arrive the server asks for a bucket key of its own (`ops::cloud_storage::keyForRestore`: the sealed exchange,
    stored as a cloud key owned by the restored vault's owner, probed, not acknowledged), restores with it, and only
    then adopts the vault (`adoptRestored`: its row `active` on that key, the key acknowledged, the bucket bound, the
    gate set). A restore that stops removes the key (`discardRestoreKey`); unacknowledged, the cloud revokes it.
19. **Also from the drill (2026-11-15).** Access back after a suspension asks for a new bucket key (the cloud never
    reinstates a revoked one; the service had waited for an active key that never came). A bucket the cloud reports
    `emptying` or `deleted` while the plan isn't `ended` (paid again after the end began deleting it, or the account
    holder deleted it in the portal) converts the vault in place as a confirmed end does; while the plan is `ended`,
    item 13's confirmation still decides.
