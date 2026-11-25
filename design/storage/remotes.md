# Several remotes per vault: equal remotes

Status: design, track M of the server mirror plan (2026-11-25); nothing here is implemented. It covers what it
means for one vault to sync with more than one bucket, the data model, the engine change and the order of work. It
does not cover managed storage's provisioning of a remote (`design/cloud/managed-remotes.md`) or the server mirror
(`design/peers/`).

## Decided and given

- **Remotes are equal** (Cooper, 2026-11-25): no primary with copies. Every remote of a vault is kept complete, a
  change made directly in any of them reaches the others, and the vault can be recovered from any one alone.
- **This replaces "one bucket per vault"** (Cooper, 2026-11-12; `design/encryption/06-publish-without-preconditions.md`,
  `design/cloud/mirrors.md`, `design/cloud/managed-remotes.md`) as the model. Those documents stay true for a vault
  with one remote, which remains the default.
- **Compatibility policy:** there is no verified customer whose installation depends on the single `bucket` field or
  on the vault-keyed state tables, so the clean model is built, with a migration that loses nothing
  (`docs/contributors/compatibility-policy.md`).
- **Given, from the encryption specs:** sealed objects are portable between buckets and providers. A VHF1 header binds
  the vault, the object, the key version and a salt, never a bucket (spec 02 §3). The same holds for KEV1 key
  envelopes. A manifest is not portable: its entries carry the provider's ETag and version ids, and its root carries
  the bucket's publish mode (spec 03 §3.3; spec 06).

## Today: one remote, structurally

- **Schema.** `s3.vault_id` is the primary key of `s3` (`deploy/psql/020_vaults.sql:60-68`): one bucket row per
  vault, holding `api_key_id`, `bucket`, `storage_tier_id`, `encrypt_upstream`, later `storage_layout`,
  `manifest_publish` and `bucket_probe`.
- **State keyed by vault that describes one bucket:**

  | Table | Migration | What it holds |
  |---|---|---|
  | `remote_object_index` | 086 | The bucket's objects, `UNIQUE (vault_id, object_key)` |
  | `remote_manifest_state`, `_root`, `_gc`, `_base`, `_pending` | 086, 125, 137, 145, 147 | The manifest chain's position in this bucket |
  | `manifest_apply_report`, `manifest_apply_deferred`, `manifest_writer_root`, `manifest_foreign_envelope`, `manifest_shared_purge` | 146-150 | Applying other writers' roots from this bucket |
  | `sync`, `rsync` | 050 | Strategy, conflict policy, interval: `UNIQUE (vault_id)` |
  | `sync_file_baseline` | 107 | The last agreed remote ETag and size per file, keyed by file |
  | `sync_conflicts` and children | 050 | Two-sided changes against this bucket |
  | `upstream_object_version`, `file_versions.upstream_state` | 111 | Provider versions; whether the bucket holds a local version |
  | `upstream_write_intent`, `upstream_event_subscription`, `upstream_event_inbox` | 110 | Writes in flight; bucket event delivery |
  | `vault_upstream_usage_daily` | 111 | Request and byte counts |
  | `vault_recovery_policy` | 111 | Provider versioning mode and retention, among other things |
  | `vault_remote_attach`, `vault_remote_detach`, `vault_remote_access`, `vault_layout_migration` | 133, 138-140 | Long-running changes to the vault's bucket binding |
  | `vault_cloud_storage`, `cloud_recovery_vault` | 135, 142 | Managed storage and cloud recovery for the bucket |

- **Engine.** `storage::Manager::vaultToEngine_` maps a vault to one `Engine` (`core/include/storage/Manager.hpp:73`).
  A `CloudEngine` holds one API key, one `s3::Controller` and one manifest service
  (`core/include/storage/CloudEngine.hpp:331-332`). Fourteen source files cast a vault's engine to `CloudEngine`, and
  about 55 use the type.
- **Sync.** One pass per vault under an in-process lease keyed by vault id (`sync::Controller`); the upload and
  download tasks take the vault's one engine.
- **Contract.** The ws `Vault` model, `storage.vault.add` and `storage.vault.update` carry scalar `api_key_id` and
  `bucket` (`core/usage/src/contract/models/vaults.cpp`). Desktop generates its client from the same contract.
- **Already per bucket:** protection locks, keyed by `BucketIdentity{provider, account_ref, bucket}`
  (`core/include/storage/upstream/Guard.hpp`), and `upstream_bucket`, whose `vault_id` is not unique.

## The model: the local vault is the hub

```
              bucket A  <──sync──>  ┌──────────────┐  <──sync──>  bucket B
                                    │ local vault  │
              bucket C  <──sync──>  └──────────────┘
```

- **A remote** is one bucket binding of a vault: credentials, bucket, storage tier, layout, publish mode, probe
  result, and all the sync state that describes that bucket.
- **Each remote syncs with the local vault independently**, with the pass that exists today. Remotes never talk to
  each other. A file changed directly in bucket A is taken into the local vault by A's pass and sent to B and C by
  theirs.
- **The vault's strategy and conflict policy apply to every remote.** Per-remote overrides are left for later.
- **Each remote has its own manifest chain**, in its own publish mode. The local database is the tree; each chain is
  that tree as published to one bucket.
- **Recovery:** `vh vault recover` needs one remote and the keys, as today. Each remote holds the envelopes and a
  complete chain.
- **Layout:** all remotes of a vault share one `storage_layout` and one `encrypt_upstream`. A vault is encrypted
  upstream everywhere or nowhere.

### Where equal needs a rule

| Question | Rule |
|---|---|
| A file is not on disk (`cache`): which remote is it read from? | The vault's read order: by default the remote with the lowest estimated egress price, then the fastest. Editable. On failure, the next |
| When may a local copy be released under `cache`? | When every remote holds it. `min_holders` can lower that to a number |
| Two remotes changed the same file outside Vaulthalla | Each pass resolves its remote against the local vault under the conflict policy, in pass order. The second pass sees the first's result as the local side |
| A remote is unreachable | Its pass fails and reports; the others carry on. Its backlog is its own |
| Provider differences | Reported per remote: events (AWS, R2 only), conditional writes (not B2), provider versioning (not R2). A feature that needs a capability is offered per remote |
| Deleting under the one-way `mirror` strategy | Applies to each remote: each bucket is made to match the vault |
| Cost | Estimates, budgets, usage and the price guard are per remote |
| File recovery | The vault's recovery policy stays one policy. Provider versioning mode and retention move to the remote, because they are facts about a bucket |

### What is refused in the first version

- More than four remotes per vault.
- Remotes with different layouts or different `encrypt_upstream`.
- Two remotes of one vault pointing at the same bucket, and a bucket that already holds another vault.
- A bucket-replicated vault (`vh vault join`) with more than one remote: several writers and several buckets at once
  is not designed.

## Data model

```sql
vault_remote (
  id                serial primary key,
  vault_id          integer not null references vault on delete cascade,
  api_key_id        integer not null references api_keys,
  bucket            text not null,
  storage_tier_id   text,
  manifest_publish  text,
  bucket_probe      jsonb,
  read_rank         integer not null default 0,
  state             text not null,      -- active | filling | paused | removing
  created_at        timestamptz not null,
  unique (api_key_id, bucket),
  unique (vault_id, id)
)
```

- `s3` keeps what is true of the vault whatever its remotes are: `encrypt_upstream` and `storage_layout`. Its
  `api_key_id`, `bucket`, `storage_tier_id`, `manifest_publish` and `bucket_probe` move to `vault_remote`.
- A vault of type `s3` has at least one `vault_remote`. Removing the last one is the existing detach.
- **Every table in the list above gains `remote_id`** referencing `vault_remote`, and its key changes from the vault
  to the remote: `remote_object_index` to `UNIQUE (remote_id, object_key)`, `remote_manifest_state` to
  `(remote_id, manifest_key)`, `sync_file_baseline` to `(file_id, remote_id)`, `file_versions.upstream_state` to a
  child table `file_version_remote (version_id, remote_id, state)`, and so on.
- `sync` and `rsync` stay one row per vault (the shared strategy and policy). Pass bookkeeping (last pass, next pass,
  backlog) moves to the remote.
- **Migration.** One migration creates `vault_remote`, inserts one row per existing `s3` row, adds `remote_id` to
  each table filled from it, and only then swaps the keys and drops the moved columns, in one transaction per table.
  No state is rebuilt from the bucket and nothing is discarded. It is checked on an upgraded install with existing
  remote vaults before it ships (`tools/contracts/` migration checks, and a lab upgrade).

## Engine

- `storage::Manager` keeps one engine per vault. A cloud vault's engine holds a list of **remote handles**; what
  `CloudEngine` holds singly today (`key_`, `s3Provider_`, the manifest service, the bucket capability) becomes a
  `Remote` object, one per `vault_remote`.
- Code that asks a vault's engine for "the controller" or "the bucket" names a remote instead. The compiler finds
  every site once the single accessors are removed; nothing keeps a "default remote" shim.
- `sync::Controller` schedules one pass per remote. The lease is keyed by remote, so passes for different remotes of
  one vault may overlap; two passes never run for the same remote.
- The planner compares the local vault with one remote's index and baseline. It is unchanged apart from being
  handed a remote.
- The publisher, garbage collection, the applier, events, protection locks, the usage ledger, attach, detach and
  layout migration each take a remote.
- Hydrating a file not on disk walks the read order.

## Contract and surfaces

- **ws.** `Vault` replaces `api_key_id`, `bucket` and `storage_tier_id` with `remotes[]`: `id`, `api_key_id`,
  `bucket`, `provider`, `storage_tier_id`, `publish`, `state`, `read_rank`, capabilities, health and backlog.
  `storage.vault.add` takes an optional first remote. New commands: `vault.remote.add`, `vault.remote.remove`,
  `vault.remote.list`, `vault.remote.set` (rank, tier, pause). The existing `vault.remote.attach` and
  `vault.remote.detach` become the first-remote and last-remote cases of add and remove. This is a breaking contract
  change, made once, with the protocol version raised and Desktop's generated client updated in step.
- **CLI.** `vh vault remote add|remove|list|set`, with `--remote <id|bucket>` on the commands that act on one bucket
  (`vh vault sync`, `sync info`, `sync reconcile`, `recover`, the recovery and bucket commands). A vault with one
  remote never needs the flag.
- **Console and Desktop.** The vault's storage pane lists its remotes with state, backlog and cost, and offers add,
  pause and remove.

### Adding and removing a remote

- **Add** is the attach-remote job generalised (`design/storage/attach-remote.md`): probe the bucket, upload every
  sealed object and envelope, publish the first root, verify, then mark the remote `active`. Until then it is
  `filling` and is not counted as a holder for cache release.
- **Remove** stops the remote's passes and forgets its state. The bucket's contents are left alone unless the
  operator asks for them to be deleted, with the usual confirmation. It is refused if a file's only copy is in that
  remote: the file is fetched first.

## With a server mirror

A vault's remotes are shared vault settings, and the core runs all of them (`design/peers/mirror.md`). Giving each
remote its own owning server is possible later and is not designed here.

## Order of work

| Step | What | Behaviour change |
|---|---|---|
| **M1** | `vault_remote`, the re-keyed tables, `Remote` handles in the engine, the pass keyed by remote, the contract's `remotes[]`. Exactly one remote per vault is still enforced | None. The whole existing test suite is the check, plus the upgrade check on a lab install |
| **M2** | Lift the limit: add and remove, the fill job, independent passes, cache release by holders, read order | Several remotes work from the CLI |
| **M3** | Console and Desktop panes; cost, usage and budgets per remote; provider versioning per remote; `recover` from a chosen remote | Complete feature |
| **M4** | Per-remote strategy overrides, if wanted | Optional |

M1 ships alone, with no feature attached, so that a regression in it has one cause.

## Invariants (each gets a test)

1. With one remote, behaviour and bucket contents are byte-for-byte what they were before M1.
2. A local copy is never released while fewer than `min_holders` active remotes hold the object.
3. Removing a remote never deletes a file's last copy.
4. One remote's failure never blocks another remote's pass or a local write.
5. Every remote's manifest chain alone, with the keys, reconstructs the vault.
6. No two remotes of any vault, and no two vaults, are bound to the same bucket.

## Open

- **Default `min_holders`:** all active remotes (recommended), which costs local disk while a slow remote catches up.
- **Read order default:** cheapest egress first needs the price data the cost estimator already has; where a
  provider has no price entry, declaration order is used.
