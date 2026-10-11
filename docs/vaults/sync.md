---
title: Sync
description: Configure and troubleshoot local, S3, and R2 vault sync behavior, remote indexes, dry-runs, inventory imports, event ingestion, and reconcile.
order: 230
status: published
tags:
  - vaults
  - sync
  - s3
  - r2
---

# Sync

Vault sync keeps Vaulthalla's local state, metadata, and remote object storage aligned according to the vault type and sync policy. S3/R2 sync adds remote-index management, request budgeting, and price-budget checks.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Manual Sync

Trigger a sync:

```bash
vh vault sync <vault>
```

Inspect policy and remote-index state:

```bash
vh vault sync info <vault>
```

Change common policy fields:

```bash
vh vault sync set <vault> --interval 15m
vh vault sync set <vault> --on-sync-conflict ask
```

S3/R2 policy updates:

```bash
vh vault sync set archive --sync-strategy cache --on-sync-conflict keep_local
vh vault sync set archive --max-remote-index-age 24h
```

## Strategies For S3/R2

| Strategy | Use when | Important behavior |
| --- | --- | --- |
| `cache` | You want a local working cache over a bucket | Remote objects can be indexed without downloading every body. Bodies are fetched when accessed or planned. |
| `sync` | Local and remote should both accept changes | Changes on either side can be propagated according to conflict policy. |
| `mirror` | The local vault should publish to the bucket | Remote changes are not treated as local source changes. |

Choose the strategy before connecting Vaulthalla to a bucket with existing data. Use dry-run and request budgets to understand planned work.

A vault created without a strategy or conflict policy gets the operator's defaults, `vaults.s3.default_remote_sync_strategy` (`cache` unless changed) and `vaults.s3.default_remote_conflict_policy` (`ask` unless changed); see [Configuration](/reference/configuration#vault-defaults).

## Conflict Policies

Local vault policies:

- `overwrite`
- `keep_both`
- `ask`

S3/R2 vault policies:

- `keep_local`
- `keep_remote`
- `keep_newest`
- `ask`

| Policy | When a file differs on both sides |
| --- | --- |
| `ask` (default for new vaults) | The conflict is recorded and that file waits for a decision. Everything else keeps syncing. |
| `keep_local` | The local copy is uploaded over the remote object. |
| `keep_remote` | The remote object is downloaded over the local copy. |
| `keep_newest` | The copy modified last wins. Without timestamps on both sides it falls back to `ask`. |

Under `ask`, only a real two-sided change is a conflict. Each pass compares both sides with what they were when they last agreed (Vaulthalla records that after every sync of the file):

- A file changed only locally is uploaded.
- A file changed only in the bucket is downloaded.
- A file changed on both sides is recorded as a conflict, once. Later passes refresh the recorded details if a side changes again, and never add a second open conflict for the same file.
- If both sides become identical again, the open conflict closes itself.

A file that has never been synced by a version that records this (for example, files synced before an upgrade) has nothing to compare against, so a difference on it is recorded as a conflict too. Resolve it once and later changes are classified normally.

The `keep_*` policies settle every content difference themselves, as before. A file that neither side changed since it was last synced is left alone under every policy. If you switch a vault from `ask` to a `keep_*` policy, its open conflicts are settled by the next sync with that policy.

## Resolving Conflicts

Resolving a conflict needs the vault permission `vault.sync.action.resolve_conflicts` and Overwrite on the file. Built-in vault roles that can trigger a sync (contributor, editor, manager, power user) include it, and upgrades grant it to every role that already had sync trigger. Admins get it through their vault globals. The vault owner gets it through their own role's self scope.

The other sync permissions work the same way: a vault role assigned to a user, or to a group the user belongs to, grants its `vault.sync.*` permissions (trigger a sync, view or edit sync settings, sign the encryption waiver) on that vault, in addition to whatever the admin vault globals grant.

Each conflict has two decisions:

- **Keep local** uploads the local copy over the remote object.
- **Keep remote** downloads the remote object over the local copy, decrypted and re-sealed exactly like a sync download.

A decision applies to the versions that were recorded. If either side changed since then, the resolution is refused and the conflict stays open; the next sync refreshes it, then decide again. Transfers count against the vault's S3 request budget and price budgets like sync does.

From the CLI:

```bash
vh sync resolve                                        # interactive, in a terminal
vh sync resolve --list [--vault <vault>] [--json]
vh sync resolve 12 13 --keep-local
vh sync resolve --vault photos --all --keep-remote --yes
```

`vh resolve` is a shortcut for `vh sync resolve`. In a terminal with no arguments it opens an interactive session. It lists open conflicts by vault, shows both sides' metadata, can show a text diff for small text files (which fetches the remote copy, one GET), and resolves one conflict or every conflict in a vault.

In the web console, the **Sync Conflicts** button in the top bar and the **System > Sync Conflicts** page appear while there are conflicts you can resolve. See [Web console](/web-console#sync-conflicts).

## Remote Index

S3/R2 vaults maintain a remote object index. The index lets Vaulthalla plan sync work without repeatedly scanning a large bucket.

The remote-index flow can use:

- A Vaulthalla manifest under `.vaulthalla/`.
- Local database index rows.
- S3 Inventory imports.
- S3 Event Notification ingestion.
- Explicit reconcile scans.

`vh vault sync info <vault>` reports remote-index source, indexed time, manifest ETag, generated time, object count, and fresh or stale status.

If the local index is older than `max_remote_index_age` and the manifest cannot be refreshed, sync stalls instead of silently trusting stale data.

## Dry-Run

Run dry-run before raising budgets or syncing a large bucket:

```bash
vh vault sync dry-run <vault>
```

Default dry-run is local-index-only. It reads local state and the local remote index, builds a plan, and prints estimated request and traffic pressure. It does not invent a plan when no usable remote index exists.

Refresh the remote index only when you intentionally allow S3 work:

```bash
vh vault sync dry-run <vault> --refresh-index
vh vault sync dry-run <vault> --refresh-remote-index
```

Pricing controls:

```bash
vh vault sync dry-run <vault> --refresh-pricing
vh vault sync dry-run <vault> --no-pricing
```

Dry-run output is the safest way to compare request budgets, price budgets, and planned body downloads before real sync work starts.

## Import S3 Inventory

For large existing buckets, import S3 Inventory instead of starting with a full bucket scan:

```bash
vh vault sync inventory <vault> --file inventory.csv
```

For CSVs without headers, provide a schema:

```bash
vh vault sync inventory <vault> \
  --file inventory.csv \
  --schema bucket,key,size,last_modified_date,etag,storage_class
```

Inventory import indexes object metadata and publishes the Vaulthalla manifest without downloading object bodies.

## Ingest S3 Events

Use event ingestion to keep the index current after initial import:

```bash
vh vault sync events <vault> --file s3-events.json
```

ObjectCreated events upsert remote-index rows. ObjectRemoved events delete rows. Sequencers prevent older events from overwriting newer index state when the provider supplies them. Manifest objects under `.vaulthalla/` are ignored.

## Reconcile

Reconcile performs an explicit ListObjectsV2 pass:

```bash
vh vault sync reconcile <vault> --allow-list-scan
```

Without `--allow-list-scan`, reconcile requires a configured LIST request budget on the sync policy. This prevents accidental unbounded scans on large buckets.

When a prior index exists, reconcile prints a rough estimate of one LIST request per 1,000 indexed objects. Use that estimate to set an appropriate `--s3-budget-list` value.

## Archive-Tier Objects

Archive-tier objects can be indexed without body download. If the provider requires restore before download, Vaulthalla skips planned body downloads and reports the skip in sync or dry-run output. Restore the object with the provider first, then run sync again.

## Budget Stalls

When a request or downloaded-byte budget is exceeded, the sync event is marked `stalled` with a budget-related reason. This is expected protective behavior, not necessarily a service failure.

Start with:

```bash
vh vault sync info <vault>
vh vault sync dry-run <vault>
```

Then raise the narrow exhausted budget field rather than switching to unlimited.
