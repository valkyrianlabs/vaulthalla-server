---
title: File Recovery
navTitle: File Recovery
description: Bring back earlier versions of files and folders with local snapshots, local versioning and AWS S3 provider versioning - how each works, what it costs, how to restore safely, and what the refusals mean.
order: 257
status: published
tags:
  - vaults
  - recovery
  - snapshots
  - versioning
  - s3
  - cost-control
---

# File Recovery

File recovery brings back earlier versions of files and folders: an overwritten spreadsheet, a deleted folder, a tree as
it was last Tuesday. Vaulthalla keeps that history in up to three places, decides which one to use for each restore,
encrypts what it keeps on the host, and prices what the provider keeps before you turn it on.

File recovery is not a backup. Snapshots and local versions live on the same host as the vault, and provider versions
live in the same bucket. Keep a real recovery set as described in [Backup And Recovery](/vaults/backup-and-recovery).

The same operations are in the CLI (`vh snapshot`, `vh recovery`, `vh vault recovery`, see the
[command reference](/cli/command-reference#file-recovery)) and in the web console (see
[File Recovery In The Web Console](/web-console/recovery)). Both run the same checks.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Three Kinds Of History

| | Local snapshots | Local versioning | Provider versioning |
| --- | --- | --- | --- |
| What it keeps | A named recovery point of a file or a folder tree | The previous contents of a file each time its contents change | Every object version and delete marker in the bucket |
| Created | Only when a person takes one | Automatically, once you turn it on | By AWS on every write and delete |
| Stored | Encrypted on this host | Encrypted on this host | In the AWS S3 bucket; Vaulthalla keeps metadata only |
| Vaults | Any vault | Any vault | S3 vaults on AWS S3 only |
| Recovery ids | `snap-<id>` (its files are `lv-<id>`) | `lv-<id>` | `pv-<id>` |
| Removed by | You (`vh snapshot delete`) | Its limits (count, age, quota) | The bucket's retention |

Which one to use:

- **Local snapshots** before something risky: a migration, a bulk edit, an audit. They capture a whole tree in one pass
  and are kept until you delete them.
- **Local versioning** for a safety net on files people edit all the time. It costs host disk, which you cap.
- **Provider versioning** for long, complete history of an S3 vault without keeping a second copy on the host. It costs
  money every month, and on AWS it can't be turned off again, only suspended.

Local versioning can run alongside either mode. On S3 vaults with provider versioning it also queues history while
AWS is unreachable (see [The Upload Backlog](#the-upload-backlog)).

## Recovery Mode

Each vault has one recovery mode: `off` (the default), `local-snapshots` or `provider-versioning`. Local versioning is a
separate on/off switch.

```bash
vh vault recovery status <vault>
vh vault recovery set <vault> --mode local-snapshots --snapshot-quota 50G
vh vault recovery set <vault> --local-versioning on --keep-last 10 --max-age-days 90 --version-quota 20G
vh vault recovery set <vault> --mode provider-versioning --retention 90d
```

In the web console: **Vaults → (vault) → Settings → Recovery**.

- The mode decides what can be *created*: snapshots need `local-snapshots`, and provider versioning is turned on by
  choosing `provider-versioning`. Snapshots and versions that already exist stay recoverable whatever the mode is.
- Changing the mode away from `provider-versioning` never suspends the bucket's versioning. `vh vault recovery status`
  says when a bucket keeps versions while the vault's mode is something else.
- Changing recovery settings needs the vault's sync settings permission. Anything that changes the bucket (turning on
  provider versioning, a retention, suspending) also needs `admin.upstream.configure` and the right to use the vault's
  API key. Adopting the vault's bucket needs `admin.upstream.provision` as well.

## Local Snapshots

### Take A Snapshot

```bash
vh vault recovery set <vault> --mode local-snapshots
vh snapshot create <vault> /finance --name "before audit"
vh snapshot create <vault> /reports/q3.xlsx
```

In the web console, right-click a file or folder in **Files**, choose **Recovery history…**, then **Create snapshot**.

Before anything is written, Vaulthalla checks that you may read and copy every file and list every folder in the tree.
One denial refuses the whole snapshot. It then checks the space: the snapshot's new bytes must fit the snapshot quota
(when set) and the vault's free space.

Nothing is ever snapshotted automatically: not on writes, deletes, renames, sync or key rotation.

### What A Snapshot Captures

A snapshot captures the last saved version of each file. Changes still open through the mounted filesystem, not yet
saved, aren't in it. The snapshot lists what it left out and why (`vh recovery inspect snap-<id>`):

| Skipped | Why |
| --- | --- |
| `symlink` | A symlink is a path, not content. |
| `upload_staging` | An upload in progress. |
| `content_unavailable` | A cloud file with no local copy that couldn't be fetched within the vault's remote-read limits. |
| `integrity_error` | The stored file failed authentication. |
| `unsealed` | A legacy plaintext file. Snapshots are never stored in plaintext. |
| `vanished`, `moved` | The file was deleted or moved while the snapshot was taken. |

Empty folders are recorded so a restore recreates them.

### Storage, Deduplication And Quota

Snapshots are stored encrypted on the host, outside the vault's own directory, exactly as the files were sealed.
Nothing is decrypted to take one.

- An unchanged file costs nothing twice: two snapshots of the same version share one stored copy, and so does a
  snapshot and a local version of it.
- Snapshot bytes count against the vault quota and against the optional snapshot quota (`--snapshot-quota`, `0` for
  none). A snapshot that wouldn't fit is refused with the bytes it needs and the bytes left.
- `vh vault recovery status` shows the count, the stored (deduplicated) bytes and the original size.

### List, Inspect And Delete

```bash
vh snapshot list <vault> [path]
vh recovery inspect snap-12
vh snapshot delete snap-12
```

Deleting a snapshot needs Delete on its path and asks you to type `DELETE` (`--yes` for scripts). File versions that a
local version or another snapshot still uses are kept. A snapshot still being taken can't be deleted.

### How Long Snapshots Last

Snapshots are kept until someone deletes them. They survive the deletion of the files they captured, so a deleted
folder can be restored from them. They are removed with the vault's other local data when a deleted vault is purged
(see [Deleting And Restoring Vaults](/vaults/deleting-vaults)).

A snapshot interrupted by a crash is marked failed at the next start and releases what it had captured. The record
stays so you can see what happened.

## Local Versioning

### Turn On Local Versioning

```bash
vh vault recovery set <vault> --local-versioning on --keep-last 10 --max-age-days 90 --version-quota 20G
vh vault recovery set <vault> --keep-last 0      # no per-file limit; the other settings stay
vh vault recovery set <vault> --local-versioning off
```

Settings you leave out keep their stored values. `0` removes a limit. With every limit removed, versions are kept
until you delete them or turn versioning off.

### When A Version Is Kept

With local versioning on, the previous contents of a file are kept each time they are replaced:

- an overwrite (through the mount, the web console, the S3 gateway or a restore), a truncation, or a deletion,
- a sync download that replaces local contents with the remote ones, and a conflict resolution that keeps the remote
  side.

Renames, moves and copies keep nothing (the contents didn't change), and neither does key rotation (same contents,
new key). Empty files, legacy plaintext files and cloud files with no local copy are skipped: the provider holds the
latter.

Versions are stored like snapshots: encrypted, deduplicated, and counted against the vault quota.

### Limits

- `--keep-last N`: at most N versions per file (1–10,000).
- `--max-age-days N`: versions older than N days are removed (1–36,500).
- `--version-quota SIZE`: the oldest versions are removed first once local versions use more than this.

Limits are applied at least every 15 minutes, and `--keep-last` also right after each new version. Two exceptions: a version
still waiting to be uploaded to the bucket is never removed, and stored bytes a snapshot also uses stay until the
snapshot is deleted.

You can delete a single version with `vh recovery delete lv-<id>`, except one still waiting to be uploaded.

### The Upload Backlog

On an S3 vault with local versioning, the versions also form an ordered upload backlog.

- When the provider is unreachable, writes keep working locally and every replaced version waits, in order.
- When the provider answers again and the bucket keeps history (provider versioning enabled and past its
  [15-minute propagation window](#turn-on-provider-versioning)), the next upload of each file first sends its waiting versions,
  oldest first, each with its original encryption metadata, and then the current contents. The bucket's version
  history then matches the history on the host.
- A bucket that doesn't keep history only needs the current contents: waiting versions are marked skipped and stay
  local, subject to the limits above.
- Price budgets and request budgets cover the replayed uploads like any other upload. A replay that fails holds back
  that file's current contents until the next sync pass, so history is never sent out of order.
- Versions caused by the remote side (a sync download, a conflict resolved for the remote copy) and deletes the vault's
  sync policy doesn't send upstream are never replayed.

`vh vault recovery status` shows the backlog: versions and bytes waiting, the oldest one, how many have failed, and the
last error.

### Smart Cache Vaults

In a `cache` vault (and an S3 gateway remote-cache bucket) with provider versioning, a version's local copy is
released as soon as the bucket holds it, unless a snapshot uses it. The host keeps history bodies only while they are
waiting to be uploaded, never as a second copy of what the provider already keeps.

## Provider Versioning (AWS S3)

With provider versioning, the bucket itself keeps every version of every object. Vaulthalla turns it on after showing
what it will cost, sets how long old versions are kept, indexes the versions, and restores from them.

:::callout[Turning on versioning can't be undone]{variant="danger"}
Once an AWS bucket keeps versions, it can never go back to unversioned. It can only be suspended, which stops new
versions and keeps (and bills) the existing ones until their retention expires them.
:::

### Supported Providers

- **AWS S3**: supported.
- **Cloudflare R2**: refused. R2 has no object versioning (no version ids, noncurrent versions or delete markers). Use
  local snapshots or local versioning on R2.
- **Other S3-compatible providers**: refused. Provider versioning is supported on AWS S3 buckets only.

### Prerequisites

- The vault's API key has provider administration turned on (`vh upstream admin enable <api-key>`) and the IAM
  permissions listed in [Managed Upstream Buckets](/vaults/upstream-buckets#aws-s3).
- The bucket is managed or adopted by Vaulthalla. An existing vault's unmanaged bucket can be adopted in the same step
  (`--adopt-bucket`, or the console's confirmation). That runs the usual admission check first; nothing in the bucket
  is deleted, overwritten or converted. A bucket another vault uses, or that holds another vault's index, is refused.
- The bucket isn't [protected](/vaults/upstream-buckets#protection-locks). Vaulthalla never changes a protected bucket.
- You hold the permissions in [Recovery Mode](#recovery-mode).

### The Cost Disclosure

Before versioning is turned on, Vaulthalla shows **Provider Versioning — Estimated Monthly Cost**:

```bash
vh vault recovery disclosure <vault> --retention 90d
```

It shows the provider, bucket, region and storage class; the vault's current data and its measured write traffic; the
estimated additional monthly storage with its range and basis; the growth of version history over 12 months; the cost
under each retention (30, 90 and 365 days, indefinite); the confidence of the estimate and the price catalog's
freshness; what isn't included; the cost of recovery operations; and the consequences (irreversibility, the
propagation window, retention deleting history, minimum storage durations, object lock and MFA delete when present).
Reading it makes at most one administrative request to the bucket and no object requests.

The disclosure ends in a token that is valid for 10 minutes and only for you, this bucket, this retention and the
price figures shown. If any of them changes, or the daemon restarts, you are shown a fresh disclosure.

Turning versioning on then needs these acknowledgements:

| Acknowledgement | When | CLI (typed / flag) |
| --- | --- | --- |
| The disclosure itself | always | `ENABLE VERSIONING` / `--yes` |
| Unpriced recurring charges | when the cost can't be estimated | `ACCEPT UNPRICED` / `--accept-unpriced` |
| A shorter retention | when it shortens the history kept now | `SHORTEN` / `--accept-retention-shortening` |
| Bucket adoption | when the bucket is unmanaged | `ADOPT` / `--adopt-bucket` |

`vh vault recovery set --mode provider-versioning` always fetches and prints the disclosure, even with `--yes`.

:::callout[Charges you can't see yet still apply]{variant="warning"}
When Vaulthalla can't estimate the cost (no price profile, pricing turned off, or a billing rule it doesn't model), it
says "cannot be estimated" with the reason, never $0.00, and asks for the separate unpriced acknowledgement.
:::

### Turn On Provider Versioning

```bash
vh vault recovery set <vault> --mode provider-versioning --retention 90d
```

In the web console: **Settings → Recovery → Provider versioning**, choose a retention, then **Review costs and
enable…**.

Vaulthalla then:

1. Reads the bucket's versioning once more.
2. Enables it only if it isn't already enabled, and reads it back until AWS confirms (a short, bounded wait; if AWS
   hasn't confirmed by then it says so and shows it once it does).
3. Records a 15-minute propagation window. AWS can take up to 15 minutes before every write is versioned. Until then the
   status says **propagating**, and Vaulthalla doesn't rely on versions for recovery or replay the upload backlog.
4. Writes the retention lifecycle rules (below).
5. Records it all in the upstream audit log.

A bucket that already keeps versions is left as it is: Vaulthalla records it and sets the retention.

### Retention

You choose how long a version is kept after it stops being current: `30d`, `90d`, `365d` or `indefinite` (the CLI
accepts any whole number of days from 1 to 36,500). There is no default.

- The retention is Vaulthalla's own lifecycle rule `vaulthalla-managed` (`NoncurrentDays`). Indefinite removes the
  expiry from that rule.
- Every other lifecycle rule on the bucket is kept exactly as it was. Rules from other applications that expire
  noncurrent versions are listed in the status and the disclosure, and the shortest one that covers the whole vault
  wins. Vaulthalla warns when one is shorter than your choice.
- Shortening the retention (indefinite to days, or fewer days) makes AWS permanently delete older versions sooner,
  including history that exists now. It always needs the separate confirmation, from scripts too.
- The expiry shown for a provider version in recovery history assumes Vaulthalla's retention. Check
  `vh vault recovery status --refresh` for rules from other applications.

Vaulthalla also adds `vaulthalla-manifest-versions`, which expires old copies of its own index under `.vaulthalla/`
after one day. That index is rewritten often, and keeping its history would only add cost.

`vh upstream lifecycle --expire-noncurrent-days` edits the same `vaulthalla-managed` rule. Prefer
`vh vault recovery set --retention` for versioned vaults, so the shortening confirmation and the recorded retention
stay in step.

### Suspend Versioning

```bash
vh vault recovery suspend <vault>
```

Suspending stops new versions. Nothing is deleted: existing versions stay in the bucket, billed, until the retention
expires them. It asks you to type `SUSPEND` (`--yes` for scripts). Buckets with object lock can't be suspended.

Vaulthalla never suspends versioning on its own: not when you change the mode, not when costs exceed the alert, not when
the vault is deleted.

### What Vaulthalla Never Does

- Turn on versioning when it creates a bucket.
- Delete object versions when a vault is deleted or purged. With the opt-in upstream purge, a versioned bucket gets
  delete markers over its objects, and the old versions remain until the retention removes them.
- Change versioning or lifecycle on a protected bucket, or on an unmanaged one you didn't agree to adopt.
- Expose object versions through the [S3 gateway](/s3-gateway).

### Provider Versions In Recovery History

Vaulthalla indexes the versions it writes from AWS's responses. Versions it didn't write (from before it watched the
bucket, or from other applications) are listed when you ask for them:

```bash
vh recovery list <vault> /finance --refresh --provider-only
```

`--refresh` (the console's **Check provider for versions**) lists the bucket's versions for that path. It reads
metadata only, downloads no file contents, and counts against the vault's request budget.

## Restore

### Plan First

Every restore starts as a plan that changes nothing:

```bash
vh recovery list <vault> /reports/q3.xlsx
vh recovery plan lv-81
vh recovery plan snap-12 --to /restored
vh recovery plan <vault> /finance --at 2026-10-01T12:00:00Z --prune
```

The plan lists every item with its action, source, destination, size and method, the counts, a consistency note, the
estimated provider requests and cost, warnings and blockers:

| Action | Meaning |
| --- | --- |
| `create` | Nothing is at the destination; the file or folder is created. |
| `overwrite` | The destination exists and is replaced. |
| `skip` | The destination already holds exactly this version. |
| `conflict` | The destination can't take it: a folder where a file goes, an open sync conflict, or local changes not uploaded yet. |
| `remove` | Point in time with `--prune`: the file didn't exist at that time. |
| `unavailable` | The source can't be restored: its stored copy is missing, it is in an archive storage class, or its key is gone. |

A plan is yours alone and valid for 30 minutes. A plan with blockers (for example, a permission you lack at a
destination, or not enough space) can't run.

### Confirm And Run

```bash
vh recovery restore lv-81
vh recovery restore snap-12 --to /restored
vh recovery restore 7 --token 3f9c2a7d…
```

`restore <recovery-id>` makes the plan, shows it and asks. When anything would be overwritten or removed you type
`RESTORE`; a restore that only creates asks yes or no. `--yes` skips the question for scripts. For a plan made earlier
with `vh recovery plan`, pass its id and the `--token` it printed: the token is the confirmation.

The console shows the same **Restore preview** and asks for `RESTORE` the same way. If a plan expires before you
confirm, it is made again and shown again.

Provider versions that Vaulthalla didn't write are marked unverified. Restoring them needs a separate acknowledgement
(`--accept-unverified`, or type `UNVERIFIED`): restore them only if you trust where they came from.

### Destinations

- **Original paths** (the default): each item goes back to the path it had when it was kept. A file that has since been
  moved is left alone, and the old path is recreated.
- **An alternate folder** (`--to /restored`, or **Restore to** in the console): the restored file or folder goes inside
  it under its own name, so `snap-12` of `/finance` lands in `/restored/finance`.

### Point In Time

```bash
vh recovery plan <vault> /finance --at 2026-10-01T12:00:00Z [--prune]
```

On S3 vaults with provider versions, a folder can be rebuilt as it was at a moment: for each file, the latest version
written at or before that time. A file whose latest event then was a delete, or that had no version yet, is absent.
`--prune` also removes files that didn't exist at that time.

This is a reconstruction from each file's own version timestamps, not an atomic snapshot, and every plan says so. Only
a local snapshot is taken in one pass. If the provider's version listing stops early (a request budget, for example),
the plan warns that it may miss versions. Local vaults restore a snapshot or a local version instead.

### How Items Are Restored

- **Snapshots and local versions** are restored from the host. A version sealed under the current key is reused as it
  is, after its authentication tag is checked. One sealed under an older key is re-encrypted under the current key as
  it is restored, and committed only after the old key authenticates it. No plaintext is written to disk.
- **Provider versions** are restored inside the bucket when they can be: a server-side copy of the old version onto the
  current key, which preserves its encryption metadata. Nothing is downloaded or uploaded, and the next sync pass sees
  the file already in agreement, so it isn't uploaded twice. In a `cache` vault the file is then fetched again only when
  someone reads it.
- A provider version over 5 GiB, or sealed under an older key, is restored by transfer: downloaded, verified,
  re-encrypted under the current key and uploaded once, under the vault's price and request budgets.
- Versions in GLACIER or DEEP_ARCHIVE storage classes are unavailable: they need a provider-side restore first.
- A provider restore waits for the vault's sync pass. If one is running, the item fails with "a sync pass is running";
  run the restore again shortly.

With local versioning on, what a restore from the host overwrites is kept as a local version, so the restore can be
undone. A provider restore leaves the replaced contents in the bucket as a provider version.

### Conflicts And Safety

Each item is restored only if its destination is still what the plan saw. A destination that changed after the plan,
a file that appeared meanwhile, or a file open through the mounted filesystem is reported as a `conflict` and left
alone. Nothing is overwritten that the plan didn't show you.

### Interrupted And Partial Restores

The outcome of each item is saved as the restore runs. A restore that was interrupted, or that finished `partial`,
can be run again with its plan id and token: finished items are kept, and only the rest runs. Running
`vh recovery restore <recovery-id>` again also works: items already restored show as `skip`. The CLI exits `1` when
anything was not restored, and `2` when the restore was refused.

Finished plans are kept for 30 days.

### Permissions

Recovery uses your normal vault permissions; there are no separate recovery permissions.

| Operation | Needs |
| --- | --- |
| See a recovery point | Read (download) on its path, and List for a folder. For a path that no longer exists: Read and List on the nearest existing folder. Points you can't read aren't shown. |
| Take a snapshot | Read and Copy on every file, List on every folder of the tree |
| Delete a snapshot or local version | Delete on its path |
| Plan a restore | Read on every source; items you can't read are left out |
| Restore | Overwrite on each file replaced, Write (upload) for each new file, Touch for new folders, Delete for `--prune` removals |
| Recovery status | Viewing the vault's sync settings |
| Recovery costs and the disclosure | Viewing the vault's sync settings and its pricing statistics (the owner, or an admin role with view and view_stats on the vault) |

Every item is authorized again when the restore runs. Recovery never bypasses file permissions or bucket protection
locks.

## Costs

### What Is Estimated

```bash
vh recovery costs <vault>
```

In the web console: **Vaults → (vault) → Sync & cost → Provider versioning cost**. The report has four parts:

1. **Versioning surcharge**: before activation, what enabling would add. Once active: month to date, projected this
   month, the steady-state monthly cost, the version history held, the write activity behind its growth, the retention
   and the alert.
2. **Current object storage**: context only, never part of the surcharge.
3. **Recovery operations**: restoring one gigabyte by transfer, and one object by provider copy.
4. **Not modelled**: free tiers, taxes, discounts and private pricing, volume tiers beyond the first, storage-class
   transitions, Intelligent-Tiering, replication, and other applications' use of the bucket.

### How It Is Estimated

Each old version is a full copy billed at the storage class rate, so history grows with the bytes you overwrite and
delete. Vaulthalla measures that per vault, per day, from its own requests (first uploads, overwrites and the bytes
they replaced, deletes, version listings and restores), and prices it with the price catalog. Under a retention of R
days history levels off at about R days of that growth; indefinite retention keeps growing, so it is shown after 12
months. Minimum storage durations and object sizes of the storage class are applied.

Every figure is labelled with its basis:

- **observed**: from this vault's measured traffic.
- **illustrative**: no measurements yet, so fixed assumptions (1 %, 5 % and 20 % of current data overwritten per
  month) stand in. They are labelled as such and never presented as your workload.
- **scenario**: a computed case rather than a measurement, such as another retention or the cost of a restore.

Confidence is **high** after 7 or more measured days with a verified, current catalog; **medium** when the catalog's signature
wasn't verified, the catalog is stale, or its versioning rules are missing or unverified; **low** with fewer than 7 days (a range is shown) or illustrative
figures; **none** when it can't be priced. Versions that existed before Vaulthalla measured the bucket are flagged as
history it hasn't accounted for. Measurements are written every minute, so a crash can lose up to a minute of them.

### Unpriced Costs

When there is no price profile for the provider, region and storage class, pricing is turned off, or the catalog bills
versions by a rule Vaulthalla doesn't model, every amount is shown as "cannot be estimated" with the reason. Never
$0.00.

### The Price Catalog

Prices come from the signed price catalog, the same one [price budgets](/cost-control/price-budgets#catalog-freshness)
use. The report shows the catalog version and age, whether its signature was verified, and whether it is stale. An
unverified or stale catalog lowers the confidence and says so.

### Alerts

```bash
vh vault recovery set <vault> --cost-alert 25.00
vh vault recovery set <vault> --cost-alert none
```

When the projected monthly cost passes the threshold, Vaulthalla raises an operator notification, at most one per
vault per day, listed with the other cost notifications in **Cost control**. The amount is in the price catalog's
currency. Alerts never block writes and never suspend versioning.

:::callout[Estimates, not invoices]{variant="info"}
Every figure is computed on this host from its own measurements and the price catalog. No usage data is sent anywhere.
The figures are estimates: your provider's bill is the authority.
:::

## Keys And Rotation

Key rotation re-encrypts a vault's live files but never its recovery data: snapshots, local versions and provider
versions keep the key version they were sealed with. Vaulthalla keeps every retired key version sealed on the host and
refuses to delete one while recovery data references it. `vh vault recovery status` lists the key versions recovery
data still needs, and history marks points sealed under an **older key**, or whose key is **unavailable**.

[Vault key exports](/vaults/secrets-and-key-export#retired-keys-for-recovery-data) include those retired versions under
`historical_keys`. Export again after a rotation.

:::callout[Export keys before deleting a vault whose bucket keeps versions]{variant="warning"}
The export of an already deleted vault carries its current key only, not the retired versions its provider versions
may need. Export the vault's keys before you delete it.
:::

## Troubleshooting

The web console and the ws API report refusals with a stable code; the CLI prints the same message and exits `2`.

| Code or message | Meaning | What to do |
| --- | --- | --- |
| `recovery_versioning_disclosure` | No disclosure token, or it expired or no longer matches (bucket, retention, prices, person, a daemon restart). | Review the disclosure again and confirm. The CLI does this for you. |
| `recovery_versioning_unpriced` | The cost can't be estimated. | Accept the unpriced charges, or fix the price catalog first. |
| `recovery_retention_shorten` | The new retention deletes history sooner. | Confirm, or keep the longer retention. |
| `upstream_adoption` | The vault's bucket is unmanaged. | Accept the adoption (needs `admin.upstream.provision`). |
| `recovery_versioning_suspend`, `recovery_point_delete` | Suspending versioning or deleting a recovery point needs confirmation. | Confirm, or pass `--yes`. |
| `recovery_restore` | The plan's token is missing or wrong. | Restore from the recovery id, or pass the plan's `--token`. |
| `recovery_plan_expired` | The plan is older than 30 minutes. | Plan again. |
| `recovery_unverified_version` | The plan restores versions Vaulthalla didn't write. | Check where they came from, then `--accept-unverified`. |
| "Cloudflare R2 has no object versioning" | Provider versioning on R2. | Use local snapshots or local versioning. |
| "is not enabled for provider administration" | The vault's API key isn't an administrative key. | `vh upstream admin enable <api-key>` |
| "bucket … is protected" | A protection lock. | Remove the lock (`admin.upstream.unprotect`), or leave the bucket alone. |
| "choose how long the provider keeps old versions" | No retention given. | Add `--retention`. |
| "snapshots need the vault's recovery mode to be local_snapshots" | Snapshots are off for this vault. | `--mode local-snapshots` |
| "the snapshot needs N bytes but …" | Snapshot quota or vault space exceeded. | Raise the quota, free space, or snapshot less. |
| "point-in-time restore uses provider versions" | A point-in-time plan in a local vault. | Restore a snapshot or a local version. |
| A local version can't be deleted | It is still waiting to be uploaded. | Let the backlog drain (see the status), then delete it. |
| "has object lock enabled" | Object lock prevents suspension. | None: AWS doesn't allow it. |
| Status shows **propagating** | Within 15 minutes of enabling. | Wait. Versions written meanwhile may not all be kept. |
| An item failed: "a sync pass is running" | Provider restores wait for sync. | Run the restore again shortly. |
| A point is not restorable: "blob missing" | Its stored copy is gone from the host. | Use another point. |
| The backlog keeps a last error | Replays to the bucket fail. | Check the bucket, the key's permissions and the vault's budgets. The next pass retries. |

## Related

- [File Recovery In The Web Console](/web-console/recovery)
- [Command Reference: File Recovery](/cli/command-reference#file-recovery)
- [Managed Upstream Buckets](/vaults/upstream-buckets)
- [Secrets And Key Export](/vaults/secrets-and-key-export)
- [Backup And Recovery](/vaults/backup-and-recovery)
