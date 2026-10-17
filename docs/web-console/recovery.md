---
title: File Recovery In The Web Console
navTitle: File Recovery
description: Browse a file's or folder's recovery history, preview and run restores, create snapshots, and turn on local versioning or S3 provider versioning with its cost disclosure from the web console.
order: 126
status: published
tags:
  - web
  - web-console
  - recovery
  - snapshots
  - versioning
---

# File Recovery In The Web Console

The web console exposes the same file recovery operations as `vh snapshot`, `vh recovery` and `vh vault recovery` (see [File Recovery](/cli/command-reference#file-recovery)). The daemon decides what you can see and do, with your normal vault permissions. The console only shows its answers. How each kind of history works, what it costs and what the refusals mean is in [File Recovery](/vaults/recovery).

:::toc[On this page]{depth="3" theme="compact"}
:::

## Where Recovery Points Come From

| Kind | What it is | Where it lives |
| --- | --- | --- |
| Snapshots | Named recovery points of a file or folder that someone created | Encrypted on this server; they count against the vault quota |
| Local versions | The previous contents of a file, kept each time its contents changed (when local versioning is on) | Encrypted on this server |
| Provider versions | Object versions kept by an AWS S3 bucket with versioning enabled | In the bucket; Vaulthalla stores only their metadata |

## Recovery History

In **Files**, right-click a file or folder (or use its ⋯ menu) and choose **Recovery history…**. A file preview also has a **History** button. Share links never offer this.

The sheet groups recovery points into **Snapshots**, **Local versions** and **Provider versions**. Each point shows its time, size, why it was kept, its retention and badges:

- **Current**: the provider's current version of the object.
- **Delete marker**: the provider recorded a deletion at this time.
- **Pending upload**: a local version still waiting to be replayed to the bucket. It can't be deleted until it has been sent.
- **Not written by Vaulthalla**: a provider version found in the bucket that Vaulthalla didn't write.
- **Older key** / **Key unavailable**: the encryption key version the point was sealed with.
- **Not restorable**, with the reason.

Provider versions also show their estimated monthly cost. When the cost can't be estimated, the console says "not estimated" and never shows $0.00.

**Check provider for versions** asks the bucket which versions it holds for the path. It lists metadata only and downloads no file contents. Its LIST requests count against the vault's request budget.

When the vault's recovery mode is **Local snapshots**, **Create snapshot** captures the file or folder as it is now. The snapshot name is optional. You can delete snapshots and local versions. Provider versions are removed only by the bucket's retention.

## Restoring

Click **Restore…** on a point. Leave **Restore to** empty to restore over the original path, or enter another vault path to restore a copy there. For folders in S3 vaults, **Restore this folder to a point in time** takes a date and time in your browser's time zone and rebuilds the folder from provider versions. You can also choose to remove files that didn't exist at that time. In a local vault the preview refuses it: restore a snapshot or a local version instead.

Neither action changes anything yet. Vaulthalla first makes a plan, and the **Restore preview** shows it:

- every item, with its action (create, overwrite, skip, conflict, remove or unavailable), source, destination, size and method,
- the counts of each action,
- the consistency note. A point-in-time restore is always labelled "a timestamp-based reconstruction from per-object version times, not an atomic snapshot",
- the estimated provider cost, or "cannot be estimated" and why,
- warnings, and blockers. A plan with blockers can't run.

:::callout{theme="warning" title="Overwrites and removals need RESTORE"}
When a restore would overwrite or remove existing files, you have to type `RESTORE` to confirm it. A restore that only creates files asks a plain yes/no question.
:::

Restoring a provider version that Vaulthalla didn't write needs a separate acknowledgement. Plans are valid for 30 minutes. If a plan expires before you restore, the console makes a fresh plan and shows it again, and nothing runs until you confirm the fresh plan. After the restore you see the outcome of each item. A **conflict** means the destination changed after the plan was made, so it was left alone.

## Vault Recovery Settings

**Vaults → (vault) → Settings → Recovery** shows the vault's recovery status and lets you change it:

- **Mode**: Off, Local snapshots or, for S3 vaults, Provider versioning. Provider versioning is disabled with the reason when the provider doesn't support it (Cloudflare R2, for example) or when your role lacks `admin.upstream.configure`. Leaving Provider versioning doesn't suspend the bucket's versioning.
- **Provider versioning**: the bucket, region, storage class, versioning status (including "propagating" until AWS has applied it to every write), whether Vaulthalla enabled it, object lock, MFA delete, retention, the effective expiry of replaced versions and lifecycle rules from other applications. When the bucket is versioned while the vault's mode is something else, the panel says so. **Suspend versioning** stops new versions and deletes nothing.
- **Snapshots**: their count and storage, and an optional snapshot quota.
- **Local versioning**: on or off, how many versions to keep per file, a maximum age and a quota. An empty field means no limit.
- **Upload backlog**: local versions waiting to be replayed to the bucket, and the last error.
- **Retained key versions** that recovery data still needs.
- **Versioning cost alert**: a monthly threshold for operator notifications. Alerts never block writes.

Shortening the retention asks for confirmation first, because the provider permanently deletes older versions sooner. Adopting the vault's own unmanaged bucket also asks first.

## Turning On Provider Versioning

1. Choose **Provider versioning**, then choose a retention: 30 days, 90 days, 365 days or indefinitely. There is no default.
2. Click **Review costs and enable…**. The **Provider Versioning — Estimated Monthly Cost** disclosure opens. It shows:
   - the provider, bucket, region and storage class,
   - the vault's current data size and its measured write traffic,
   - the estimated additional monthly storage, with its range and basis. Figures from your measured workload are kept separate from illustrative assumptions,
   - the projected version history over 12 months and the four retention scenarios,
   - the confidence of the estimate and the price catalog's freshness and verification,
   - what isn't included in the estimate, and the cost of recovery operations,
   - the consequences. On AWS, versioning can only be suspended once it is enabled. It can take up to 15 minutes to apply to every write. Retention permanently deletes older versions.
3. Tick every acknowledgement. When the costs can't be estimated, the dialog says **Costs cannot be estimated** and adds a separate acknowledgement for unpriced recurring charges.
4. Click **Enable provider versioning**. If the disclosure expired or its figures changed, the console fetches it again and asks you to acknowledge it again.

## Recovery Costs

For S3 vaults, **Vaults → (vault) → Sync & cost** shows a **Provider versioning cost** panel, labelled "Estimates, not provider invoices". Its four sections match `vh recovery costs`:

1. **Versioning surcharge**: before activation, what enabling would add. Once active: month to date, projected this month, the next 30 days, the version history held (with a note when the bucket holds versions from before Vaulthalla started measuring), the write activity behind the growth, the retention and the cost alert.
2. **Current object storage**: context only. It isn't part of the surcharge.
3. **Recovery operations**: the estimated cost of restoring a gigabyte and a single object.
4. **Not modelled**: account-level items the estimate leaves out, and its assumptions.

The **Cost control** overview links to each S3 vault's panel. It doesn't add the vault estimates together, because each one has its own basis and confidence.
