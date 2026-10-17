<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# File recovery: snapshots, local versioning and provider versioning

Vaulthalla can now bring back earlier versions of files and folders. Each vault chooses a recovery preference in
**Vault settings → Recovery** or with `vh vault recovery set <vault> --mode …`:

- **Local snapshots.** Explicit, named recovery points of a file or a whole folder, taken with **Recovery history →
  Create snapshot** or `vh snapshot create <vault> <path> --name …`. Snapshots are stored encrypted, deduplicated (an
  unchanged file costs nothing twice), count against an optional snapshot quota and the vault quota, and survive the
  deletion of the files they captured. Nothing is ever snapshotted automatically.
- **Provider versioning (AWS S3).** For S3 vaults, the bucket itself keeps every version. Vaulthalla turns versioning
  on only after showing an estimate of what it will cost — **Provider Versioning — Estimated Monthly Cost** — and
  after you acknowledge it (and, when costs can't be estimated, a separate acknowledgement of unpriced recurring
  charges). AWS versioning can't be undone, only suspended; Vaulthalla says so before you enable it, never suspends it
  on its own, and never deletes old versions when you remove a vault. You choose how long old versions are kept
  (30, 90 or 365 days, or indefinitely). Cloudflare R2 doesn't support object versioning and is refused.
- **Local versioning** (optional, any vault). Every change to a file keeps its previous version on this server, with
  limits you set (keep the last N, a maximum age, a size quota). For S3 vaults these versions also queue up while the
  provider is unreachable and are sent in order once it is back, so a versioned bucket ends up with the full history.

**Recovery history.** Right-click a file or folder in the web console (or `vh recovery list <vault> <path>`) to see
its snapshots, local versions and provider versions. Restoring always shows a preview first — what will be created,
overwritten or skipped, and what it costs — and asks you to type RESTORE before anything is overwritten. A folder can
be restored to a point in time from provider versions; that is a reconstruction from each file's version timestamps,
not an atomic snapshot, and the preview says so. Restoring from the provider in a smart-cache vault copies the old
version inside the bucket: nothing is downloaded to list versions and nothing is uploaded twice.

**Costs you can see.** The cost panel in **Sync & cost** and `vh recovery costs <vault>` show the estimated monthly
versioning surcharge, month to date, the 30-day forecast, how much history is retained, and what drives its growth.
Estimates are computed on this server from its own measurements and the signed price catalog — no usage is sent
anywhere — and they are labelled as estimates, not invoices. You can set a monthly threshold; going over it raises a
notification and never blocks writes.

**Fixes.** Editors can save over files on the mount again (renaming a temporary file over the original failed with an I/O error); with local versioning on, the version the save replaces is kept. Vault keys load again after a restart in the middle of a key rotation. S3 bucket listings past 1,000
objects no longer fail their signature. Deleting a folder no longer leaves its subfolders cached. A sync pass whose
bucket listing fails part-way now stops instead of working from a partial view, and S3 vaults with more than 1,000
objects index all of them. Unsent versions of a deleted file no longer stay pending in `vh vault recovery status`:
maintenance sends them to a versioned bucket (the file stays deleted) or drops them where there is no history to keep.
