## Cloud storage

- **Make an S3/R2 vault local again.** `vh vault remote detach <vault> --confirm <vault name>` turns an S3/R2 vault
  into a local vault in place, keeping its ID, keys, permissions, shares and files, with a full copy on this server.
  - In the background, every file without a local copy is fetched from the bucket (checked against the price
    budget), every local copy is verified, and the vault's recovery envelopes are copied from the bucket into the
    server's database. Only then does the vault switch, in one step; until then it stays an S3/R2 vault and syncs as
    before. Files that change meanwhile are checked again.
  - The bucket and every object in it are left as they are: a detach never writes to or deletes from the bucket.
    Earlier versions whose contents only the bucket holds, and trashed files without a local copy, stay in the
    bucket; the status counts them before the switch.
  - Refused, with the vault unchanged, while an attach, a layout migration, a key rotation or a salvage runs, while
    legacy content remains, while event-driven sync is on, or while sync conflicts are open.
  - If anything fails before the switch, run the command again to resume, or abort it with
    `vh vault remote abort <vault> --confirm <vault name>`. `vh vault remote status` follows it; `vh status` shows a
    failed detach as degraded.
  - Provider versioning as the recovery mode becomes local snapshots, and a gateway bucket bound to the vault serves
    it as a local bucket afterwards. Detaching is decided by a person: agents can't start it.
- **Remote storage in the web console.** Vault → Settings → Remote storage attaches a bucket to a local vault (choose
  a credential and an empty bucket), shows the progress, aborts or resumes it, and detaches the bucket from an S3/R2
  vault. Attaching, detaching and aborting ask for a step-up confirmation.
