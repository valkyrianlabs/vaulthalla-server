## Cloud storage

- **Give a local vault a bucket.** A vault created as a local vault can now become an S3/R2 vault in place:
  `vh vault remote attach <vault> --api-key <key> --bucket <name>`. The vault keeps its ID, keys, permissions, shares
  and files; its content is uploaded as encrypted objects under opaque names, and it then syncs like any S3/R2 vault.
  - The vault stays local and in use while the upload runs in the background, and the upload continues after a
    restart. Files that change meanwhile are sent again. Every object is verified, the vault's encrypted manifest is
    published and read back from the bucket, and only then does the vault switch to its bucket in one step. It starts
    in the `cache` sync strategy with every file still on disk.
  - The attach is refused, with the vault unchanged, unless the bucket is empty (every object version and delete
    marker counts) and unused by another vault, the bucket can hold the manifest (it is probed first), the vault holds
    no content in the legacy format (`vh vault format status`), no key rotation or salvage is running, and the vault
    has recovery material that doesn't depend on this server: a recovery recipient or an export of its current key.
  - `vh vault remote status <vault>` shows the state, the progress with the rate and the time left, the cost estimate
    and the last error; `vh status` shows a failed attach as degraded. The cost is checked against the price budget
    first (`--accept-unpriced` when the provider can't be priced).
  - If anything fails before the switch, the vault is still local and nothing of it changed: run the command again
    with the same API key and bucket to resume, or `vh vault remote abort <vault> --confirm <vault name>` to delete
    what was uploaded (only what the attach wrote, each object by its recorded version) and free the bucket.
  - A key rotation asked for during an attach waits until it has ended. Snapshots and local versions from before the
    attach stay local recovery points; the bucket's history starts with the attach. A gateway bucket bound to the
    vault serves it as a cached remote afterwards.
  - Attaching a bucket is decided by a person: agents can read the status but can't start an attach. From the web
    console and paired devices, attach and abort ask for a fresh sign-in confirmation (step-up).
  - `vaults.remote_attach.max_passes` (default 3) in `config.yaml` bounds how often changed files are sent again
    before the switch. There is no way back from S3/R2 to a local vault yet.
- **Recovery recipients on local vaults.** `vh vault keys recipient add` now works on a local vault. A local vault
  has no bucket, so its key envelopes are kept in the server's database; they restore its keys on the same host
  (`vh vault keys import --recovery-kit`) and are copied into the bucket when one is attached. They don't replace a
  backup of a local vault, whose files exist only on this server's disk.
