## Security

- **Restore a vault from its bucket and your recovery kit: `vh vault recover`.** When the server that ran an S3 vault is
  gone (its database, its TPM, everything), a new Vaulthalla server you run rebuilds the vault from the vault's bucket
  and your recovery kit (or a key export): files, folders, names, the trash, provider versions, snapshot records and
  every key version. No account or payment is needed, and nothing goes anywhere but your server and your bucket.
  `--dry-run` shows what a restore would do and writes nothing; the restored vault downloads a file only when it is
  read. See *Restore A Vault From Its Bucket* in the key export docs.
- **Only keys your material proves come back.** A key version is restored only when the original server's signature
  of it verifies against a signing key your kit (or export) pins; the new server's own keys never count, and a key
  someone planted in the bucket is ignored. Anything that can't be proven stops the restore, and `--salvage`
  re-encrypts what the supplied keys decrypt under a new key, without storing them. The kit's checkpoint protects
  against a bucket that presents an older state of the vault (`--accept-rollback` to restore it anyway).
- **New encrypting S3/R2 vaults use opaque storage.** Your storage provider only ever sees encrypted, opaquely named
  objects. It can't see your file names, folders or contents. It can see how many objects you store, their sizes and
  when they change. Vaults created before this release keep their current layout (names visible to the provider) until
  you migrate them with `vh vault migrate-layout` (below); nothing changes for them on upgrade.
- Pin each vault in your kit (`vh vault keys status <vault> --json`, then `vh-recovery kit add-vault`) and refresh it
  after a restore: the restored server signs the key versions it creates with its own key.

### Restore drill (release gate for opaque storage)

The catastrophic restore drill of design spec 03 §7 passed on 2026-11-06 (`vhh drill recover`, fake S3 with
versioning): node A wrote 2,000 files (2,123 entries: nested folders, 0-byte, small and multipart-sized files, a
symlink, renamed files and folders, a purged file, overwrites, 5,920 provider versions, a snapshot, two key rotations,
a recovery recipient enrolled after the first, an export before the second, a checkpoint, an abandoned multipart
upload); node A's daemon, database, swtpm state and backing store were destroyed; node B, with its own database and
swtpm, restored the vault from the bucket and the kit in 4.2 s with 19 requests and 0 content bytes (2.8 MB of
manifest, 450 bytes of envelopes): every file's path, kind, size, mode, mtime, symlink target and bytes equal node A's,
key versions 1-3 verified against the kit's pinned key and shown with their origin, freshness verified against the
checkpoint; the restored vault rotated to version 4 and synced; a second restore on node C proved node A's versions
with the original kit and all four with a kit refreshed from node B. 30/30 checks, including the negative drills:
deleted root (versioned → the newest retained root; unversioned → blind rebuild under /Recovered), corrupt segments,
rollback refused against the checkpoint and accepted explicitly, wrong seed, a kit for another vault, an export alone
after a rotation (the later version reported missing, never invented), and kits with no, another node's or the
restoring node's own attestation keys (salvage only).

The same drill ran live on Cloudflare R2 the same day (`tools/harness/drill_recover_r2.sh`, 300 files, nodes A, B and C
as independent private instances on one host, bucket `vh-test-recover-drill` deleted afterwards): 16/16 checks; the
restore took 5.8 s and read 0 content bytes (469 kB of manifest) before the first file read, key versions 1-3 verified,
freshness verified.
