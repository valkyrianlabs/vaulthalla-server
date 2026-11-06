## Security

- **Move older S3/R2 vaults to opaque storage: `vh vault migrate-layout`.** Encrypting vaults created before this
  release name each object after the file's path, so your storage provider sees file and folder names. Migrating one
  re-seals every object, every version your provider keeps and every pending upload under random ids in the newer
  encrypted format, under the same keys (not a key rotation). Afterwards the provider sees what it sees for new vaults:
  encrypted, opaquely named objects, their count, sizes and change times. Nothing migrates on upgrade: you start each
  vault yourself (`vh vault migrate-layout <vault>`), it runs in the background, and the vault's files stay readable and
  writable meanwhile (its sync waits until the migration is done). See *Migrating A Vault To Opaque Storage* in the
  encryption docs.
- **Every byte stays recoverable.** Each new object is authenticated before it is uploaded, the provider has to prove
  it holds exactly those bytes (or it is read back and decrypted), and a sample is always read back. If anything fails
  before the switch, the vault stays as it was and nothing is deleted: run the command again to resume. The cost is
  estimated and checked against your price budget before anything is written (`--accept-unpriced` when it can't be
  priced). The migration needs recovery material that doesn't depend on the server: a recovery recipient or a current
  key export.
- **The old objects go only when you say so.** They stay untouched in the bucket for 7 days after the switch
  (`vaults.layout_migration.cleanup_wait_days`). Then `--cleanup` lists what would be deleted and
  `--cleanup --confirm <vault name>` deletes exactly those versions, one by one. A bucket with a protection lock is
  never cleaned, and a version under Object Lock retention or a legal hold stays until its date. Versions that can't be
  migrated (an archive storage class, a key this server doesn't hold, another application's object) are kept and
  listed with the reason; the migration says `complete` only when no path-named object, version or delete marker is
  left.
- The server's health now reports `legacy_content`: whether any content in the earlier format is left on this server.
  A later release will refuse to upgrade while it is.
- Once a vault has been migrated, downgrading the package below this release is unsupported: earlier releases can't
  read opaque storage.
