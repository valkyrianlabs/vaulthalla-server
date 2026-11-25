## Folders and linked servers

- **Permanent ids for every folder and symlink.** Every folder, symlink and snapshot of every vault, local or cloud,
  now has a permanent id from the moment it is created, the groundwork for mirroring a vault between two Vaulthalla
  servers. The upgrade gives one to every existing folder, symlink and snapshot in the same transaction as the schema
  change and changes nothing else: no account, file or folder is modified, no change-journal entry is written, and
  every id an encrypted bucket vault already published in its manifest stays as it is. There is nothing to do before
  or after upgrading.
- Account names and emails stay unique among the accounts that sign in on this server. Accounts that belong to a
  linked server, which a later release adds for attribution, may share a name with a local one, and can never sign
  in, hold an admin role or a global vault policy here.
