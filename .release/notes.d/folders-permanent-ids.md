## Folders and files

- **Permanent ids for every folder and symlink.** Every folder, symlink and snapshot of every vault, local or cloud,
  now has a permanent id from the moment it is created (mirrored vaults name every entry by it). The upgrade gives
  one to every existing folder, symlink and snapshot in the same transaction as the schema change and changes nothing
  else: no account, file or folder is modified, no change-journal entry is written, and every id an encrypted bucket
  vault already published in its manifest stays as it is. There is nothing to do before or after upgrading.
- **`chmod`, `chown` and `touch` through the mount are recorded.** They used to change only the file on disk and were
  lost on the next refresh; they are now stored with the file, a mode change never moves its modification time, and a
  change of owner or group needs a super admin.
- **`vh fs put` no longer reports a file as stored when someone else created it first**; it says the path was created
  meanwhile. A missing file is now reported as missing (`not_found`) to someone who may see the folder it would be in,
  and as a permission refusal to anyone else.
