## Linked servers and mirrored vaults

- **Upgrading.** Migrations 157 and 160 to 170 add the tables, columns and database triggers linked servers and
  mirrored vaults use, and change no existing row: on a server that links nothing they stay empty (158 and 159 give
  every folder and symlink its permanent id, under "Folders and files"). Every change to a mirrored
  vault is recorded, on its core, in the order it was made; on other vaults a file operation costs one extra lookup
  (under 0.1 ms per write on the test machine), and web uploads' temporary staging files (`.upload-http-*.part`) are
  never recorded. A file's key rotation now takes its locks in a fixed order (no behaviour change). There is nothing
  to do before or after upgrading.
- Account names and emails stay unique among the accounts that sign in on this server. The accounts a linked server's
  people appear as (the owner of a vault it mirrors here, the author of a change) may share a name with a local one,
  and can never sign in, hold an admin role or a global vault policy here.
