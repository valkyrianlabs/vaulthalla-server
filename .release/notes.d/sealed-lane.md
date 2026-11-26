## Folders and linked servers

- **Groundwork for mirroring a vault between two servers: file contents.** A linked server can be sent a file's
  encrypted bytes exactly as they are stored, never decrypted or re-encrypted on the way, and a mirror can receive
  them, check them against the size, hash and vault key it expects, and only then put them in place. Only for a vault
  mirrored between the two servers, and no vault can be mirrored yet, so nothing is sent: the upgrade adds one empty
  table and changes no existing row. There is nothing to do before or after upgrading.
