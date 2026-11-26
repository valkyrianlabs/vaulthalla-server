## Folders and linked servers

- **Groundwork for mirroring a vault between two servers: the first copy and following.** A server holding a mirror
  of another server's vault can now copy that vault's tree and then follow every change, checking after each step that
  its copy matches the other server's exactly and stopping that vault, with the reason, when it does not. All of it is
  behind the experimental linked-servers switch, and no vault can be mirrored yet (starting a mirror is the next
  piece), so nothing runs on an upgraded server: the upgrade adds one empty table and a few columns, and a file's key
  rotation now takes its locks in a fixed order (no behaviour change). There is nothing to do before or after upgrading.
