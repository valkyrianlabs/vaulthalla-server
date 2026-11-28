## Linked servers and mirrored vaults

- **Reconnecting a vault two servers once mirrored.** When a mirror ended but both servers still hold the vault (one
  detached it, the core ended the mirror or the servers were unlinked and linked again, or an old core stopped after a
  take over), `vh mirror relink <vault> --with <server>` on either server compares the two copies entry by entry: what
  only one holds, and what both hold and changed on this side, the other or both since they last agreed. Then either
  keep one server's files everywhere (`--keep this` or `--keep theirs`, with `--confirm <vault name>`), or go through
  the changes (`--review`, `--choose`, `--apply`): for each entry keep this server's version, the other's, or both
  (the second as a conflict copy beside the first). The server whose files win becomes the vault's core and the other
  its mirror again. Nothing is dropped: whatever the losing side had that differs is kept as a held change with its
  bytes (`vh mirror held`), a conflict copy, or in the core's trash. A plan is refused once either copy changes under
  it (compare again), and while either server has changes waiting, a switch or a start running, or is deleting the
  vault. Super admins only; the console's Reconnect action on a detached, orphaned, rejoining or forked vault does the
  same, after confirming your identity. Both servers must hold the same keys for the vault: a relink moves no keys.
