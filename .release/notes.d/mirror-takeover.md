## Folders and linked servers

- **Mirrored vaults: taking over when the main server is gone.** If the server a vault is mirrored from stops for
  good, a super admin on the copy can make that server the vault's main one: `vh mirror takeover <vault> --confirm
  <vault name>`. Changes made on the copy that were still waiting become ordinary changes there; changes the other
  server had refused stay listed for a super admin. The command warns that the old server may hold changes this one
  never received; it is refused while the old server still answers (use `vh mirror switch` then). It is also the way
  out of a switch whose other server never came back, which `vh mirror info` now explains. Behind the experimental
  linked-servers switch; the upgrade adds two tables.
