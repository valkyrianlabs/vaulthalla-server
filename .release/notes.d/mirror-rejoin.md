## Folders and linked servers

- **Mirrored vaults: the old main server learns it was replaced.** When a server that was taken over comes back, it
  stops taking changes to the vault at once. If it made no changes since, it simply becomes the copy of the new main
  server. If it did, it keeps them and stays read-only, and `vh mirror info` on both servers says how many changes the
  new main server never received; `vh mirror resync` on the old one brings it back, keeping those changes aside for a
  super admin (merging them automatically is the next step). If both servers took over while cut off, both stay
  read-only until you pick the one to keep.
