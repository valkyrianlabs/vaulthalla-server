## Folders and linked servers

- **Mirrored vaults: changes made on the mirror.** On a server that holds a mirror of another server's vault, a person
  allowed to change it (within what the vault's own server grants) can now create folders, rename, move and delete
  while the link is up: they see the change at once, the vault's own server carries it out as that person and sends it
  back, and both copies stay identical. When the other server refuses (the name was taken there meanwhile, or the
  change is not allowed), nothing the person did is lost: a name clash becomes a copy named "name (conflict ...)", and
  anything else is kept aside as a held change with the reason, while the entry goes back to the other server's state.
  A copy made on the mirror is carried out by the vault's own server and appears when it comes back. Uploads and file
  contents written on a mirror are not part of this yet. All of it is behind the experimental linked-servers switch;
  the upgrade adds four empty tables and nothing runs on a server that mirrors nothing. There is nothing to do before
  or after upgrading.
