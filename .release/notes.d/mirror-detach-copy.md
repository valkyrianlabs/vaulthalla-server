## Linked servers (experimental, off by default)

- **Detach a copy.** A server holding a copy of another server's vault can now write a new, separate vault of its own
  from it and leave the copy as it is (`vh mirror detach <vault> --copy [--name <name>] [--owner <user>]`): the copy
  keeps following its owning server (or stays read-only), and the new vault has its own id and its own key, every
  folder, file and symlink with their modes and modification times, and none of the trash, versions, shares or access
  rules. Nothing is asked of the other server, which may be unreachable. It runs in the background
  (`--copy --status` shows how far it is, `--copy --cancel` stops it), needs room for a second copy (refused up front
  otherwise), lists exactly the files whose contents never arrived (they are left out), and ends with a complete vault
  or none. The same permission as detaching ("Detach mirrored vaults"); audited.
