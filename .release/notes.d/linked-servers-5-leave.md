## Linked servers and mirrored vaults

- **Ending a mirror.** `vh mirror cancel <vault>` ends it from either side at any step of a start; on the core it ends
  at once, and the other server is told (when it is reachable again, if it isn't now). By default the other server
  **keeps its copy** as an orphaned copy (read-only); `--remove-copy` asks it to remove the copy, which it does unless
  its link is set to keep the vaults this server removes (`vh mirror keep-removed <server> on`, off by default). A
  copy that was never completed is removed either way. A super admin removes an orphaned copy with `vh mirror cancel
  <vault>`; a live mirror is left with `vh mirror detach` instead.
- **Leaving a mirror with its files.** The server holding a copy can always walk away with it as an ordinary vault of
  its own: `vh mirror detach <vault> [--owner <user>]`, whatever state the copy is in (live, stopped, out of step,
  behind, or orphaned) and whether the core is reachable or not; nothing is asked of the core, which is told when it
  is next reachable and ends the mirror on its side. `--dry-run` (with `--json` to export) shows first what you would
  get: where the copy left the core's history, whether it was confirmed identical there, the changes made here not
  yet confirmed (they become ordinary changes), and every file whose contents never arrived. Those files stay listed,
  marked missing: opening one says so and never shows empty or wrong contents. Nothing is deleted on either server and
  no bucket is touched. The detached vault keeps the original's id and keys, so the two servers won't mirror it with
  each other again; `vh mirror list` lists it as detached, with a re-key recommended.
- **Detaching a copy instead.** `vh mirror detach <vault> --copy [--name <name>] [--owner <user>]` writes a new,
  separate vault from the copy and leaves the copy as it is (it keeps following its core, or stays read-only). The
  new vault has its own id and its own key, every folder, file and symlink with their modes and modification times,
  and none of the trash, versions, shares or access rules. It runs in the background (`--copy --status` shows how far
  it is, `--copy --cancel` stops it), needs room for a second copy (refused up front otherwise), lists exactly the
  files whose contents never arrived (they are left out), and ends with a complete vault or none.
- **Who may detach:** a super admin, or the new admin permission "Detach mirrored vaults" (`admin.mirror.detach`);
  both detaches are audited.
- **Deleting a mirrored vault.** On the core, `vh vault delete` asks what happens to the linked server's copy
  (`--mirror-copy remove` or `leave`, no default) and deletes the vault as usual. The mirror is kept, read-only, for
  the restore window (it says why and until when); restoring the vault lets it follow again, and only the purge ends
  it with your choice, which you can change until then. The other server still keeps its copy if it keeps the vaults
  this server removes. A copy held for another server is never deleted as a vault: detach it, or remove an orphaned
  one with `vh mirror cancel`.
- **Versions on the mirror, opt-in.** A mirror can keep versions of what its core replaces or deletes (`vh mirror
  versions <vault> on [--keep-last N] [--max-age-days D] [--quota-bytes B]`; off by default; 10 versions per file for
  30 days unless you say otherwise), a safeguard against an unintended deletion over there. They are the mirror's
  own, listed with `vh recovery list`, and restoring one is a change made on the mirror like any other.
