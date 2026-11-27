## Linked servers (experimental, off by default)

- **Leaving a mirror with its files.** A server that holds a copy of another server's vault can always walk away with
  it as an ordinary vault of its own (`vh mirror detach <vault> [--owner <user>]`), whatever state the copy is in (live,
  stopped, out of step, behind, or orphaned) and with the other server reachable or not; nothing is asked of it, it is
  told when it is next reachable and ends the mirror on its side. `--dry-run` (with `--json` to export) shows first
  what you would get: where the copy left the other server's history, whether it was confirmed identical there, the
  changes made here not yet confirmed (they become ordinary changes), and every file whose contents never arrived.
  Those files stay listed, marked missing: opening one says so and never shows empty or wrong contents. Nothing is
  deleted on either server and no bucket is touched. The detached vault keeps the original's id and keys until the
  re-key pass (a later version), so the two servers won't mirror it with each other again until then. Detaching takes
  a super admin, or the new admin permission "Detach mirrored vaults" (`admin.mirror.detach`), and is audited.
- **Deleting a mirrored vault in one step.** On the server that owns a mirrored vault, `vh vault delete` now asks what
  happens to the linked server's copy (`--mirror-copy remove` or `leave`, no default) and deletes the vault as usual. The
  mirror is kept, read-only, for the restore window (it says why and when); restoring the vault lets it follow again,
  and only the purge ends it with your choice, which you can change until then. The other server still keeps its copy if it is set to keep the
  vaults this server removes. A copy held as another server's vault is never deleted as a vault: detach it first, or
  remove an orphaned one with `vh mirror cancel`.
- **Versions on the mirror, opt-in.** A mirror can keep versions of what the owning server replaces or deletes
  (`vh mirror versions <vault> on [--keep-last N] [--max-age-days D] [--quota-bytes B]`; off by default; 10 versions
  per file for 30 days unless you say otherwise), a safeguard against an unintended deletion over there. They are the
  mirror's own, listed with `vh recovery list`, and restoring one is a change made on the mirror like any other.
- **Held changes can be downloaded.** `vh mirror save <id> <dest>` saves the version of a held write you made.
