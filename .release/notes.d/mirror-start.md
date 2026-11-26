## Linked servers (experimental, off by default)

- **Starting a mirror of a vault.** A server can offer one of its vaults to a linked server
  (`vh mirror add <vault> --to <server>`); it stays the vault's **core**, and the other server becomes its
  **mirror**. Before anything is offered, the vault is checked and each problem is refused with its own reason and
  what to do: it is mirrored or being mirrored already, replicated through its bucket (`vh vault join`), a remote
  attach, detach, layout migration, key rotation or key salvage is running, it is scheduled for deletion, it still
  holds files in a legacy format, a key version is missing or not attested by this server, a trashed file from before
  permanent ids is in its trash, or some files are only in its bucket (download them first). On the other server the
  offer waits for a super admin (`vh mirror pending`, `vh mirror accept <offer>`, `vh mirror decline <offer>`), or is
  accepted at once when its link is set to accept every vault from that server (`vh mirror accept-all <server> on`;
  off by default). The mirror refuses a vault whose uid or name it already has, or that would not fit on its disk.
  Unanswered offers expire after 7 days.
- **Keys go over the link, proven.** Once accepted, the core sends every key version the vault needs, each wrapped to
  the mirror's own peer key, with the core's attestation. The mirror checks each one against the attestation key it
  pinned when the two servers were linked; if a single version can't be proven, the whole start is refused and
  nothing is written. Proven keys are sealed under the mirror's own vault master, with where they came from recorded.
  The mirror then creates the vault, with the same vault id as the core's, owned by the core's owner (shown as an
  account of the other server), and empty until its contents are copied (a later step). Nobody on the mirror can use
  it until the core says what it grants; after that, the mirror's super admins get exactly that role, and the grant
  follows every change on the core (`vh peer policy set`, `vh vault role assign ... --peer`, the role's permissions).
- **Ending a mirror.** `vh mirror cancel <vault>` ends it from either side at any step. On the core it ends at once,
  and the other server is told (when it is reachable again, if it isn't now). By default the other server **keeps its
  copy** as an orphaned copy (read-only); `--remove-copy` asks it to remove the copy, which it does unless it was set to
  keep the vaults this server removes (`vh mirror keep-removed <server> on`, off by default). A copy that was never
  completed is removed either way. `vh mirror info` on the core shows what the other server did. A super admin on the
  other server removes an orphaned copy with `vh mirror cancel <vault>`; a mirror that is still live can't be removed
  from that side (leaving a mirror with its copy comes later). Unlinking the two servers keeps every copy as an
  orphaned copy and drops a removal that was not delivered yet.
- **A mirrored vault can't be deleted** on either server until its mirror is ended (`vh mirror cancel` first), and an
  orphaned copy is removed through `vh mirror cancel`, not `vh vault delete`.
- **Key rotation is refused on a mirrored vault** (on both servers) until rotation over the link exists: cancel the
  mirror first.
- `vh mirror list` and `vh mirror info <vault>` show each mirrored vault, this server's role, the linked server, the
  grant and what step a start is at. Like the rest of linking, every command is **experimental and off by default**
  (`peers.experimental: true` in `/etc/vaulthalla/config.yaml`), for a person only (never an agent or a device with
  limited access), and audited (`mirror.offer`, `mirror.accept`, `mirror.decline`, `mirror.keys`, `mirror.start`,
  `mirror.cancel`, `mirror.cancel.copy`, `mirror.remove`, `mirror.orphan`, `mirror.accept_all.set`,
  `mirror.keep_removed.set`), never with key material.

Requires migration 163 (additive: a `mirror_offer` table, the per-link `accept_vaults` and `keep_vaults` settings,
and `peer` as a recorded origin of a key version). Nothing to do before or after upgrading.
