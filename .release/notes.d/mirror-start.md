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
- **Cancelling** (`vh mirror cancel <vault>`) works from either side at any step: on the core it ends the mirror and the
  mirror removes the copy it was given; on the mirror it removes a start that has not completed. Removing a completed
  mirror from the mirror's side is refused for now (leaving a mirror with its copy comes later).
- **Key rotation is refused on a mirrored vault** (on both servers) until rotation over the link exists: cancel the
  mirror first.
- `vh mirror list` and `vh mirror info <vault>` show each mirrored vault, this server's role, the linked server, the
  grant and what step a start is at. Like the rest of linking, every command is **experimental and off by default**
  (`peers.experimental: true` in `/etc/vaulthalla/config.yaml`), for a person only (never an agent or a device with
  limited access), and audited (`mirror.offer`, `mirror.accept`, `mirror.decline`, `mirror.keys`, `mirror.start`,
  `mirror.cancel`, `mirror.accept_all.set`), never with key material.

Requires migration 163 (additive: a `mirror_offer` table, the per-link `accept_vaults` setting, and `peer` as a
recorded origin of a key version). Nothing to do before or after upgrading.
