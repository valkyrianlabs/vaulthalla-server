## Linked servers and mirrored vaults

- **Mirroring a vault.** `vh mirror add <vault> --to <server>` on the core offers it. Before anything is offered the
  vault is checked, and each problem is refused with its own reason and what to do: it is mirrored or being mirrored
  already, replicated through its bucket (`vh vault join`), a remote attach, detach, layout migration, key rotation
  or key salvage is running, it is scheduled for deletion, it still holds files in a legacy format, a key version is
  missing or not attested by this server, a trashed file from before permanent ids is in its trash, or some files are
  only in its bucket (download them first). On the other server the offer waits for a super admin (`vh mirror
  pending`, `vh mirror accept <offer>`, `vh mirror decline <offer>`), or is accepted at once when that link is set to
  accept every vault from the core (`vh mirror accept-all <server> on`; off by default). The mirror refuses a vault
  whose uid or name it already has, or that would not fit on its disk. Unanswered offers expire after 7 days.
- **Mirroring every vault.** `vh mirror mirror-all <server> on` on the core (off by default) offers that server each
  vault not mirrored yet and each new vault as it is created. An offer it declined, or that ended, is not made again
  until the setting is turned off and on again, and a vault whose checks refuse it is tried again later. With the
  other server's `accept-all` on, mirroring needs nobody on either side.
- **Keys go over the link, proven.** Once an offer is accepted, the core sends every key version the vault needs,
  each wrapped to the mirror's own key, with the core's attestation. The mirror checks each one against the
  attestation key it pinned when the servers were linked; if a single version can't be proven, the whole start is
  refused and nothing is written. Proven keys are sealed under the mirror's own vault master, with where they came
  from recorded, and never appear in a log, an audit entry or an error.
- **The first copy, then every change.** The mirror creates the vault with the core's vault id, owned by the core's
  owner (shown as an account of the other server), copies its tree and then follows every change in the order it
  was made, checking after each step that its copy matches the core's exactly; a copy that no longer matches stops,
  with the reason. File contents travel as the encrypted bytes the core stores, never decrypted or re-encrypted on
  the way, and are checked against the size, hash and key the mirror expects before they are put in place. Contents
  that have not arrived yet are fetched in the background; opening such a file waits for it briefly and then says
  why it can't be read (the link is down, it is still on its way, it failed), never showing empty or wrong contents.
- **Who uses the mirror.** Nobody on the mirror can use the vault until the core says what it grants; after that the
  mirror's super admins get exactly that role, and no local role, group, admin role, vault policy or ownership gives
  access to it there. Its access list is shown read-only, marked as the other server's.
- **Working in the mirror.** While the link is up, a person allowed to change the vault can work in it on the mirror
  through the mount, the web console, uploads, `vh fs put`, shares and the S3 gateway: creating folders and files,
  writing, renaming, moving, deleting, and changing a file's mode or time. They see the change at once; the core
  checks it, carries it out as that person and sends it back, and both copies stay identical. When the core refuses
  (the name was taken there meanwhile, the file changed there, or the change is not allowed), nothing is lost: it
  becomes a copy named "name (conflict ...)" or a **held change** with the reason (`vh mirror held`, `vh mirror retry
  <id>`, `vh mirror discard <id>`, `vh mirror save <id> <dest>` to download your version). A file open for writing
  when the link drops is kept and sent when the link returns. A copy made on the mirror appears when the core has
  made it; owners and symlinks are changed on the core only.
- **When a mirror is read-only.** While the link is down, during the first copy, while a copy is stopped, paused or
  switching, and for an orphaned copy, nothing can change the vault on the mirror, by anyone, through any way in: the
  mount answers "Read-only file system", the console and `vh` refuse with `read_only` and the reason, uploads and
  text saves answer 503 with `Retry-After`, `vh fs put` exits with code 69, and share uploads, the S3 gateway (503
  `ServiceUnavailable`), restores, the vault's settings and attaching a remote refuse. Changes from the core keep
  arriving. The vault's settings, keys and remote are always the core's, and changed there. Background work (format
  conversion, local versioning and its retention, key rotation, the trash purge) leaves a mirror's copy alone.
- **Key rotation on a mirrored vault.** `vh vault keys rotate` works on the core while the vault is mirrored: the
  core first sends the new key version to the mirror, proven the same way, and rotates only once the mirror has it;
  if the mirror is not live, its link is down or it refuses the key, nothing is rotated and the refusal says what to
  do. The mirror switches to the new version when the core's changes say so and fetches the re-sealed files like any
  other change; the old version stays on both servers, so files still sealed under it stay readable until their new
  bytes arrive. Rotating on the mirror's side, and key salvage on a mirrored vault, are refused.
- **Status.** `vh mirror list` and `vh mirror info <vault>` (and ws `mirror.list`, `mirror.get`) show each mirrored
  vault, this server's role, the linked server, the grant, the state with its reason, the first copy's progress,
  whether the link is up, the changes not confirmed yet, when the last position was acknowledged, and the settings
  that apply (a mirror's versions, and this server's accept-all, keep-removed and mirror-all for that server).
  Everything is audited (`mirror.offer`, `mirror.accept`, `mirror.keys`, `mirror.start`, `mirror.cancel` and the
  rest), never with key material.
