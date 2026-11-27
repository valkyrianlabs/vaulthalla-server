- Web console: Linked servers page (`/linked-servers`, features/peers) for super admins: the `peer.list` health, rename and unlink, Accept a link (`peer.pairing.open`,
  `.pending`, `.approve` through the device.trust step-up, `.deny`, `.close`) and Link a server (`peer.link.start`
  through the step-up, `.status`, `.cancel`).
- An agent is refused every `peer.*` command (`peer_forbidden`) and `vh peer` stays out of the MCP catalog.
- Linked servers: a link's `compared_by` now records who compared the code, from the channel of the call that made
  it on each side (`desktop` over a full-access device session, `person` from the console or `vh`), instead of
  `desktop` whenever a key was pinned; the `peer.link` audit event carries `pinned` (true when `expect_spki` was
  given).
