- Web console: Linked servers page (`/linked-servers`, features/peers) for super admins, experimental and shown only
  while `peers.experimental` is on: the `peer.list` health, rename and unlink, Accept a link (`peer.pairing.open`,
  `.pending`, `.approve` through the device.trust step-up, `.deny`, `.close`) and Link a server (`peer.link.start`
  through the step-up, `.status`, `.cancel`).
- ws `peer.status` (read; super admins, the same callers as the other `peer.*` management commands) answers
  `{enabled}`: the one `peer.*` command that doesn't refuse with `peers_experimental` while the switch is off, so a
  console or Desktop can leave linked servers out. Additive; an agent is refused (`peer_forbidden`, as for every
  `peer.*` command) and `vh peer` stays out of the MCP catalog.
