## Linked servers (experimental, off by default)

- **Mirror every vault to a linked server.** On a vault's core, a super admin can now set a link to receive every
  vault this server owns: `vh mirror mirror-all <server> on` (ws `mirror.mirror_all.set`; off by default). Each vault
  that is not mirrored yet is offered to that server, and each new vault as it is created. An offer the other server
  declined, or that ended, is not made again unless the setting is turned off and on again, and a vault whose checks
  refuse it is tried again later. Turning it on sends vaults' keys, so the web console asks for the same keys step-up
  as `mirror add`. With the other server's `vh mirror accept-all` on, mirroring is fully automatic.
