## Security

- **Recovery kits and recovery recipients for S3 vaults.** Create a recovery kit on your own computer with the new
  offline tool `vh-recovery kit create`, then enroll its public key on a vault with
  `vh vault keys recipient add <vault> --public-key <key>`. Vaulthalla wraps every key version of the vault to that key,
  now and at every future rotation, and stores the wrapped keys in the vault's own bucket (`.vaulthalla/key/`), so a
  rotation no longer leaves the newest key on the host alone until you export again. A rotation writes the new
  version's wrapped key before the new key encrypts anything; if the bucket can't be reached, the rotation doesn't
  start.
- **Recovery stays under your control.** The server only receives the public key; the kit's seed never leaves your
  device, wrapped keys go to the vault's bucket and nowhere else, and Valkyrian Labs receives no recovery keys or
  decryption authority. No account, payment, subscription or upgrade enrolls a recipient. `vh vault keys recipient
  list|revoke` show and revoke recipients; revoking stops new wrapped keys, and status tells you when a key rotation is
  needed to cut a revoked recipient off from new data. Enrolling and revoking work from the local `vh` CLI (and from a
  paired device once device approvals arrive), never from the web console or an agent.
- **`vh vault keys import <vault> --recovery-kit <kit>`** restores a vault's keys from its bucket after this host's
  vault master was lost. Only key versions this server's own records and signatures prove the vault had are restored;
  anything else in the bucket is ignored.
- **New health warning: `recovery_material_missing`.** A self-hosted S3 vault that encrypts its bucket and has neither
  a recovery recipient nor an export of its current key version now shows as degraded in `vh status`, the console's
  health and `vh vault keys status`. After upgrading, existing vaults without a current export show this until you
  enroll a recipient or export the keys (`vh vault keys export`). A key rotation makes an export stale.
- Key exports now include each signing key's public key (`attestation.public_key`). Older exports still import on the
  server that made them.
