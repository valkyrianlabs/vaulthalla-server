- Encrypted manifest (opaque_v1 vaults): a root another server published is now applied to this server's database,
  view and change journal (`sync::vault_manifest::Applier`) instead of being recorded without its content, and a
  publish that meets such a root applies it and publishes again instead of merging in memory. A vault's recorded root
  advances only by an apply or by its own publish. A solo vault's pass still costs one HEAD of the root when nothing
  moved. Replicated vaults remain unsupported.
- A root this server published but did not record (a crash or a database failure between the two) is recognized as its
  own at the next pass and recorded, never applied as another server's: local changes made since are kept.
- Migration 146: `remote_manifest_state.publishing_root_sha256` (the last root this server sent) and
  `manifest_apply_deferred` (changes waiting for an open file to close). Additive and idempotent.
- New audit event `manifest.applied`.
