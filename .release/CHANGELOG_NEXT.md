<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->

- fix(vault): a restart during an unfinished key rotation could not load the vault's key
  (`get_rotation_old_vault_key` selected `*` from `vault_keys_trashed`, which has no `updated_at`); regression test
  `VaultKeyRestartDbTest`.
