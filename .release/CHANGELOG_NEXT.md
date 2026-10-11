<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
## Identities
- identities::Manager owns one canonical User/Group object per id and publishes immutable states into it
  (atomic shared_ptr); readers take one state per check, user+group views are coherent across a publication.
- Identity and RBAC writes (users, groups, memberships, vault role assignments, overrides, role templates) commit,
  reload what they touched in one snapshot and publish before returning; ops/auth/seed/CLI paths go through it.
- Migration 108: identity_revision counter and identity_change_log maintained by triggers (NOTIFY vh_identity);
  the daemon polls it every second to apply out-of-band changes; a state never replaces a newer one.
- Batched identity loader: any number of accounts and groups in ~8 statements, no group member lists, no
  password hashes; credential checks use a dedicated query.
- FUSE: the caller and vault owner come from memory; deactivated accounts are refused (they were not).
- Vault permission checks no longer load the vault owner from the database; API key listing no longer
  dereferences a missing owner.
- Contract test: identity writes outside identities::Manager are rejected (tools/contracts).
