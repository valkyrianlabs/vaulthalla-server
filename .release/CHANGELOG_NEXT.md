<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->

- Depend on vaulthalla-archive-keyring, which owns /usr/share/keyrings/vaulthalla.gpg (the signed-by= path
  install.sh writes) so APT signing-key renewals reach existing installs through upgrades (#121).
- S3 data plane: the vault controller signs its query in SigV4 canonical order (paged listings past 1,000 keys
  signed `continuation-token` out of order), treats a CompleteMultipartUpload 200 carrying an <Error> body as a
  failure, and gains version-aware ListObjectVersions / HEAD / GET / CopyObject ?versionId= plus per-PUT ETag and
  version-id capture for file recovery.
- File recovery, local versioning: with vault_recovery_policy.local_versioning on, every content change (overwrite,
  FUSE seal, truncate, delete, sync download, restore, conflict) keeps the prior sealed generation as a local version
  (zero-copy link), pruned by keep-last / max-age / quota; in upstream vaults unsent versions are replayed in order
  before the next upload when the bucket keeps history. Backing files are now never written in place (new files are
  created exclusively or replaced by rename; contract-tested).
