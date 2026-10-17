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
- File recovery surfaces: `vh snapshot create|list|delete`, `vh recovery list|inspect|plan|restore|delete|costs`,
  `vh vault recovery status|set|suspend|disclosure` and the ws `recovery.*` / `vault.recovery.*` commands over
  ops::recovery (restore previews and confirmation, provider-versioning cost disclosure and acknowledgements).
