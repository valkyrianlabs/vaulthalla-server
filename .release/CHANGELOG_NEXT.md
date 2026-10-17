<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- fix(s3): the data-plane SigV4 signer sorts the canonical query string (by name, then value) instead of signing it
  as written, so ListObjectsV2 pages after the first (`continuation-token` written last) no longer fail with
  SignatureDoesNotMatch on AWS; listings of more than 1,000 objects now complete
