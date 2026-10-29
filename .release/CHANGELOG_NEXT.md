<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- Source moved to github.com/valkyrianlabs/vaulthalla-server (Homepage, debian/copyright Source, release.toml);
  the old vaulthalla/server URLs redirect. CI runs on the Valkyrian Labs VPS build pool (label vps-ci).
- The macOS installer's Nexus mirror moved to the valkyrian-raw repository (pkg.vaulthalla.sh).
- S3 gateway: a signed content-length that a proxy stripped (Cloudflare drops Content-Length: 0) is canonicalized
  as 0 when the request has no body and no Transfer-Encoding; every response sends Cache-Control: private, no-store.
- TPM sealer: seal/unseal are serialized per process (each holds 2 of the TPM's 3 transient object slots; the swtpm
  TCTI has no resource manager), so concurrent unseals no longer fail Esys_Load with TPM_RC_OBJECT_MEMORY; transient
  TPM warnings (object/session memory, retry, yielded, testing) are retried up to 5 times with backoff.
- Stats: rollup retention is configurable per tier (stats_snapshots.rollup_5m_retention_days, default 30;
  rollup_1h_retention_days, default 365, never below the 5-minute value) instead of a hard-coded 365 days for both;
  the purge logs how many rows it deleted. Operator docs describe a one-time VACUUM (FULL) / pg_repack.
