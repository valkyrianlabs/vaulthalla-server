<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- Web console: replace the default Next.js favicon with the Vaulthalla logo
  (favicon.ico, icon.png and apple-icon.png).
- Resumable HTTP uploads (`/upload/sessions`, capability `http.upload.resumable`) on the web and device
  listeners, shares included: persisted sessions/files/parts (migration 114), idempotent parts at any offset,
  Content-Digest, parts encrypted on arrival as their own AES-256-GCM messages in a ciphertext-only spool
  (`<state>/.upload-spool`), a background sealing cursor and commit workers, restart recovery, expiry by the DB
  janitor, typed JSON errors; files up to 2^36 - 32 bytes.
- Config: new `transfer:` section (part sizes, in-flight limit, file and session limits, commit workers, session
  TTLs, web listener part cap), validated at load and on settings.update (never clamped).
- `Filesystem::createFile`: a sealed writer may hand over a precomputed content hash.

