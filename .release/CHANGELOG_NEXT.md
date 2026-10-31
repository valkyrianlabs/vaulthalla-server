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
- Web console: resumable uploads through /upload/sessions when the server advertises
  http.upload.resumable (parts ≤ 64 MiB, ≤ 3 in flight, Content-Digest, backoff with
  Retry-After, gap-only resend from the session status, resume after reload via
  sessionStorage); whole-file /upload/session flow kept for older servers.
- Web console: per-file errors for partly failed upload batches.
- Web console: the pairing dialog shows device.pairing.open endpoints and a
  vaulthalla://pair link (node, spki, endpoints) when the server sends them.
- Web: unit tests run with node --test (pnpm test:unit, part of pnpm test).
