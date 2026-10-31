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
- Device listener: dual-stack bind (`[::]`, IPV6_V6ONLY off, falling back to `0.0.0.0`); loopback-only also binds
  `[::1]`; IPv4-mapped peers are unmapped before authorization. `device.remote.status` gains `diagnostics` (bind
  addresses, advertised candidates, read-only firewall detection, last public device handshake).
- ws `device.endpoints` (paired devices) and `node_id`/`server_spki_sha256`/`endpoints` in `device.pairing.open`:
  interface addresses classified loopback/lan/vpn/wan, mDNS name, `device_server.advertise` (new config section,
  validated at load and in `settings.update`). Capability `device.endpoints`.
- Device listener `/transfer/probe`, `/transfer/sink`, `/transfer/source` calibration lanes (at most 2 per device,
  nothing stored). Capability `device.lanes.transfer`.
- Web console: resumable uploads through /upload/sessions when the server advertises
  http.upload.resumable (parts ≤ 64 MiB, ≤ 3 in flight, Content-Digest, backoff with
  Retry-After, gap-only resend from the session status, resume after reload via
  sessionStorage); whole-file /upload/session flow kept for older servers.
- Web console: per-file errors for partly failed upload batches.
- Web console: the pairing dialog shows device.pairing.open endpoints and a
  vaulthalla://pair link (node, spki, endpoints) when the server sends them.
- Web: unit tests run with node --test (pnpm test:unit, part of pnpm test).
- Resumable HTTP uploads (`/upload/sessions`, capability `http.upload.resumable`) on the web and device
  listeners, shares included: persisted sessions/files/parts (migration 114), idempotent parts at any offset,
  Content-Digest, parts encrypted on arrival as their own AES-256-GCM messages in a ciphertext-only spool
  (`<state>/.upload-spool`), a background sealing cursor and commit workers, restart recovery, expiry by the DB
  janitor, typed JSON errors; files up to 2^36 - 32 bytes.
- Config: new `transfer:` section (part sizes, in-flight limit, file and session limits, commit workers, session
  TTLs, web listener part cap), validated at load and on settings.update (never clamped).
- `Filesystem::createFile`: a sealed writer may hand over a precomputed content hash.

