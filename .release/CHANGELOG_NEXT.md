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
