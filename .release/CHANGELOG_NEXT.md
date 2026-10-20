<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
## Devices
- Add the device listener (runtime service DeviceServer, port 36971): TLS 1.3 only, client certificate required,
  authorization by the client key's SPKI SHA-256 at handshake time; /ws reaches the ws router as a Device session
  (the device's user, no tokens) or a pairing-only session (device.pair.* and meta.contract.get; anything else
  answers data.code device_unknown).
- Seal the listener's ECDSA P-256 key through the secrets KeyProvider (device_tls) on first start; keep its
  self-signed certificate as device_server_certificate.pem in the state directory.
- Add migration 112: devices (user_id ON DELETE CASCADE, approved_by ON DELETE SET NULL, unique current and
  previous key) and device_node. Pairing windows and requests stay in memory.
- Add ops::devices with ws device.pair.request|confirm|status, device.identity.rotate, device.server.identity,
  device.pairing.open|close|pending|approve|deny, device.list|rename|revoke and device.remote.status|enable|disable,
  and the CLI vh device pair|pending|approve|deny|list|rename|revoke|remote status|enable|disable.
- Number matching: pending requests offer three codes (one is the device's), and any wrong code denies the request.
- Add config section device_server (enabled, port, remote, max_connections); remote defaults to off (loopback) and
  is written only by vh device remote enable|disable, which rebinds the listener without a restart.
- auth revokeSessions closes live device sessions; device revocation closes them immediately.
- Audit log lines written while a device's command runs end with "[via device <id>]".
