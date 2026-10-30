<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- ws protocol negotiation: new command meta.hello (allowed where meta.contract.get is: signed-in web, paired device
  and pairing-only device connections; unauthenticated web and share sessions get UNAUTHORIZED) answers {server {name, version}, protocol {version, min, max}, capabilities, commands,
  contract}; the session keeps the negotiated version (kProtocolVersion = kProtocolMin = 1); no overlap is ERROR
  data.code protocol_unsupported with server_min/server_max/server_version; a paired device's client.version
  refreshes devices.app_version.
- ws: an unknown command on a signed-in web or device session answers data.code unknown_command (text unchanged).
- Contract document version 3: vh_usage --json adds protocol, capabilities (name, since, description) and
  envelope.error_codes, covered by contract_hash. A frozen protocol-1 baseline (core/usage/protocol/v1.json) and the
  meson test protocol_compat fail the build on a breaking ws change without a protocol bump.
