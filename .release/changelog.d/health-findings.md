- Health findings carry operator state (design/health/findings.md): `health::Catalog` (every code the dashboard cards
  raise, with `notifies` and remedies), migration 172 (`health_finding_state`; `admin.stats.manage` listed and given
  to the built-in super_admin), `ops::health` behind ws `health.findings.list`, `health.finding.acknowledge`,
  `.silence`, `.unsilence` and `vh health [list|ack|silence|unsilence]`. `stats.dashboard.overview` and `.severity`
  gain `unattended_error_count` / `unattended_warning_count`, attention items gain `state`; severities and the
  existing counts are unchanged. Capability `health.findings`.
- The three state-changing commands are excluded from the MCP catalog and refused for scoped devices; each is
  audited.
