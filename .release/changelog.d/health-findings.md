- Health findings carry operator state (design/health/findings.md): `health::Catalog` (every code the dashboard cards
  raise, with `notifies` and remedies), migration 172 (`health_finding_state`; `admin.stats.manage` listed and given
  to the built-in super_admin), `ops::health` behind ws `health.findings.list`, `health.finding.acknowledge`,
  `.silence`, `.unsilence` and `vh health [list|ack|silence|unsilence]`. `stats.dashboard.overview` and `.severity`
  gain `unattended_error_count` / `unattended_warning_count`, attention items gain `state`; severities and the
  existing counts are unchanged. Capability `health.findings`.
- The three state-changing commands are excluded from the MCP catalog and refused for scoped devices; each is
  audited.
- ws push for health findings: `health.subscribe` (admin.stats.view; answers `{revision}`) and `health.unsubscribe`,
  and the unsolicited `health.changed` event (revision, status and counts, no findings). Service `HealthNotifier`
  evaluates the findings every 15 s only while a session is subscribed, pushes when the digest changes and at once
  after an acknowledge, silence or unsilence, re-checks the permission every 30 s (a last `"subscribed": false`
  event), and holds one pending event per session while its write queue is long. Capability `health.push`.
