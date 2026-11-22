- MCP: one Streamable HTTP transport (`protocols/mcp/HttpTransport`) serves the device listener's `/mcp` and, later,
  remote connectors; a principal carries an effect ceiling (read, write or destructive) that limits the tools it is
  shown and the calls it may run, enforced by the catalog and again by the executor. Paired devices keep every effect,
  exactly as before.
- Remote connectors, groundwork (nothing listens yet): migration 151 adds `connector_settings`, `connector_clients`,
  `connector_grants` and `connector_refresh_tokens` (refresh tokens stored as digests only, rotated on every use, a
  reused one ends its grant). Grants end with their user's rights: deactivation, deletion, sign out everywhere, an MFA
  reset or recovery-code sign-in, and after 90 days (30 without a refresh).
