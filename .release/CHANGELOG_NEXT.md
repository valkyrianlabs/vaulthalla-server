<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
## Devices
- Add the device listener (runtime service DeviceServer, port 36972): TLS 1.3 only, client certificate required,
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
- Serve /preview*, /download* and /upload* on the device listener over TLS as the device's user (no cookies, no
  share lanes) and remote MCP at /mcp (Streamable HTTP: POST, JSON responses, Origin and MCP-Protocol-Version
  checks, the vh mcp catalog run through the CLI router, 10-minute call deadline). The HTTP session runs over a
  plain or TLS byte stream; device HTTP connections end on revocation, revokeSessions or remote-off.
- MCP never offers vh device pair|approve|deny or vh device remote enable|disable; every vh device leaf declares
  its effect.
- device.pairing.close closes only the caller's window unless a super admin passes any (CLI: vh device pair --close
  --any); device.pairing.open and .pending return server_time, and .open the listener's port and remote.

## CLI
- Add `vh mcp`: an MCP server (JSON-RPC 2.0 over stdio, protocol 2025-11-25, also 2025-06-18 and 2025-03-26).
  - Tools: `vh_help` (usage book), `vh_read` (read-only commands), `vh_run` (any agent-available command) and one
    typed tool per catalogued operation with a CLI binding, annotated readOnly/destructive from the command's effect.
  - Each tool call is a non-interactive control-socket request authorized by peer UID like any `vh` run; `--json`
    is added where supported; confirmation flags are only passed from the agent's explicit `confirm` argument.
  - A command with effect `destructive` is refused before it runs unless `confirm` carries `"destructive": true`,
    independent of the command's own prompt (closes the non-interactive `vault delete` path for agents).
  - A refusal for want of a confirmation becomes a `needs_confirmation` result, from the result frame's new
    `confirmation` member (text matching only for older daemons).
  - Calls run concurrently (ping and cancellation are never queued behind one); `notifications/cancelled` closes
    the call's connection; a call is abandoned after `VAULTHALLA_MCP_TIMEOUT` seconds (default 600).
  - Never exposed: `vault keys export`, `secrets export|update`, `setup …`, `teardown …`, `fs get|put`.
- Add `vh skill install --agent claude|codex [--scope user|project] [--no-register] [--force]`: writes the
  `vaulthalla` skill (`SKILL.md`, `references/commands.md`) to `~/.claude/skills` / `~/.agents/skills` (or the
  project's `.claude/skills` / `.agents/skills`) and registers `vh mcp` via `claude mcp add` / `codex mcp add`;
  idempotent, replaces a changed skill only with `--force`, needs no daemon.
- The control socket's `result` frame gains an optional `confirmation` member (`code`, `flag`, `flags`) when a
  command refused because nobody confirmed it; the CLI ignores it.
- Every CLI leaf declares its effect (`read`, `write`, `destructive`), exported as `effect` by `vh_usage --json`.
