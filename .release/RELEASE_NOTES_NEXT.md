<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Pair Vaulthalla Desktop, and let AI agents operate Vaulthalla

## Paired devices

The daemon now serves Vaulthalla Desktop through its own **device listener** on port 36972: TLS 1.3 with a
certificate on both sides, each side pinning the other's key. No browser cookie, nginx or certificate authority is
involved. The listener answers on **loopback only** until a super admin runs `vh device remote enable`, which opens
it to the network at once (no restart) and keeps it that way across restarts and upgrades; `vh device remote
disable` closes it again.

Any signed-in user can pair a Mac with their own account: `vh device pair` opens a 10-minute pairing window, lists
the Mac when it asks, and offers three codes. Pick the one the Mac shows; a wrong pick denies the request. A paired
device acts as its account with that account's permissions, and follows it: role changes apply at once,
deactivation refuses it, and a password reset or role change closes its open connections. Manage devices with
`vh device list | rename | revoke` (super admins: `vh device list --all`). Revoking is final: the device's
connections close immediately and its key is never accepted again.

A paired Mac also downloads, previews and uploads files over the same connection, with the same permission checks
as the web console (share links aren't offered there), and its AI agents can use **remote MCP** at `/mcp`: the same
tools, limits and confirmations as `vh mcp`. Agents can never approve pairing requests, turn remote connections on or
off, or export keys or secrets.

### In the web console

**Devices** (in the main navigation and the account menu) lists your paired Macs with their platform, app version,
when they were paired and last seen, the last address and the device id, and lets you rename or revoke them. **Pair a
device** is one click: the dialog opens a pairing window, shows the Mac's request with three codes as large buttons,
and you click the one the Mac shows. A wrong click declines the request; if another user is pairing on the node at
the same time, the dialog says so and leaves their window alone. The dialog shows the address and port to enter
in Desktop and counts down by the server's clock. Closing the dialog closes your window.

Super admins also get **Devices → All devices**: every user's devices with their owners, and a **Remote connections**
card with the listener's live status (address, port, connections, any bind error, the server key fingerprint) and an
on/off switch. Settings → Device listener links there.

## Let Claude Code or Codex operate Vaulthalla

`vh mcp` is a Model Context Protocol server built into the `vh` CLI, and `vh skill install --agent claude|codex`
sets an agent up in one step: it writes a `vaulthalla` skill (safety guidance plus a reference of every command
agents may run) and registers the server with the agent's CLI, or prints the command when that CLI isn't installed.

- **The agent acts as you.** Every tool call is an ordinary, non-interactive `vh` command, so your Vaulthalla roles
  and permissions decide what works.
- **Destructive commands need your OK every time.** Deleting, revoking, purging, rotating keys or restoring over files
  is refused by the MCP server until the agent passes an explicit destructive acknowledgement, which it is told to
  give only after you approve, even where the command itself wouldn't ask without a terminal.
- **Confirmations stay with you.** A command that would ask you to confirm (deleting a user or vault, an encryption
  waiver, a restore over files, a bucket cleanup) refuses first; the agent has to show you the message and may only
  pass the confirmation after you approve. The server never adds `--yes` or `--accept-*` itself.
- **Keys and secrets stay out of reach.** Vault key export, secret export, `secrets update`, `setup`, `teardown`
  and `fs get|put` are never available to agents.
- Tools: `vh_help` to browse commands, `vh_read` for read-only commands, `vh_run` for the rest, and typed tools such
  as `users_create`, `vaults_delete` and `recovery_restore`. Each is marked read, write or destructive, so clients
  can run read-only tools freely and ask before destructive ones.

Calls run side by side, can be cancelled by the agent, and are abandoned after 10 minutes without a result
(`VAULTHALLA_MCP_TIMEOUT`).

See [AI Agents And MCP](https://vaulthalla.io/docs/admin/mcp-and-agents).

## Every command now says what it does

Each `vh` command declares whether it reads, writes or is destructive. The machine-readable contract
(`vh_usage --json`) carries it as `effect`.

## Every ws command is in the published contract

The ws contract the daemon publishes (`vh_usage --json`, identified by `meta.contract.get`) now describes every
command it answers on `/ws`: 218 commands, up from 76. File management, vaults and API keys, roles and permissions,
shares and share sessions, stats and dashboards, sync conflicts, pricing budgets, the S3 gateway, settings,
operator email and paired devices are covered, each with its payload, response, session requirement, refusals and
client timeout. Native clients can be generated from it, and the web console now takes every command's timeout from
the server.

The contract also publishes the shape of every object those commands send: 165 named models (users and roles,
vaults, devices, files and folders, share links, stats, recovery plans, upstream buckets, S3 gateway credentials,
budgets, settings sections and more), with unions and patch payloads spelled out. A daemon unit test serializes
each model with the real code and fails if the published shape and what is sent ever differ. `meta.contract.get`
adds `models_hash`.

Refusals are now machine-readable almost everywhere: file, share, pricing, email, settings, S3 gateway, vault and
dashboard commands answer refusals with a `data.code` (`denied`, `not_found`, `invalid`, `conflict`) instead of
bare text, with the same messages as before. The contract lists, per command, the questions it may ask before
proceeding (confirmations such as the encryption waiver) and which request field accepts each one.

Malformed or failing requests no longer leave clients waiting: a frame the daemon can't route is answered with an
error that carries the request's id, an internal fault answers the request it belongs to with an ordinary error
instead of an "Unknown" response, and a command sent without a payload is treated as an empty one. The contract
documents the request and answer frames.
