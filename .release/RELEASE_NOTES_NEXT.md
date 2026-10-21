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

The web console's Devices page comes in a later release; the ws commands it will use (`device.*`) are available now.

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
