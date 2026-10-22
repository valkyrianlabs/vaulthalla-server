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

## Vault key backup, status and restore

`vh vault keys status` shows each vault's key backup state without printing key material: the current key version
and its **key check** (a public fingerprint that identifies a key without revealing it), the last exported version,
whether a rotation is under way, and every key version the vault still needs. Deleted vaults whose key is still
retained are included. A paired Vaulthalla Desktop uses the same information to back keys up to 1Password: it exports
over its paired connection and confirms each backup by its key check, and the server records the backup only if the
key is still current.

Key exports are now complete during a rotation: an export taken before the rotation finished re-encrypting the vault
used to omit the previous key, which still decrypts the files not yet re-encrypted. Every export now carries all
versions the vault needs (the current key, an unfinished rotation's previous key, and retired keys recovery data
uses), each with its key check, and a deleted vault's export carries them too. Keys still leave the server only
through the local `vh` CLI or a paired device, never the web console or an AI agent.

**Restoring keys.** `vh vault keys import <vault> --file <export>` is a recovery mechanism: it puts back key
versions a vault already had when this host can no longer use them, after the master key was lost or replaced (for
example a database restored onto a new host), after a database restore that predates a key rotation, or for a
deleted vault that can still be restored. It can't be used to set your own key: every export now carries the
server's **attestation** of each key version (a signature by a signing key sealed on the host, never exported), and
a version is restored only when its attestation verifies and the vault's records show it had that version. A key
the host can still use is never replaced, and a version the vault has no record of is refused. `vh` reads the export
on your side (`--file -` reads standard input, so a GPG export can be decrypted into a pipe). Writing asks you to type
the vault's name (`--confirm-name` without a terminal); the vault starts again right away. A paired Vaulthalla
Desktop restores from 1Password the same way. **Export your vault keys again after upgrading**: older exports carry
no attestations.

**Salvage.** A key version that can't be proven (an older export, another server's key) is reported as needing
salvage, and nothing is written for it. `--salvage` then makes a best effort: the server creates a fresh key of its
own, re-encrypts every file the supplied key decrypts under it (crash-safe, resumable), reports the files it couldn't
decrypt as unrecoverable, and never stores the supplied key. Files that exist only in an S3 bucket go through the
vault's price budget, and are reported as skipped with the estimate when it refuses.

**No new key over encrypted data (behavior change).** Vaulthalla used to create a fresh key at startup for a vault whose
key record was missing, even when the vault held encrypted files that key could never decrypt. Now such a vault (or one
whose key doesn't unseal, or whose files need a key version that is gone) does not start: `vh status` reports degraded and
names it, the console's health turns degraded, `vh vault keys status` says why, and the log names the import
command. New and empty vaults still get their first key automatically.

See [Secrets And Key Export](https://vaulthalla.io/docs/vaults/secrets-and-key-export).

## See every vault you can reach

`vh vault list --accessible` lists every vault you can reach and how: as its owner, through a vault role assigned to
you or to one of your groups, through your admin role, or as a super admin. Each vault says whether you can browse its
files and whether you can manage it, decided by the same permission checks that apply when you open it. `vh vault
list` is unchanged and still shows only the vaults your admin role lets you view, so an account whose access comes
from a vault role or from owning a vault finds those vaults with `--accessible`. Vaulthalla Desktop's file browser
uses the same list (ws `storage.vault.accessible.list`), and AI agents get it as the read-only tool
`vaults_accessible_list`.

**More than 100 vaults.** At startup the daemon brought up only the first 100 vaults (by id): after a restart, any
vault beyond those was unreachable on every surface until it was changed. `vh vault keys status all`, `vh vault keys
export all` and resolving an S3 gateway vault by name also stopped at 100. They all cover every vault now.

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
command it answers on `/ws`: 223 commands, up from 76. File management, vaults and API keys, roles and permissions,
shares and share sessions, stats and dashboards, sync conflicts, pricing budgets, the S3 gateway, settings,
operator email, paired devices and vault key backup are covered, each with its payload, response, session
requirement, refusals and client timeout. Native clients can be generated from it, and the web console now takes
every command's timeout from the server.

The contract also publishes the shape of every object those commands send: 170 named models (users and roles,
vaults, devices, vault key status and exports, files and folders, share links, stats, recovery plans, upstream
buckets, S3 gateway credentials, budgets, settings sections and more), with unions and patch payloads spelled out.
A daemon unit test serializes each model with the real code and fails if the published shape and what is sent ever
differ. `meta.contract.get` adds `models_hash`.

Refusals are now machine-readable almost everywhere: file, share, pricing, email, settings, S3 gateway, vault and
dashboard commands answer refusals with a `data.code` (`denied`, `not_found`, `invalid`, `conflict`) instead of
bare text, with the same messages as before. The contract lists, per command, the questions it may ask before
proceeding (confirmations such as the encryption waiver) and which request field accepts each one.

Malformed or failing requests no longer leave clients waiting: a frame the daemon can't route is answered with an
error that carries the request's id, an internal fault answers the request it belongs to with an ordinary error
instead of an "Unknown" response, and a command sent without a payload is treated as an empty one. The contract
documents the request and answer frames.
