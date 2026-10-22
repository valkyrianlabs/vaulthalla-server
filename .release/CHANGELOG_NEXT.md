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

## Web console
- Add Devices (/devices, any signed-in user): own devices with rename, revoke (confirm) and copyable ids, and the
  lazy "Pair a device" dialog (device.pairing.open, device.pairing.pending polled every 2 s while visible, number
  matching via device.pairing.approve, deny, a countdown by the node's clock (server_time), the listener port
  from device.pairing.open, device.pairing.close on dismiss; another user's window is shown, never closed).
- Add /devices/all for super admins: device.list {all} with owners and the remote-connections card
  (device.remote.status|enable|disable); Settings shows device_server as managed there.
- Add tests/e2e/devices.spec.ts, which also runs with no daemon (VAULTHALLA_E2E_OFFLINE=1).

## Vault keys
- Add ops::vault_keys with ws vault.keys.status, vault.keys.export and vault.keys.export.confirm and the CLI
  `vh vault keys status <vault|all> [--json]`; `vh vault keys export` goes through the same op.
- Key check: BLAKE2b-128 (crypto_generichash) keyed by the vault key over "vh-key-check-v1" ‖ vault_id (ASCII
  decimal) ‖ UInt32BE(version), lowercase hex; status and exports carry it per version, never key bytes in status.
- Exports carry every needed version under historical_keys (key_check, reason): an unfinished rotation's outgoing key
  (it used to be omitted mid-rotation), recovery-referenced retired keys, and for deleted vaults too.
- vault.keys.export and .export.confirm answer only paired device sessions (data.code export_requires_device for any
  other session); confirm records the export only while the version is current and the key check matches.
- Add `vh vault keys import <vault> --file <path|-> [--confirm-name] [--json]` and ws vault.keys.import (paired
  devices only, import_requires_device elsewhere): restores key versions this host can't unseal or doesn't hold
  (live vaults and restorable deleted vaults), after verifying each against its key check and a GCM tag check of
  up to 16 local files and 16 recovery blobs sealed under it; refuses a key the host still unseals with other bytes
  (conflict), a key that authenticates nothing it checked (invalid); skips versions with nothing to verify against;
  NeedsConfirmation vault_key_import until the vault's name is given; one transaction under the rotation lock; then
  reloads or starts the vault's engine.
- EncryptionManager::load_key no longer mints a key for a vault with sealed content (files with an IV, recovery
  blobs, live provider versions, encrypted remote index entries): a missing vault_keys row, a row that doesn't
  unseal, or a missing version live files or a pending rotation need throws vault::KeyUnavailable (key_missing |
  key_unsealable | version_missing); the engine stays down, storage::Manager records the vault, stats.system.health
  gains vaults_unavailable (degraded) and vh status lists it; vault.keys.status reports the code as
  unavailable_reason plus unavailable_detail.
- Import verifies a cloud vault's version without local ciphertext against its smallest upstream object (price
  preflight key_import_verify, 1 HEAD + 1 GET capture, If-Match, authenticated in memory), and accepts a version no
  ciphertext is sealed under on the backup's key check alone.
- The vh client reads the import file itself and attaches it to the request (`input` member, at most 512 KiB); the
  daemon never opens a caller-named path for it.
- MCP: key commands refuse when run for an MCP client (remote /mcp, or a vh mcp request marked agent), in addition
  to the catalog exclusions.
- ws contract: vault.keys.* responses are models (VaultKeyStatus, VaultKeyNeededVersion, VaultKeyExport,
  VaultKeyImportResult, checked against their serializers); import declares the vault_key_import confirmation
  (accept_field confirm_name) and SystemHealth declares vaults_unavailable.

## Vaults
- Add ops::vaults::listAccessible with ws storage.vault.accessible.list (human and device sessions) and
  `vh vault list --accessible [--json]` (operation vaults.accessible.list, MCP tool vaults_accessible_list): every
  live vault the actor reaches as owner, by a vault role of its own or a group's, by its admin role, or as super
  admin. Rows carry a vault summary (model AccessibleVault) plus browse (rbac::resolver::Vault, FilesystemAction::List
  at the root's FUSE path, as fs.dir.list enforces it), manage (admin vault View, as storage.vault.get) and via
  (owner | vault_role | group_role | admin_policy | super_admin). A deactivated account gets an empty list.
- Filesystem denials found while listing are not logged (rbac::resolver::vault::QuietFilesystemDenials); refused
  requests still are.
- Add db::query::vault::Vault::listLiveVaults (unpaginated). Storage engine startup, vault key status/export of all
  vaults and S3 gateway vault name resolution used listVaults' default 100-row page and silently skipped later
  vaults.

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

## WS contract
- ws contract: the usage book (`core/usage/src/contract/ws`) declares every registered ws command (223, was 76).
  `UsageContract.EveryRegisteredWsCommandHasABookEntry` and `test_ws_contract.py` fail on a command without one.
- web: client timeouts come only from the contract; WebSocketCommandMap payload types follow the server (no `null`
  payloads, no members the handlers never read).
- ws contract version 2: `models[]` and `models_hash` (170 named model shapes, `core/usage/src/contract/models`),
  field `one_of` / `values` / `element` / `partial`, command `response_model`; `meta.contract.get` answers
  `models_hash`. `ContractModels.*` checks every model against its serializer with seeded instances;
  `UsageContract.UnionsObjectsAndArraysAreSpelledOut` keeps unions and objects typed (free-form JSON is an explicit
  allowlist).
- Handler JSON builders the contract tests need are public and database-free (S3 gateway, vault details and removal
  plan, share entries and links, email history, vault stats); their output is unchanged.
- ws contract: commands list `refusal_kinds` and `confirmations` (`{code, accept_field, description}`, 20 codes);
  `refusal_codes` stays their union. Kinds are the generic ones plus the device pairing codes
  (`no_pairing_window`, `rate_limited`, `device_unknown`) and, on the vault key commands only,
  `export_requires_device` / `import_requires_device`. Generated TS exports `WS_CONTRACT_CONFIRMATIONS`.
- ws: fs, share, pricing, email, settings, S3 gateway, vault/API key, permission and dashboard-preference refusals
  carry `data.code` (untyped refusals: 61 commands, now 2); messages unchanged. Share Manager, TargetResolver and
  PrincipalResolver throw ops refusal types; HTTP share lanes are unaffected.
- ws: unroutable frames are answered `parse_error` with `error` (and `message`, kept for old clients) and the
  frame's requestId; router faults answer `<command>.response` with status ERROR instead of `UNKNOWN` /
  `Unknown.response`; a non-string requestId no longer breaks an answer; a missing `payload` reads as `{}`.
- ws contract: `envelope` documents the request, answer and error frames.

## Security fixes
- RBAC: the filesystem evaluator's last stage (global vault policy) tried the self, admin and user scopes in turn,
  but a stage always decides, so the self scope's bits answered for every vault. It now reads only the scope the vault
  falls under for the account (owner self; an admin-owned vault admin; otherwise user), through
  rbac::resolver::vaultScope, the function the admin vault resolver (admin.vaults.<scope>) and the sync/role globals
  resolver now share. FUSE's listing-override check reads the same single scope. Seeded presets are identical in every
  scope, so no seeded role changes; covered by VaultScopeRbacTest.
