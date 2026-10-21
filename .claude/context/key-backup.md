# Vault key backup and restoration (Vaulthalla Desktop S2/S6)

Plan of record: `vaulthalla/desktop` `docs/architecture.md` §2 S2, §6, decisions D4 (key export only through paired
devices or the local CLI, never browser sessions or MCP), D6 (Desktop keeps every needed version in one 1Password
item), D7 (real restoration via `vh vault keys import`). Desktop's consumer: `Sources/VHOnePassword/BackupStatus.swift`.

## Keys in one paragraph

Each vault has a random 32-byte AES-256-GCM key, sealed (AES-256-GCM) under the host's `vault_master`
(`vault/EncryptionManager.cpp`). `vault_keys(vault_id, encrypted_key, iv, version, created_at, updated_at,
exported_version, exported_at)` holds the current version; a rotation moves it to `vault_keys_trashed` (with
`rotation_completed_at` NULL until the sync pass has re-encrypted every file); trigger
`recovery_guard_retired_vault_key` keeps retired versions recovery data references. A deleted vault's versions are
copied (still sealed) into `vault_deletion_key` until `key_retain_until`.

## Key check (`vault/KeyCheck.hpp`)

`key_check` = lowercase hex of BLAKE2b-128 (libsodium `crypto_generichash`, 16-byte output) keyed by the 32 key
bytes, over `"vh-key-check-v1" ‖ vault_id ‖ UInt32BE(version)`, where `vault_id` is the vault's numeric id as ASCII
decimal (no sign, no leading zeros). Vault ids are integers (there is no vault UUID); Desktop's `vaultUUID` field
carries this decimal string. Vectors (key = bytes `00 01 … 1f`):

| vault_id | version | key_check |
|---|---|---|
| 42 | 3 | `72e4c8b7f8ab43b8ed8869a57cef1703` |
| 1 | 1 | `c7a67cdafd3140b29e19b0b5e543cb13` |

Pinned by `VaultKeyCheck.MatchesTheDocumentedVectors`; the operator doc carries the first one. Comparisons are
constant time (`keyCheckEquals`).

## Surfaces (`ops::vault_keys`, `ops/VaultKeys.{hpp,cpp}`)

| Operation | CLI | ws | Who | Where (D4, `Channel`) |
|---|---|---|---|---|
| status | `vh vault keys status <vault\|all> [--json]` | `vault.keys.status {vault_id?}` | encryption-key View (super admins) | any session, MCP too: never key bytes |
| export | `vh vault keys export <vault\|all> [--recipient --output]` | `vault.keys.export {vault_id}` | encryption-key Export | CLI or a paired device's session |
| confirm | (the CLI marks on export, as before) | `vault.keys.export.confirm {vault_id, version, key_check}` | encryption-key Export | paired device |

- Channels: `Cli`, `Device` (`ws::Session::isDeviceSession()` with a peer), `Console` (any other ws session: refused
  with `ops::Refused{"export_requires_device"}`, so data.code `export_requires_device`), `Agent` (refused, Denied).
  The ws router lets browser sessions reach the handler on purpose (book auth `human`), so the refusal is typed.
- **Agents:** `mcp::exclusions()` keeps `vault key export` (and `import`) out of `vh mcp` and `/mcp`. Defense in
  depth: `protocols::shell::AgentCallScope` (thread-local) is set by the remote `/mcp` executor
  (`protocols/device/Mcp.cpp`) and by the CLI server when a `vh mcp` request carries `"agent": true`
  (`cli.cpp runCaptured`); the CLI key handlers map it to `Channel::Agent`. A local agent that runs `vh` itself in a
  shell is the terminal's user (not preventable, and D4's "local CLI").
- **Needed versions** (status `needed_versions`, export `historical_keys`): the current version (`reason: current`),
  every `vault_keys_trashed` row with `rotation_completed_at IS NULL` (`rotation`: the outgoing key still decrypts
  files the sync pass hasn't reached; fixes the mid-rotation export gap), and every version `recovery_blob` / live
  `upstream_object_version` rows reference (`recovery`). A version that is several reports the first. Versions not
  held are `missing_versions` / `missing_key_versions`, never invented.
- **Key sources:** a live vault with an engine reads keys from memory (`historicalKeySnapshot` for retired ones); a
  vault without an engine (its key doesn't unseal here) and a deleted vault read their sealed rows through a
  `KeyProvider` that is only initialized when a row actually needs unsealing. Status caches key checks of sealed rows
  per (vault, version, sealed bytes) in memory, so polling never re-asks the TPM; an unreadable key is
  `key_check: null`, `key_available: false` with `unavailable_reason`.
- **Deleted vaults** (within key retention, for callers who may remove them, `ops::vaults::listDeleted`) are listed
  with `deleted: true` and `key_retain_until`; their export now carries needed versions too (from
  `vault_deletion_key`), confirm marks `vault_deletion.key_exported_at`.
- **Export JSON** = the CLI's shape (`generate_json_key_object`) plus top-level `key_check` and `key_info.key_check`;
  `historical_keys[]` entries are `{key_version, key, key_check, reason, created_at, retired_at}`. A ws export is not
  recorded: Desktop calls `vault.keys.export.confirm` after 1Password stored the key. Confirm succeeds only while
  `version` is current and the key check matches (`markExportedIfCurrent` is one conditional UPDATE, so a rotation in
  between wins): else `conflict`. The CLI keeps marking the current version on a successful export.
- Audit: every export and confirmation writes an audit line naming the actor, vault, version and channel; device
  commands end with `[via device <id16>]` (`log::AuditOrigin`). Non-super-admin exports warn as before.
- Web: the console never calls export/confirm; `WebSocketCommandMap` types them only because every command is
  typed. "Keys are never exported through the browser" stays true.

Tests: `test_vault_keys.cpp` (`VaultKeyCheck`, `VaultKeysDbTest`: status incl. rotation/recovery/missing, export
D4 + mid-rotation versions, confirm incl. a rotation in between, deleted vaults, CLI ↔ ws for every seeded admin
role), `DeviceHttpTest.VaultKeyExportOnlyOnAPairedDevice` (real TLS, `/mcp` reads status but reaches no export),
`McpCatalog` exclusions.
