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
| import | `vh vault keys import <vault> --file <path\|-> [--confirm-name] [--json]` | `vault.keys.import {vault_id, keys, confirm_name?}` | encryption-key Export | CLI or a paired device (`import_requires_device` elsewhere) |

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
`McpCatalog` exclusions. Import: `VaultKeysDbTest.Import*` (a key that no longer unseals restored and files read
through `openPlaintextReader`; wrong key, damaged backup, other vault, a key the host unseals refused; partial version
sets mid-rotation and a missing retired row re-inserted with the rotation resumed; a deleted vault restored after
import), `cli_fs_client` (`vh` reads the file itself, `-` = stdin, never connects without it).

## Key import (S6, D7): design

Written before the code; the as-built notes below it say where the code differs.

**Scenarios supported.** The vault's metadata (its `vault` row, `files` rows) and backing ciphertext exist on this
host, but key versions are unusable:
1. Sealed rows that no longer unseal: `vault_master` lost or replaced (a database restored onto a new host or a
   reinstalled TPM/`swtpm` state), or a damaged `encrypted_key`/`iv`. The engine fails to start (`load_key` throws), so
   the whole vault is unreadable; import re-seals the backed-up bytes under this host's `vault_master` and starts it.
2. Missing rows: a retired version (`vault_keys_trashed`) that files still sealed under it (an unfinished rotation) or
   recovery data need, e.g. after restoring a database backup older than the rotation; import inserts it.
3. A deleted vault within key retention whose purge hasn't started (pending: rows and backing files still exist):
   import re-seals its `vault_keys`/`vault_keys_trashed` rows and its `vault_deletion_key` copies, so a restore works.
4. Any subset of versions (a partial backup): each version stands alone; the engine starts once every version it
   needs to load (current, plus the outgoing key while rotating) unseals.

**Out of scope, and why.**
- Rebuilding a vault from backing files alone after total database loss. Backing files are named by random base32
  aliases; the IV, key version, plaintext size, name, folder, owner, RBAC, shares and sync state of each exist only in
  the database (`files`, `fs_entry`). A key alone can't say which file is which or even which IV to use. Restore the
  database backup first (`backup-and-recovery.md`), then import keys.
- A purged deleted vault: its files are gone, so nothing on this host can verify a key (refused as unverifiable).
- Replacing a key this host can unseal with different bytes (that would be a rotation, or a wrong backup), and
  importing into another vault id (entries are matched by `vault_id`, which the key check binds).
- A current version newer than the database knows (backup newer than the restored database): no `files` row is sealed
  under it, so it is unverifiable and refused.
- (Decided 2026-10-20, revision 2.) `load_key` never mints a key for a vault that already has sealed content: see
  "Missing keys at startup" below.

**Input.** The export JSON (`vh vault keys export` / `vault.keys.export`): one vault object or the `all` array; the
entry whose `vault_id` is the target vault; its versions are `key` + `key_info.key_version` and every
`historical_keys[]` entry (base64, 32 bytes). The CLI `vh vault keys import <vault> --file <path|->` reads the file
**client-side** (`vh`, or stdin with `-`) and sends its text in the request frame (`"input": {"v": 1, "text": ...}`,
at most 512 KiB); the daemon never opens a path the caller names (`--file` is only a label there). A GPG-encrypted
export is decrypted by the operator first (`gpg -d keys.json.gpg | vh vault keys import 12 --file - --confirm-name
archive`). ws `vault.keys.import {vault_id, keys, confirm_name?}` on paired device sessions only (D4;
`import_requires_device` elsewhere, Denied for agents; excluded from MCP).

**Verification before anything is written** (per version):
1. Shape: base64 of exactly 32 bytes, version > 0, no duplicate version with other bytes.
2. Key check: when the backup carries one for the version, it must equal `keyCheck(bytes, vault_id, version)`, else
   the backup is damaged: refused (`invalid`).
3. Same bytes as this host: a sealed row that unseals here is compared in constant time: identical → `unchanged`
   (no write, no verification needed); different → the whole import is refused (`conflict`), nothing written.
4. Ciphertext: a streaming GCM tag check (`gcmVerifyFd`, no plaintext kept) of up to 16 local ciphertexts sealed
   under the version, smallest first (all when fewer): `files` rows with that `encrypted_with_key_version` and an IV
   whose backing file exists here (local vaults and cloud vaults' local copies), then `recovery_blob` rows with that
   `key_version`. Verified when at least one authenticates (a 128-bit tag under the key is conclusive); others that
   fail are reported as damaged files. None authenticates → not this vault's key: whole import refused (`invalid`).
5. Upstream (revision 2): a cloud vault with no local ciphertext under the version verifies against the **smallest**
   object recorded under it (`remote_object_index` rows with `encrypted` and that key version; else `files` rows
   without a local copy), fetched whole so the GCM tag authenticates, through the metered remote-read path: price
   preflight (`RemoteFetchGate`, operation `key_import_verify`), a usage capture of 1 HEAD + 1 GET + the object's
   bytes, HEAD then GET with If-Match on the HEAD's ETag, authenticated in memory (`GcmStreamVerifier`), never written
   to disk. The HEAD must still name that key version (and the index's IV). Fails authentication → whole import
   refused (`invalid`); a refused or failed preflight, a budget, an archived/missing/changed object → the version is
   `unverifiable` with that detail. The fetch runs on a key-less verification engine
   (`CloudEngine::forKeyVerification`), never registered with the storage manager.
6. No ciphertext anywhere (revision 2): when nothing records ciphertext under the version (no `files` row with an IV,
   no `recovery_blob`, no live `upstream_object_version`, no encrypted `remote_object_index` row), e.g. a fresh
   rotation target, the version is accepted when the backup carries a key check for it that matches the bytes for
   this vault id and version: the backup is internally consistent and nothing can be mis-decrypted. Outcome
   `restored`, detail "no ciphertext under this version; accepted on key check". Without a key check: `unverifiable`.
7. Otherwise (ciphertext exists but nothing could be checked) the version is `unverifiable` and skipped; the others
   proceed. Never "trust the user".

**Missing keys at startup (revision 2).** `EncryptionManager::load_key` mints a key only for a vault without sealed
content (no `files` row with an IV, no recovery blob, no live provider version, no encrypted remote index entry): new
and empty vaults. Otherwise it throws `vault::KeyUnavailable{code}` and the engine doesn't start:
`key_missing` (no `vault_keys` row), `key_unsealable` (a needed row doesn't unseal under this host's vault master),
`version_missing` (the outgoing key of a pending rotation, or a version live files are sealed under, isn't held). The
message names the command to run (`vh vault keys import <id> --file <export.json>`). `storage::Manager` records the
vault as unavailable (`unavailableVaults()`), health (`stats.system.health` `vaults_unavailable`, `vh status`) reports
it and is at least degraded, and `vault.keys.status` reports `key_available: false` with `unavailable_reason` = that
code and `unavailable_detail`. With no `vault_keys` row, the status version is the highest version data records, and
an import's current version is the higher of that and the backup's current version (inserted into `vault_keys`).

**Safety rules.** Never replace a key this host can unseal with different bytes (above); same bytes are a no-op.
Writes happen in one transaction under the vault's rotation lock (`pg_advisory_xact_lock(vault_id)`, as
`rotate_vault_key`), after re-reading every sealed row it evaluated (`FOR UPDATE`) and refusing (`conflict`) if one
changed meanwhile. Each restored version is re-sealed under the current `vault_master` with a fresh IV: `UPDATE
vault_keys` / `UPDATE vault_keys_trashed` keep version, created_at, export marks and `rotation_completed_at`; a new
retired row is inserted with `rotation_completed_at` NULL only when it is the version just below current and live
files are still sealed under it (an unfinished rotation), else completed. A deleted vault's `vault_deletion_key`
copies are updated or inserted the same way. Rotation state is never changed otherwise. After commit: cached key
checks for the vault are dropped; a live vault without an engine gets one (`storage::Manager::reinstateVault`, which
also refreshes sync), and the result says whether it started. Audit: who, which vault, which versions, through which
channel (device id via `AuditOrigin`).

**Confirmation.** The op plans first. Nothing to write → `unchanged`, no confirmation. Otherwise it throws
`NeedsConfirmation{"vault_key_import"}` (text: what will be written) unless `confirm_name` equals the vault's name.
The CLI asks at a terminal ("type the vault name"), or takes `--confirm-name <name>` non-interactively.

**Permissions.** Same as export: super admins or the encryption-key Export permission; a deleted vault only for
callers who may remove it (ops::vaults' rule).

**Desktop (restore milestone 3).** Reveal the item's versions from 1Password (`item.reveal`), build the export shape
(`{vault_id, key, key_check, key_info: {key_version}, historical_keys: [{key_version, key, key_check}]}`), send
`vault.keys.import {vault_id, keys}` over the paired connection, show the `vault_key_import` confirmation text, ask the
user to type the vault name, resend with `confirm_name`, then poll `vault.keys.status` (`key_available`).

**As built** (`ops::vault_keys::importKeys`, `VaultKeys.cpp`; `db::query::vault::Key::writeImported`,
`sampleSealedFiles`, `sampleRecoveryBlobs`; ws `handler::VaultKeys::importKeys`; CLI `handle_vault_keys_import`):
- Client side: `protocols/shell/ClientInput.hpp` (`client_input::plan`, mirrored aliases `vault|vaults|v` +
  `key|keys|k` + `import`), `cli.cpp read_client_input` (regular file or stdin, ≤ 512 KiB, buffers zeroed after
  sending); the server validates `input` and passes it as `CommandCall::input` (`Router::executeLine`'s new last
  parameter). An unrecognized spelling reaches the daemon without input and is refused.
- Plan per version: shape and key check (`invalid`, whole import) → versions newer than current are `unverifiable` →
  slots (`vault_keys` for the current version, `vault_keys_trashed` for older ones while the vault row exists,
  `vault_deletion_key` for a deleted vault) → a slot that unseals to other bytes is `conflict` (whole import), to the
  same bytes makes the version verified by identity (no sampling) → otherwise up to 16 `files` + 16 `recovery_blob`
  samples, smallest first, `gcmVerifyFd` (O_NOFOLLOW, regular files only): none authenticates but some were checked →
  `invalid` (whole import); none checked → `unverifiable` (skipped).
- `writeImported` re-checks every updated row's sealed bytes in its WHERE clause (and `ON CONFLICT DO NOTHING` for
  inserts), so a concurrent change is `conflict` with nothing written.
- After writing: a running engine reloads its keys (`EncryptionManager::load_key`, so a re-inserted outgoing key and
  the resumed rotation take effect); a live vault without an engine is started with `storage::Manager::reinstateVault`;
  a deleted vault reports that it needs a restore. `key_available` says whether the vault runs now.
- Deleted vaults: only while restorable (pending); purging/purged are `conflict` (no ciphertext left to verify).
- Revision 2 as built: `KeyUnavailable` in `vault/EncryptionManager.hpp`; `Key::sealedContentSummary`,
  `liveFileKeyVersions`, `dataKeyVersions`, `ciphertextExistsUnder`, `remoteSamples`; `storage::Manager::
  unavailableVaults()` (set when an engine fails in `initStorageEngines` / `reloadEngine` / `reinstateVault`, cleared
  when it starts, on retire and remove); `SystemHealth::vaultsUnavailable` (degraded); `vh status` lists them. Status
  `needed_versions` also lists versions live files are sealed under (reason `rotation`), and `unavailable_reason` is a
  code with `unavailable_detail` text. Upstream verification: `CloudEngine::forKeyVerification` +
  `verifyRemoteObjectWithKey` (`CloudRemoteRead.cpp`); test seam `ops::vault_keys::
  setKeyVerificationEngineFactoryForTesting`.
