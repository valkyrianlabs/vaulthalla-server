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
copied (still sealed) into `vault_deletion_key` until `key_retain_until`. All three tables carry the version's
recorded provenance (`key_check`, `attestation_key_id`, `attestation`; migration 113, below).

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
- **Export JSON** = the CLI's shape (`generate_json_key_object`) plus top-level `key_check` / `attestation` and
  `key_info.key_check` / `key_info.attestation`; `historical_keys[]` entries are `{key_version, key, key_check,
  attestation, reason, created_at, retired_at}` (`attestation` = `{key_id, signature}` or null; an export signs and
  records one when the row has none). A ws export is not
  recorded: Desktop calls `vault.keys.export.confirm` after 1Password stored the key. Confirm succeeds only while
  `version` is current and the key check matches (`markExportedIfCurrent` is one conditional UPDATE, so a rotation in
  between wins): else `conflict`. The CLI keeps marking the current version on a successful export.
- Audit: every export and confirmation writes an audit line naming the actor, vault, version and channel; device
  commands end with `[via device <id16>]` (`log::AuditOrigin`). Non-super-admin exports warn as before.
- Web: the console never calls export/confirm; `WebSocketCommandMap` types them only because every command is
  typed. "Keys are never exported through the browser" stays true.
- **ws contract (v2)** (`core/usage/src/contract/ws/keys.cpp`, models in `contract/models/keys.cpp`): models
  `VaultKeyStatus` (status `vaults[]`, with `attestation` and `last_salvage`), `VaultKeyNeededVersion`,
  `VaultKeyAttestation` (`key_id` 1..2^31 - 1: `key_attestation_keys.id` is a SERIAL), `VaultKeyExport` (export's
  `response_model`), `VaultKeyImportDocument` (import's `keys`: `one_of` one object or the `all` array; exactly what
  `ops::vault_keys::readImportDocument`, the import's parser, reads: `vault_id`, `key`, `key_info.key_version`
  required, `key_check` / `attestation` (top level, else `key_info`) and `historical_keys[] {key_version, key,
  key_check?, attestation?}` optional; undeclared members are accepted and ignored, so a whole export is one),
  `VaultKeyImportResult` (import's `response_model`), `VaultKeySalvageReport` and `VaultKeySalvageFailure`, each
  checked against its `toJson` by `ContractModels.VaultKeys` (`models_keys.cpp`; the import document through
  `Checker::checkInput`, which accepts undeclared members). `ContractModels.VaultKeyImportDocumentRequiresWhatTheImportReads`
  removes and nulls every declared member and requires the parser to refuse exactly what the model calls a problem
  (and the same for `key_version`'s bounds); `ContractModels.VaultKeyAttestationKeyIdBoundsAreTheImports` pins
  `key_id`'s bounds to `vault::attestation::kMinKeyId`/`kMaxKeyId`.
  `refusal_kinds` add the D4 channel codes only where they are sent: `export_requires_device` (export, confirm),
  `import_requires_device` (import); `UsageContract.RefusalsSplitGenericKindsFromConfirmations` pins them to those
  commands like the device pairing codes. A key that can't be read here is `conflict`; the `KeyUnavailable` codes
  are status fields (`unavailable_reason`), never refusals. Import's confirmations: `vault_key_import` (mode recover) and
  `vault_key_salvage` (every mode salvage request that writes) → `accept_field` `confirm_name` (a string: the vault's
  name). Health's `vaults_unavailable` is in `SystemHealth`.

Tests: `test_vault_keys.cpp` (`VaultKeyCheck`, `VaultKeyAttestation` (the vector), `VaultKeysDbTest`: status incl.
rotation/recovery/missing, export D4 + mid-rotation versions, confirm incl. a rotation in between, deleted vaults,
CLI ↔ ws for every seeded admin role), `DeviceHttpTest.VaultKeyExportOnlyOnAPairedDevice` (real TLS, `/mcp` reads
status but reaches no export), `McpCatalog` exclusions. Import (revision 3): provenance recorded on create/rotate and
backfilled after a restart; a key that no longer unseals restored on its attestation and files read through
`openPlaintextReader`; an invented key → needs_salvage, damaged backup / other vault → invalid, a key the host
unseals → conflict; partial version sets mid-rotation and a missing retired row re-inserted with the rotation
resumed; a deleted vault restored after import (salvage refused); a fresh rotation target restored on its
attestation, never on the backup's key check; tampered signature, unknown signing key, another version's / vault's /
node's attestation, a `key_id` out of range (the genuine id + 2^32, 2^31, 0) → needs_salvage; an invented version and a backup claiming a higher version → refused, current
stays the records'; a TPM reset → new signing key, old exports still restore; mode salvage with nothing to salvage → `vault_key_salvage`, then only restores; salvage (local: re-keys what
authenticates, damaged and foreign files unrecoverable, the supplied key stored nowhere, the vault restarts; crash
after a commit → resumes on the same key; remote-only: refused preflight → skipped_remote with the estimate, then
re-keyed through HEAD + If-Match GET and uploaded). `SqlDeployerHistoryDb.KeyProvenanceMigrationIsAdditiveAndIdempotent`
(migration 113). `cli_fs_client` (`vh` reads the file itself, `-` = stdin, never connects without it).

## Key import (S6, D7): design, revision 3

**The rule (maintainer, binding): only a key version that is verified and version-signed by this node is restored as
canonical. Anything else gets best-effort salvage: decrypt what it can, re-encrypt it under a fresh daemon-generated
key, and never keep the supplied key in the database.** Import restores key versions the vault had, proven by the
daemon's own records; it never introduces a key. "Totally fine with recovery", never key creation.

Revision history: revision 1 (S6) verified a version by authenticating ciphertext sealed under it; revision 2 added
upstream verification and accepted a version with no ciphertext on *the backup's own* key check. Both made a supplied
key canonical on evidence the supplier controls or that only shows the key decrypts some bytes (anyone can invent a
key and compute its key check; a key that decrypts a planted file proves nothing about the vault's history).
Revision 3 (2026-10-21) removes both paths: ciphertext authentication now only feeds salvage.

### Provenance: recorded key checks and node attestations (migration 113)

- `vault_keys`, `vault_keys_trashed` and `vault_deletion_key` gain `key_check` (TEXT), `attestation_key_id`
  (→ `key_attestation_keys.id`) and `attestation` (BYTEA, 64 bytes), all nullable. A rotation copies them into the
  retired row; a deletion copies them into `vault_deletion_key`.
- **Attestation signing key (per node).** Ed25519 (libsodium `crypto_sign`), seed sealed through
  `crypto::secrets::KeyProvider("key_attest")` (`test_key_attest` in test mode), generated on first need, never
  exported. Its public key is a row of `key_attestation_keys(id, public_key BYTEA(32) UNIQUE, created_at, retired_at)`.
  If the seed can't be unsealed (TPM reset, a database restored onto a new host), the daemon generates a new keypair
  (new row; older rows get `retired_at`) and keeps every old public key, so old attestations still verify.
- **Attestation of one key version** = `Ed25519(sk, "vh-key-attest-v1" ‖ node_id ‖ UInt64BE(vault_id) ‖
  UInt32BE(version) ‖ key_check)`, where `node_id` is this install's id (`device_node.node_id`, migration 112: a
  UUID string, its UTF-8 bytes; the fixed-size tail keeps the message unambiguous) and `key_check` is the 16 raw bytes
  of the key check. Stored as `(attestation_key_id, attestation)`. Vector in `vault/KeyAttestation.hpp` and
  `VaultKeyAttestation.MatchesTheDocumentedVector` (fixed seed `00 01 … 1f`). An import reads a `key_id` outside
  1..2^31 - 1 (the SERIAL's range) as a malformed attestation (that version needs salvage), never narrowed to another
  signing key's id.
- **When.** Recorded when a version is created (`load_key` minting an empty vault's first key, `prepare_key_rotation`,
  the salvage key) and **backfilled lazily**: whenever the daemon unseals a version (startup `load_key`, the retired
  key cache, rotation, status and export through `Unsealer`) and the row's `key_check` differs from the key's or its
  attestation is missing, it stores both with one conditional UPDATE per table, matched on the sealed bytes
  (`Key::recordProvenance`). A row that never unseals again keeps NULLs.
- **Public.** The key check is a keyed BLAKE2b-128 PRF output and the attestation is a signature over it: neither
  reveals anything usable about the key. Status (`needed_versions[].attestation`, top-level `attestation`) and exports
  (`attestation`, `key_info.attestation`, `historical_keys[].attestation`; `{key_id, signature}` with the signature
  base64) carry them.

### Import modes (`mode`: `recover`, the default, or `salvage`)

**Recover (canonical).** Per version in the backup, after the shape and the backup's own key check (consistency
only: a mismatch refuses the whole import as damaged, `invalid`):
1. *Recovery only.* The version must be one the daemon's records reference (`Key::referencedKeyVersions`): the
   `vault_keys` row, retired rows and the version each retirement rotated to (v + 1), a deleted vault's retained copies
   and recorded version, or data sealed under it (files, recovery blobs, live provider versions, encrypted remote
   index entries). Otherwise: outcome `refused` ("the vault has no record of key version v; an import never
   introduces a key version"). With no `vault_keys` row the current version is the highest referenced version, never
   the backup's claim.
2. *Never replace a held key.* A slot (row) that unseals here to other bytes refuses the whole import (`conflict`);
   to the same bytes → `unchanged` (no write), or, when another slot of that version doesn't unseal, that slot is
   re-sealed (detail "matches a key this host holds").
3. *Attested.* Otherwise the backup must carry an attestation for the version that verifies under a public key in
   `key_attestation_keys`, over this node's id, this vault id and version, and the key check recomputed from the
   imported bytes; and every recorded `key_check` for the version must equal that check. Then the version is restored
   (re-sealed under this host's vault master with its key check and the backup's attestation): outcome `restored`,
   detail "attested by this node (signing key N)".
4. Anything else (no attestation: an export from before revision 3; an unknown signing key; a bad signature; another
   node, vault or version; a recorded key check that differs) is `needs_salvage` with the reason, and nothing is
   written for it. The other versions proceed.

Writing (rows only) needs `confirm_name` (NeedsConfirmation `vault_key_import`). Rotation state is never changed
except that a re-inserted retired row whose live files still need it gets `rotation_completed_at` NULL (the rotation
resumes, as before); the current version never moves.

**Salvage (best effort; `mode: "salvage"`, CLI `--salvage`, NeedsConfirmation `vault_key_salvage` + the typed vault
name).** A salvage request is confirmed as a salvage whatever it turns out to do: when no version needs salvage (every
one is restorable), it still asks under `vault_key_salvage`, the text says "Nothing needs salvage", and confirming only
restores (no fresh key, no pass, `salvage: null`); with nothing to write it asks nothing. Runs recover first (attested versions are restored canonically in the same request), then, for the versions
that need salvage (referenced, not held here, with a supplied key):
1. Preconditions (refused with `conflict`, nothing written): a live vault (restore a deleted one first); no pending
   rotation whose outgoing key this host holds (let it finish); after salvage every version live files are sealed
   under is held, salvaged, or has a retired row (so the vault can start); no salvage of this vault already running in
   this process.
2. A `vault_key_salvage` row (state `running`, the versions) is written first. While a salvage row names a version,
   `load_key` doesn't refuse to start over files sealed under it, the rotation pass doesn't try to re-key them, and
   status doesn't list it as needed: those files are being salvaged or are unrecoverable.
3. A fresh daemon key becomes the next version through the rotation path (attested like any other): a running engine
   calls `prepare_key_rotation` (the old current key stays loaded; the normal rotation pass re-encrypts its files);
   without an engine `EncryptionManager::mintSalvageKey` does the same database rotation and closes the retired row's
   rotation (and any pending one, whose outgoing key isn't held) because no held key could finish it. The vault is
   started (`reinstateVault`).
4. The pass: for each `files` row sealed under a salvage version, `sync::rotation::rotateFile` with salvage seams
   (`crypto` decrypts with the supplied key held in memory and seals with the fresh key; the catalog's compare-and-set,
   content lock, busy check and cache refresh are the runtime ones). Local copies go through the sidecar protocol
   (`<backing>.vh-rotate`, fsync, publish upstream for cloud vaults that encrypt upstream, compare-and-set, rename);
   remote-only cloud files go through the metered remote path: price preflight (`key_salvage`, one HEAD + one GET +
   the object's bytes), HEAD, GET with If-Match, authenticated in memory, re-encrypted and PUT, compare-and-set. A
   refused preflight or a missing/archived/changed object is `skipped_remote` (with the estimate); a tag that doesn't
   authenticate (corrupted, or another key's file) or a missing local backing file is `unrecoverable`; a file open
   for writing is `deferred`; anything else `failed`.
5. Crash safety: an interrupted pass leaves the salvage row `running`. Re-running the salvage with the same key
   resumes it on the same fresh version (a new one is minted only when the recorded one is no longer current): it
   first resolves `*.vh-rotate` sidecars with the salvage seams (a sidecar is promoted iff it authenticates under the
   row's state, discarded iff the backing file does: the rotation protocol's rule), then continues with the files
   still under the salvage versions.
6. The report (`vault_key_salvage`: versions, new version, counts `salvaged`, `unrecoverable`, `skipped_remote`,
   `deferred`, `failed`, the first 50 failures `{path, version, kind, reason}`, state, times) is returned in the
   import result (`salvage`), shown by status (`last_salvage`) and written to the audit log. The supplied key bytes
   live only in memory (`crypto::SecretKey`, wiped when the pass ends) and are never written to any table. Versions
   salvaged stay unheld; recovery data (snapshots, local versions, provider versions) sealed under them stays
   unreadable.

**Out of scope, and why.** Rebuilding a vault from backing files alone after total database loss (names, IVs, key
versions and structure live only in the database: restore the database first, then import). A purged deleted vault
(nothing left to verify or salvage). Importing into another vault id (entries are matched by `vault_id`, which the
key check and the attestation bind).

**Missing keys at startup (revision 2, still true).** `EncryptionManager::load_key` mints a key only for a vault
without sealed content (no `files` row with an IV, no recovery blob, no live provider version, no encrypted remote
index entry): new and empty vaults. Otherwise it throws `vault::KeyUnavailable{code}` and the engine doesn't start:
`key_missing` (no `vault_keys` row), `key_unsealable` (a needed row doesn't unseal under this host's vault master),
`version_missing` (the outgoing key of a pending rotation, or a version live files are sealed under, isn't held and
no salvage names it). The message names the command to run (`vh vault keys import <id> --file <export.json>`).
`storage::Manager` records the vault as unavailable (`unavailableVaults()`), health (`stats.system.health`
`vaults_unavailable`, `vh status`) reports it and is at least degraded, and `vault.keys.status` reports
`key_available: false` with `unavailable_reason` = that code and `unavailable_detail`. With no `vault_keys` row, the
status version (and an import's current version) is the highest version the daemon's records reference.

**Input.** The export JSON (`vh vault keys export` / `vault.keys.export`): one vault object or the `all` array; the
entry whose `vault_id` is the target vault; its versions are `key` + `key_info.key_version` (with `key_check` /
`attestation` at the top level or in `key_info`) and every `historical_keys[]` entry (base64, 32 bytes). The CLI
`vh vault keys import <vault> --file <path|-> [--salvage]` reads the file **client-side** (`vh`, or stdin with `-`) and
sends its text in the request frame (`"input": {"v": 1, "text": ...}`, at most 512 KiB); the daemon never opens a
path the caller names. ws `vault.keys.import {vault_id, keys, mode?, confirm_name?}` on paired device sessions only
(D4; `import_requires_device` elsewhere, Denied for agents; excluded from MCP).

**Safety rules (both modes).** Row writes happen in one transaction under the vault's rotation lock
(`pg_advisory_xact_lock(vault_id)`), each UPDATE conditional on the sealed bytes the plan read (else `conflict`,
nothing written). After commit: cached key checks are dropped; a running engine reloads its keys; a live vault without
an engine is started (`storage::Manager::reinstateVault`), and the result says whether it runs. Audit: who, which
vault, which versions (restored / salvaged, with the report's counts), through which channel.

**Permissions.** Same as export: super admins or the encryption-key Export permission; a deleted vault only for
callers who may remove it (ops::vaults' rule).

**Desktop (restore milestone 3).** Reveal the item's versions from 1Password (`item.reveal`), build the export shape
(`VaultKeyImportDocument`: `{vault_id, key, key_check, attestation, key_info: {key_version}, historical_keys:
[{key_version, key, key_check, attestation}]}`; Desktop stores the attestation it received with each export), send `vault.keys.import {vault_id,
keys}` over the paired connection, show the `vault_key_import` confirmation text, ask the user to type the vault name,
resend with `confirm_name`, then poll `vault.keys.status` (`key_available`). Versions answered `needs_salvage` are
offered as a separate, explicit salvage (`mode: "salvage"`, always confirmed under `vault_key_salvage`).

**As built (revision 3).** `vault/KeyAttestation.{hpp,cpp}` (`message`, `signWithSeed`, `verifySignature`, `attest`,
`check`, `provenanceOf`, `backfill`); `db::query::vault::Key` (`Provenance`, `addVaultKey`/`rotateVaultKey` with
provenance computed before the transaction, `recordProvenance`, `attestationKeyId`/`attestationPublicKey`,
`referencedKeyVersions`, `startSalvage`/`runningSalvage`/`lastSalvage`/`finishSalvage`/`salvageVersions`,
`filesSealedUnderVersion`); `EncryptionManager::mintSalvageKey`; `CloudEngine::fetchSealedObject` (replaces revision
2's `forKeyVerification` + `verifyRemoteObjectWithKey`, which import no longer uses); `ops::vault_keys::importKeys`
(recover, then `runSalvage` with `salvageDeps`: `sync::rotation::runtimeDeps` with the crypto seams swapped);
`get_files_older_than_key_version` and `load_key` skip salvage versions. Test seams:
`setSalvageStepHookForTesting` (crash after a protocol step), `setSalvageEngineHookForTesting` (fake bucket, price
gate). Limits: salvage runs inside the request (ws client timeout 600 s); recovery blobs and provider versions sealed
under a salvaged version are not re-keyed; a re-run after a finished pass reuses its key only while it is current.
