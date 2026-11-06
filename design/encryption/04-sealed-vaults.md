# 04. Sealed vaults: client-side cryptographic authority

Status: design for review (#329, workstream 4). **Blocked on #325** (MFA, step-up re-authentication, pairing
hardening) before implementation starts. Uses VHF1 ([02](02-authenticated-file-format.md)), manifest v2 and KEV1
([03](03-metadata-recovery.md)), the `OpaqueV1` layout ([01](01-provider-blind-storage.md)).

## 1. Decisions this spec encodes (maintainer, #329)

- A sealed vault is a **separate, opt-in trust architecture**, not a checkbox on server-encrypted vaults and not a
  variant of `encrypt_upstream`.
- Devices generate and hold the keys. Existing, user-authorized devices approve new devices with cryptographically
  verifiable grants; server-side membership confers nothing.
- The server holds ciphertext, opaque metadata and wrapped keys only.
- Server features that need plaintext are unavailable and the UI says so: previews, search, FUSE plaintext, the S3
  gateway, server-run rotation, guest shares.
- A practical device-loss recovery path that never gives the operator unilateral decryption.
- Pairing and step-up hardening (#325) comes first.
- **D4 (#344):** v1 is single owner with multiple owner-approved devices, macOS Desktop first; multi-user sharing
  and web access are phase 2. The server never receives plaintext, file names or unwrapped content keys, and never
  enrolls an encryption-capable device on its own: only a chain entry signed by an existing device of the owner (or
  the owner's recovery key) adds one.
- **D2 (#344):** a recovery recipient is mandatory before the vault is created or written (§6).
- **Custody amendment (#344):** sovereignty is the default. Sealed vaults stay noncustodial; nothing here holds or
  sends recovery material to Valkyrian Labs (§6).

## 2. Threat model

| Adversary | Can | Cannot |
|---|---|---|
| Server operator (incl. Valkyrian Labs on a hosted instance), a compromised daemon, a DB or backup thief | see ciphertext sizes, counts, tree shape (parent links), timing, which device and account wrote what, name-equality tokens within a folder; delete, withhold, roll back or fork state; refuse service | read content or names; add a device or user to the vault; obtain a content key; make a device accept a forged membership change or a rollback below what that device has seen |
| Storage provider | what spec 01 §3 lists | the same as above |
| An attacker with a user's password (and no device) | sign in to the server (until #325's MFA) | join the vault: joining needs an existing device's approval after a code comparison on both screens |
| A stolen, unlocked device | everything that device's user could do | — (revoke it from another device, then rotate; past data it already decrypted is gone) |
| Valkyrian Labs as software vendor | ship a malicious Desktop update | — this is outside the scheme; mitigated by signing/notarization and stated in claims (spec 05) |

**Not addressed:** endpoint compromise, malicious client builds, metadata listed above, availability, traffic
analysis, coercion of a user.

## 3. What changes for the server

| Server today | Sealed vault |
|---|---|
| Daemon generates the vault key, seals it under `vault_master` (`EncryptionManager::load_key`) | Desktop generates content keys; the server stores only KEV1 envelopes addressed to device and recovery keys |
| `fs_entry.name`, `path` hold plaintext names | `fs_entry` holds `name_ct` (encrypted name) and `name_token`; `path` is a uid path (`/<uid>/<uid>`), never a name |
| The daemon seals files (FUSE, HTTP uploads, sync) | Desktop uploads VHF1 objects it sealed; the daemon stores them byte for byte (resumable upload in a `sealed` mode) and validates structure only (magic, kind, vault uid, size formula), not content |
| Manifest published by the daemon | manifest roots and segments sealed by a device, relayed and stored by the daemon; the daemon may publish only what devices hand it |
| Backing aliases derive a prefix from the name (`id::Generator({.namespace_token = name})`, e.g. `core/src/fs/Filesystem.cpp:237` for folders, `:400` for symlinks) | aliases use no name input (the daemon has none) |
| Logs name entries per `logging.file_paths` (#327) | uids only; `full` mode is unavailable for sealed vaults |

### 3.1 Unavailable features (server-enforced, shown in the UI)

| Feature | Why | UI |
|---|---|---|
| Thumbnails, previews, media transcoding, PDF rendering | need plaintext on the server | file tiles show type icons from the client; the console shows "Previews aren't available in sealed vaults" |
| Search (content and names) | the server has neither | Desktop searches locally |
| FUSE mount on the server, `vh fs get/put` plaintext | the server can't decrypt | the mount omits sealed vaults; `vh fs` refuses with `sealed_vault` |
| S3 gateway | serves plaintext over S3 | binding a sealed vault is refused |
| Server-run key rotation and salvage | need the key | rotation is a device action (§5.4) |
| Guest shares, public links, share uploads | recipients have no device key | refused; sharing to other users is phase 2 (§8) |
| Web console content access | the browser holds no device key in v1 | the console lists the vault as sealed: counts and sizes only |
| Server-side MCP tools reading content, conflict auto-merge by content, dedupe | need plaintext | refused / client-side |
| Key export through `vh vault keys export` | the server holds no key | the recovery kit (§6) replaces it |

Sealed vaults keep: quotas (ciphertext bytes), RBAC on who may write ciphertext or relay grants (account level),
sync to an `OpaqueV1` bucket, provider versioning, the change journal (uids), audit logs (uids).

## 4. Keys

### 4.1 Per device (Desktop)

| Key | Algorithm | Where | Use |
|---|---|---|---|
| Device identity (exists) | P-256, Secure Enclave | Keychain | TLS client certificate to the daemon (pairing, `docs/pairing.md` in the Desktop repo) |
| Vault signing key (new) | P-256 ECDSA, Secure Enclave | Keychain | signs membership-chain entries; separate from the TLS key so a TLS signature can never be replayed as a grant |
| Vault agreement key (new) | P-256 ECDH, Secure Enclave | Keychain | recipient of KEV1 suite 2 envelopes (content keys) |

### 4.2 Per vault

- **Content key** `VCK_v` (32 random bytes on a device), versioned `v = 1, 2, …`. It is the VHF1 "vault key" for
  content, manifest segments and roots of the sealed vault.
- **Name key** `K_name_v = HKDF-Expand(HKDF-Extract(salt = vault_uid, IKM = VCK_v), "vh.sealed.name.v1", 32)` and
  **token key** `K_tok_v = … "vh.sealed.token.v1"`.
- `name_ct = AES-256-GCM(K_name_v, random 12-byte nonce, UTF-8 NFC name, AAD = vault_uid ‖ entry_uid ‖ parent_uid ‖
  UInt32BE(v))`, stored as `UInt32BE(v) ‖ nonce ‖ ct ‖ tag`.
- `name_token = HMAC-SHA-256(K_tok_v, parent_uid ‖ casefold(NFC(name)))[0..16]`: lets the server enforce unique
  names per folder (case-insensitively, as Finder expects). It reveals equality of names within one folder only.
- Recovery recipient: the recovery seed's X25519 key and Ed25519 signing key (spec 03 §5.3).

### 4.3 Envelopes

Every content key version is wrapped (KEV1 suite 2) to every authorized device's agreement key and (suite 1) to the
recovery recipient. Envelopes are stored by the daemon and in the bucket (`.vaulthalla/key/`), so a bucket-only
restore works (spec 03 §6.3).

## 5. Membership chain

An append-only, hash-linked log of signed entries per vault. Devices verify it; the server sequences and stores it.

### 5.1 Entry

Signed blob: `entry = UInt32BE(len) ‖ payload ‖ signature`; the signature is over `"vh.sealed.chain.v1\0" ‖
payload` with the author's signing key (P-256 ECDSA for devices, Ed25519 for the recovery key). Verifiers check the
exact bytes, so no canonical JSON is needed. Payload (JSON):

```json
{"vault_uid": "…", "seq": 7, "prev": "<hex SHA-256 of entry seq 6>", "at": "…",
 "author": {"kind": "device", "id": "<hex SHA-256 of the signing public key>"},
 "op": "add_device",
 "device": {"id": "…", "user": "<account id>", "label": "Cooper's MacBook Pro",
            "sign_pub": "<b64 SEC1>", "kem_pub": "<b64 SEC1>"},
 "grants": [{"key_version": 3, "kid": "<b32>"}]}
```

| `op` | Fields | Rule |
|---|---|---|
| `genesis` (seq 0) | creating device, owner account, `policy` (`{"approvals": 1}`), recovery recipient | signed by the creating device; must name a recovery recipient (§6) |
| `add_device` | device record, grants for every live content key version | author: a current device of the same user, or the recovery key |
| `remove_device` | device id | author: any current device of the user, or the recovery key; must be followed by `rotate_key` in the same publication |
| `rotate_key` | new version `v`, grants to every remaining device and the recovery recipient | author: a current device |
| `replace_recovery` | new recovery recipient + its grants | author: a current device; needs step-up and an explicit confirmation |

### 5.2 Verification

- A device pins the genesis hash when it creates or joins the vault (it receives it inside the approval, §5.3).
- On every sync it fetches entries after its last known `seq`, verifies each signature, `prev` link and rule, and
  stores the new head. A server that presents a chain not extending the device's head (rollback, fork) is refused
  and the user is warned. The server can freeze the chain (availability), not rewrite it.
- The current member set and key version are a pure function of the verified chain. The server's own records of
  devices (the `devices` table) don't enter it.

### 5.3 Approving a new device

1. The new device (signed in, paired to the server for transport, and step-up-verified per #325) creates its keys
   and posts a join request `{vault_uid, sign_pub, kem_pub, label, commit = SHA-256(nonce_new)}`.
2. An existing device of the same user shows the request. It sends `nonce_old`; the new device reveals `nonce_new`
   (commit-then-reveal, so neither side picks the code).
3. Both screens show `SAS = first 6 digits of SHA-256("vh.sealed.sas.v1" ‖ genesis ‖ sign_pub ‖ kem_pub ‖ nonce_old
   ‖ nonce_new)`. The user confirms they match on the old device, which also requires local user presence
   (Touch ID or password) and a fresh server step-up.
4. The old device appends `add_device` with grants for every live key version and gives the new device the genesis
   hash inside the signed entry.

A server that substitutes keys produces a different SAS. A server that never relays the request causes no harm.

### 5.4 Removing a device and rotating

`remove_device` + `rotate_key`: new data is sealed under `v + 1`, which the removed device never receives. Data the
removed device could already read stays readable to it if it kept copies; re-encrypting old data is an optional
device-run job ("re-seal everything"), never server-run.

## 6. Device-loss recovery

| Situation | Path | Operator involvement |
|---|---|---|
| One device lost, another remains | the remaining device removes the lost one and approves a replacement (§5.3, §5.4) | none |
| Every device lost, recovery kit kept | on a new device, enter the recovery seed: derive the recovery keys, unwrap the content keys from the recovery envelopes (daemon or bucket), append `add_device` signed by the recovery key, then `remove_device` for the lost ones and `rotate_key` | none: the operator relays bytes |
| Everything lost | data unrecoverable, by design | none can help; stated at creation |

Creating a sealed vault requires a recovery recipient (the genesis entry must name one; the server refuses a
genesis without one and refuses every write before a valid genesis is stored) and asks the user to store the kit
(1Password item or print) before the first file is written. Sealed vaults are noncustodial: there is no operator
escrow and no "reset" by an administrator; a super admin can delete a sealed vault, not open it. This stronger
guarantee holds for every sealed vault this design creates. A future custodial option (tier C, spec 05 §3.1;
planned, not implemented, separate approval) could only be added by an owner device signing a new chain entry for
it; the server can't add one, every device shows the vault's recipients, and a sealed vault with such a grant would
lose the operator-blind claim (spec 05 §3).

## 7. Migration

Sealed vaults are new vaults. Converting a server-encrypted vault into a sealed one is a client-side copy (Desktop
reads through the normal API, seals, uploads into the new vault), after which the user deletes the old vault. A
server-side conversion would leave the plaintext key path on the server for the old data and is not offered. There
is no existing data in this format, so no migration of stored data is needed; the rollback for a failed copy is to
keep the source vault.

## 8. Phasing

- **v1:** single-owner vaults (the owner's devices plus the recovery key), Desktop on macOS only, sync to `OpaqueV1`.
- **Phase 2:** other users as members (their devices' keys verified out of band: safety numbers or an in-person QR,
  then trust-on-first-use with change warnings), web access through a passkey-derived device key (WebAuthn PRF), a
  Linux client.

## 9. Test plan

| Test | Proves |
|---|---|
| Swift: VHF1, KEV1 suite 2, recovery seed vectors (`vectors.json`) | cross-language format agreement |
| Chain verification vectors (to be generated once the entry format is final; ECDSA signatures are randomized, so the vectors are verify-only) | signature, link and rule checks |
| `SealedVaultServer*` | every unavailable feature refuses with `sealed_vault`; the daemon never receives a content key (key tables empty, no `vault_keys` row); no plaintext name reaches the DB or logs (scan) |
| `SealedUpload*` | pre-sealed objects stored byte for byte; malformed headers and impossible sizes refused |
| `SealedChain*` (server) | append-only sequencing; conflicting `seq` refused; the server cannot author entries; a genesis without a recovery recipient and writes before genesis are refused |
| `SealedNoServerEnrollment` | no server API, admin command or pairing flow results in a device holding a grant without a device- or recovery-signed `add_device` entry; a server-side device record (`devices` table) alone gives no key access |
| `SealedServerNeverSees*` | request capture across create, upload, rename, rotate and recovery: no plaintext, name or unwrapped key in any request body, DB row or log line |
| Desktop UI tests | SAS flow, rollback/fork warning, recovery from seed, removal + rotation |
| Drill | spec 03 §7 with a sealed vault: restore from bucket + seed, no server key involved |

## 10. Proposed implementation issues (all after #325)

- **WS4-a. Sealed vault model on the server.** `vault.trust_model`, encrypted names and tokens, uid paths,
  pre-sealed uploads, chain and envelope storage/relay, feature refusals, log and DB scans.
- **WS4-b. Membership chain and grants protocol** (both repos): entry format, verification rules, join/approve
  ceremony, verify-only vectors.
- **WS4-c. Desktop client crypto and UX** (`vaulthalla-desktop`): Secure Enclave keys, VHF1/KEV1/manifest in Swift,
  File Provider integration for sealed vaults, recovery kit, rotation and re-seal jobs, "not available" copy.
