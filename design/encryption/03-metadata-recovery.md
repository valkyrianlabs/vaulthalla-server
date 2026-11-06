# 03. Encrypted metadata recovery: the bucket is enough

Status: design for review (#329, workstream 3). Formats: manifest objects are VHF1 kinds 2 and 3
([02](02-authenticated-file-format.md)); key envelopes are KEV1 (§5). Vectors: `vectors.json` sections `manifest`
and `kev1`.

## 1. Decisions this spec encodes (maintainer, #329)

- The north star: **a fresh installation with only the customer's authorized recovery material and the encrypted
  bucket reconstructs files, names, versions and layout after the old server, database and TPM are destroyed.**
- Recovery metadata is part of the storage product: an encrypted, authenticated, self-describing manifest in the
  bucket, readable without PostgreSQL.
- Tested: missing and corrupt manifests, replay and rollback, key-version histories, snapshots, deleted and renamed
  files, recovery when the original signing hardware is gone; the integrity and anti-rollback limits of an untrusted
  bucket are stated.
- The Recovery service restores into **customer-operated** instances (spec 05).
- **D1 (#344):** on a fresh node, a key version is canonical only when its original-node attestation verifies
  against the original public key pinned in customer-held recovery material; otherwise explicit salvage and
  re-encryption. A fresh server's self-attestation never proves old provenance (§6.2).
- **D2 (#344):** customer-held recovery recipients are mandatory for managed storage and sealed vaults before
  creation or writes; recommended but optional for self-hosted BYOS when an independently verified key export gives
  a viable recovery path (§5.5).
- **Recovery custody amendment (#344):** "Sovereignty is the default. Custody is an option. Neither should compromise
  the other." By default, Vaulthalla recovery is independently customer-controlled. Valkyrian Labs receives no
  recovery keys or decryption authority unless a customer separately enrolls in an explicitly authorized custodial
  recovery service. D2's "do not escrow content-decryption material to Valkyrian Labs" is the default for every vault;
  custody exists only through tier C (spec 05 §3.1) after its own approval, and is **not implemented**. The formats
  are extensible for separately authorized recipients and threshold participants without a redesign (§5.2, §5.7).
- **Replay limit (#344):** an untrusted bucket can replay an older valid state unless the customer keeps an
  independent freshness checkpoint (§4.5).
- **Quality gate (#344):** `opaque_v1` creation is not offered as fully recoverable until the manifest, recovery
  recipients/exports and the catastrophic restore drill pass; until then it is staged internally (README, "Quality
  gates").

## 2. Today

| Fact | Source |
|---|---|
| The remote manifest `.vaulthalla/index-v1.json` is plaintext JSON keyed by path, with sizes, IVs, key versions, content hashes, ETags and version ids; its only integrity is an unkeyed SHA-256 over the object list | `core/src/sync/model/RemoteManifest.cpp:27-77` |
| It is a sync cache: a pass reloads the index from it when the index is empty or the ETag moved; it has no names beyond paths, no folders, modes, owners, snapshots or key history | `CloudEngine::refreshRemoteIndexFromManifestIfChanged`, `CloudEngine.cpp:411-443` |
| Vault keys exist only sealed under the host's `vault_master` (TPM2, Secure Enclave or file backend), plus whatever the customer exported | `.claude/context/key-backup.md` "Keys in one paragraph" |
| Exports carry every needed key version with its key check and a node attestation (Ed25519, seed sealed by the TPM); import restores only attested versions, everything else is salvage | `key-backup.md` "Key import (S6, D7): design, revision 3" |
| "Restoring a vault from its encrypted files alone, after the database is lost, is not possible" | `docs/vaults/secrets-and-key-export.md:180`; `key-backup.md` "Out of scope" |
| An export taken before a rotation doesn't contain the new version: until the customer re-exports, files sealed under it depend on the host alone | `vault_keys.exported_version` tracking, `key-backup.md` |

## 3. Manifest v2 (`OpaqueV1` vaults)

A copy-on-write tree: one small root that names immutable segments. The root is rewritten per publish with a
conditional PUT; segments are written once under fresh random names and collected later.

### 3.1 Objects

| Key | Kind | Encrypted under | Content |
|---|---|---|---|
| `.vaulthalla/root` | VHF1 kind 3, `object_uid = vault_uid` | current vault key version | root document (§3.2) |
| `.vaulthalla/seg/<sid>` | VHF1 kind 2, `object_uid = sid` | the key version current when it was written | segment document (§3.3) |
| `.vaulthalla/key/<kid>` | KEV1 | recipient's public key | one vault key version for one recovery recipient (§5); `kid` = base32(SHA-256(envelope)[0..16]) |
| `.vaulthalla/layout.json` | cleartext | — | `{"layout":"OpaqueV1","vault_uid":"…","format":1}`: a hint for discovery, never trusted |

Documents are UTF-8 JSON. The AEAD authenticates bytes, so no canonical serialization is required; the vectors use
sorted keys without whitespace to be reproducible.

### 3.2 Root document

```json
{
  "type": "vh.manifest.root", "v": 1,
  "vault_uid": "as4f38nkrkaydxr834n3pk2xdr",
  "layout": "OpaqueV1",
  "epoch": 2,
  "prev": "<hex SHA-256 of the previous root object's bytes, or null for epoch 1>",
  "published_at": "2026-11-05T12:02:00Z",
  "producer": {"node_id": "<device_node.node_id>", "vault_id": 42, "software": "vaulthalla 1.20.0"},
  "vault": {"name": "Finance", "created_at": "…", "quota_bytes": null, "sync_strategy": "cache",
            "recovery_policy": {"mode": "provider_versioning", "retention": {"days": 90}}},
  "keys": [
    {"version": 1, "key_check": "<hex>", "attestation": {"key_id": 3, "public_key": "<b64>", "signature": "<b64>"},
     "created_at": "…", "retired_at": "…", "envelopes": ["<kid>", "…"]},
    {"version": 2, "key_check": "<hex>", "attestation": {…}, "created_at": "…", "retired_at": null, "envelopes": […]}
  ],
  "recovery_policy": {"v": 1, "threshold": null, "grants": [
    {"grant_id": "<b32>", "recipient_id": "<hex SHA-256 of the recipient public key>", "class": "customer",
     "suite": 1, "label": "Recovery kit 2026-11", "added_at": "…", "authorized_by": "<entry id or device id>",
     "revoked_at": null}]},
  "segments": [{"sid": "<b32>", "range": ["00", "7f"], "count": 4096, "object_sha256": "<hex>", "size": 391104}],
  "snapshots": [{"sid": "<b32>", "object_sha256": "<hex>", "size": 1234}],
  "stats": {"files": 7311, "dirs": 402, "bytes": 18234411231}
}
```

- `epoch` increases by exactly 1 per publish. `prev` chains roots.
- The roots and segment in `vectors.json` are reduced documents (no `vault`, `recipients` or `envelopes`): they pin
  the encryption, kinds and chain rules, not the full schema.
- `keys` is the vault's complete key history: every version any file, version or snapshot in the manifest
  references, with the version's recorded key check and node attestation (migration 113). Retired versions stay
  listed while anything references them (the same rule as `recovery_guard_retired_vault_key`).
- `segments[*].object_sha256` and `size` pin the exact segment bytes: a root can't be combined with other segments.

### 3.3 Segment documents

Entries are partitioned by the first byte of their uid (`range`, inclusive hex bounds); a segment splits when it
exceeds 8,192 entries or 4 MiB of plaintext and merges with a neighbor below 1,024.

```json
{"type": "vh.manifest.segment", "v": 1, "vault_uid": "…", "range": ["00", "7f"], "entries": [
  {"uid": "<b32>", "kind": "dir", "parent": "<b32 or null for the root>", "name": "Reports", "mode": 493,
   "owner": {"uid": 1000, "gid": 1000}, "mtime": "…", "ctime": "…"},
  {"uid": "<b32>", "kind": "file", "parent": "<b32>", "name": "Q3 board pack.pdf", "mode": 420, "mtime": "…",
   "size": 3172, "mime": "application/pdf", "format": 1, "key_version": 1, "generation": "<hex salt>",
   "content_hash": "<hex>",
   "object": {"etag": "\"…\"", "size": 3356, "version_id": "…", "storage_class": "STANDARD"},
   "versions": [{"version_id": "…", "generation": "…", "key_version": 1, "size": 3356, "etag": "…",
                 "last_modified": "…", "noncurrent_at": "…", "delete_marker": false, "origin_last_modified": "…"}],
   "names": [{"until": "…", "parent": "<b32>", "name": "draft.pdf"}],
   "trashed": null},
  {"uid": "<b32>", "kind": "symlink", "parent": "<b32>", "name": "latest", "target": "Reports/Q3 board pack.pdf"}
]}
```

- The tree is `parent` + `name` (not full paths), so renaming a folder changes one entry.
- `names` keeps prior locations for as long as provider versions of the file are retained (bounded by the retention
  window, and to 32 entries), so a point-in-time folder restore can place a file where it was at time *t*
  (`recovery.md` "Directory point-in-time restore" assumes path keys today).
- `trashed` (`{"at": …, "by": …}`) keeps files in the vault trash (`files_trashed`); purged files leave the entries,
  except as **tombstones** (`kind: "tombstone"`, uid, last parent/name, versions) while the provider still retains
  versions of their object.
- A snapshot segment lists `{snapshot id, name, created_at, members: [{uid, path_at_capture, generation,
  key_version, provider_version_id | null}]}`. Local snapshot blobs live on the host only (`.vh-recovery/`), so after
  a catastrophe a member is restorable only when the bucket holds that generation (a provider version or the
  current object). The manifest states this per member; nothing claims more.
- As implemented (#368): one snapshot per segment (VHF1 kind 2, object uid = its sid, named by the root's
  `snapshots`), immutable once written: `{"type": "vh.manifest.snapshot", "v": 1, "vault_uid": "…", "snapshot":
  {"id": 7, "name": "…" | null, "created_at": "…", "root_path": "/Reports", "members": [{"uid": "<b32>" | null,
  "path_at_capture": "…", "generation": "<hex>"?, "key_version": 1?, "provider_version_id": "…" | null,
  "restorable_from_bucket": true}]}}`. Directories and symlinks carry their own uids (`directories.uid`,
  `symlinks.uid`, migration 125) like files (`files.object_uid`); `mtime` / `ctime` are the entry's `updated_at` /
  `created_at`; a trashed file keeps its uid (`files_trashed.object_uid`) and `trashed.path` (where it was; its parent
  may be gone). Since #370 `recovery_policy.grants` lists every recovery grant of the vault (revoked ones with
  `revoked_at`, oldest first) and `keys[].envelopes` names the kids of each version's KEV1 envelopes (absent for a
  version without any); see §5.8.
- No field holds plaintext content or a plaintext digest. `content_hash` is the sealed bytes' hash (spec 02 §3.8).

### 3.4 Publish protocol

1. Under the vault's pass lease, compute the changed segments. PUT each as a new `seg/<sid>` with
   `If-None-Match: *`.
2. Build the root (`epoch = known + 1`, `prev = known root hash`), seal it under the current key version and PUT
   `.vaulthalla/root` with `If-Match: <known root ETag>` (`If-None-Match: *` for epoch 1).
3. On `412 Precondition Failed`: another writer published. Load the new root, verify it (§4), merge our pending
   changes on top, retry (bounded, as `publishRemoteIndexManifestWithRetry` does today). Never overwrite blindly.
4. Record `(epoch, root SHA-256, ETag)` in `remote_manifest_state`.
5. Garbage collection (janitor, daily): delete segments referenced neither by the current root nor by the previous
   two, and older than 24 h. A reader that loaded an older root a moment ago therefore still finds its segments.

Objects are always written before the manifest that references them. A crash between an object PUT and the next
publish leaves an object no manifest names (an orphan, §4.4), never a manifest entry without its object.

Publish cadence: once per sync pass that changed anything (as today, `upstream-control-plane.md` #248), and after
key events (rotation, recipient enrollment). The root carries the key history, so a rotation is recoverable as soon
as its first publish lands.

### 3.5 Costs

| Vault | Per publish | Notes |
|---|---|---|
| ≤ 8,192 entries | 1 segment PUT + 1 root PUT | today: 1 PUT of the index (`recovery.md` live measurements) |
| 100,000 entries, 1 file changed | 1 segment PUT (≈ 4 MiB) + 1 root PUT | today: 1 PUT of a ≈ 25 MB plaintext index |
| Rename of a folder with N files | 1 segment PUT (the folder's entry) + 1 root PUT | today: N PUT + N DELETE |
| GC | DELETE of superseded segments (free on S3 and R2) | versioned buckets keep them 1 day (`vaulthalla-manifest-versions`) |

## 4. Reading, consistency and anti-rollback

### 4.1 Loading a root

1. GET `.vaulthalla/root`; VHF1 open with expectations kind 3, object uid = vault uid, held key (spec 02 §3.6).
2. Apply the chain rules against what the reader knows (`remote_manifest_state` in normal operation, a customer
   checkpoint in a restore, nothing in a blind restore):

| Condition | Result |
|---|---|
| `epoch < known.epoch` | `rollback`: refuse, alert (`operator_notification`), keep the DB's state |
| `epoch == known.epoch` and hash ≠ known | `fork`: refuse, alert |
| `epoch == known.epoch + 1` and `prev ≠ known hash` | `fork` |
| `epoch > known.epoch + 1` | accept only if the chain back to `known` can be walked through retained root versions; otherwise accept with a `gap` warning (another writer published several times, e.g. a restore elsewhere) |
| no known state | accept, record |

Vectors: `manifest.chain` states every row a single root can (`fresh_restore_accepts_epoch_2`, `advance_1_to_2`,
`rollback_2_to_1`, `rollback_3_to_2`, `fork_same_epoch`, `gap_1_to_3` with no retained roots, so `"warning": "gap"`)
and both segment pins (`segment_replaced`, `segment_missing`). The walk through retained versions is tested in C++
(`ManifestChain.*`).

3. Fetch every segment the root names, check `SHA-256` and size (`segment_mismatch`, `segment_missing`), open each
   (kind 2, object uid = sid).

### 4.2 Missing or corrupt manifest objects

| Failure | Recovery, in order |
|---|---|
| Root missing or failing authentication | (a) newest authentic root among the provider's versions of `.vaulthalla/root` (versioned buckets); (b) rebuild from the DB when the daemon is alive (normal publish); (c) blind rebuild (§4.3) |
| Segment missing or mismatched | (a) the segment's own provider versions (same key; immutable objects only get deleted); (b) an older root whose segment for that uid range is intact, then reconcile with objects; (c) the uid range is rebuilt blind |
| Envelope missing | another recipient's envelope, or a key export (§5.4) |
| `layout.json` missing or wrong | ignored: the layout is learned from the authenticated root |

### 4.3 Blind rebuild (no usable manifest)

List `o/`, read each object's 120-byte header (ranged GET), keep those that authenticate under a held key, and
recover them as files under `/Recovered/<file uid>` with their sizes, key versions and generations. Names and the
tree are lost in this case; content is not. This is the floor, and the drill (§7) measures that it works.

Per-object encrypted name hints (the path at last write, sealed inside each object) were considered and left out of
v1: they go stale on every rename (renames don't rewrite objects), and they add a second encrypted field to every
object. Revisit if the drill or field data show manifest loss is a realistic failure.

### 4.4 Objects vs manifest

| Situation | Normal operation (DB present) | Restore (no DB) |
|---|---|---|
| Object in `o/` that no manifest entry names | orphan from an interrupted write; the DB knows it, the next publish lists it | if it authenticates: `/Recovered/<uid>`; the restore reports it |
| Entry whose object is missing | reported, file marked unavailable; provider versions listed if any | the entry is restored as unavailable (name kept), with its versions |
| Object generation ≠ entry generation | the provider served another version: fetch by `version_id`; if that fails, report | same |

### 4.5 What an untrusted bucket can and cannot do

| Attack by someone with bucket write access but no keys | Detected? |
|---|---|
| Read content, names, tree | prevented (encryption) |
| Modify any object, header, chunk, segment or root | detected (AEAD, header tag, segment pinning) |
| Move ciphertext between files, vaults, kinds or versions | detected (header expectations, AAD) |
| Mix segments from different roots | detected (root pins segment hashes) |
| Roll back the whole vault to an older authentic root (if they kept a copy, or from provider versions) | detected by a reader that knows a newer epoch (the live daemon, or a restore with a fresher checkpoint); **not detectable by a blind restore**: it will see an older but authentic vault |
| Roll back one file to an older authentic generation | detected against the manifest (generation check) unless the manifest was rolled back too (row above) |
| Delete objects, segments, roots, envelopes | detected as missing; not preventable (availability is the provider's) |
| Withhold the newest root while the daemon is down | equals rollback; bounded by the newest checkpoint the restorer holds |

**The replay limitation, precisely.** Everything in a root, its segments and the objects it names is authenticated
under the vault key, so the bucket can't invent or alter state. But any state that was once valid stays valid: a
bucket writer who kept (or can list as provider versions) an older root, its segments and the object versions it
names can present that whole older state, and it authenticates. A reader can reject it only by comparing with
freshness information it holds independently of the bucket. Without such a checkpoint a restore **cannot
distinguish the latest state from any earlier valid state**, and it says so in its report ("freshness unverified:
no checkpoint supplied"). With a checkpoint, the restore rejects anything older than the checkpoint, and still
cannot detect a rollback to a state between the checkpoint and the true latest one. Deletion (of everything after
some point) is the same attack and is likewise bounded only by the checkpoint.

Freshness therefore needs state outside the bucket. Vaulthalla keeps it in two places:

- The daemon's DB (`remote_manifest_state.epoch`, root hash).
- **Customer checkpoints**: `{vault_uid, epoch, root_sha256, at}` recorded by Desktop with every key-backup
  confirmation (1Password item, `key-backup.md` D6) and in the recovery kit (§5.3). A restore warns when the root is
  older than the newest checkpoint supplied, and refuses without `--accept-rollback`.

Signing roots with the node's attestation key would add provenance, not freshness, and that key dies with the TPM;
the AEAD under the vault key already excludes everyone who lacks the key. Not in v1.

## 5. Recovery recipients and key envelopes (KEV1)

### 5.1 Why

An export is a snapshot: a rotation after the last export leaves the newest key only on the host. A **recovery
recipient** is a customer public key enrolled on the vault; the daemon wraps every key version, current and future,
to it and stores the envelopes in the bucket. The private key never reaches the daemon except during a restore the
customer runs (spec 05 §3).

This is the customer-wrapped escrow the maintainer's custody comment describes. It adds a customer-held decryption
path; it does not add one for Valkyrian Labs. Customer-controlled recipients are the default and the only recipient
class this design implements (tier A, spec 05 §3.1); restore with them needs nothing from Valkyrian Labs: no
account, payment, registration or VL infrastructure.

### 5.2 Envelope format (KEV1)

| Offset | Length | Field | Value |
|---|---|---|---|
| 0 | 8 | magic | `89 56 48 4B 0D 0A 1A 0A` (`\x89VHK\r\n\x1a\n`) |
| 8 | 2 | version | `1` |
| 10 | 2 | suite | `1` X25519 + HKDF-SHA-256 + AES-256-GCM (recovery recipients); `2` P-256 ECDH + HKDF-SHA-256 + AES-256-GCM (device grants, spec 04: Secure Enclave keys are P-256) |
| 12 | 1 | purpose | registry: `1` = a whole vault key version (32 bytes); `2`-`255` reserved (e.g. a threshold share, whose payload a future spec defines) |
| 13 | 1 | recipient_class | registry: `0` = customer-controlled (recovery recipients and owner devices: every envelope this design writes); `1`-`255` reserved for separately authorized classes (e.g. custodian, threshold participant) |
| 14 | 2 | reserved | `0` |
| 16 | 4 | key_version | ≥ 1 |
| 20 | 16 | vault_uid | |
| 36 | 32 | recipient_id | SHA-256 of the recipient public key (32 raw bytes for X25519; 65-byte uncompressed SEC1 point for P-256) |
| 68 | 2 | epk_len | 32 (suite 1) or 65 (suite 2) |
| 70 | epk_len | epk | ephemeral public key, fresh per envelope |
| 70 + e | 48 | wrapped | `AES-256-GCM(K_wrap, nonce = 0^12, vault_key (32), AAD = bytes[0 .. 70+e))` |

`prefix = bytes[0 .. 70+e)`; `Z` = X25519(esk, rpk), or the P-256 shared x-coordinate; reject an all-zero `Z`.

```
K_wrap = HKDF-Expand(HKDF-Extract(salt = epk ‖ rpk, IKM = Z), "vh.kev1.wrap" ‖ prefix, 32)
```

The zero nonce is safe because `K_wrap` is single-use (fresh ephemeral key). Sizes: 150 bytes (X25519), 183 bytes
(P-256). Reader checks, in order: `bad_magic`, `unsupported_version`, `unsupported_suite`, `bad_purpose`,
`unsupported_recipient_class`, `reserved_nonzero`, `vault_mismatch`, `recipient_mismatch`, `bad_length`, `bad_ephemeral`, `wrap_auth_failed`. All primitives exist in
OpenSSL 3.0, libsodium, Python `cryptography` and CryptoKit (`Curve25519.KeyAgreement`, `P256.KeyAgreement`
including `SecureEnclave.P256`, `HKDF<SHA256>`, `AES.GCM`); HPKE (RFC 9180) was not chosen because Ubuntu 24.04's
OpenSSL 3.0 lacks it.

### 5.3 Recovery kit

Generated on a customer-controlled device (Desktop, or the offline `vh-recovery kit create` tool), never on the
server. One kit can serve many vaults.

```json
{"type": "vh.recovery-kit", "v": 1,
 "recovery_seed": "148hr6b6azfczjm7b2hs4x7hn0j",
 "vaults": [{"vault_uid": "…", "origin": {"node_id": "…", "vault_id": 42},
             "attestation_public_keys": [{"key_id": 3, "public_key": "<b64>"}],
             "checkpoint": {"epoch": 812, "root_sha256": "<hex>", "at": "…"}}]}
```

- `recovery_seed` is 16 random bytes, written as its 26-symbol base32 form plus one check symbol
  `alphabet[SHA-256(seed)[0] >> 3]` (27 symbols; display grouping is cosmetic). It derives the keys:
  `PRK = HKDF-Extract(salt = "vh.recovery.v1", IKM = seed)`, X25519 recipient key `HKDF-Expand(PRK, "x25519", 32)`,
  Ed25519 signing seed `HKDF-Expand(PRK, "ed25519", 32)` (used by sealed vaults, spec 04 §4). Vectors:
  `recovery_seed`. The public key is enrolled on the vault (`vh vault keys recipient add <vault> --public-key …`,
  or from Desktop over the paired connection, `vault.keys.recipients.add`, step-up per #325).
- `attestation_public_keys` pin the original node's attestation keys (`key_attestation_keys`), so a restore can
  verify that each recovered key version was minted by the node that owned the vault (§6.2). Desktop refreshes them
  whenever `vault.keys.status` shows a new signing key.
- `checkpoint` bounds rollback (§4.5).
- Storage: the vault's 1Password item (D6) holds the kit; printing it is the offline alternative.

### 5.4 Key material a restore can use

| Material | Covers | Freshness | Trust anchor for D1 |
|---|---|---|---|
| Recovery seed (+ envelopes in the bucket) | every version wrapped while the recipient was enrolled | automatic | the kit's `attestation_public_keys` |
| Key export (`vh vault keys export`, Desktop's 1Password item) | the versions in that export | as of the export | the export's `attestation.public_key` (added by WS3-b: today's exports carry `{key_id, signature}` only, `key-backup.md`; an export without the public key can't anchor provenance on a fresh node) |
| Both | union | | either |

### 5.5 When a recovery recipient is required (D2)

| Vault | Rule | Enforced at |
|---|---|---|
| Managed storage (VL-managed B2), any server vault | a recovery recipient must be enrolled before the vault is created (the creation request carries the recipient public key) and before any write; removing the last recipient is refused | `ops::vaults::create`, the write path (a vault without one refuses writes with `recovery_recipient_required`), recipient removal |
| Sealed vault (spec 04) | the genesis entry must name a recovery recipient; the server refuses a genesis without one and writes before the genesis | sealed vault creation, chain append |
| Self-hosted BYOS, `encrypt_upstream=true` | recommended, optional. Without a recipient, the vault must have a **verified export** covering every needed version (`vault.keys.status`: current `exported_version`, a Desktop confirmation with a matching key check, and no `missing_versions`); otherwise status and health report `recovery_material_missing` (degraded, never hidden) and the console shows the recommendation prominently. A rotation makes an export stale, which returns the vault to `recovery_material_missing` until re-exported. | status, health, console |
| Local vaults, `transparent` vaults | the existing export guidance | — |

By default, Vaulthalla recovery is independently customer-controlled: kits are generated on customer devices
(§5.3), the server only ever receives public keys, and neither managed-storage onboarding nor account creation,
adding a payment method or upgrading Vaulthalla generates a seed, uploads a key or enrolls a recipient. Valkyrian
Labs receives no recovery keys or decryption authority unless a customer separately enrolls in an explicitly
authorized custodial recovery service (tier C, spec 05 §3.1; planned, not implemented). The server can't verify
who holds a public key, so the class in the envelope and the root is what the customer declared and authorized;
a recipient Valkyrian Labs holds is never offered as class `0`.

### 5.6 The same host after a TPM loss

With the database intact but the TPM state (or the Secure Enclave keys) gone, `KeyProvider::initGuarded` refuses to
generate a new `vault_master` while vault keys depend on it and throws `MasterSecretLost` (#326,
`core/include/crypto/secrets/KeyProvider.hpp`). The ways back stay what #326 lists (restore the sealed state, import
key backups) plus one: `vh vault keys import <vault> --recovery-kit <file>` unwraps the vault's envelopes from the
bucket with the kit's seed and feeds them to the normal import, which verifies attestations against this node's
own `key_attestation_keys` (revision 3, unchanged). No bucket-level restore is needed in that case.

### 5.7 Extensibility for separately authorized recipients (no implementation)

The recipient system must be able to accept, later, recipients that are not customer devices (a custodian's key,
threshold participants) without a destructive change to VHF1, KEV1 or the manifest. Checked concretely:

| Surface | How a future recipient type fits | Effect on existing data |
|---|---|---|
| VHF1 objects | content keys are independent of who can unwrap them | none |
| KEV1 | `recipient_class` (byte 13) names the class and `purpose` (byte 12) the payload type, both inside the authenticated prefix; a new suite can be added for a custodian's key type | every envelope written now has class `0` and purpose `1` and stays byte-identical (vectors unchanged); v1 readers reject (and a restore skips, without failing) classes and purposes they don't know: vectors `reserved_recipient_class`, `reserved_purpose_threshold_share` |
| Manifest root | `recovery_policy` is versioned (`v`); each recipient is an **independently revocable grant** (`grant_id`, `class`, `authorized_by`, `revoked_at`); `threshold` is reserved (`null`); readers ignore unknown members and never use a grant of an unknown class to decrypt | none |
| Sealed vault chain (spec 04 §5) | a future op (e.g. a custodial grant) would be a new `op` signed by an owner device, never by the server | none |

Revocation of a grant stops new envelopes for it. It does not revoke access the recipient already had: an envelope
it received keeps unwrapping the versions it covers, so a revocation is followed by a key rotation (and, where the
recipient could have read old data, re-encryption of that data) when the customer needs the recipient's access cut
off. Nothing here adds an API, table, billing hook or code path for custodians, and no recovery material may be
sent to Valkyrian Labs until such a service is designed, approved and explicitly enabled by the customer.

### 5.8 As implemented (#370)

- **Codecs.** `crypto::kev1` (`core/{include,src}/crypto/recovery/Kev1.*`: `wrap`, `unwrap` with the reader's checks in
  §5.2's order, `inspect`, `kid`, `skippedByRestore`; suites 1 and 2, OpenSSL 3), `crypto::recovery::RecoverySeed`
  (`Seed.*`) and the kit (`Kit.*`, `parseKit`/`toJson`). Every `kev1` and `recovery_seed` vector passes
  (`Kev1Vectors`, `RecoverySeedVectors`, `Kev1ReservedFields`, `RecoveryKit`).
- **Grants and envelopes** (migration 127): `vault_recovery_grant` (one row per grant: `grant_id` base32, `recipient_id`,
  X25519 `public_key`, suite 1, `class` CHECKed to `customer`, label, `added_at`, `authorized_by` = `user:<id> via
  cli|device`, `revoked_at`/`revoked_by`; one active grant per recipient key) and `vault_key_envelope` (grant ×
  version → kid). `vault::envelopes` (`vault/RecoveryEnvelopes.*`) wraps and PUTs (`If-None-Match: *`) to the vault's
  own bucket through its API key; nothing else ever receives an envelope. A vault without a usable grant makes no
  request.
- **When envelopes are written.** Before a new version is committed: `EncryptionManager::prepare_key_rotation`, the
  salvage key (`mintSalvageKey`) and a vault's first key put the version's envelopes first and fail (nothing committed)
  when a PUT fails; at enrollment for every held version; and at the start of each cloud sync pass for anything still
  missing (`CloudEngine::ensureRecoveryEnvelopes`), which also asks an `opaque_v1` vault to republish its root.
- **Surfaces.** `vh vault keys recipient list|add|revoke` and ws `vault.keys.recipients.list|add|revoke`
  (`ops::recovery_recipients`). List: the encryption-key View permission, any session. Add and revoke: the Export
  permission, the local CLI or a paired device (`recipient_requires_device` for browser sessions, agents denied and
  excluded from MCP), and a `keys` step-up bound to the vault (#359; the host CLI is exempt, a device is refused until
  #361). Audit: `vault.recovery.recipient.add|revoke`. S3 vaults only (a local vault has no bucket).
- **D2 (§5.5).** `vault::envelopes::material` → `vault.keys.status` `recovery`
  (`not_required | recipient | export | recovery_material_missing`, `uncovered_versions`, `export_current`,
  `rotation_needed`) and health `vaults_recovery_material_missing` (degraded). "Verified export" is
  `vault_keys.exported_version` = the current version (the CLI's export or a device's confirmation with a matching key
  check). The managed-storage rules (recipient required at creation and for writes, last recipient not removable) land
  with managed storage itself (#375): there is no managed storage in the server yet.
- **Exports** carry `attestation.public_key`; an import on this node requires it to be its own key of that id (older
  exports without it import as before).
- **§5.6.** `vh vault keys import <vault> --recovery-kit <file|->` (the kit is read client-side): lists
  `.vaulthalla/key/`, unwraps with the seed (another recipient's and reserved envelopes are skipped and counted), keeps
  per version only the key whose key check the vault's records name (planted keys are `ignored`), takes the attestation
  this node recorded for it (else, for `opaque_v1`, the root's key history opened with the unwrapped keys) and runs the
  normal recover rules: never a new version, never the current version moved, never a held key replaced. Recover mode
  only; audit `vault.keys.import.recovery_kit`. A kit that lists vaults but not this one is refused.
- **Kit tool.** `vh-recovery kit create|public-key|add-vault|show` (`core/main/recovery.cpp`, shipped as
  `/usr/bin/vh-recovery`): offline, writes kits with mode 0600 and never over a file; `add-vault` pins a vault from
  `vh vault keys status --json` (which now reports `vault_uid`, `node_id`, `attestation_public_keys`, `checkpoint`).
- **Tests.** `RecoveryRecipient.*`, `RecoveryRequirement.*`, `RecoveryNoSilentCustody.*`, `KeysImportFromKit.*`,
  `VaultKeyExportProvenance.*` (`test_recovery_recipients.cpp`, DB), `SqlDeployerHistoryDb.RecoveryRecipients*`,
  `recovery_tool` (meson). `vh vault recover` on a fresh node with the kit's pinned keys as the anchor: §6.4 (#371).

## 6. Restore into a new instance

### 6.1 Command

`vh vault recover --bucket <name> --api-key <id> --kit <file | -> [--export <file>] [--into <new vault name>]
[--accept-rollback] [--dry-run]`, on a fresh install (or any instance), run by its operator. ws: a paired-device
command (key material never travels through browser sessions, D4).

### 6.2 Procedure

1. Read `.vaulthalla/layout.json` as a hint; list `.vaulthalla/key/`.
2. Derive the recipient key from the seed; unwrap every envelope addressed to it for the kit's `vault_uid`
   (`recipient_mismatch`, `bad_purpose` and `unsupported_recipient_class` envelopes are skipped, never fatal). Add versions from `--export` if given.
3. Open the root with the held versions; apply the chain rules with the kit's checkpoint as `known` (§4.1).
4. **Provenance (the key-import rule, carried to a new node).** A version becomes canonical in the new vault only if
   its `key_check` (recomputed from the bytes, with the *origin* vault id) matches the root's and its attestation
   verifies under an attestation key pinned in the kit, over the origin node id and origin vault id
   (`"vh-key-attest-v1" ‖ node_id ‖ UInt64BE(vault_id) ‖ UInt32BE(version) ‖ key_check`, `key-backup.md`). This is
   revision 3's rule with the trust anchor moved from the dead node's database to the customer's kit: keys are
   recovered, never introduced. A version without such proof is not made canonical: the restore stops and offers
   salvage (decrypt what authenticates, re-encrypt under a fresh key, `key-backup.md` "Salvage"), confirmed
   separately. Trust-anchor cases, each tested:

   | Anchor | Result |
   |---|---|
   | pinned key in the kit or export verifies the version's attestation | canonical |
   | no anchor supplied (no kit, or a kit/export without public keys) | salvage only |
   | anchor present but empty | salvage only |
   | anchor that doesn't verify (another node's key, a forged key, an attestation over another vault id, node id or version) | salvage only, and the report names the mismatch |
   | attestations re-signed by the **restoring** node | never accepted as proof of origin: the new node's key is not in the customer's material |
   | key check recomputed from the bytes differs from the root's or the attestation's | the version is refused (damaged or foreign key) |

5. Load segments, create a new vault (new numeric id, same `vault_uid`) bound to the bucket with
   `storage_layout = 'opaque_v1'`, rebuild `fs_entry`/`files`/trash/symlinks, `remote_object_index`,
   `upstream_object_version`, snapshot records (members marked restorable only where the bucket holds the
   generation), key rows (sealed under the new host's `vault_master`, provenance recorded: "recovered from node X
   vault Y, attestation verified with kit key N", then re-attested by the new node).
6. Reconcile with a listing of `o/` (§4.4): orphans to `/Recovered/`, missing objects marked.
7. Start the vault in cache strategy (nothing is downloaded until read), publish a new root (`epoch + 1`) so the old
   node, if it ever comes back, sees a fork and stops (§4.1).
8. Report: files, folders, versions, snapshots (restorable / not), key versions recovered, orphans, missing objects,
   checkpoint comparison.

`--dry-run` does steps 1-6 into a scratch schema and reports without creating anything; the migration's
verification (spec 01 §6.3) is the same code.

### 6.4 As implemented (#371)

- **Plan** (`vault::recover`, `core/{include,src}/vault/Recover.*`; no database writes): the vault uid (the caller's,
  else the kit's, else the bucket's hint; a hint the kit doesn't list is `kit_vault_mismatch`), every KEV1 envelope
  (`kid` → recipient id and version; the kit's seed unwraps those addressed to it, `recovery_material_mismatch` when
  none is), the export's versions (`parseExport`; exports now carry `node_id` and `vault_uid`), `loadForRestore` with
  the kit's checkpoint (`rollback` refused unless `accept_rollback`, `fork` always), else a blind rebuild. Per version
  one key: the root's key check picks among candidates (planted keys lose), the export's first without a root.
  Reconciliation: one LIST of `o/`; objects no entry names are read by their 120-byte header and placed under
  `/Recovered/<uid>` (empty plaintext needs no key); an object whose ETag or size moved since the manifest is read by
  its header (generation and key version); entries without an object are restored and reported `missing_objects`;
  entries whose folder is gone (a lost segment) or that form a cycle go under `/Recovered`. `MeteredStore` counts
  manifest, envelope, header and content bytes (`downloads.content_bytes` stays 0).
- **D1** (`prove`): evidence per version from the root (its producer's node and vault id), the root's recorded
  `keys[].origin` (a version an earlier restore recovered) and the export; pins from the kit entry (keys, origin node
  and vault) and export public keys. Verdicts `verified`, `no_anchor`, `empty_anchor`, `unattested`, `unverified`,
  `wrong_node`, `wrong_vault`, `self_attested` (a pinned key that is any of the restoring node's own attestation keys)
  and `key_check_mismatch` (refused, not salvaged). `blocking()` = versions live files (or the current version) need
  that aren't canonical; any blocking version makes the restore `salvage_required`.
- **Write** (`db::query::vault::Recover::apply`, one transaction; migration 131 `vault_key_origin`): the vault (a
  reserved id, the bucket's uid, `opaque_v1`, cache strategy), the tree with the manifest's uids and inodes from the FS
  cache, trash, `remote_object_index` (source `manifest`), `upstream_object_version` (origin `observed`), snapshot
  records (members `upstream_state = sent` where the bucket holds their generation, else `none`), the canonical key
  versions (re-sealed, re-attested by this node, the verified evidence as their origin), grants of class customer with
  a public key (the root's `grants[].public_key`, added by #371, or the kit's own) and their envelope rows, the file
  recovery preference, and `remote_manifest_state`/`remote_manifest_root` at the loaded root. Salvage: a fresh key at
  `max(every version the bucket names) + 1` as current, canonical versions retired, a `vault_key_salvage` row naming
  the salvageable versions, then `ops::vault_keys::salvageRecoveredVault` runs the import's salvage pass; files under
  versions nothing holds are left out and reported. The supplied keys are never stored.
- **Surfaces** (`ops::vault_recover`): `vh vault recover --api-key --bucket [--kit] [--export] [--into] [--vault-uid]
  [--accept-rollback] [--dry-run] [--salvage --confirm-name]` (the kit and export are read by `vh` and sent as one
  bundle) and ws `vault.recover` (paired devices; `recover_requires_device` elsewhere; keys step-up bound to the
  bucket; excluded from MCP). Audit `vault.recover`. After the write the vault is reinstated and publishes epoch + 1.
  `--dry-run` plans in memory (no scratch schema): the same code without the write.
- **Also fixed here:** key rotation and salvage record the object they PUT in the remote index
  (`CloudEngine::recordOwnUpload`), so an `opaque_v1` manifest names the object the bucket holds after a rotation;
  `vh vault keys status` reports each recovered version's `origin`.
- **Tests:** `VaultRecoverTrustAnchor.*` (every row of the step 4 table), `VaultRecoverDb.*` (fresh node from the kit,
  second restore through the recorded origin, dry run, salvage, export-only after a rotation, rollback, wrong
  material, deleted root versioned and unversioned, corrupt segment). The drill (§7): `vhh drill recover` (fake S3
  with versioning, three private instances with their own databases and swtpm) and `tools/harness/drill_recover_r2.sh`.

### 6.3 Sealed vaults

Spec 04's manifest is written by devices under the vault content key; the same restore reads it with the sealed
vault's recovery recipient. The new instance never holds the content key: the restore rebuilds the opaque
namespace (uids, sizes, encrypted names) and a device holding the recovery seed rejoins (spec 04 §6).

## 7. Catastrophic restore drill

Automated in the harness (fake S3 with versioning) and run live once per release candidate on R2 and, when the test
identity allows versioning, AWS (one `vh-test-*` bucket per run, deleted afterwards).

**Setup:** an `opaque_v1` vault with 2,000 files in nested folders (0-byte, small, multipart-sized), symlinks,
renames of files and folders, files in the trash and purged files, two key rotations (one with the retired version
still referenced by provider versions), provider versioning with retained history (AWS), a snapshot, an aborted
multipart upload, a recovery recipient enrolled after the first rotation, a key export taken before the second
rotation, and a checkpoint.

**Destroy:** stop the daemon; drop the database; wipe the TPM state (`swtpm` state directory) or the Secure Enclave
keys; delete the host's backing store.

**Restore:** fresh install, new TPM; `vh vault recover --kit kit.json`.

**Pass criteria:** the plaintext tree (path, bytes, mode, mtime, symlink targets) equals the pre-destroy tree; trash
equals; every provider version is listed with the right key version and restores; snapshot members are restorable
exactly where the bucket holds their generation and labelled otherwise; key status shows every version present and
attested-by-origin; the vault rotates its key and syncs afterwards; a second `recover` of the same bucket into
another instance is consistent; zero bytes downloaded beyond headers, manifest and envelopes until a file is read.

**Negative drills:** root deleted (versioned → older root; unversioned → blind rebuild; content intact under
`/Recovered`); one segment corrupted; root rolled back with a newer checkpoint (refused; accepted with
`--accept-rollback`); wrong seed; a kit for another vault; an export only (no seed) after a rotation (versions after
the export are reported missing, never invented); envelopes present but the kit lacks attestation keys (salvage
offered, nothing canonical); a kit whose attestation key belongs to another node, and one with an empty key list
(salvage only); restored attestations re-signed by the restoring node presented as an anchor (refused).

**Independent host:** the restore runs on a different machine from the one that wrote the vault (harness: a second
private instance with its own database and swtpm state; live: written on dev, restored on a separate VM or Mac), with
nothing shared but the bucket and the customer material.

## 8. Test plan

| Test | Proves |
|---|---|
| `ManifestVectors` (C++), Desktop equivalent | the manifest objects, chain rules and KEV1 envelopes in `vectors.json` |
| `ManifestPublish*` (fake S3) | CoW order (segments then root), `If-Match` conflict → merge, GC keeps the last three roots' segments, cadence |
| `ManifestChain*` | rollback, fork, gap, missing/mismatched segments, older-root fallback |
| `ManifestContent*` | every DB fact the restore needs is in the manifest (round trip DB → manifest → scratch schema → compare) |
| `RecoveryRecipient*` | enrollment requires a paired device + step-up; envelopes written for every existing and future version; removal stops new envelopes (old ones stay: they can't be unpublished from the customer's copies anyway) |
| `VaultRecover*` | §6.2 steps incl. the provenance rule; dry run writes nothing |
| `VaultRecoverTrustAnchor*` | every row of the §6.2 step 4 table: verified, missing, empty, wrong-node, wrong-vault, self-attested and key-check mismatch anchors |
| `RecoveryRequirement*` | managed-storage creation and writes refused without a recipient; last-recipient removal refused; BYOS without a recipient or a verified, current export reports `recovery_material_missing`; a rotation makes an export stale |
| `Kev1ReservedFields` | envelopes of a reserved purpose or recipient class are rejected by the reader and skipped by a restore that still succeeds from the customer's envelopes |
| `RecoveryNoSilentCustody` | creating an account-free vault, upgrading, adding managed storage or enrolling a recipient never adds a non-customer grant or sends key material anywhere but the bucket (request capture) |
| `KeysImportFromKit*` | `MasterSecretLost` on the same host, then import from the kit's envelopes restores the vault under the existing attestation rules |
| `ManifestReplay*` | an older complete state (root + segments + object versions) authenticates; without a checkpoint the report says "freshness unverified"; with one, older states are refused |
| Drill (§7) | the north star, end to end |

## 9. Proposed implementation issues

- **WS3-a. Manifest v2.** Root/segment documents, CoW publish with conditional PUT, GC, chain rules,
  `remote_manifest_state` epoch, replaces `index-v1.json` for `opaque_v1` vaults. Depends on WS2-a, WS1-a.
- **WS3-b. Recovery recipients and KEV1.** Enrollment (CLI or a paired device, D4; #325's step-up once it lands), envelope writer, root key
  history with attestations, attestation public keys in exports, the D2 requirement rules (§5.5),
  `vh vault keys import --recovery-kit` (§5.6), `vh-recovery kit create` offline tool, kit format. Depends on WS3-a.
- **WS3-c. `vh vault recover` + drill.** Restore procedure with the D1 trust-anchor rules, dry run, harness drill on
  an independent instance, live R2 drill script. Passing it lifts the internal staging of `opaque_v1` creation.
  Depends on WS3-a, WS3-b.
- **Desktop: recovery kit and checkpoints** (in `vaulthalla-desktop`): generate the seed, enroll the recipient,
  store the kit and checkpoints in the 1Password item, refresh attestation keys. Depends on WS3-b.
