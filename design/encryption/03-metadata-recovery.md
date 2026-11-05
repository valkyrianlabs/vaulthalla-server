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
  "recipients": [{"id": "<hex SHA-256 of the recipient public key>", "suite": 1, "label": "Recovery kit 2026-11",
                  "added_at": "…"}],
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
path; it does not add one for Valkyrian Labs.

### 5.2 Envelope format (KEV1)

| Offset | Length | Field | Value |
|---|---|---|---|
| 0 | 8 | magic | `89 56 48 4B 0D 0A 1A 0A` (`\x89VHK\r\n\x1a\n`) |
| 8 | 2 | version | `1` |
| 10 | 2 | suite | `1` X25519 + HKDF-SHA-256 + AES-256-GCM (recovery recipients); `2` P-256 ECDH + HKDF-SHA-256 + AES-256-GCM (device grants, spec 04: Secure Enclave keys are P-256) |
| 12 | 1 | purpose | `1` = a vault key version |
| 13 | 3 | reserved | `0` |
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
`vault_mismatch`, `recipient_mismatch`, `bad_length`, `bad_ephemeral`, `wrap_auth_failed`. All primitives exist in
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
  `recovery_seed`. The public key is enrolled on the vault (`vh vault recovery-recipient add --public-key …`, or
  from Desktop over the paired connection, step-up per #325).
- `attestation_public_keys` pin the original node's attestation keys (`key_attestation_keys`), so a restore can
  verify that each recovered key version was minted by the node that owned the vault (§6.2). Desktop refreshes them
  whenever `vault.keys.status` shows a new signing key.
- `checkpoint` bounds rollback (§4.5).
- Storage: the vault's 1Password item (D6) holds the kit; printing it is the offline alternative.

### 5.4 Key material a restore can use

| Material | Covers | Freshness |
|---|---|---|
| Recovery seed (+ envelopes in the bucket) | every version wrapped while the recipient was enrolled | automatic |
| Key export (`vh vault keys export`, Desktop's 1Password item) | the versions in that export | as of the export |
| Both | union | |

## 6. Restore into a new instance

### 6.1 Command

`vh vault recover --bucket <name> --api-key <id> --kit <file | -> [--export <file>] [--into <new vault name>]
[--accept-rollback] [--dry-run]`, on a fresh install (or any instance), run by its operator. ws: a paired-device
command (key material never travels through browser sessions, D4).

### 6.2 Procedure

1. Read `.vaulthalla/layout.json` as a hint; list `.vaulthalla/key/`.
2. Derive the recipient key from the seed; unwrap every envelope addressed to it for the kit's `vault_uid`
   (`recipient_mismatch` envelopes are skipped). Add versions from `--export` if given.
3. Open the root with the held versions; apply the chain rules with the kit's checkpoint as `known` (§4.1).
4. **Provenance (the key-import rule, carried to a new node).** A version becomes canonical in the new vault only if
   its `key_check` (recomputed from the bytes, with the *origin* vault id) matches the root's and its attestation
   verifies under an attestation key pinned in the kit, over the origin node id and origin vault id
   (`"vh-key-attest-v1" ‖ node_id ‖ UInt64BE(vault_id) ‖ UInt32BE(version) ‖ key_check`, `key-backup.md`). This is
   revision 3's rule with the trust anchor moved from the dead node's database to the customer's kit: keys are
   recovered, never introduced. A version without such proof is not made canonical: the restore stops and offers
   salvage (decrypt what authenticates, re-encrypt under a fresh key, `key-backup.md` "Salvage"), confirmed
   separately.
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
offered, nothing canonical).

## 8. Test plan

| Test | Proves |
|---|---|
| `ManifestVectors` (C++), Desktop equivalent | the manifest objects, chain rules and KEV1 envelopes in `vectors.json` |
| `ManifestPublish*` (fake S3) | CoW order (segments then root), `If-Match` conflict → merge, GC keeps the last three roots' segments, cadence |
| `ManifestChain*` | rollback, fork, gap, missing/mismatched segments, older-root fallback |
| `ManifestContent*` | every DB fact the restore needs is in the manifest (round trip DB → manifest → scratch schema → compare) |
| `RecoveryRecipient*` | enrollment requires a paired device + step-up; envelopes written for every existing and future version; removal stops new envelopes (old ones stay: they can't be unpublished from the customer's copies anyway) |
| `VaultRecover*` | §6.2 steps incl. the provenance rule; dry run writes nothing |
| Drill (§7) | the north star, end to end |

## 9. Proposed implementation issues

- **WS3-a. Manifest v2.** Root/segment documents, CoW publish with conditional PUT, GC, chain rules,
  `remote_manifest_state` epoch, replaces `index-v1.json` for `opaque_v1` vaults. Depends on WS2-a, WS1-a.
- **WS3-b. Recovery recipients and KEV1.** Enrollment (paired device + #325 step-up), envelope writer, root key
  history with attestations, `vh-recovery kit create` offline tool, kit format. Depends on WS3-a.
- **WS3-c. `vh vault recover` + drill.** Restore procedure, dry run, harness drill, live R2 drill script. Depends on
  WS3-a, WS3-b.
- **Desktop: recovery kit and checkpoints** (in `vaulthalla-desktop`): generate the seed, enroll the recipient,
  store the kit and checkpoints in the 1Password item, refresh attestation keys. Depends on WS3-b.
