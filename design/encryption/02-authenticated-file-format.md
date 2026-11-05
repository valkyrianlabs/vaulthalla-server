# 02. VHF1: versioned, self-describing authenticated ciphertext format

Status: design for review (#329, workstream 2). Golden vectors: [`vectors/vectors.json`](vectors/vectors.json),
generated and verified by [`vectors/vh_crypto_vectors.py`](vectors/vh_crypto_vectors.py) (`--check`). Those vectors
are the cross-language contract for C++ (daemon) and Swift (Desktop, sealed vaults).

## 1. Decisions this spec encodes (maintainer, #329)

- A versioned header, chunked AEAD, nonce discipline, AAD binding vault id, file id, key version, chunk index and
  the final-chunk flag; truncation, reordering and splicing are detected.
- Authenticated range reads that never emit unauthenticated plaintext.
- **One object per file version**: the chunks are serialized inside one self-describing object. Multipart upload is
  transport only. No per-chunk S3 keys, no object-per-block layout, no extra billed PUTs per chunk.
- Consistent under partial uploads, retries, multipart, abort and provider versioning.
- The legacy headerless AES-GCM format is retired through a verified migration with a clear retirement point. No
  permanent dual format "behind a flag" (the issue body's original wording is superseded by the maintainer's
  compatibility comment).

## 2. Today's format (legacy, "GCM0")

| Property | Today | Source |
|---|---|---|
| Layout | `ciphertext ‖ tag(16)`, one AES-256-GCM message per file, no header | `EncryptionManager::encryptFileToFile` `core/src/vault/EncryptionManager.cpp:345-380`; `docs/reference/transfer-protocol.md` §3.5 |
| IV | 12 random bytes per write, stored base64 in `files.encryption_iv` | `EncryptionManager.cpp:359-360`; `include/crypto/util/encrypt.hpp:10-12` |
| Key version | `files.encrypted_with_key_version`, and `x-amz-meta-vh-key-version` upstream | `deploy/psql/040_files.sql:37-44` |
| AAD | empty | `GcmStreamEncryptor encryptor(key->bytes(), iv)` with no AAD, `EncryptionManager.cpp:362` |
| Key | the vault key itself, for every file of the vault | `EncryptionManager::encrypt`, `:335-343` |
| Range reads | GCM's CTR keystream at an offset (`gcmCtrDecryptAt`, `core/src/crypto/util/Gcm.cpp:55`), plaintext served before the tag is checked; `optimistic` integrity (the default) verifies in the background and fails later reads (`storage/GcmFileReader.cpp:146-162`, `architecture.md` "Verify-once integrity"); remote `ranged` mode has no per-range authentication (`storage/RemoteRangedReader.cpp:147`) | |
| Self-description | none: without the DB row (or the object metadata) a file can't be decrypted | `docs/vaults/secrets-and-key-export.md:180` |

Consequences: ciphertext can be swapped between files of a vault or between versions of one file (no AAD binds
them), range reads emit unauthenticated plaintext, every write under one key draws a random 96-bit IV (the NIST
2^32-messages bound per key applies to the whole vault's history), and recovery needs the database.

The derived-artifact cache already uses a headered, AAD-bound format (`VHDERIV1`, `architecture.md` "Derived
cache"); VHF1 is the same idea for vault content.

## 3. Format

### 3.1 Object layout

```
object = header (120 bytes) ‖ C_0 ‖ C_1 ‖ … ‖ C_{n-1}
C_i    = AES-256-GCM(K_enc, nonce_i, P_i, AAD_i) = ciphertext_i ‖ tag_i (16)
```

The same bytes are the local backing file, the recovery blob and the upstream object: an upload stays a byte copy,
and a recovery blob is still a hard link of the backing file (`recovery.md` "Local storage").

### 3.2 Header (version 1, 120 bytes)

| Offset | Length | Field | Value / rule |
|---|---|---|---|
| 0 | 8 | magic | `89 56 48 46 0D 0A 1A 0A` (`\x89VHF\r\n\x1a\n`: non-ASCII first byte, CR-LF and ^Z detect text-mode mangling) |
| 8 | 2 | format_version | `0x0001` |
| 10 | 2 | header_len | `120` (v1 readers reject anything else) |
| 12 | 2 | suite | `0x0001` = AES-256-GCM chunks, HKDF-SHA-256 key schedule, HMAC-SHA-256 header tag |
| 14 | 1 | chunk_log2 | writers: `16` (64 KiB); readers accept `10..22` |
| 15 | 1 | kind | `1` file content, `2` manifest segment, `3` manifest root (spec 03) |
| 16 | 4 | key_version | ≥ 1; the vault key version (server vaults) or content key version (sealed vaults) |
| 20 | 4 | reserved | `0`; readers reject non-zero |
| 24 | 16 | vault_uid | spec 01 §4.1 |
| 40 | 16 | object_uid | `file_uid` for kind 1; `sid` for kind 2; `vault_uid` for kind 3 |
| 56 | 32 | salt | 32 bytes from the CSPRNG, fresh for every sealing (= the generation id) |
| 88 | 32 | header_tag | `HMAC-SHA-256(K_hdr, header[0..88))` |

`header[0..88)` is the **header body**. `hh = SHA-256(header body)`.

### 3.3 Key schedule and chunk encryption

```
PRK    = HKDF-Extract(salt = header.salt, IKM = vault_key[key_version])         -- RFC 5869, SHA-256
K_hdr  = HKDF-Expand(PRK, "vh.f1.hdr" ‖ hh, 32)
K_enc  = HKDF-Expand(PRK, "vh.f1.enc" ‖ hh, 32)

C       = 2^chunk_log2
n       = max(1, ceil(P / C))            -- P = plaintext length; an empty file has one empty final chunk
P_i     = plaintext[i·C, min((i+1)·C, P))
nonce_i = 0x00000000 ‖ UInt64BE(i)                      -- 12 bytes
AAD_i   = hh ‖ UInt64BE(i) ‖ UInt8(final_i)             -- 41 bytes; final_i = 1 iff i = n − 1
```

What binds what:

| Property | Mechanism |
|---|---|
| Vault id, file id, kind, key version, chunk size, generation | all in the header body → in `hh` → in every `AAD_i` and in both HKDF infos; the header tag covers them too |
| Chunk position | `i` in the nonce and the AAD |
| End of file (truncation, extension) | `final_i` in the AAD: a reader decrypts its last chunk with `final=1`, every other with `final=0` |
| Nonce uniqueness | `K_enc` is unique per sealing (256-bit random salt); within a sealing each index is used once |
| Per-key volume | one `K_enc` per file generation instead of one key per vault; no vault-wide random-IV bound |

Nonce discipline (MUST): a sealing never encrypts two different plaintexts at the same index. Any content change,
however small, is a new sealing with a new salt. A retry re-sends identical bytes (it re-reads the sealed file; it
never re-encrypts). A writer that must restart a sealing after a crash draws a new salt (§4.3).

The vault key never encrypts content directly. HKDF-Expand needs one HMAC block for 32 bytes, so the reader in the
reference implementation computes it as `HMAC(PRK, info ‖ 0x01)`.

### 3.4 Size

`S = 120 + P + 16·n`. Readers derive `(n, P)` from `S` (no length field, so writers can stream):

```
B = C + 16;  (q, r) = divmod(S − 120, B)
r = 0 and q ≥ 1     → n = q,     P = q·C
r = 16 and q = 0    → n = 1,     P = 0          (empty file)
r > 16              → n = q + 1, P = q·C + r − 16
otherwise           → bad_size  (includes S − 120 < 16 and an empty final chunk after full ones)
```

| Plaintext | Chunks (64 KiB) | Object | Overhead |
|---|---|---|---|
| 0 B | 1 | 136 B | 136 B |
| 1 B | 1 | 137 B | 136 B |
| 1,000 B | 1 | 1,136 B | 13.6 % |
| 64 KiB | 1 | 65,672 B | 0.21 % |
| 1 MiB | 16 | 1,048,952 B | 0.036 % |
| 5 MiB | 80 | 5,244,280 B | 0.027 % |
| 100 MiB | 1,600 | 104,883,320 B | 0.025 % |
| 1 GiB | 16,384 | 1,074,004,088 B | 0.024 % |
| 10 GiB | 163,840 | 10,740,039,800 B | 0.024 % |

Legacy overhead is 16 bytes per file. The difference is irrelevant to storage cost; it can move a file just under
5 MiB across the multipart threshold.

### 3.5 Object counts and provider operations

The chunks are inside the object, so object count and PUT count don't depend on the chunk count:

| File | Objects per version | Upload requests (legacy and VHF1) | Note |
|---|---|---|---|
| 0 bytes | 1 (136 B) | 1 PUT | today: 1 PUT of 16 bytes (`CloudEngine.cpp:176-186`) |
| < 5 MiB ciphertext | 1 | 1 PUT | `uploadObjectWithMetadata` (`CloudEngine.cpp:195`) |
| ≥ 5 MiB ciphertext | 1 | 1 CreateMultipartUpload + ⌈S / part⌉ UploadPart + 1 CompleteMultipartUpload | `uploadLargeObject` → `Controller::completeMultipartUpload` (`storage/s3/file.cpp:19-69`); parts are byte ranges of the object, unaligned with chunks |
| Range read | — | 1 ranged GET (header from the manifest) or 2 the first time without it | over-read ≤ 2 chunks + tags (≤ 128 KiB) |
| Full read | — | 1 GET | |

Storage class minimums (S3 IA: 128 KiB billable, 30 days) are unaffected (one object, not one per chunk).

### 3.6 Reading (normative check order)

Readers MUST perform these checks in this order and MUST NOT release any plaintext of a chunk before its tag
verifies. The error codes are the vectors' `expect.error` values.

1. `bad_magic`, `unsupported_version`, `bad_header_length`, `unsupported_suite`, `bad_chunk_size`,
   `reserved_nonzero`.
2. Expectations from the caller (the DB row or the manifest entry): `kind_mismatch`, `vault_mismatch`,
   `object_mismatch` (an object stored under the wrong key, or a ciphertext moved between files), `key_unavailable`.
3. `header_auth_failed`: recompute the header tag (constant-time compare).
4. Size: `size_mismatch` when the caller knows the object size from authenticated metadata and it differs;
   `bad_size` when `S` has no valid layout.
5. Chunks in index order: `chunk_auth_failed` with the index.

Generation check: when the caller expects a generation (the manifest's `generation` or the DB row), the header salt
MUST equal it; otherwise the provider is serving another version of the file (stale read or rollback), and the
reader fetches by version id or fails.

### 3.7 Authenticated range reads

To read plaintext `[a, b)`:

1. The object size `S` MUST come from authenticated metadata (the manifest entry, the DB row) and MUST equal the
   size the provider reports (the `Content-Range` total of the ranged GET). Without it, a reader can't tell a
   truncated object (cut at a chunk boundary) from a short file: `size_unknown` / `size_mismatch`.
2. Compute `i0 = ⌊a / C⌋`, `i1 = ⌊(b − 1) / C⌋`, fetch object bytes `[120 + i0·(C+16), end of chunk i1)` in one
   ranged GET (plus the header when the manifest doesn't carry it).
3. Authenticate each whole chunk with its own index and `final_i = (i = n − 1)`, then cut `[a, b)` out.
4. Emit nothing from a chunk that failed. A failure is sticky for that generation, like today's `IntegrityRegistry`.

A range read proves the returned bytes are the bytes at that offset of this generation of this file. It does not
prove that chunks outside the range are intact (vector `range_tampered_outside`); a full read or the background
verifier does. `gcmCtrDecryptAt` is not used for VHF1. The `optimistic`/`strict` distinction disappears for VHF1
local reads: per-chunk authentication costs one GHASH per 64 KiB, so every read is strict at chunk granularity, and
`preview.media.remote=ranged` becomes authenticated.

### 3.8 Writing

- Size known up front (FUSE seal of a working copy, `createFile` from a buffer or path, resumable uploads, which
  declare the size at create): seal chunks in order, the last with `final=1`.
- Size unknown (streams): hold back one chunk; seal it as final at close.
- The header is written first and never rewritten. The writer computes the header tag before the first chunk.
- `content_hash` (BLAKE2b of the sealed bytes, `fuse/WorkingCopies.cpp:268`) keeps its meaning (a hash of the sealed
  object); under `OpaqueV1` it is never sent to the provider (spec 01 §4.3).
- The generation id (`storage::Generation::sourceId()`, today the IV) becomes the salt (base64), so ETags and
  `content_version` keep their "changes on every write, survives rename" semantics (`architecture.md` "Byte-serving
  spine").

## 4. Consistency under upload failure modes

| Situation | Behavior |
|---|---|
| Single PUT fails or times out | Retry the same bytes. The object is either absent, the previous version, or this version; all are complete VHF1 objects. A reader checks the generation against the manifest. |
| Multipart part fails | Today the upload aborts (`storage/s3/file.cpp:44-63`). VHF1 doesn't change this: parts are opaque byte ranges of an already sealed file. Retrying a part re-sends identical bytes. |
| Multipart abort fails, or the daemon dies mid-upload | An incomplete multipart upload is invisible to GET/LIST and is not an object; the bucket lifecycle `AbortIncompleteMultipartUpload` (R2 creates a default rule; Vaulthalla's `vaulthalla-managed` rule should carry one too) removes it. |
| Complete succeeds but the response is lost | The object exists; the next pass sees its ETag/size and the header generation and records it (spec 01 §6.2). |
| Local sealing interrupted (crash) | The sidecar protocol (`*.vh-rotate`, `recovery.md`) promotes a sidecar only if it authenticates; with VHF1 that is a full chunk walk with the final flag, so a torn sidecar is always discarded. |
| Resumable upload part retried with different bytes | The sealing cursor seals only the contiguous, decided prefix (`transfer-protocol.md` §3.5). With VHF1 it seals whole chunks as the prefix grows; it never re-seals an index under the same salt. After a restart it rebuilds by authenticating the sealed prefix (no re-encryption), and if the decided bytes for a sealed index ever differ it restarts the file with a new salt. |
| Provider versioning | Each version is a complete, independent VHF1 object with its own salt. Backlog replays PUT older generations as they were sealed (their own key version and salt). A provider rollback of the current object is detected by the generation check (§3.6). |
| Key rotation | Re-seal under the new key version: new salt, new object version. Retained generations keep their key version (`recovery.md` "Keys"). |

## 5. Threat model

**Addresses:** confidentiality of content against anyone without the vault key (provider, bucket readers, stolen
backing disks or backups); integrity and authenticity of every emitted byte, including against reordering,
truncation, extension, splicing between files, vaults or versions, and header tampering; unauthenticated plaintext
release on range reads.

**Does not address:** an adversary holding the vault key (the daemon host in the server model: spec 05); rollback to
an older but authentic generation when the reader has no fresher metadata (spec 03 §4.5 bounds it); availability;
size and access-pattern leakage (spec 01 §3); key-committing security (GCM is not key-committing: an attacker who
chooses two keys can craft a ciphertext that decrypts under both. Here keys are random and derived per file by HKDF,
never attacker-chosen, and the header tag plus the AAD binding make the multi-key attack irrelevant to this
system; sealed vaults inherit the same argument because content keys are generated on devices).

## 6. Migration and retirement of the legacy format

### 6.1 What is converted

| Data | Converter | Network |
|---|---|---|
| Local backing files (all vaults) | re-seal: legacy GCM decrypt (streaming, authenticated before commit) → VHF1 under the same key version; sidecar + compare-and-set + rename, the rotation protocol (`sync::rotation::rotateFile`) | none |
| Recovery blobs (`.vh-recovery/`) | re-seal into a new blob, swap `recovery_blob` row (IV → salt, format) in one transaction, then unlink the old blob; a blob shared with a live file by hard link converts once (dedupe on generation) | none |
| Upstream objects of `path_v0` vaults, their provider versions and the backlog | spec 01 §6 (layout and format together) | GET (remote-only) + PUT |
| Upstream objects of `transparent` vaults | none (plaintext upstream); only their local backing files convert | none |
| Resumable upload parts in flight | not converted: an upload started before the upgrade finishes in the legacy format and is converted by the next local pass | none |

Key versions stay the same (no rotation, per the issue's rule that no existing key is rotated by these changes).
Same-key conversion still draws a new salt, so the generation id changes and caches keyed on it (derived artifacts,
`IntegrityRegistry`) refresh naturally.

### 6.2 Verification per item

Before the rename/commit of each converted item: authenticate the legacy tag over the whole input, compute
BLAKE2b of the plaintext while streaming, authenticate the VHF1 output (full chunk walk) and compare its plaintext
BLAKE2b. Only then commit. The legacy bytes of a local file are not kept after a verified commit: the conversion is
reversible from the VHF1 bytes (same key, same plaintext), so keeping both would only be a second copy.

### 6.3 Retirement point

| Release | Writers | Readers | Gate |
|---|---|---|---|
| N (ships VHF1) | VHF1 for every new generation | VHF1 and legacy | local conversion runs automatically per vault (background, rate-limited, resumable, `vh vault format status` shows progress); upstream conversion through spec 01 §6 |
| N … N+k | VHF1; legacy writer only for the spec 01 §6.4 soak rollback | both | — |
| Retirement release | VHF1 only | VHF1 only | `preinst`/startup refuses to proceed while any `files`, `recovery_blob`, `upstream_object_version` (live) or backlog row is legacy, and names the command that converts it. No stored data is ever left without a reader. |

The retirement release is the first one cut after every known install reports zero legacy rows (today: Cooper's
installs; no external customer depends on the legacy format).

## 7. Test plan

| Test | Proves |
|---|---|
| `Vhf1Vectors` (C++, reads `vectors.json`) | byte-exact sealing of every positive vector from its params; every negative rejected with its code and chunk index; every range plan and plaintext |
| Desktop `VHF1VectorsTests` (Swift, the same JSON) | the same in CryptoKit (sealed vaults, spec 04) |
| `Vhf1Streaming*` | streaming writer equals one-shot; hold-back of the final chunk; 0-byte; exact multiples of the chunk size |
| `Vhf1RangeReader*` | never returns bytes of a failed chunk; size from authenticated metadata required; sticky failure |
| `Vhf1Upload*` (fake S3) | 0-byte, small, multipart objects are one object each; part failure → abort, nothing stored; lost Complete response reconciled; retry re-sends identical bytes |
| `Vhf1Resumable*` | sealing cursor seals whole chunks only; restart rebuilds by authentication; divergent bytes restart with a new salt |
| `Vhf1Sidecar*` | torn sidecar discarded, complete one promoted |
| `FormatMigration*` | local conversion idempotent and resumable; plaintext digest compared; recovery blobs and hard-linked live files converted once; retirement gate refuses with legacy rows present |
| `IntegrityContract` (tools/contracts) | no `gcmCtrDecryptAt` call reachable for VHF1 generations |
| Fuzz (`libFuzzer`, dev box) | header parser and chunk walker never crash or emit plaintext on malformed input |

## 8. Proposed implementation issues

- **WS2-a. VHF1 codec + golden vectors in C++.** `crypto::vhf1` (header, key schedule, streaming writer/reader,
  range reader, size math), `Vhf1Vectors` test reading `design/encryption/vectors/vectors.json`, fuzz target. No
  product behavior change.
- **WS2-b. VHF1 at rest for new generations.** FUSE seal, `createFile`, resumable sealing cursor, rotation, recovery
  capture/reseal, `GcmFileReader` → chunk reader, generation id = salt, DB format/generation columns; legacy reads
  kept. Depends on WS2-a, WS1-a (file uid).
- **WS2-c. Local format conversion** of backing files and recovery blobs (background, resumable, verified, status).
  Depends on WS2-b.
- **WS2-d. Legacy format retirement** (remove legacy reader/writer, upgrade gate). Depends on WS2-c and WS1-c being
  committed on every known install.
- **Desktop: VHF1 in Swift + vectors** (in `vaulthalla-desktop`, for sealed vaults). Depends on WS2-a.
