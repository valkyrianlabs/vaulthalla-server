# 01. Provider-blind storage: opaque object ids under `encrypt_upstream=true`

Status: design for review (#329, workstream 1). Depends on [02](02-authenticated-file-format.md) (object format) and
[03](03-metadata-recovery.md) (encrypted manifest). Normative words: MUST, MUST NOT, SHOULD.

## 1. Decisions this spec encodes (maintainer, #329)

- Opaque object ids are **intrinsic to `encrypt_upstream=true`**. There is no `opaque_objects` or
  `encrypt_filenames` switch. `encrypt_upstream=false` keeps readable S3 keys and plain objects.
- Managed storage (VL-managed B2) enforces `encrypt_upstream=true` and the opaque layout. No downgrade toggle.
- The layout is an internal, versioned field (`storage_layout`), not a security choice offered to users.
- One S3 object per logical file version. AEAD chunks live inside it (spec 02), never as separate objects.
- Existing encrypted buckets migrate through an idempotent, verified migration that covers current objects, provider
  versions, the upstream backlog and recovery objects, with rollback until verified.
- No plaintext path, name or content fingerprint is emitted to the provider under `encrypt_upstream=true`.
- **D3 (#344):** every required retained upstream version and recovery generation is re-sealed into the opaque
  layout; inventories and actual decryption are verified before anything path-keyed is deleted; Object Lock,
  retention, incomplete history and failed deletes are respected; the migration is never called finished while names
  remain in provider history; bounded verify/soak/rollback period and destructive-cleanup guardrails (§6.3-§6.5).

## 2. What the provider sees today (`PathV0`)

| Surface | Today, `encrypt_upstream=true` | Source |
|---|---|---|
| Object key | The vault path without its leading slash (`Reports/Q3 board pack.pdf`) | `CloudEngine::upload` `core/src/storage/CloudEngine.cpp:159` (`stripLeadingSlash(f->path)`), same in every upload/delete/HEAD path (`:216`, `:222`, `:267`, `:627`, `:912`, `:923`) |
| Prefixes | The folder tree, one prefix per folder | follows from the key |
| Object metadata | `x-amz-meta-vh-encrypted`, `vh-iv` (base64 IV), `vh-key-version`, `content-hash` (BLAKE2b of the sealed bytes) | `CloudEngine::getMetaMapFromFile` `CloudEngine.cpp:123-135`; metadata rewrites `storage/s3/meta.cpp:112-170` add `vh-algo=aes256gcm` |
| Manifest | `.vaulthalla/index-v1.json`, **plaintext JSON**: every key (= path), size, mtime, content hash, IV, key version, ETag, version id; integrity only an unkeyed SHA-256 | `sync/model/RemoteManifest.cpp:37-77`, published by `CloudEngine::publishRemoteIndexManifest` `CloudEngine.cpp:445-476` with `x-amz-meta-vh-manifest-version` |
| Rename | A new key plus a removed key: the planner diffs by path (`Planner::build`, `core/src/sync/Planner.cpp:28-54`), so the provider sees the old and new names, a re-upload and (in versioned buckets) a delete marker under the old name | |
| Versions, delete markers | Listed per path key: every retained version and every delete marker names the file | `upstream_object_version.object_key` (`deploy/psql/111_file_recovery.sql:197-220`) |
| Backlog replay | Older generations PUT under the path key, with their own `vh-iv`/`vh-key-version` | `CloudEngine::uploadGeneration`, `.claude/context/recovery.md` "Local versions as the upstream backlog" |
| ETag | MD5 of the ciphertext (single PUT) or the multipart form `md5(md5s)-N` | provider behavior |
| Size | Ciphertext = plaintext + 16 | legacy format (spec 02 §2) |
| Copies | Copy reuses the sealed bytes and IV, so two keys carry byte-identical objects | `recovery.md` "Keys" |

The operator documentation already says so: "The bucket operator still sees object names and provider metadata"
(`docs/vaults/encryption.md:93`). `PathV0` is not provider-blind and must not be described as such (spec 05).

## 3. Threat model

**Adversary:** the storage provider, or anyone with read (and possibly write) access to the bucket, its access logs,
inventory reports, event notifications or replication targets. Passive and active (may replace, delete, roll back
or reorder objects and versions).

**Goal (provider-blind):** from the bucket alone the adversary learns no file or folder name, no path, no tree shape,
no plaintext content, and no plaintext-derived fingerprint; active tampering is detected (spec 02, spec 03).

**Still leaks (documented, not addressed by v1):**

| Leak | Granularity |
|---|---|
| Number of files | object count under `o/` (≈ files + bounded metadata objects) |
| Exact plaintext size per file | object size − 120 − 16 × chunks (spec 02 §3.4); no padding in v1 |
| Write times and frequency per file | stable id per file: overwrites of one file land on one key |
| Read pattern | which objects are read, when, and which byte ranges (ranged GETs reveal chunk ranges) |
| Request counts and timing per sync pass | including the manifest root rewrite per pass |
| Number of content versions and deletion times | provider versions and delete markers per `o/<id>` |
| Number of key versions (rotations) | header `key_version` (cleartext) and key-envelope count |
| Approximate manifest size | segment sizes ≈ entry count |
| That the bucket is a Vaulthalla vault | the layout descriptor and the key shapes |
| Vault creation time, account, region, storage class | provider account data |

**Not addressed here:** the host running the daemon (it holds keys, the database and names: spec 05 states who that
is), traffic analysis of client ↔ daemon connections, availability (the provider can delete everything).

## 4. The `OpaqueV1` layout

### 4.1 Identifiers

| Id | Bytes | Assigned | Stable across | Stored |
|---|---|---|---|---|
| `vault_uid` | 16 from the CSPRNG (`randombytes_buf`) | vault creation, or migration for existing vaults | restore into a new instance (it comes back from the manifest) | `vault.uid` (new, UUID column, raw 16 bytes, no version semantics) |
| `file_uid` | 16 from the CSPRNG | file creation (any path that creates a `files` row: FUSE create, `createFile`, sync download of a new key, upload, copy) | rename, move, content changes, key rotation | `files.object_uid` (new) |
| `sid` (segment), `kid` (envelope) | 16 | per object, spec 03 | immutable objects | manifest root |

A copy is a new file: new `file_uid`, and the bytes are re-sealed (spec 02 binds the file uid), so no two objects
carry identical ciphertext.

Text form: lower-case Crockford base32 of the 16 bytes, 26 symbols, big-endian bit order, the 2 padding bits zero.
Decoders MUST reject upper case, non-alphabet symbols, other lengths and non-zero padding (one spelling per id).
Vectors: `vectors.json` `object_ids`.

### 4.2 Object keys

| Key | Content | Format | Mutability |
|---|---|---|---|
| `o/<file_uid>` | file content, one object per file; provider versions = content versions | VHF1 kind 1 (spec 02) | overwritten on content change |
| `.vaulthalla/layout.json` | cleartext hint: `{"layout":"OpaqueV1","vault_uid":"<b32>","format":1}` | JSON, ≤ 256 bytes | written once; never trusted (spec 03 §6) |
| `.vaulthalla/root` | manifest root | VHF1 kind 3 (spec 03) | overwritten with `If-Match` per publish |
| `.vaulthalla/seg/<sid>` | manifest segment | VHF1 kind 2 | immutable, garbage-collected |
| `.vaulthalla/key/<kid>` | key envelope to a recovery recipient | KEV1 (spec 03 §5) | immutable |

No fan-out prefixes (`o/ab/…`): neither S3 nor R2 needs them at Vaulthalla's request rates, and fewer prefixes mean
fewer listing calls. The `.vaulthalla/` prefix is kept so the existing lifecycle rule `vaulthalla-manifest-versions`
(`recovery.md`, "Retention on the bucket") still scopes metadata. A bucket holds one vault (`s3.vault_id` is the
key of `s3`, `deploy/psql/020_vaults.sql:60-68`), so keys carry no vault prefix.

### 4.3 Request content rules (MUST, for every request on an `OpaqueV1` vault)

1. No `x-amz-meta-*` headers on content, segment, root or envelope objects. `vh-encrypted`, `vh-iv`,
   `vh-key-version`, `vh-algo`, `content-hash` and `vh-manifest-version` are all gone: the header inside the object
   (spec 02) carries what the reader needs, and the encrypted manifest carries the rest.
2. `Content-Type: application/octet-stream` for every object (already true for data: `storage/s3/file.cpp:109`,
   `multipart.cpp:92`). No `Content-Disposition`, `Content-Encoding`, `Content-Language`, tags (`x-amz-tagging`) or
   website redirects.
3. Checksums (`Content-MD5`, `x-amz-checksum-*`), when sent, are computed over the ciphertext bytes on the wire,
   never over plaintext.
4. Storage class: the vault's configured class only (it is per vault, not per file).
5. Query strings carry no names (`ListObjectsV2` prefixes are `o/` or `.vaulthalla/…` only).
6. Server-side copy (`CopyObject`) is used only onto the same key (provider-version restore) with directive `COPY`;
   there is no metadata to replace.

These rules are enforced in one place: the `OpaqueV1` request builder, plus a fake-S3 test that records every
request and fails on any header or key outside an allowlist (§8).

As implemented (#369): the one place is `s3::Controller::enforceRequestPolicy`, which every operation of a controller
set to `opaque_v1` runs before it sends or meters anything (the fake bucket runs it too). A full listing sends no
prefix at all (the query then names nothing) so that foreign keys can be reported; the import of a foreign object is
the only request that names a foreign key (a GET, never a write). Checksums are SigV4's `x-amz-content-sha256` of the
bytes sent; no `Content-MD5` or `x-amz-checksum-*` is sent.

### 4.4 Data-plane behavior

| Operation | `PathV0` today | `OpaqueV1` |
|---|---|---|
| New file | PUT `<path>` | PUT `o/<file_uid>` |
| Overwrite | PUT `<path>` | PUT `o/<file_uid>` (new provider version if versioned) |
| Rename / move | PUT new path (+ DELETE old under mirror) | **no object request**; the manifest changes |
| Copy | PUT new path with identical sealed bytes | re-seal (new file uid, new generation), PUT `o/<new uid>` |
| Delete | DELETE `<path>` | DELETE `o/<file_uid>` |
| Read | GET `<path>`, metadata from HEAD or the index | GET `o/<file_uid>`; header from the manifest or the first 120 bytes |
| Key rotation | re-seal + PUT `<path>` | re-seal + PUT `o/<file_uid>` |
| Backlog replay | PUT older generations at `<path>` with their metadata | PUT older generations at `o/<file_uid>` (the header carries the key version) |
| Provider-version restore | CopyObject `?versionId` onto `<path>` | the same onto `o/<file_uid>` (the header binds the file uid, not the version) |

Sync identity changes from the path to the file uid. The planner keys local and remote state by `file_uid`;
`remote_object_index`, `upstream_object_version`, `file_versions.upstream_key`, write intents, the usage ledger and
the event inbox store object keys (`o/<b32>`) instead of paths. A rename is a manifest-only change, so sync's
rename handling becomes exact (today it is a delete plus an add).

**Objects without a manifest entry** (`foreign_objects`): an `o/<id>` object whose header authenticates but that no
manifest entry or DB row names is an orphan of an interrupted write (spec 03 §4.4). Any other key in an `OpaqueV1`
bucket is foreign: `ignore` (default) leaves it alone and reports it; `import` reads it as plaintext, seals it into
a new file under `/Imported/<key>` and leaves the original untouched (deleting it is a separate, confirmed action).
The rule "an object without Vaulthalla metadata is an authentication failure unless the vault imports foreign
objects" (`upstream-control-plane.md`) carries over unchanged in substance.

As implemented (#369): the policy is the event subscription's `foreign_objects` (no subscription: `ignore`). An
import happens once per key: an existing `/Imported/<key>` (live or in the trash) is never imported again. An orphan
is left alone (counted and logged per pass) until a restore (#371) places it; objects of files in the vault trash
wait for the trash purge.

**Events** (`sync/events/`): decoded keys are object keys. `o/<id>` is resolved to a file through the index; the
`.vaulthalla/` keys stay "self" and are skipped, as manifest keys are today.

### 4.5 Database and logs

Provider-blindness is about the bucket. The daemon's host is inside the trust boundary of the operator model (spec
05) and keeps the path ↔ object mapping in PostgreSQL (`files.object_uid` beside `fs_entry.path`). Rules:

- Transport logs (`[S3Provider]`, `[CloudStorageEngine]` request lines) name object keys only. Filesystem logs follow
  `logging.file_paths` (#327: entry ids by default). No log line pairs an object key with a path or name, so a
  shipped transport log reveals nothing the provider doesn't already have.
- Diagnostics and support bundles (spec 05 §5) carry object keys and entry ids, never names, unless the customer
  exports names explicitly.
- Sealed vaults (spec 04) go further: the server never holds names at all.

### 4.6 `storage_layout` and `encrypt_upstream`

New column `s3.storage_layout TEXT NOT NULL` with values:

| Value | Meaning | Allowed with |
|---|---|---|
| `transparent` | readable keys, plaintext objects, readable `x-amz-meta-*` (today's `encrypt_upstream=false`) | `encrypt_upstream = false` only |
| `path_v0` | legacy: path keys, legacy GCM objects, plaintext index | `encrypt_upstream = true`, existing vaults until migrated |
| `opaque_v1` | this spec | `encrypt_upstream = true` |

`CHECK ((encrypt_upstream AND storage_layout IN ('path_v0','opaque_v1')) OR (NOT encrypt_upstream AND
storage_layout = 'transparent'))`. New `encrypt_upstream=true` vaults are created `opaque_v1`. The migration
backfills `transparent` and `path_v0`. No API, CLI or console field exposes the layout as a choice; status shows it
(`vh vault status`: "storage layout: opaque (v1)"), and the migration state.

Changing `encrypt_upstream` on an existing vault (`ops/Vaults.cpp:389-391`, behind the sign-waiver permission) is a
layout conversion run by the same migration engine (§6): `transparent → opaque_v1` encrypts and re-keys every object;
`opaque_v1 → transparent` decrypts them into path keys. Until the conversion commits, the old layout stays
authoritative. Managed storage refuses `encrypt_upstream=false`.

## 5. Cost and request impact

| Event | `PathV0` requests | `OpaqueV1` requests |
|---|---|---|
| Upload of a new or changed file | 1 PUT (or multipart) + manifest PUT per pass | 1 PUT (or multipart) + per pass: changed segment PUTs + 1 root PUT (spec 03 §3.4) |
| Rename / move of one file | 1 PUT (full bytes) + 1 DELETE (+ delete marker) | 0 object requests; segment + root PUTs at the next publish |
| Rename of a folder with N files | N PUT + N DELETE | 0; usually one segment + root |
| Sync pass that changes nothing | HEAD manifest | HEAD root |
| Read (hydrate) | HEAD + GET | GET (header comes from the manifest) |
| Metadata HEADs to learn IV/key version | 1 HEAD per object when the index lacks it (`CloudEngine::resolveRemoteEncryptionContext`, `CloudEngine.cpp:697`) | none: the header is in the object and the manifest |

Steady-state cost is the same or lower, renames become free, and the only new fixed cost is that a publish writes a
root plus each changed segment instead of one JSON file (spec 03 §3.5 gives the counts).

## 6. Migration of existing `path_v0` buckets

**As built (#373, consolidated scope of 2026-11-06).** The soak-with-rollback state machine and `encrypt_upstream`
toggling were dropped: a vault that fails verification stays `path_v0` with nothing deleted (that is the safety net),
and after the cutover the legacy objects stay untouched for a fixed waiting period (default 7 days) before an operator
may clean them up. States: `copying → verifying → cut_over → cleanup → cleanup_blocked | complete`, plus `failed`
(still `path_v0`, resumable). The canary-first cleanup step was dropped; the dry run, typed confirmation, explicit
version ids, protection locks, Object Lock and the audit trail stay. Verification gates the cutover (§6.3 steps 1, 3
and 4); the bucket-only reconstruction (step 2) runs right after the cutover against the published manifest and gates
the cleanup instead. Operator docs: `docs/vaults/encryption.md`, "Migrating A Vault To Opaque Storage".

One engine converts layout and format together, because both rewrite every object: `path_v0` + legacy GCM →
`opaque_v1` + VHF1. Converting twice would double the cost. Local-only format conversion (local vaults,
`transparent` vaults' backing files, recovery blobs) is spec 02 §6 and can ship first.

### 6.1 Preconditions (checked before anything is written)

1. Every key version the vault's files, recovery blobs and provider versions reference is held and attested
   (`vault.keys.status` `needed_versions`, attestation backfilled per `key-backup.md`). Otherwise refuse: never
   migrate data whose key can't be proven.
2. Customer-held recovery material exists (decision D2, spec 03 §5.5): a recovery recipient for managed storage;
   for self-hosted BYOS a recovery recipient or a verified export covering every needed version. A migration is the
   worst time to discover a missing key backup.
3. No rotation, salvage or layout migration is running for the vault; the pass lease is free.
4. A price preflight (the recovery cost machinery, operation `layout_migration`) covers the worst case: per current
   file 1 PUT (+ 1 GET and the bytes when there is no local copy), per retained provider version 1 GET + 1 PUT and its
   bytes, plus metadata. Unpriced → explicit `accept_unpriced`. Request budgets apply.
5. Bucket capability probe: conditional PUT (`If-Match`, `If-None-Match`) works, or the migration refuses with the
   reason (the manifest's atomic publish depends on it, spec 03 §3.4).

### 6.2 State machine

`vault_layout_migration (vault_id, from_layout, to_layout, state, started_at, verified_at, cutover_at, soak_until,
committed_at, counts JSONB, last_error)` and one row per object to move in `vault_layout_migration_item (vault_id,
kind [current|version|backlog], file_id, source_key, source_version_id, target_key, target_version_id,
target_generation, plaintext_blake2b, state [pending|copied|verified|failed|skipped], error)`.

| State | Work | Writes to the bucket | Rollback |
|---|---|---|---|
| `planned` | assign `vault_uid`, `file_uid`s (persisted before any PUT), enumerate items, preflight | none | delete the rows |
| `copying` | per item, oldest version first, then current: read (local backing file, else GET with `If-Match`), authenticate the legacy GCM, re-seal as VHF1 under the **same key version**, PUT to `o/<uid>` with `If-None-Match: *` for the first version of a key; record the target ETag, version id and generation | new `o/` objects only; legacy keys untouched | delete the new `o/` objects (the items list them) |
| `catching_up` | files whose generation changed since copy are re-copied, under the pass lease and the content lock; repeats until a pass finds none | same | same |
| `verifying` | publish the encrypted manifest (spec 03) and run the **bucket-only verification** (§6.3) | root, segments, envelopes | delete them; the legacy index stays authoritative |
| `cutover` | one DB transaction: `storage_layout = 'opaque_v1'`, index rows rewritten to object keys, `files` format/generation updated | none | flip back (§6.4) |
| `soak` | normal operation on `opaque_v1`; legacy objects kept read-only for a bounded period (default 7 days, minimum 24 h, maximum 30 days, `soak_until`); the pre-cleanup inventory (§6.3 step 4) is repeated at the end | normal writes | §6.4 |
| `cleanup` | after soak, the inventory check and explicit confirmation: delete exactly the inventoried legacy version ids, delete markers and `.vaulthalla/index-v1.json`, canary first (§6.4) | DELETE by version id (irreversible) | none for what was deleted; everything not yet deleted stays |
| `cleanup_blocked` | some legacy versions can't be deleted yet (Object Lock, legal hold, provider retention, a failed or refused delete, an archived version not yet migrated); each is listed with its reason and, where known, the date it becomes deletable; retried daily | retries | — |
| `complete` | a full, successful `ListObjectVersions` of the bucket shows no legacy key, version or delete marker | none | — |

Idempotency: every step is keyed by the item row. A crash mid-PUT leaves `pending`; the resume HEADs the target and
compares the generation in the object's header with the recorded one; a stray version from a lost response is
deleted by version id after the right one is recorded. Writes to the vault continue during `copying`: they land in
`path_v0` and are caught up. Only `cutover` holds the pass lease and blocks uploads (seconds: one transaction).

### 6.3 Verification (gate for cutover)

1. Every item `verified`: the target exists (HEAD), its size equals the VHF1 size of the plaintext, its header
   authenticates and names the file uid and key version, and the plaintext BLAKE2b recorded while copying equals the
   legacy plaintext's (computed during the same streaming pass; nothing is decrypted twice into storage).
2. **Bucket-only reconstruction dry run:** load the new manifest from the bucket with only the key material, build
   the namespace into a scratch schema, and compare with the live database: same files, names, sizes, key versions,
   generations, version ids. Any difference blocks cutover.
3. **Actual decryption of what the provider stores.** Every re-sealed item was authenticated in full from the exact
   bytes that were PUT (the writer decrypts its own output before sending it). Proof that the provider holds those
   bytes: the stored ETag equals the MD5 the writer computed (single PUT), or the multipart ETag computed from the
   parts' MD5s. Where the provider's ETag isn't an MD5 (AWS SSE-KMS, some S3-compatible stores), every item is read
   back with a GET and authenticated end to end (priced in the preflight). On top of that, a random sample (1 % or
   100 files, whichever is more) is always read back and authenticated.
4. **Inventory.** A complete `ListObjectVersions` (every page; a truncated, failed or permission-denied listing
   counts as incomplete) of the legacy keys is matched one to one with the migration items: every legacy version and
   delete marker is either `verified` (its opaque copy exists and passed 1-3) or explicitly `skipped` with a reason.
   An unmatched legacy version blocks cutover. The inventory is stored (version ids, sizes, ETags) and is the only
   list cleanup may delete from.

### 6.4 Rollback, cleanup guardrails and completion

- **Before `cutover`:** abort deletes what the migration wrote; the vault never left `path_v0`.
- **During `soak`:** `vh vault layout rollback <vault>` flips back to `path_v0`. Legacy objects were never touched;
  files changed since cutover are re-published to their path keys in the legacy format by a catch-up pass (the
  release that ships the migration keeps the legacy writer for exactly this), the legacy index is republished, and
  the new objects are deleted. Soak is bounded (§6.2) so the legacy writer has a removal date.
- **Cleanup guardrails** (data-preservation gate, maintainer decision D3 on #344):
  1. Nothing path-keyed is deleted until §6.3 passed, soak ended, and the end-of-soak inventory still matches.
  2. The operator sees a dry-run listing (counts, bytes, oldest/newest, anything `skipped` that will remain) and
     confirms with the typed vault name. The confirmation is recorded in the audit trail (#323).
  3. Deletes name explicit version ids from the stored inventory: never a prefix, never "all versions of a key",
     never a lifecycle rule. A version the inventory doesn't list is never deleted.
  4. Canary first: 1 % of the keys (at least 10) are deleted, then the opaque copies of those files are read back
     and the manifest reloaded from the bucket; any failure stops cleanup.
  5. A version that was not re-sealed (archived, key not held, Object Lock or retention) is never deleted. Archived
     versions can be restored (priced, explicit) and then migrated, or kept.
  6. Protected buckets (`upstream-control-plane.md` protection locks) refuse cleanup, as they refuse every
     destructive operation.
  7. A delete the provider refuses or fails is retried, never reported as done.
- **What status says:** `complete` only when a complete listing shows no legacy key, version or delete marker.
  Until then the vault reports `cleanup_blocked` or `cleanup` with the count of legacy versions that still carry
  file names in provider history, and the claims in spec 05 for `opaque_v1` are qualified for that vault ("names
  of N earlier versions remain in the provider's version history until <date>"). The migration is never described
  as finished while identifying names remain in provider history.
- **Package downgrade** below the release that shipped the migration is unsupported once any vault left `path_v0`
  (release notes, per `docs/contributors/compatibility-policy.md`).

### 6.5 Provider history and recovery objects

- **Provider versions** (AWS, versioning on): every retained version of a path key that recovery may still need is
  re-sealed into the new key's history oldest first, so `o/<uid>` has the same sequence of contents. Original
  timestamps don't carry over (the provider stamps the PUT); the manifest keeps each version's original
  `last_modified` and maps old version ids to new ones so recovery points keep their identity. Retention of the new
  versions follows the vault's recorded retention from their *original* times (the noncurrent clock restarts at the
  PUT; Vaulthalla's own retention sweep, not only the lifecycle rule, expires re-sealed versions that were past
  retention, so the migration doesn't extend history the customer chose to drop).
- **Versions that can't be re-sealed now** (archive tiers, a key not held) are `skipped` with the reason and stay
  under the legacy key; status names them (§6.4).
- **Object Lock and retention:** legacy versions under compliance or governance retention or a legal hold can't be
  deleted before their date; the migration reads the bucket's Object Lock configuration and each version's
  retention before cutover, reports the dates and leaves those versions in place (`cleanup_blocked`). Governance
  bypass is never used.
- **Incomplete history:** if the listing can't be completed (permissions, pagination failure) or the bucket's
  versioning state changed during migration, cutover is refused; nothing is deleted on a partial picture.
- **Delete markers** of path keys are history too: recorded in the manifest (path, time) and removed with the legacy
  versions at cleanup.
- **Upstream backlog** (`file_versions.upstream_state = 'pending'`): rows get `upstream_key = o/<uid>`; their blobs
  are converted by spec 02 §6; replay after cutover targets the opaque key.
- **Local recovery generations** (`.vh-recovery/` blobs of snapshots and local versions) are local only: every one
  is re-sealed by spec 02 §6 (verified, then swapped), not uploaded.
- **Events:** subscriptions stay; the event filter prefix (if any) is updated to `o/` and `.vaulthalla/` at cutover.

## 7. Implementation notes (non-normative)

- One `ObjectKeys` module owns key construction (`o/`, `.vaulthalla/…`) and parsing; `stripLeadingSlash(path)` calls
  in `CloudEngine` become `objectKey(file)`.
- Multipart part size must grow with the object: today every multipart upload uses 5 MiB parts
  (`Controller::MIN_PART_SIZE`, `include/storage/s3/Controller.hpp:171`; `CloudEngine.cpp:199`), which caps objects
  at 10,000 × 5 MiB ≈ 48.8 GiB. Use `max(5 MiB, ceil(size / 10,000))` rounded to 1 MiB. Independent of this spec but
  found while counting objects; it belongs in the data-plane issue.

## 8. Test plan

| Test | Proves |
|---|---|
| `OpaqueRequestAudit` (fake S3 recording every request): create, overwrite, rename, move, copy, delete, rotate, backlog replay, provider restore, manifest publish | no request carries a path, name, `x-amz-meta-*`, plaintext-derived digest or non-allowlisted header; every key matches `^(o/[0-9a-hjkmnp-tv-z]{26}\|\.vaulthalla/(layout\.json\|root\|seg/…\|key/…))$` |
| `OpaqueObjectCount` | final object count = live files + retained versions + bounded metadata (root, segments ≤ ⌈entries/8192⌉ + GC backlog, envelopes) for 0-byte, small and multipart files; no object per AEAD chunk; renames add none |
| `OpaqueRenameCostsNothing` | rename/move of a file and a folder of 1,000 files issues 0 object requests and one publish |
| `OpaqueCopyReseals` | a copy produces a different object (different ETag, header file uid) with the same plaintext |
| `OpaqueEvents` | event decode/apply with object keys; manifest keys skipped |
| `OpaqueForeignObjects` | `ignore` and `import` semantics |
| `LayoutCheckConstraint` | the DB refuses `transparent` with encryption on and vice versa |
| Migration: `LayoutMigration*` (fake S3 with versioning, Object Lock and fault injection) | idempotent resume after a crash at each step; catch-up of concurrent writes; verification failure blocks cutover; an incomplete or failed listing blocks cutover; an unmatched legacy version blocks cutover; non-MD5 ETags force read-back; rollback before cutover and during soak restores `path_v0` exactly; cleanup deletes exactly the inventoried version ids and markers, canary first, and stops on a canary failure; locked, retained, archived and keyless versions are kept and reported (`cleanup_blocked`, never `complete`); a refused delete is retried and reported; price refusal stops before any PUT; status never says `complete` while a legacy version is listed |
| `LayoutMigrationCost` | the request and byte counts of a migration match the preflight estimate (per current file, per version, metadata, read-back) within the documented bounds |
| Live R2 (`LiveR2.*`, one `vh-test-*` bucket) | object counts and request audit against the real provider; multipart upload, abort and retry of an `o/` object |
| Live AWS (when the test identity has versioning rights) | migration of a versioned bucket with delete markers |
| Harness Tier B | a `path_v0` vault migrated while the FUSE mount and a sync pass are busy |

## 9. Proposed implementation issues

- **WS1-a. Schema: vault uid, file uid, storage layout.** Migration `NNN`: `vault.uid`, `files.object_uid`,
  `s3.storage_layout` + CHECK, backfill (`transparent`/`path_v0`), uids assigned for every existing row. No behavior
  change.
- **WS1-b. `OpaqueV1` data plane.** Object keys, request rules (§4.3), sync keyed by file uid, index/version/backlog/
  ledger/event tables on object keys, rename as manifest-only, request audit + object-count tests, adaptive multipart
  part size. `opaque_v1` creation stays internal (test mode and the harness) until WS3-c's drill passes (README,
  "Quality gates"). Depends on WS1-a, WS2-b, WS3-a.
- **WS1-c. Layout migration engine** (`path_v0` → `opaque_v1`, provider history, backlog, inventory and
  decryption verification, bounded soak, rollback, guarded cleanup, `cleanup_blocked`/`complete`) and
  `encrypt_upstream` toggling through it. Depends on WS1-b, WS2-b, WS3-a, WS3-c.
- **WS1-d. Operator docs** for the new layout, the migration and its costs, and the corrected claims (spec 05),
  shipped with WS1-c.
