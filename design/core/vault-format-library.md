# The shared vault format library (wave 4, workstream J)

Status: design for review (managed storage plan of 2026-11-12, §4.11 and workstream J); nothing here is built. It
covers how the server's file format, object naming and manifest code becomes one library that the server, the
Desktop-only engine and the portal's browser reader link, what each of them needs from it, and in what order. It does
not design the Desktop engine's File Provider side, the cloud's device access (workstream K) or the portal's screens.

## Decided and given

- **Decided (Cooper, 2026-11-12, plan §3.1 item 7):** Desktop-only is wave 4: managed storage only, keys held on the
  device, end to end encrypted, previews at `app.vaulthalla.cloud` decrypted in the browser. Item 3: one account
  recovery key across deployments.
- **Decided (Cooper, 2026-11-14):** the library's licence is AGPL-3.0-or-later (last section).
- **From the plan's design (§4.11), adopted here:** the bucket is the database and no database ships in the app;
  the engine is the server's own format code, extracted into a `vl-*` library with its vectors and a narrow C API;
  the server switches to it; File Provider keeps local state, on-demand download and eviction.
- **Decided in this document** under the compatibility policy's rule 5 (no customer depends on the old form, durable
  data stays recoverable, the implications are understood, tests can pin the behaviour): everything else, each with
  its reason in "Decided here".
- **Precedent:** vl-keykit 0.1.0 was "extracted from vaulthalla-server 1.22.2" (its `CHANGELOG.md`), MIT, with
  libsodium replaced by OpenSSL, a verbatim copy of `design/encryption/vectors/`, and a server test
  (`test_keykit_vectors.cpp`) that requires the two copies to be identical. Consumed as a `wrap-file` with its tarball
  in `subprojects/packagecache/` (`core/meson.build:155-162`), like vl-sigv4 and vl-webauthn.

## The code today

Read on the branch of draft PR #441 at `5384fdc5`. Lines are header plus source.

| Unit | Lines | Includes from outside the candidate set |
|---|---|---|
| `crypto/vhf1/Format` | 599 | `crypto/SecretKey.hpp` (→ `crypto/util/encrypt.hpp`, constants only), `crypto/util/Gcm.hpp`; OpenSSL, libsodium |
| `crypto/vhf1/Reader` | 275 | libsodium (`sodium_memzero`) |
| `crypto/vhf1/Writer` | 145 | none |
| `storage/ObjectKeys` | 131 | `crypto/id/ObjectUid.hpp` |
| `sync/manifest/Document` | 933 | `crypto/id/ObjectUid.hpp`, nlohmann, fmt; `gmtime_r` |
| `Content`, `Partition` | 179, 144 | none |
| `Objects` | 150 | `crypto/util/digest.hpp` (OpenSSL EVP), fmt |
| `Chain`, `VersionLog` | 204, 295 | fmt (Chain) |
| `Reader` | 568 | fmt |
| `Publisher` | 698 | `crypto/id/ObjectUid.hpp` (fresh sids), `<thread>` (default sleep), fmt |
| `Store` | 361 | header: `storage/Fwd.hpp`, `storage/s3/Capability.hpp`; source: `storage/s3/Controller.hpp`, pugixml, `timegm` |
| `Service` | 366 | `vault/Fwd.hpp`, `db/query/device/Device`, `db/query/sync/Manifest`, `log/Registry`, `notifications/OperatorNotificationBus`, `vault/EncryptionManager` |

Without `Service` the set is **4,682 lines** (5,048 with it), plus about 800 lines of support it uses: `SecretKey`
(63), `SecretBytes` (144), `Gcm` (401, of which VHF1 uses `GcmStreamEncryptor` and `gcmDecrypt`), `digest` (59),
`ObjectUid` (148, whose UUID form for PostgreSQL stays). `core/tests/fuzz/meson.build` already builds VHF1 alone
from exactly Format, Reader, Writer, SecretKey, SecretBytes and Gcm, on OpenSSL and libsodium.

What has to move or be inverted:

- **Logging, config, notifications:** none outside `Service`. Errors are exceptions with stable names
  (`vhf1::Error` codes, `FormatError` codes, `ChainError` via `chainErrorName`, `PreconditionFailed`,
  `PutOutcomeUnknown`, `PublishUnsettled`), which a C API can map one to one.
- **Time:** already injected (`PublishOptions::now`, `std::time_t now` on every GC call). `Service` calls
  `std::time(nullptr)`.
- **Sleep:** `PublishOptions::sleep`, defaulting to `std::this_thread::sleep_for` (`Publisher.cpp:118-122`).
- **Randomness:** libsodium `randombytes_buf` (VHF1 salts, `ObjectUid` for sids and directory uids).
- **The `ObjectStore` seam** (`Store.hpp:79-125`) is the right shape for manifest objects but holds whole objects in
  memory (`kMaxManifestObjectBytes`, 256 MiB). Content objects `o/<uid>` never pass through it: the server uploads
  them through `CloudEngine` and `s3::Controller`. A database-free engine needs a streamed content seam beside it.
- **The bucket mode:** `Store.hpp` includes `storage/s3/Capability.hpp` for `WriteCapability` and
  `sendsPreconditions`, both defined in `Capability.cpp` beside `probeBucket`, which includes `s3::Controller` and
  `storage/upstream/Guard.hpp`. Its comment says the `version_log` root publish "is not implemented yet and refuses";
  `Publisher.cpp` implements it.
- **The S3 controller:** `S3Store` is the only S3 code in the set, and through `s3::Controller` it reaches curl, the
  usage ledger (`recovery/usage/Ledger.cpp`: `db/Transactions.hpp`, `<pqxx/pqxx>`), `vault/model/APIKey` and logging.
- **Uid and secret duplicates:** `crypto::id::ObjectUid` and its base32, and `crypto::SecretBytes`, still exist next
  to vl-keykit's `Uid`/`toBase32` and `SecretBytes`, which vl-keykit says it extracted from them.

**The plan's figure is out of date.** "About 4,000 lines, no database, FUSE, RBAC or protocol includes apart from
`manifest/Service.cpp`" is true of direct includes, but #441 adds `VersionLog` (295) and grows `Publisher`, `Reader`,
`Store` and `Service` (1,221 lines added to these files): the set is now about 4,700 lines plus 800 of support. And
`Store.cpp` reaches the database transitively through `s3::Controller` and the usage ledger.

## The cut

Name: **`vl-vaultfmt`** (`valkyrianlabs/vl-vaultfmt`), namespace `vl::vaultfmt`, headers `<vl/vaultfmt/*.hpp>`,
following `vl::keykit` and `vl::sigv4`. Sub-namespaces: `vhf1` (file format), `keys` (object keys), `manifest`
(documents, content, partition, objects, chain, version log, reader, publisher, store seam), `engine` (the
database-free session, wave 4), and `c` for the C API. It depends on vl-keykit for `Uid`, `SecretBytes`, `wipe`,
`equalConstantTime` and `kev1::objectKey`, so there is one base32 and one secret type.

| Goes into the library | Stays in the server |
|---|---|
| VHF1 (`Format`, `Reader`, `Writer`), its AEAD wrapper and key type | `Gcm`'s legacy v1 positioned decrypt and `gcmVerifyFd`; `crypto::SecretKey` as a thin adapter |
| `ObjectKeys` (content keys, allowlist, part sizes) | `ObjectUid`'s UUID form for PostgreSQL |
| `Document`, `Content`, `Partition`, `Objects`, `Chain`, `VersionLog`, `Reader` | `db::query::sync::Manifest` (`collect` and the state tables) |
| `Publisher`, both modes (`conditional`, `version_log`), `checkHeadForWriter`, GC and the root janitor as functions | when GC runs, `gc_at`, the daily schedule |
| The `ObjectStore` seam and the publish mode enum with its two helpers | `S3Store` over `s3::Controller` (metering, budgets, protection guard) and `probeBucket` |
| `Session`: the decision logic now in `Service.cpp` (publish and record, `verifyRemote` in both modes, repair, refusal) over a `StateStore` interface | the `StateStore` on PostgreSQL, `Devices::nodeId`, logging, `notifyRefusedRoot` and the operator notification bus |
| A pure three-way content diff (base, ours, theirs), shared with the mirrors' applier | applying a diff to the database (`design/cloud/mirrors.md`, item 2) |
| Fuzz target, unit tests, an in-memory versioned store for them | `test_manifest_db.cpp`, the HTTP-level fake bucket (`helpers/versioned_bucket.hpp`) for `S3Store` |

KEV1 stays in vl-keykit. The library writes envelopes only through `ObjectStore::putOnce` with
`kev1::objectKey(kid)`, as `vault/RecoveryEnvelopes.cpp:85` does today.

## State a database-free engine keeps

Today the database is the engine's memory. Without one, the engine keeps the same facts in a state file per vault
in the File Provider extension's app group container, written atomically and flushed with `F_FULLFSYNC`
(`.claude/context/macos.md`, `durable::sync`). It is not the replica database (`VHFinder/ReplicaStore.swift`, a
cache Desktop may delete): losing it loses unpublished changes.

| Fact | Today | Database-free engine |
|---|---|---|
| Chain position: epoch, root hash, ETag, root and base version ids, settle window, own epoch | `remote_manifest_state` (migrations 125, 137) | state file; written before a publish counts as settled |
| A refused root (reason, epoch, hash, time) | `remote_manifest_state.refused_*` | state file; publishing stops until the chain moves on |
| Sids of the last three roots; when each sid became unreferenced; last GC | `remote_manifest_root`, `remote_manifest_gc`, `gc_at` | state file |
| What the last publish produced (the base of pending changes) | `PublisherCache::last_produced`, memory only | persisted: `mirrors.md` shows a cold start without it drops other writers' entries |
| The tree, versions, trash, key history, vault settings | `directories`, `files`, `files_trashed`, `upstream_object_version`, vault keys (`collect`) | working content = the last settled `Content` plus a journal of local operations not yet published |
| Vault keys | sealed by the TPM or Secure Enclave | the Mac's keychain, each version wrapped to the account key in the bucket |
| The writer's identity in `writers` | `Devices::nodeId()` | the Desktop installation id |
| File bytes on disk | FUSE cache | File Provider, not the library |

If the state file is lost, the engine re-anchors from the bucket (C1 without an anchor, spec 06 §5.1) and reports
"freshness unverified" as `loadForRestore` does. Content uploaded but never published is then found only by
`blindRebuild`, without names.

## Public surface

**Desktop engine, through a C API.** Opaque handles, every entry point `noexcept`, results as an error code, a
category and a message; callbacks return status codes that the shim turns into the exceptions the library expects.

| Call | Does |
|---|---|
| `vlvf_vault_open(uid, store, keys, state, node_id)` | load from the anchor in `state`, or blind; returns a vault handle |
| `vlvf_vault_refresh` | `verifyRemote`: one HEAD while unchanged; a new canonical root is diffed into the working content |
| `vlvf_list(dir)`, `vlvf_stat(uid)`, `vlvf_changes(after)` | read the working content |
| `vlvf_read(uid, version, offset, length, sink)` | `RangeReader` over `o/<uid>`; only authenticated chunks reach the sink |
| `vlvf_write_begin(parent, name, uid?)`, `_chunk`, `_finish` | seal a VHF1 kind 1 object under the current key, stream it up, record the version id |
| `vlvf_mkdir`, `vlvf_rename`, `vlvf_trash`, `vlvf_restore`, `vlvf_purge` | journal a tree change |
| `vlvf_key_add(version, key, envelopes)` | a new key version, its envelopes PUT before first use (spec 03 §5.8 order) |
| `vlvf_publish`, `vlvf_gc_if_due(now)` | publish (mode from the vault's record), repair, janitor |
| `vlvf_error_*`, `vlvf_free` | read the last error; release library-owned buffers |

Callback tables: **store** (get, get range, head, put once, put, list, versions since, remove, remove version, plus a
streamed content put and ranged get), **keys** (look up a version into a caller-provided buffer the library wipes,
current version), **state** (load and save one blob atomically). Swift implements them: the store over `URLSession`
with the short-lived access of workstream K. Swift sees a small `VHVault` package over an XCFramework; no C++
types cross, so the app needs no Swift C++ interop mode.

**Browser reader (WebAssembly), read only.** What compiles: everything in the set but `S3Store`, which is why it stays
in the server. curl and pugixml leave with it. libsodium is used only for wiping, comparison and randomness, so it
goes, as in vl-keykit; libsodium's AES-256-GCM would not have helped, because it requires hardware AES. OpenSSL's
libcrypto (HKDF, HMAC, SHA-256, AES-GCM) has to be built with Emscripten, or replaced behind a five-function crypto
backend. WebCrypto cannot be that backend directly: it is asynchronous and the library is synchronous (the relay's
option (b) in vaulthalla-cloud `relay.md` meets the same problem). Exceptions need `-fwasm-exceptions`. The
surface works on bytes the page fetched, so no blocking network call runs in wasm: open a root, decide C1 over a
version listing, name the segments needed, open them, return the listing as JSON, open a content header and decrypt
a range, and unwrap KEV1 envelopes with vl-keykit built the same way.

**Server.** Everything above but the engine and the C API, plus its own `S3Store`, PostgreSQL `StateStore` and the
probe. Behaviour, request counts and the existing tests stay as they are; `Service` shrinks to wiring.

## Dependencies, build and versioning

- **Dependencies:** OpenSSL 3 libcrypto, nlohmann_json (the vendored copy the server overrides, `core/meson.build:159`),
  vl-keykit, GoogleTest for tests. fmt is replaced by `std::format`, which libstdc++ 14, libc++ and Emscripten carry.
- **Consumption:** a `wrap-file` pinned to a release, its tarball in `subprojects/packagecache/` for the Debian build
  (`--wrap-mode=nodownload`), and a contract like `tools/contracts/test_webauthn_contract.py` that pins the wrap and
  fails if an in-tree copy remains. During co-development `subprojects/vl-vaultfmt-<version>` is a local symlink to a
  checkout, never committed, as the forti repositories do.
- **CI:** Linux in the shared `ci/run-ci` container (GCC 14, ASan and UBSan, unity on and off), macOS on the
  `CI_MACOS_RUNNER` route (clang and libc++, the XCFramework), Emscripten for the reader with the vectors run in Node.
  These jobs join the shared runner pool; they are short, but per the fleet rules the first runs are watched beside
  vaulthalla-server's.
- **Vectors:** `vectors.json` and `vh_crypto_vectors.py --check` move with the code; the server, vl-keykit and
  Desktop keep verbatim copies checked identical, as `test_keykit_vectors.cpp` does today. There are no vectors for
  C1 walks, `contentOf` or `mergePending`; they are added before any second consumer relies on those rules.
- **Versioning and lockstep:** semver, before 1.0 a minor may break the API. A format change lands in the library
  with its vectors first, then one wrap bump each in the server, Desktop and the portal. Readers ignore unknown
  members (`Document.hpp:25`), but writers rebuild documents from typed structs, so **an older writer republishing
  drops a newer writer's members.** With one server per vault that never happens; with several Macs, mirrors or a
  server adopting a Desktop vault it does. So the root names the lowest format revision allowed to write, and a
  writer below it reads but refuses to publish, saying an update is needed.

## Risks

- **Unity build and namespaces.** The server builds `unity_size=9`; about 340 file-scope `using namespace` remain
  (`architecture.md`). `vh::crypto::id::toBase32` and `vl::keykit::toBase32` take the same `std::array`, so a
  directive in a neighbour makes calls ambiguous; removing the duplicate removes it. `Service` cannot stay in
  `vh::sync::manifest` once that name is gone, and an alias would collide with it: call sites are renamed, with no
  alias (compatibility policy). The library's CI builds unity on and off.
- **Exceptions across a C boundary** terminate the process. Every C entry catches everything; a Swift callback never
  throws through C; a callback that cannot answer returns "unknown outcome", never a guess.
- **Key material in a browser.** Wasm memory cannot be locked and is readable by any script on the origin, so an
  injection on `app.vaulthalla.cloud` reads names and files whatever the reader is written in. The portal's CSP
  (`portal.md`) is the real control; keys live only for the tab, are never stored unwrapped, and are wiped on close.
- **A second implementation drifting.** A TypeScript reader (WebCrypto) is the alternative to wasm:

| | C++ library built to wasm | Separate TypeScript reader |
|---|---|---|
| Rules (C1, chain, merge, partition) | the server's own code | rewritten, about 1,800 lines of reader-side rules |
| Drift caught by | the same unit tests and vectors | vectors only, which don't cover C1 or `contentOf` today |
| Crypto | OpenSSL built with Emscripten, or a backend seam | WebCrypto, asynchronous, no build work |
| Size and build | a wasm build to maintain; size to be measured | small, ordinary portal code |
| A format change | one wrap bump | a second change and review per format change |

  Decided: wasm, because the rules that decide rollback and fork must not exist twice; TypeScript only for fetching
  and the UI.

- **OpenSSL in the Mac app.** The XCFramework carries a static libcrypto beside CryptoKit; it is updated with the
  library's releases. Desktop's Swift `VHRecovery` (KEV1, seed, uids) remains a second KEV1 in the same app.

## Work items, in landing order

**Now, in the server repository, no decision needed:**

1. Move `WriteCapability`, `to_string`, `publishModeFromString` and `sendsPreconditions` into a manifest header;
   `Store.hpp` stops including `storage/`; fix the stale comment in `Capability.hpp` (S).
2. Move `S3Store` out of `sync/manifest/Store.*` into `storage/`, so the seam's files include nothing of the server (S).
3. VHF1 and the manifest on OpenSSL only; VHF1's two GCM pieces and its key type beside it; `ObjectUid`'s base32
   and `crypto::SecretBytes` replaced by vl-keykit's; vectors unchanged byte for byte (M).
4. Split `Service` into `Session` (logic, over `StateStore` and an alert callback) and the server's wiring, under a new
   namespace (M).
5. An in-memory versioned `ObjectStore`; the interleavings suite runs on it as well as on the HTTP fake (M).
6. A contract test that the candidate directories include only each other, vl-keykit, OpenSSL and nlohmann (S).

**With the licence decided:** 7. create `vl-vaultfmt`, move code, tests, fuzz target and vectors, CI, release 0.1.0;
the server switches through the wrap (plan item J, M). 8. The C API and its tests (S).

**Wave 2:** nothing. The relay pairs the browser with a server, which renders previews itself (plan item H).

**Wave 4:** 9. `engine::Session` without a database: working content and journal, the streamed content seam, a
reference file `StateStore` (L). 10. The three-way content diff and its vectors, shared with mirrors (M). 11. Sealed
thumbnails: no VHF1 kind, object key or manifest member exists for them, and `ObjectKeys::isAllowedKey` refuses
anything else, so it is a format change with a spec and vectors, and servers must keep them (M). 12. The
XCFramework and `VHVault` in Desktop (part of plan item L). 13. The Emscripten build and the reader surface, vectors
in Node and a browser (part of plan item M, L).

## Decided here (compatibility policy rule 5)

None of these touches stored data, keys or custody, and each is pinned by tests or vectors.

1. **Name `vl-vaultfmt`, namespace `vl::vaultfmt`:** it follows `vl::keykit` and `vl::sigv4` and says what it holds.
2. **Vectors live in the library, with the code;** specs stay in `design/encryption/`: a format change is then one
   pull request with its code and vectors, and every consumer's identical-copy test catches the rest.
3. **Desktop bridges through a C API and a Swift package over an XCFramework,** not Swift's C++ interop: interop must
   be enabled in every importing module, and an exception crossing into Swift ends the process.
4. **Browser crypto starts with OpenSSL built by Emscripten,** measured in a spike; a five-function backend seam only
   if the size is unacceptable: one AEAD implementation everywhere is the safer default.
5. **The portal reader is the library built to wasm,** not a TypeScript reimplementation (table above).
6. **Swift talks HTTP for Desktop** through the store callbacks; the library ships no HTTP client: `URLSession`
   already carries Desktop's TLS policy, and the server keeps its metered controller.
7. **The writer floor lands before a second kind of writer exists** (before workstream I or L): it is the only
   guard against an older writer silently dropping newer metadata, which rule 3 forbids.
8. **Unpublished changes are durable:** the journal is flushed before an operation returns, and the engine publishes
   soon after each change, so a lost Mac costs at most the names of the last unpublished changes, never file bytes
   (spec 03 §4.3 blind rebuild) or keys (envelopes are PUT before a key version is used).
9. **Desktop-only vaults are `version_log` from creation:** they exist only on managed B2, which rejects conditional
   PUT (spec 06 §1), so the engine takes the mode from the vault's record and never runs the server's probe.

## Decided by the maintainer (2026-11-14)

**The library's licence: AGPL-3.0-or-later** (Cooper, 2026-11-14; plan §3.3 item 5). It is what the code is under
today, so nothing is relicensed. Valkyrian Labs LLC owns all of it and uses the library in its own closed products
(the portal's wasm, a Mac App Store app, the cloud's services) by that ownership, which means every outside
contribution to the library needs a copyright assignment or contributor agreement. Third parties may use it in
software they publish under the AGPL, which already lets a customer read their own bucket without Valkyrian Labs.
It can be loosened to MIT later; MIT could not be taken back. The audit that produced this document had recommended
MIT, for consistency with vl-keykit, vl-sigv4 and vl-webauthn. Work item 7 is no longer blocked.
