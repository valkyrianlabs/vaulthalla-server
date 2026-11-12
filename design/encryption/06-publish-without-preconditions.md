# 06. Publishing the manifest on buckets without conditional writes

Status: design for review (managed storage plan of 2026-11-12, workstream E, step 0); nothing here is implemented.
Depends on [01](01-provider-blind-storage.md) and [03](03-metadata-recovery.md); used by
[`design/cloud/mirrors.md`](../cloud/mirrors.md). Normative words: MUST, MUST NOT, SHOULD.

A second publish path for the `opaque_v1` manifest (spec 03 §3) on versioned buckets that reject `If-Match` /
`If-None-Match` on PUT, as B2 does, for one writer and several, and how the server picks it per bucket. It
changes no VHF1, KEV1, key or segment format and does not design mirrors, which need more (`mirrors.md`).

## 1. Decisions this spec encodes

- **Decided (Cooper, 2026-11-12, plan §3.1):** one bucket per vault; mirrored deployments optional, per vault, solo by
  default, starting simple with the existing conflict resolution. **Earlier (#329, spec 01 §1):** managed storage
  enforces `encrypt_upstream=true` and `opaque_v1`. Everything else here is a proposal; open choices are in §10.
- **Found, not decided:** B2 answers conditional PUTs with `501 NotImplemented`. Confirmed live on 2026-11-12
  (`s3.us-west-004`, both `If-None-Match: *` and `If-Match`, nothing written), after reports from others.

## 2. Today: what depends on conditional writes

| Write | Condition | Code | What the condition protects |
|---|---|---|---|
| Root `.vaulthalla/root` | `If-Match: <known ETag>`; `If-None-Match: *` at epoch 1 | `manifest::publish` (`sync/manifest/Publisher.cpp`), `S3Store::putIfMatch/putIfAbsent` (`Store.cpp:78-94`) | the lost update between writers: the loser gets 412, loads, verifies, merges, retries (spec 03 §3.4 step 3). A rebuilt root (`loadBase`, §4.2 (b)) is PUT with `If-Match` on the unreadable root's ETag, so it never overwrites an authentic root published meanwhile |
| Segments, snapshot segments `.vaulthalla/seg/<sid>` | `If-None-Match: *` | `Publisher.cpp` ("a fresh 128-bit sid: never exists"; a 412 is not caught) | overwriting an object of the same name: only a sid collision or a hostile bucket writer |
| Layout hint `.vaulthalla/layout.json` | `If-None-Match: *`, 412 ignored | `Publisher.cpp`, first publish | keeps an existing hint (identical for every writer) |
| Envelopes `.vaulthalla/key/<kid>` | `If-None-Match: *`, 412 ignored | `vault/RecoveryEnvelopes.cpp:77` | idempotence only: `kid` is the envelope's hash, so the same name holds the same bytes |
| `path_v0` index `.vaulthalla/index-v1.json` | `If-Match` / `If-None-Match: *` | `CloudEngine::publishRemoteIndexManifest` (`CloudEngine.cpp:547-581`), retry loops (`:583-618`, `applyRemoteIndexMutation`) | a sync cache against concurrent overwrite; every vault that is not `opaque_v1` |
| Layout migration | spec 01 §6.1 step 5 refuses without conditional PUT; §6.2 says `If-None-Match` on `o/` | as built (#373): `requirePreconditions` (`vault/LayoutMigration.cpp:1323`) has no probe; `putMigratedObject` (`storage/CloudEngineLayoutMigration.cpp:21`) PUTs unconditionally | only the manifest its `verifying` state publishes needs it |
| Content `o/<uid>` | none | `CloudEngine` upload paths; its one conditional call (`CloudEngine.cpp:565`) is the index row above | — |

`storage/s3/buffer.cpp:99-180` maps 409/412 to `ConditionalRequestFailed`, any other failure (501 too) to
`std::runtime_error`. Read-side preconditions, GET `If-Match` (`s3/stream.cpp:146`: hydration, ranged reads, conflicts,
provider restore) and `x-amz-copy-source-if-match` (`s3/version.cpp:365`), are probed too (§7); the reports concern PUT.

### 2.1 What this means for BYOS vaults on B2 today

**They are broken.** The 501 is confirmed; what follows is read from the code, not reproduced with a server. **`opaque_v1`** (every new
encrypting vault since #371): content uploads land, but every publish fails at its first segment PUT, each pass that
changed anything ends in an error, and **no root is ever written**, so `vh vault recover` has only the blind rebuild
(names and tree lost, spec 03 §4.3). Envelope PUTs fail: recipient enrollment fails, and so does rotating a vault that
has a recipient (envelopes go first, spec 03 §5.8). **`path_v0`:** every changing pass fails at the index publish after
its uploads, and the stale-index gate (`Cloud::initBins`) probably stalls a quiet vault after 24 h. No external
customer exists, so the fix ships without a transition.

## 3. The starting sketch, evaluated

Writers are honest, uncoordinated daemons holding the vault key (no channel between them, clocks untrusted; each
serializes its own publishes); the bucket is untrusted as in spec 03 §4.5. The sketch (random names for write-once
objects; an unconditional root PUT, then the key's version list; among roots naming the same `prev` the earliest by
provider order wins; the loser removes its version and republishes merged; readers ignore losing siblings) is
**sound only with these corrections**:

1. **Earliest-wins is the only stable rule** (latest-wins lets a slow writer overturn everyone), and only if listings
   show every earlier version and never insert one below a version already seen (A3, A4).
2. **It needs a chain from an anchor:** a root built on a loser is a loser although its `prev` is unique (§5.1).
3. **A root is known only once settled:** today `recordRoot`/`verifyRemote` adopt a root at once, and a reader that
   adopted a loser would later call the winner a fork.
4. **Crashed losers need repair, and lifecycle must never expire noncurrent roots** (a winner under a crashed loser
   would vanish); **GC must follow the canonical chain;** **A3/A4 violations must be detected and stop publishing.**
5. **Collisions need no read-back:** 128-bit sids don't collide in practice, envelopes are content-addressed, the hint
   is identical for every writer, and the root's SHA-256 pins catch the rest.

| Alternative | Verdict |
|---|---|
| **Versions of `.vaulthalla/root` as the log** (the corrected sketch, §5) | Recommended: one key, so the HEAD-only no-change check, spec 03's readers, restores and the wave 4 reader keep their object; one LIST more per publish |
| **Epoch-named roots** `.vaulthalla/roots/<epoch>/<random>` | No versioning needed, but still a tie-break: the same assumptions, or a longest-chain rule that accepts reorganizations (weaker rollback detection); every no-change pass becomes a LIST; a format change for all readers. Kept for providers with neither conditional PUT nor versioning (refused today, §7) |
| **Arbiter at vaulthalla.cloud** (a compare-and-swap pointer per vault) | Last resort, rejected: every publish would depend on the cloud being up, BYOS without an account couldn't use it, a cloud call would sit on the sync path, and the cloud could withhold or fork a vault's history |

## 4. Assumptions about the provider

B2 documents always-on versioning, `ListObjectVersions`, delete-by-name hiding only the newest version, and delete by
version id; not listing consistency or the order of near-simultaneous versions. **Checked live on 2026-11-12**
(`s3.us-west-004`, one run, `misc/s3_version_checks.py`): A1, A2, A5, A7 and A8 held in every check. A3 held in 200
sequential PUT-then-list trials and A4 with six concurrent writers on one key (72 versions, 72 listings, none out of
order): evidence, not proof. **Not verified:** a writer whose body stalls while others commit (B2 answered the
stalled PUT with `500 InternalError`), and A6 (the run stopped before the lifecycle check).

| | Assumption | Needed by |
|---|---|---|
| A1 | every PUT creates a new version and returns `x-amz-version-id` | all |
| A2 | `ListObjectVersions` lists one key's versions newest first with id, ETag, `IsLatest`, and pages correctly | all |
| A3 | listings are linearizable with PUTs: a listing issued after a PUT returned shows that version and every version ordered before it | two or more writers |
| A4 | the order is commit order and stable: no version ever appears below one a listing already showed; ties ordered alike for all clients | two or more writers |
| A5 | GET and DELETE by version id work; deleting the newest version makes the previous one current | all |
| A6 | no lifecycle rule expires noncurrent `.vaulthalla/root` versions (configuration; B2 rules are per name prefix) | all |
| A7 | a single PUT's ETag is its body's MD5 (else §5.2 step 2 fetches and hashes) | optimization |
| A8 | GET `If-Match` and `x-amz-copy-source-if-match` are honoured | read paths (§2) |

## 5. The `version_log` publish path

### 5.1 The canonical chain (rule C1)

*L* = the authentic versions of `.vaulthalla/root` in provider order (delete markers and versions failing the VHF1
open are skipped). For a root *X*, **succ(X)** is the earliest version in *L* with `epoch = X.epoch + 1` and
`prev = SHA-256(X)`. From an anchor *A* the **canonical chain** is *A*, succ(*A*), succ(succ(*A*)), …, ending at the
**head**. The anchor is the settled known root (normal operation), the customer checkpoint (restore), or with neither
the end of the longest chain in *L* (ties: earliest). Any other version is a **sibling** (canonical `prev`, not
first), a **branch** (non-canonical `prev`), a **duplicate** (a canonical root's bytes) or **stale** (none of these:
only tampering or replay makes one; ignored and reported as `manifest_replay`, security, warning).

### 5.2 Writer

1. Segments, snapshot segments, envelopes and the layout hint are PUT without conditions under today's names, under
   the pass lease, before the root (spec 03 §3.4 step 1). The ETag MAY be checked against the bytes' MD5 (A7).
2. Root on base *B* (always canonical): `epoch = B.epoch + 1`, `prev = SHA-256(B)`, new members `"publish":
   "version_log"` and `writers` (§5.5). PUT unconditionally, keep `x-amz-version-id` (none: `SyncStalled`,
   `bucket_capability_changed`). After a transport error, find the version by ETag (A7) or by fetching and hashing.
3. List the key's versions (newest first, paging until *B*'s). Ours missing: list again after 1, 2, 4, 8 s; still
   missing, the publish stays unsettled (`listing_lag` warning) and the next pass retries.
4. Decide by C1 from *B* (one GET by version id per unknown version, cached by id: versions are immutable):
   - **Won** (succ(*B*) is ours): record epoch, hash, ETag, **version id** and the *settle window* (ids listed between
     *B* and ours, normally none) in `remote_manifest_state`, and the root's sids, as `recordRoot` does.
   - **Lost** (succ(*B*) is another version): DELETE ours by id. Our changes stay pending (the database, and
     `PublisherCache::last_produced` of our last settled publish, which the retry loop already keeps). Load the head,
     verify it (§5.3), `mergePending` onto it, back to step 2; at most `max(3, writers + 1)` attempts, jittered.
   - **Base displaced** (*B* no longer canonical; only when A3 or A4 fails): `order_violation`. Refuse, record and
     alert once, as `Service::refused` does for a fork, and publish nothing more for the vault.
5. Repair (§5.4).

### 5.3 Reader (`Service::verifyRemote`, `manifest::load`, `vault::recover`)

HEAD the root: the settled ETag means unchanged (one HEAD, as today; sound by I3). Otherwise list, apply C1 from the
anchor, fetch and check the head's segments (spec 03 §4.1 step 3). C1 replaces spec 03 §4.2 (a)'s version fallback.

| Finding | Result |
|---|---|
| canonical successors of the anchor | advance to the head, record it as settled |
| only non-canonical versions above the anchor | unchanged; repair |
| an id inside a recorded settle window that wasn't there at settlement | `order_violation`: refuse, alert |
| anchor absent from *L*: best candidate older / another root at its epoch / newer roots not linking to it | `rollback` / `fork` / `gap` (the longest chain's head, warning), as today |
| the head names another `publish` mode than the bucket's | refuse, `publish_mode_mismatch` (I9) |

### 5.4 Repair, retention, garbage collection

- **Repair:** after any listing, non-canonical versions and delete markers *newer than the head* are deleted by id, so
  the head is current again (A5). **Root janitor** (daily): deletes by id non-canonical versions older than 24 h and
  canonical roots superseded over 7 days, never the head or its two predecessors (gap walk, spec 03 §4.2).
- **Lifecycle (A6):** between a crash and the next repair the head is noncurrent; expiring it leaves the loser as sole
  candidate, which settled readers report as a fork (a head lost anyway gets that refusal, never a silent switch). The
  cloud's managed rule (`managed-storage.md`: noncurrent content under `o/` only) never touches `.vaulthalla/`; on
  BYOS B2 the server sets no rule (no B2 adapter); AWS and R2 stay `conditional` with `vaulthalla-manifest-versions` as is.
- **Segments:** `collectGarbage` keeps the last three **canonical** roots' sids; "older than 24 h" becomes "unreferenced
  for 24 h" (`first_unreferenced_at` per sid: another writer can supersede a segment minutes after it appears); on
  `version_log` buckets every version of a collected key is deleted by id (a B2 DELETE by name only hides one).

### 5.5 Who may write (both paths)

The root gains `writers`, the node ids allowed to publish (the producer among them; one for a solo vault). **A daemon
not in the head's `writers` stops publishing the vault** (`manifest_superseded`, alert); any key holder may change the
set. This closes a gap: spec 03 §6.2 step 7 expects the old node to see a fork after a restore elsewhere, but it does
only if it published past the state the restore read; otherwise it merges the restored root as another writer's, and
after a restart (cold `PublisherCache`: `before = theirs`) `mergePending` drops every entry its database lacks.

### 5.6 Cases

| Case | What happens |
|---|---|
| Writer crashes after writing a losing root | it stays newest until anyone's next listing repairs it; the crashed writer never recorded it and republishes its changes on the head after restart |
| Crash between segments and root | orphan segments, collected after 24 h unreferenced (spec 03 §3.4) |
| Slow writer lands long after others moved on | its `prev` already has a successor: sibling; it deletes its version and merges onto the head; readers ignore it |
| Three writers on one base | the earliest wins, the others merge and race again; *n* writers settle within *n* rounds (I7) |
| Reader in the middle | sees a prefix of the canonical chain (A3) and GETs the head by version id, even under a newer loser |
| Restore elsewhere while the old node lives | the restored root has `writers = [new]`; if the old node wins a race the restore merges onto it, keeps its `writers`, and the old node stops (§5.5) |
| Bucket replays an old root as a new version | stale: ignored, reported, repaired; rollback detection as spec 03 §4.5 |

### 5.7 Costs

| Operation | `conditional` | `version_log` |
|---|---|---|
| Publish, no other writer | changed segments + 1 root PUT | the same + 1 `ListObjectVersions` |
| Publish that lost once | + root and segment GETs, a retry | + 1 DELETE, 1 GET per new version, segment GETs, a retry with its LIST |
| Pass that changed nothing | 1 HEAD | 1 HEAD |
| Another writer published | 1 root GET + changed segments | 1 HEAD + 1 LIST + 1 GET per new version (usually 1) + changed segments |
| Repair after a crash / daily GC | — / 1 LIST of `seg/` + DELETEs | 1 DELETE per stray version / 1 `ListObjectVersions` of `.vaulthalla/` + DELETEs by id |

## 6. Correctness

| Invariant | Why it holds |
|---|---|
| I1 every object a root names was PUT, and its PUT returned, before the root's PUT was sent | §5.2 steps 1-2; a crash leaves orphans, never dangling names |
| I2 C1 is a function of (*L*, anchor) | definition: everyone with the same listing computes the same chain |
| I3 a settled root stays canonical (A3, A4) | below |
| I4 no lost update | a root is recorded only once won; a lost root is deleted and its changes stay pending (database plus last settled base) until `mergePending` carries them onto the head |
| I5 known advances only along the canonical chain; readers never adopt a sibling | only settled roots are recorded; content, `vault.keys.status` checkpoints and Desktop's checkpoints come from them |
| I6 Vaulthalla deletes only non-canonical versions, canonical roots ≥ 3 epochs and 7 days behind, and segments unreferenced ≥ 24 h by the last three canonical roots | §5.4; A6 covers the provider's rules |
| I7 *n* concurrent writers settle within *n* rounds | each round the earliest PUT on the current base wins; bounded attempts, then `PublishConflict` as today |
| I8 a break of I3 is detected | it puts an id inside a recorded settle window; that writer's next listing (every publish and changed pass lists) refuses and alerts |
| I9 one mode per vault | the root names its mode; readers and writers refuse a mismatch |

**I3.** A writer settled *R* on listing ℓ, issued after *R*'s PUT returned; a later listing orders *S* before *R*
with the same epoch and `prev`. By A4 *S* committed before *R*; by A3 ℓ showed *S*; so C1 on ℓ chose *S*:
contradiction. Later commits sort after *R* (A4); every base is canonical by induction from a settled anchor. **One
writer needs less:** no root PUT is concurrent, so A1, A2, A5, A6 suffice. **Wave 1 (solo managed and BYOS vaults)
rests on documented B2 behaviour**; two or more writers (a mirror, a restore racing its old node) also need A3, A4.

## 7. Choosing the path

**Stored per bucket:** `s3.manifest_publish` (`conditional | version_log`) and `s3.bucket_probe` (JSONB), in the next
free migration (the first of wave 1: then attach-remote, the key manager's pin tables, managed remotes). **Probed** at S3 vault creation, attach-remote,
managed provisioning, `vh vault recover`, mirror join, before a layout migration (spec 01 §6.1 step 5) and by `vh
vault storage probe <vault>` (new; owner or super admin; audited), on `.vaulthalla/probe/<random uid>` (spec 01 §4.3
holds): PUT `If-None-Match: *` (200), again (412), PUT `If-Match` wrong (412) and right (200); distinct version ids
newest first; GET by id; GET `If-Match` mismatch (412); DELETE every version by id (a protected bucket keeps them).

| Result | Mode |
|---|---|
| conditional PUT as expected | `conditional` |
| conditional PUT rejected (501, 400 `NotImplemented`) or **silently ignored** (200 where 412 was due); versioning works | `version_log` |
| neither | `opaque_v1` and managed storage refused: `bucket_capability_insufficient` |
| GET `If-Match` fails | refused: reads depend on it (§10 Q4) |

**Never silently downgraded:** a later 501 or 400 on a `conditional` bucket stalls the vault
(`bucket_capability_changed`) until the operator re-probes (a downgrade weakens multi-writer safety and can come from a
bad endpoint or proxy); an upgrade too, with one writer only (I9). Envelopes, hint and `path_v0` index are PUT plainly
on non-conditional buckets.

**The `Store` seam** (`sync/manifest/Store.hpp`) gains `PutResult {etag, version_id}` from a new unconditional
`put(key, bytes)` and from `putIfAbsent`/`putIfMatch` (`Controller::lastPutOutcome()`); `StoredVersion::etag`,
`is_latest`, and `versions()` in documented provider order, able to stop at a version id; `removeVersion(key, id)` over
`Controller::deleteObjectVersion`; `mode()`, on which `publish`, `load` and GC branch. `Known` gains `version_id`;
`remote_manifest_state` gains `root_version_id` and `settle_window` (text[]).

## 8. Test obligations

**8.1 Fake bucket** (`tests/helpers/versioned_bucket.hpp`): `conditionalPuts(Supported | Reject501 | Ignore)`,
`listingLag(n)` (breaks A3), `orderBy(Commit | Start)` with `holdPut(key)` (breaks A4), `expireNoncurrent(prefix,
days)`. `ManifestPublish*`, `ManifestChain*` run in both modes; `ManifestProbe*` covers every row of §7's table.

**8.2 Interleavings and faults** (`ManifestVersionLog*`): a deterministic scheduler steps writers (segment PUT, root
PUT, list, GET, DELETE, retry) and readers: every interleaving of two writers and a reader, every root-PUT-level
interleaving of three writers plus seeded random schedules. After each step I1, I2, I4-I6, I9 hold; at quiescence one
head, nothing stray above it, every writer's changes in it. Faults: a crash at every step (restart from the database
only), lost PUT responses, 503 after commit, failed DELETEs, a head under a crashed loser past `expireNoncurrent`
(fails loudly). Under `listingLag` or `orderBy(Start)` every run satisfies I3 or ends in `order_violation`. Also
`vault::recover` over a bucket holding siblings, and a solo vault paying exactly one LIST more per publish.

**8.3 Live on Backblaze** (one `vh-test-*` bucket per run, deleted afterwards): (1) conditional PUTs (the coordinator's
probe script), then §7's probe; (2) A1, A2, A7: version ids, ETag form (single and multipart), paging; (3) A3: PUT
then list at once, same and fresh connection, thousands of trials, lag recorded; (4) A4: two to eight concurrent
writers on one key listing after each PUT (never a version below one already seen), then a PUT whose body stalls
30-120 s while others commit; (5) A5: delete by id the newest, a noncurrent version, a delete marker, HEAD after each;
(6) A6: per-prefix rules leaving `.vaulthalla/root` out; does superseding count as hiding; (7) A8; a bucket-limited
key lists versions and deletes by id; (8) the recover drill on B2, then two daemons (dev, a VM) on one bucket.

## 9. Work items, in order

1. Live checks (§8.3 items 1-7) once a Backblaze key exists, in parallel with 2-4.
2. Store seam and fake bucket knobs (no behaviour change).
3. Capability probe, columns, `vh vault storage probe`, the layout migration precondition.
4. Plain PUTs where conditions bought nothing (§7): this alone fixes BYOS `path_v0` vaults and envelopes on B2.
5. `version_log` publish, read, repair, GC and `writers` (`Publisher`, `Reader`, `Chain`, `Service`, `vault::recover`)
   with §8.1-8.2: solo `opaque_v1` vaults then work on B2. Managed remotes (plan workstream E) build on 3-5.
6. The drill in `version_log` mode on the fake (`vhh drill recover`), then live (§8.3 item 8).
7. Multi-writer enablement (wave 3) once A3 and A4 are confirmed (`mirrors.md`).

## 10. Open questions (recommendation first)

1. **Path for B2:** versions of the root key under C1; epoch-named roots only for providers without versioning, later.
2. **If B2 breaks A3 or A4:** solo vaults only on B2 (mirrors refuse such buckets), plus a settle delay (decide on a
   listing Δ after the PUT) only if the measured lag is bounded. No cloud arbiter.
3. **Root history:** three canonical roots and seven days, kept by the janitor; no lifecycle rule on the root.
4. **A provider failing GET `If-Match`:** refuse the bucket rather than read unpinned.
5. **`writers` in both modes,** shipped with work item 5 (a root format addition to spec 03 §3.2).
6. **Backblaze (plan §8):** add listing consistency and the order of near-simultaneous versions to question 1.
