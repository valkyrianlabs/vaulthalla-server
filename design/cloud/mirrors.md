# Mirrored vaults (wave 3): two or more servers on one bucket

Status: design for review (managed storage plan of 2026-11-12, §4.7 and workstream I); nothing here is implemented.
It covers what the server needs for one vault to be kept in sync by several of the customer's servers through its
bucket: what works today with a second writer, what breaks, the join and leave flows, and key rotation. It does not
cover the publish protocol itself ([spec 06](../encryption/06-publish-without-preconditions.md)), the cloud's records
(vaulthalla-cloud `account-model.md`, `key-manager.md`, `managed-storage.md`) or the Desktop and portal screens.

## Decided and given

- **Decided (Cooper, 2026-11-12, plan §3.1 item 6):** mirrors are optional, per vault; vaults are solo by default; a
  cluster of servers keeps a vault in sync; start simple; reuse the existing conflict resolution. Item 1: one bucket
  per vault, one application key per server and bucket.
- **From the plan's design (§4.7), adopted here:**
  - A second server joins a vault that already has a bucket and receives the vault keys wrapped to its own key by a
    device holding the account key (the restore relay).
  - Both servers sync against the bucket only: no server-to-server channel, no mirroring of bucketless vaults in v1.
  - The cloud's `vault_replica` records membership; adding one needs the account holder's step-up
    (`account-model.md`, `vault.replica.add`).

**Name.** `mirror` is already a sync strategy (`RemotePolicy::Strategy::Mirror`, `sync/model/RemotePolicy.hpp`): a
one-way image that deletes the other side's leftovers (`deleteRemoteLeftovers` under `keep_local`,
`deleteLocalLeftovers` under `keep_remote`). Server code and this design say **replica** and **replicated vault**,
matching the cloud's `vault_replica`. A replicated vault refuses the `mirror` strategy: it would delete the other
servers' uploads.

## How a remote-backed vault syncs today

One daemon per vault runs passes under an in-process lease (`sync::Controller::tryAcquirePass`, an `activePasses_`
set). A pass (`sync/Cloud.cpp`) indexes the bucket from `remote_object_index`, refreshed by a LIST, events or the
`path_v0` index. It plans per file against the database (`Planner`; `cache`, `sync` or `mirror` with `keep_local`,
`keep_remote`, `keep_newest` or `ask`), records two-sided changes as conflicts (`sync/model/Conflict`,
`ConflictResolver`), uploads and downloads, and publishes the manifest once if anything changed. For `opaque_v1` the
manifest is only verified and published, **never applied to the database**: "the v2 manifest is verified … never
loaded into the path-keyed remote index" (`CloudEngine::refreshRemoteIndexFromManifestIfChanged`). Objects in `o/` that
no local file names are counted as orphans, "left alone, never downloaded" (`Cloud::keyByObjectUid`).

## A second daemon on the same bucket today

| Area | Today | With two writers |
|---|---|---|
| Content objects `o/<uid>` | random file uids, one object per file, provider versions kept | **works**: no collisions; a same-file edit on both sides is a content conflict the existing machinery can decide |
| Manifest publish | conditional publish with merge and retry (spec 03 §3.4) | **works on AWS/R2; refused on B2**: Backblaze orders versions by upload start (spec 06 §4, A4 false, measured 2026-11-16), so a second writer on a `version_log` bucket is refused (spec 06 §5.5; §11 proposes one root log per writer) |
| The other writer's changes | never applied to the database | **breaks**: B never sees A's new files, renames or deletes; A's objects are orphans to B |
| Deletes | B still has a file A purged | **breaks**: B re-uploads it (`uploadLocalOnly`), and its publish keeps the entry (`mergePending`: B didn't change it, theirs has none, so ours), so the delete is undone |
| Cold start | `PublisherCache` is in memory | **breaks**: after a restart `before = theirs`, so B's first publish drops every entry its database lacks, deleting A's new files from the manifest |
| Snapshot records | merged by `SnapshotRecord::id`, a per-server database id | **breaks**: two servers' snapshot 7 overwrite each other |
| Key history | merged by `KeyRecord::version` | **breaks** if both rotate: two different keys called v3 |
| Key rotation by one server | the other holds only old versions; live reads refuse retired keys (`EncryptionManager::keySnapshot`) | **breaks**: B can't open roots or objects sealed under the new version. `load` falls back to an older retained root, which the chain rules call a **rollback** (a false critical alert) |
| Vault settings, recovery grants | the root's `vault` and `recovery_policy` are always "ours" in `mergePending` | **flaps**: each server's publish overwrites the other's name, quota, strategy and grant list. Grants live per server (`vault_recovery_grant`); envelopes are a union in the bucket |
| Pass lease, rotation, salvage and migration guards | per process / per database | not exclusive across servers; harmless for publishing (spec 06), unsafe for rotation, salvage and layout migration |
| Protection locks | per server database (`storage/upstream/Guard.hpp`) | a lock on A does not stop B's deletes |
| Usage ledger | `usage::noteUpstreamWrite` reads this server's index | each server counts its own writes; partial figures, while billing reads Backblaze's report (plan §4.9) |
| Upload backlog, local snapshots | per host (`recovery/local/`, `.vh-recovery/`) | stay per host; the manifest says per snapshot member whether the bucket holds it (spec 03 §3.3) |
| GC | keeps the segments of this server's last three recorded roots and young segments | mostly safe because every pass verifies before it collects; spec 06 §5.4 makes it follow the canonical chain |
| Conflict timestamps | `cache` and `sync` compare `updated_at` | two servers' clocks are compared; skew decides `keep_newest` |

## What the first version adds

1. **Spec 06 on every replicated vault**, with `writers` listing the replicas. Several writers on a `version_log`
   bucket are refused: A4 is false on Backblaze (spec 06 §4, 2026-11-16), and the library refuses any root naming more
   than one writer there (spec 06 §5.5). Replicated vaults need a bucket with conditional PUT.
2. **A manifest applier, the core of the feature.** On every newly settled canonical root, a three-way merge into
   the database (designed in issue #442), with the last applied root as base. The base is a local copy of that root
   and its sealed segments plus an `applying` marker: the epoch and hash alone are not enough, because the bucket may
   already have collected that root's versions and segments. That also gives a cold start its base:
   - new entries become remote-only files bound to `o/<uid>` (`cache` hydrates on open);
   - renames, moves, trash and purges are applied;
   - key records are checked, never applied, and a key version this server doesn't hold stalls the vault; snapshot
     records are applied; recovery grants come only from the account's signed policy (item 4);
   - content changed on both sides goes through the existing conflict path under the vault's policy.
   - Tree rules (issue #442): an edit beats a delete, in both directions; for placement and attributes the head
     wins and the undone change is reported ("later" is not defined against unpublished local changes); of two names
     clashing in one folder the entry with the greater uid becomes `name (<uid[0..8]>)`, as `vault::recover::plan`
     already does, so every server makes the same rename; a move that would close a directory cycle is not applied.
   Publishing always runs after applying, and a publish that loses a round applies the head and publishes again
   instead of merging in memory, so `mergePending`'s "before" is always the applied base and no published root holds
   entries the database lacks.
3. **Collision-free ids in the manifest.** Snapshot records keyed by a random uid. Key versions minted only by the
   rotation's owner (below).
4. **Shared settings.** The root's `vault` settings are applied like entries (the head wins), not overwritten as
   "ours". **Recovery grants are not merged between replicas** (decided, Cooper, 2026-11-14): one account-signed
   recovery policy, carried in the root and served by the cloud, is verified by every replica against the account
   key it pinned, and is the only thing that adds or revokes an account-managed grant (`key-manager.md`, "The
   account's recovery policy"). The customer approves a recipient once, not once per server.
5. **Refusals on a replicated vault:** the `mirror` strategy, layout migration (replicas must be `opaque_v1`), key
   salvage, and `vh vault recover --into` over the same uid.
6. **Status:** the replica set, each writer's last root and time, and whether this server is behind.

## Join (server side)

1. The account holder links server B (`installation-linking.md`), then asks B to join: `vh vault join --vault-uid
   <uid> [--api-key <key>]` (new; super admin, or a paired device's step-up; never a browser session or an agent).
2. B files a restore request (`POST /v1/recovery/restores`). Its approval with the `recovery.restore` step-up adds the
   replica in the same transaction (`account-model.md`), and the screen says "this adds vault X to server Y".
3. A device holding the account key delivers the vault's key versions through the restore relay. Restore codes are
   compared on both screens (`key-manager.md`).
4. B runs the recover path (`ops::vault_recover`, spec 03 §6.4) with its D1 provenance checks: each version's
   attestation must verify under a key pinned in the delivered material. B builds its database from the manifest (no
   content download) and publishes a root that adds itself to `writers`. Unlike a takeover restore, it keeps A.
5. Credentials: a managed bucket gets B's own key (`POST /v1/storage/vaults/{uid}/credentials`, `managed-storage.md`
   wave 3); BYOS uses the operator's own API key. Either way B runs spec 06's probe and must agree with the stored
   mode (I9).
6. A applies B's root on its next pass and accepts B as a writer. Nothing is re-uploaded.

## Leave

- **B leaves:** `vh vault leave` publishes a root without B in `writers`, stops syncing, reports
  `DELETE /v1/vaults/{uid}/replica`, and keeps or deletes B's local copy as the operator chooses. The last replica
  can't leave; it deletes or detaches the vault as a solo vault does.
- **The owner removes B** in the portal: the cloud revokes B's managed key (`onReplicaRemoved`). The next remaining
  replica's background cloud service drops B from `writers` (matched by the `node_id` the cloud lists).
- **A dead B removed by a server** (`vh vault replica remove` on A): only the manifest changes. The cloud's replica set
  stays the account holder's (one server never evicts another there): A reports it (`POST /v1/vaults/{uid}/replicas/
  unlisted`), the portal shows B as `unlisted`, and B's key works until the owner removes B. `vh vault sync info`
  shows each writer's standing at the cloud and the servers the cloud lists that aren't writers.
- **A compromised replica** still holds the keys. Removal therefore offers a rotation that excludes it (below), and
  revokes B's credential.

## Key rotation across replicas

- **One rotation owner at a time:** the server that starts it. Others refuse to rotate while the root shows one
  pending.
- **Every replica gets a replica key at join:** X25519, sealed like the server's other secrets, its public half in
  its `writers` entry.
- **Steps:**
  1. The owner mints `v(n+1)`.
  2. It writes KEV1 envelopes to the recovery recipients and to every replica key (`.vaulthalla/key/`, readable
     without the new version).
  3. It publishes a root listing `v(n+1)` as **pending**, sealed under `v(n)`.
  4. Each replica unwraps its envelope, checks the attestation against the owner's attestation key (pinned in its
     `writers` entry by the delivering device at join, D1), and publishes `holds: n+1`.
  5. When every writer holds it, the owner makes it current and the rotation pass re-seals.
  6. `v(n)` retires only once no entry references it.
- **A replica that is offline** blocks the switch. The owner can remove it, after which its acknowledgement is not
  awaited.
- **Recovery** needs no cloud or device for the rotation itself: the account key, as a recipient, receives the new
  version like any recipient (`key-manager.md`, automatic enrollment).

## Deliberately later

A server-to-server channel; mirroring bucketless vaults; partial replicas (some folders); different strategies per
replica; replicas on different providers; more than three replicas; a conflict-review screen across replicas.

## Open questions (recommendation first)

1. **Naming.** "Replica" in server code and the protocol; "mirrored" only in Desktop and portal copy. Rename the
   `mirror` sync strategy (to `image`, say) in the release that ships replicas, since both names would appear on one
   screen.
2. **Multi-writer on B2:** A4 failed live (2026-11-16): replicas are refused on such buckets, enforced (spec 06
   §5.5). Recommended path, if wanted: one root log per writer (spec 06 §11.2); a settling period rests on a provider
   bound Backblaze doesn't document (§11.1). No cloud arbiter.
3. **Replica keys for rotation** (above) instead of a device ceremony per rotation. A KEV1 envelope of class `0`
   (customer-controlled: the customer's own server), kept outside `vault_recovery_grant`.
4. **Tree conflict rules:** settled in issue #442 under the compatibility policy's rule 5, as listed in "What the
   first version adds", item 2. Not an open question any more.
5. **Conflict policy:** one per vault, carried in the root, `keep_local` by default as today. Under `keep_local` the
   server that syncs last wins, and the other version stays a provider version. Recommend `ask` for replicated vaults,
   which records two-sided changes instead of deciding by clock.
6. **Replica count in v1:** at most three (spec 06 I7 bounds publish attempts by `writers + 1`).
7. **Usage shown per server:** show the cloud's figures (Backblaze's report) for replicated vaults, not the server's
   partial ledger.
