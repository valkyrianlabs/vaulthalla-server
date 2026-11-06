# Encryption architecture specs (#329)

Design documents under review, not product documentation: they live outside `docs/` so `pmdocs` never publishes
them. Operator docs change when the features ship (spec 05 §7).

North star (maintainer, #329): **a fresh installation with only the customer's authorized recovery material and the
encrypted bucket reconstructs files, names, versions and layout after the old server, database and TPM are gone.**

| Spec | Workstream | One line |
|---|---|---|
| [01 Provider-blind storage](01-provider-blind-storage.md) | 1 | `encrypt_upstream=true` means opaque object ids (`o/<uid>`), no `x-amz-meta-*`, an internal `storage_layout` field (`path_v0` → `opaque_v1`), and one verified migration of existing buckets incl. versions and backlog |
| [02 VHF1 file format](02-authenticated-file-format.md) | 2 | 120-byte authenticated header, per-generation HKDF keys, 64 KiB AES-256-GCM chunks with AAD = header hash ‖ index ‖ final flag, inside one object per file version; authenticated range reads; legacy GCM retired |
| [03 Metadata recovery](03-metadata-recovery.md) | 3 | encrypted copy-on-write manifest (root + segments) with epochs, KEV1 key envelopes to a customer recovery recipient, the recovery kit, `vh vault recover`, the catastrophic restore drill |
| [04 Sealed vaults](04-sealed-vaults.md) | 4 | device-held keys, a signed membership chain, SAS-verified device approval, recovery seed; the server stores ciphertext, encrypted names and envelopes; blocked on #325 |
| [05 Claims and custody](05-claims-and-custody.md) | 5 | provider-blind vs operator-blind vs device E2EE by deployment model, support-access rules, allowed wording |
| [`vectors/`](vectors/) | 2, 3 | `vh_crypto_vectors.py` (reference implementation) and `vectors.json` (66 vectors: object ids, VHF1, range reads, negatives, KEV1, recovery seed, manifest chain). `python3 vectors/vh_crypto_vectors.py --check` |

## Dependencies

```mermaid
flowchart TD
  W5a["WS5-a claims wording (now)"]
  W2a["WS2-a VHF1 codec + vectors (C++)"]
  W1a["WS1-a schema: vault uid, file uid, storage_layout"]
  W2b["WS2-b VHF1 at rest for new writes"]
  W2c["WS2-c local format conversion"]
  W3a["WS3-a encrypted manifest v2"]
  W1b["WS1-b OpaqueV1 data plane"]
  W3b["WS3-b recovery recipients + KEV1"]
  W3c["WS3-c vh vault recover + drill (lifts opaque_v1 staging)"]
  W1c["WS1-c layout migration path_v0 → opaque_v1 (D3 gate)"]
  W1d["WS1-d operator docs"]
  W5c["WS5-c managed-storage guardrails"]
  W2d["WS2-d legacy format retirement"]
  P325["#325 MFA, step-up, pairing hardening"]
  W5b["WS5-b support grants"]
  W4["WS4-a/b/c sealed vaults (server, chain, Desktop)"]
  DSK["Desktop: VHF1 Swift + recovery kit"]

  W2a --> W2b --> W2c
  W1a --> W2b
  W1a --> W3a
  W2a --> W3a
  W3a --> W1b
  W2b --> W1b
  W3a --> W3b --> W3c
  W1b --> W1c
  W2b --> W1c
  W3c --> W1c
  W1c --> W1d
  W1b --> W5c
  W2c --> W2d
  W1c --> W2d
  W3c --> W2d
  P325 --> W5b
  P325 --> W4
  W3b --> W4
  W2a --> DSK --> W4
  W3b --> DSK
```

## Implementation order

1. **WS5-a**: correct claims now (`path_v0` names are visible to the provider) and add the phrase lint. No code
   risk; it governs everything after.
2. **WS2-a**: the VHF1 codec and the C++ vector test. Pure library, no behavior change.
3. **WS1-a**: schema (uids, `storage_layout`). Additive.
4. **WS2-b**: new generations are written as VHF1 (local at rest); legacy stays readable.
5. **WS3-a**: manifest v2, used by new `opaque_v1` vaults.
6. **WS1-b**: the `opaque_v1` data plane; new encrypting vaults are created opaque.
7. **WS3-b**, then **WS3-c**: recovery recipients, the kit and the restore drill. The north star is met for new
   vaults here, and `opaque_v1` creation leaves internal staging.
8. **WS2-c** (local conversion; can start right after 4) and **WS1-c** (bucket migration of existing vaults), then
   **WS1-d** docs.
9. **WS2-d**: retire the legacy format behind a version floor and local upgrade gates.
10. **#325** (in parallel with 2-9), then **WS5-b** and **WS4** (sealed vaults) with the Desktop work.

Each step is a separate PR with its own tests; none rotates an existing key. Steps 8 and 9 are the only ones that
rewrite stored data, and both are verified before anything old is removed.

## Decisions (maintainer, #344)

The four questions raised in review were decided on #344; the specs encode them.

| | Decision | Where |
|---|---|---|
| **D1** | On a fresh node, a key version is canonical only when its original-node attestation verifies against the original public key pinned in customer-held recovery material (the kit, or an export that carries the public key). Otherwise explicit salvage and re-encryption. A fresh server's self-attestation never proves old provenance. Empty, missing and wrong anchors and an independent-host restore are tested. | 03 §5.4, §6.2, §7, §8 |
| **D2** | Customer-held recovery recipients are mandatory for managed storage and sealed vaults before creation or writes. Self-hosted BYOS: prominently recommended, optional when an independently verified, current key export exists; otherwise `recovery_material_missing`. No content-decryption material is escrowed to Valkyrian Labs. | 03 §5.5, 04 §6, 05 |
| **D3** | Every required retained upstream version and recovery generation is re-sealed into the opaque layout. Inventories and actual decryption are verified before anything path-keyed is deleted. Object Lock, provider retention, incomplete history and failed deletes are respected; the migration is never reported finished while names remain in provider history. Bounded verify/soak/rollback period; destructive-cleanup guardrails. | 01 §6 |
| **D4** | Sealed vault v1: single owner, multiple owner-approved devices, macOS Desktop first; sharing and web access in phase 2. The server never receives plaintext, names or unwrapped content keys, and never enrolls an encryption-capable device on its own. | 04 |

Settled earlier on #329 and not reopened: opaque ids are intrinsic to `encrypt_upstream=true` (no second switch;
readable paths only for `encrypt_upstream=false`); AEAD chunks live inside one object per file version, with
ordinary multipart transport and no per-chunk objects.

## Quality gates

- **Recoverability before exposure.** `opaque_v1` creation is staged internally (test mode and the harness only)
  until the encrypted manifest (WS3-a), recovery recipients and exports (WS3-b) and the catastrophic restore drill
  (WS3-c) pass. New encrypting vaults stay `path_v0` until then, and no claim says a vault is recoverable from the
  bucket (spec 05). The release that enables `opaque_v1` creation records the drill result.
- **No unverified plaintext, no auxiliary leaks.** VHF1 readers emit only authenticated chunks (02 §3.6-3.7); the
  request audit test fails on any name, path or plaintext-derived value in any request (01 §8).
- **Verified everywhere it matters:** negative vectors, local and remote format conversion, provider versioning and
  retention, retries and aborts, cross-language interoperability (C++ and Swift against `vectors.json`), remote
  costs against the preflight, rollback.
- **Replay limit, stated precisely.** An untrusted bucket can replay an older valid state unless the customer keeps
  an independent freshness checkpoint; with one, it can still replay any state newer than the checkpoint (03 §4.5).
  Restores without a checkpoint report "freshness unverified".
- **Rollout:** retirement of legacy formats uses local upgrade gates and a supported version floor (02 §6.3), never
  install-wide reports (the product has no telemetry).

## Prerequisites already merged

- #326 (sealing fails closed): `KeyProvider::initGuarded` and `MasterSecretLost` stop a host from silently replacing
  a lost `vault_master`; spec 03 §5.6 adds the recovery-kit import path to its ways back.
- #328 (encrypted working copies and staging): `crypto::ScratchFile` is the only way plaintext may touch disk during
  conversions and restore transfers (02 §6.2).
- #323 (tamper-evident audit trail): migration cleanups, restores, recipient changes and support grants are recorded
  there (01 §6.4, 05 §5).
- #327 (paths out of logs): transport logs name object keys, filesystem logs entry ids (01 §4.5).

## Not in scope

Size padding (sizes leak exactly in v1; spec 01 §3), per-object name hints (spec 03 §4.3), signing manifest roots
(spec 03 §4.5), HPKE (spec 03 §5.2), server-side conversion into sealed vaults (spec 04 §7).
