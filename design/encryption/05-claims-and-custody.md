# 05. Claims and custody: who can decrypt, by deployment model

Status: design for review (#329, workstream 5). This spec comes **before any key-custody implementation** (maintainer,
#329) and governs the wording of docs, the console, the website and sales material. It refines the maintainer's
custody comment on #329 without changing it.

## 1. The rule

Whoever runs the daemon holds live vault keys: the daemon generates every server-vault key and keeps it unsealed in
memory while the vault runs (`EncryptionManager::load_key`, `core/src/vault/EncryptionManager.cpp:110-131`).
Customer-held recovery material (exports, recovery recipients, spec 03 §5) adds a customer path to the keys; it never
removes the operator's. Therefore:

- **Every encryption claim names its deployment model and vault type.**
- Only sealed vaults (spec 04) can be operator-blind when Valkyrian Labs runs the service.
- The Recovery service restores into customer-operated instances.
- Support access is customer-initiated, scoped, expiring and audited (§5).

Release gate (#344): until spec 03's manifest, recovery recipients/exports and the catastrophic restore drill pass,
`opaque_v1` is staged internally and **no claim says or implies that a vault is recoverable from the bucket**.
After that, the recovery claim for a vault also requires its recovery material to be in place (spec 03 §5.5); a
vault reporting `recovery_material_missing` gets no recovery claim. A vault whose migration is `cleanup_blocked`
carries the qualifier from spec 01 §6.4 (earlier names remain in provider history until a date).

No content-decryption material is escrowed to Valkyrian Labs (D2): VL never generates, receives or stores recovery
seeds, kits, exports or device keys, and no wording may suggest VL can restore access.

## 2. Terms

| Term | Means | Against whom |
|---|---|---|
| **Provider-blind** | the storage provider sees only opaque, encrypted objects: no names, paths, tree, content or content fingerprints; tampering is detected. Sizes, counts and timing still leak (spec 01 §3). | the bucket's provider and anyone with bucket access |
| **Operator-blind (to X)** | party X, who operates some part of the service, cannot decrypt content or names, because X neither runs the daemon nor holds keys or admin access to it | a named operator, e.g. "to Valkyrian Labs" |
| **Device E2EE** | content and names are encrypted on the user's devices; only enrolled devices and the customer's recovery key hold keys | the server operator and the provider (and anyone who compromises them) |

"Zero-knowledge" is not one of these terms. It is used only as §6 allows.

## 3. Claim matrix

Deployment models: **A** self-hosted daemon with the customer's own bucket (BYOS); **A′** self-hosted daemon with
VL-managed storage (B2); **B** VL-hosted daemon (managed instance); **C** recovery into a new instance operated by
the customer; **C′** recovery into an instance VL operates.

| Vault type | A (self-hosted, BYOS) | A′ (self-hosted, VL-managed B2) | B (VL-hosted) | C (customer restore) | C′ (VL-operated restore) |
|---|---|---|---|---|---|
| `encrypt_upstream=false` (`transparent`) | none: plaintext in the bucket | not offered (managed storage enforces encryption) | none upstream; VL can read everything | none | none |
| `encrypt_upstream=true`, `path_v0` (today) | content encrypted; **names visible to the provider**: not provider-blind | content encrypted; names visible to VL as storage operator: **not operator-blind** | VL can read everything | as A | VL can read everything |
| `encrypt_upstream=true`, `opaque_v1` | **provider-blind** | **provider-blind and operator-blind to VL**, if VL has no daemon, admin or key access and the customer controls updates (§4) | provider-blind; **not operator-blind**: "managed, encrypted" | provider-blind; operator-blind to VL (keys unwrapped only in the customer's instance) | not operator-blind (VL unwraps keys) |
| Sealed vault | provider-blind + device E2EE | provider-blind + device E2EE + operator-blind to VL | **device E2EE: operator-blind to VL** | device E2EE (the instance never holds keys) | device E2EE (the instance never holds keys) |

Every cell assumes the conditions in §4 and inherits spec 01-04's "still leaks" lists.

## 4. Conditions behind "operator-blind to Valkyrian Labs" (A′)

1. The customer runs the daemon on infrastructure VL does not administer, and VL holds no admin account, SSH access,
   device pairing or API key to it.
2. VL never receives vault keys, exports, recovery seeds or kits. Managed storage credentials are scoped to the
   customer's bucket and can't read the daemon's database.
3. The customer controls updates (can pin a version: `apt-mark hold vaulthalla`; macOS: a fixed cask version).
   Valkyrian Labs remains in the threat model **as software vendor**: a malicious update could exfiltrate keys.
   Mitigations to state, not to overclaim: signed APT repository and packages, notarized macOS builds, published
   source (AGPL); reproducible builds are future work.
4. Support access, if any, follows §5.

If any condition fails, the claim falls back to "provider-blind".

## 5. Support access

| Rule | Mechanism |
|---|---|
| Customer-initiated | A customer administrator creates a support grant on their instance (`vh support grant create --scope … --expires …`, step-up per #325). VL can't create, extend or request one through the product. |
| Scoped | Scopes: `diagnostics` (health, versions, config with secrets redacted, logs in `logging.file_paths: ids` mode), `metadata` (vault and file metadata of named vaults, still no content), `content` (read files of named vaults, explicitly listed). Never in any scope: key export or import, recovery recipients, secrets export, sealed vault content (impossible anyway). |
| Expiring | Default 24 h, maximum 72 h; revocable at once; expiry closes sessions. |
| Audited | Every support action runs as a distinct support identity and is recorded in the tamper-evident audit trail (#323: hash chain with signed heads, `core/include/audit/Chain.hpp`) tagged with the grant id; the customer's admins are notified when the grant is used and when it ends, and can export the grant's slice of the trail with its signed head. |
| Bound to people | The grant names the support engineer's account and requires their MFA (#325) and a paired device; shared credentials are not possible. |
| VL-hosted (B) | Host-level access (SSH, DB) to a managed instance is outside the product's control. The claim for B is therefore "managed, encrypted": VL commits to policy (customer-visible access log of host access, least privilege, break-glass records), not to impossibility. |

Diagnostics bundles produced for support follow the same scopes and never contain names in `ids` mode (#327).

## 6. Allowed wording

Use these sentences (or tighter ones). Anything else that implies more needs a review against this spec.

| Context | Allowed | Not allowed |
|---|---|---|
| `opaque_v1`, any model | "Your storage provider only ever sees encrypted, opaquely named objects. It can't see your file names, folders or contents. It can see how many objects you store, their sizes and when they change." | "Your provider knows nothing about your files"; "zero-knowledge storage" |
| `path_v0` (until migrated) | "File contents are encrypted before upload. File and folder names are visible to your storage provider." | "Encrypted storage" without the name caveat |
| A′ (self-hosted + VL-managed B2) | "Valkyrian Labs stores only data your own server encrypted, with keys we never receive. We can't read your files or their names." with the vendor footnote: "You control your server and its updates." | "Nobody can read your data"; "end-to-end encrypted" |
| B (VL-hosted, server vaults) | "Managed, encrypted: files are encrypted on the server and in storage. Valkyrian Labs operates the server that holds the keys; support access requires your approval and is logged." | "zero-knowledge", "we can't access your data", "end-to-end encrypted" |
| Sealed vaults (any model) | "End-to-end encrypted: files and names are encrypted on your devices. The server and storage hold only ciphertext and wrapped keys, so neither we nor your provider can read them. Previews, search, the S3 gateway and share links aren't available in sealed vaults." | "anonymous", "metadata-free"; omitting the unavailable features |
| "Zero-knowledge" | only for sealed vaults, and only with the metadata sentence: "The server still sees file sizes, counts and activity times." | anywhere else |
| Recovery | "Restore from your bucket and your recovery kit into a server you run, even if ours is gone." | "Valkyrian Labs can recover your data"; "we can restore your keys" |
| Compliance | "Designed to support the technical safeguards in <framework>; see <doc>." | "HIPAA compliant", "certified" (compliance is a property of the customer's organization and agreements, not of software) |

Never: "military-grade", "unbreakable", "unhackable", "bank-level".

## 7. Current text that must change

| Where | Today | Action |
|---|---|---|
| `docs/vaults/encryption.md:89-94` | lists provider-visible names correctly | keep until `opaque_v1` ships; then replace with the `opaque_v1` sentence and add the leak list and the claim matrix |
| `docs/vaults/secrets-and-key-export.md:180` | "Restoring a vault from its encrypted files alone … is not possible" | true until WS3-c ships; then link the restore procedure |
| Website and README feature lists | (not in this repo) | audit against §6 before any managed-storage or hosted offer launches |

No product text promises a capability before it ships (`.claude/context/docs-authoring.md`: never imply a full
backup/restore that doesn't exist).

## 8. Test and review plan

- A docs lint (contract test) that fails on the disallowed phrases in `docs/`, `web/src` strings and `README.md`
  unless the line carries an approved qualifier.
- Each feature PR that changes a cell in §3 updates this matrix and the operator docs in the same change.

## 9. Proposed implementation issues

- **WS5-a. Claims in docs and console.** Wording per §6 for `path_v0` now; the matrix page when `opaque_v1` ships;
  the disallowed-phrase contract test.
- **WS5-b. Support grants.** Customer-created, scoped, expiring, audited support access (§5). Depends on #325.
- **WS5-c. Managed-storage guardrails.** Managed (VL B2) credentials scoped per customer bucket; `encrypt_upstream`
  and `opaque_v1` enforced; refusal of `transparent`. Depends on WS1-b.
