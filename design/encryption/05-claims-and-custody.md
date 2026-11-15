# 05. Claims and custody: who can decrypt, by deployment model

Status: design for review (#329, workstream 5). This spec comes **before any key-custody implementation** (maintainer,
#329) and governs the wording of docs, the console, the website and sales material. It refines the maintainer's
custody comment on #329 without changing it, and carries the recovery custody amendment on #344 and the managed
storage amendment of 2026-11-12 (product owner, managed storage plan revision 4 §3.1 and §3.2; marked where it
applies).

> **Sovereignty is the default. Custody is an option. Neither should compromise the other.**

## 1. The rule

Whoever runs the daemon holds live vault keys: the daemon generates every server-vault key and keeps it unsealed in
memory while the vault runs (`EncryptionManager::load_key`, `core/src/vault/EncryptionManager.cpp:110-131`).
Customer-held recovery material (exports, recovery recipients, spec 03 §5) adds a customer path to the keys; it never
removes the operator's. Therefore:

- **Every encryption claim names its deployment model, vault type and recovery tier (§3.1).**
- Only sealed vaults (spec 04) can be operator-blind when Valkyrian Labs runs the service.
- No vault is called operator-blind (to Valkyrian Labs) while its recovery configuration gives Valkyrian Labs
  unilateral plaintext recovery.
- The Recovery service restores into customer-operated instances.
- Support access is customer-initiated, scoped, expiring and audited (§5).

Release gate (#344): until spec 03's manifest, recovery recipients/exports and the catastrophic restore drill pass,
`opaque_v1` is staged internally and **no claim says or implies that a vault is recoverable from the bucket**. Passed
by #371 (the drill result is in its release note): new encrypting vaults are `opaque_v1`, and the recovery claim
reads "from your bucket and your recovery kit", never from the bucket alone.
After that, the recovery claim for a vault also requires its recovery material to be in place (spec 03 §5.5); a
vault reporting `recovery_material_missing` gets no recovery claim. A vault whose migration is `cleanup_blocked`
carries the qualifier from spec 01 §6.4 (earlier names remain in provider history until a date).

**Sovereignty default.** By default, Vaulthalla recovery is independently customer-controlled. Valkyrian Labs
receives no recovery keys or decryption authority unless a customer separately enrolls in an explicitly authorized
custodial recovery service. D2's "do not escrow content-decryption material to Valkyrian Labs" is that default, for
every vault; custody can only ever come from Tier C (§3.1), which is planned, not implemented, and needs its own
approval. Self-hosted and BYOS deployments work fully, now and later, with no vaulthalla.cloud account, no payment,
no VL-held keys or plaintext, no contact with VL infrastructure for encryption, decryption, authentication or
disaster recovery, and no telemetry, registration or central authorization. Restore works with the original server,
database, TPM and every piece of VL infrastructure gone. None of this may be removed, weakened or commercially
restricted. Noncustodial sealed vaults and fully self-managed deployments keep the stronger guarantee: no party but
the customer's devices and recovery key can ever decrypt.

## 2. Terms

| Term | Means | Against whom |
|---|---|---|
| **Provider-blind** | the storage provider sees only opaque, encrypted objects: no names, paths, tree, content or content fingerprints; tampering is detected. Sizes, counts and timing still leak (spec 01 §3). | the bucket's provider and anyone with bucket access |
| **Operator-blind (to X)** | party X, who operates some part of the service, cannot decrypt content or names, because X neither runs the daemon nor holds keys or admin access to it | a named operator, e.g. "to Valkyrian Labs" |
| **Device E2EE** | content and names are encrypted on the user's devices; only enrolled devices and the customer's recovery key hold keys | the server operator and the provider (and anyone who compromises them) |
| **Self-hosted E2EE** (amended 2026-11-12) | model A′ with `opaque_v1`: content and names are encrypted on hardware the customer controls (their own server, which holds the vault keys, and their devices); keys leave it only wrapped to customer-held keys (§4) | the storage provider and Valkyrian Labs as storage, recovery and relay operator; **not** Valkyrian Labs as software vendor (§4 condition 3) or as the portal's publisher (§4 condition 5) |

"Zero-knowledge" is not one of these terms. It is used only as §6 allows.

## 3. Claim matrix

Deployment models: **A** self-hosted daemon with the customer's own bucket (BYOS); **A′** self-hosted daemon with
VL-managed storage (B2); **B** VL-hosted daemon (managed instance); **C** recovery into a new instance operated by
the customer; **C′** recovery into an instance VL operates. Amended 2026-11-12: no VL-hosted daemon (B) is planned
(managed storage plan revision 4); its column stays so that any future offer is held to it.

| Vault type | A (self-hosted, BYOS) | A′ (self-hosted, VL-managed B2) | B (VL-hosted) | C (customer restore) | C′ (VL-operated restore) |
|---|---|---|---|---|---|
| `encrypt_upstream=false` (`transparent`) | none: plaintext in the bucket | not offered (managed storage enforces encryption) | none upstream; VL can read everything | none | none |
| `encrypt_upstream=true`, `path_v0` (today) | content encrypted; **names visible to the provider**: not provider-blind | content encrypted; names visible to VL as storage operator: **not operator-blind** | VL can read everything | as A | VL can read everything |
| `encrypt_upstream=true`, `opaque_v1` | **provider-blind** | **provider-blind and operator-blind to VL**, if VL has no daemon, admin or key access and the customer controls updates (§4); **self-hosted E2EE** under the same conditions (§2; amended 2026-11-12) | provider-blind; **not operator-blind**: "managed, encrypted" | provider-blind; operator-blind to VL (keys unwrapped only in the customer's instance) | not operator-blind (VL unwraps keys) |
| Sealed vault | provider-blind + device E2EE | provider-blind + device E2EE + operator-blind to VL | **device E2EE: operator-blind to VL** | device E2EE (the instance never holds keys) | device E2EE (the instance never holds keys) |

Every cell assumes the conditions in §4 and inherits spec 01-04's "still leaks" lists. Every cell also assumes
Recovery Tier A or B (§3.1). Tier C enrollment that lets Valkyrian Labs recover plaintext on its own removes
"operator-blind to VL" (and "device E2EE" or "self-hosted E2EE" in the strict sense) from that vault, whatever the
cell says.

**Planned, no claims: Desktop-only (D).** Amended 2026-11-12: a later wave (plan revision 4 §3.1 item 7) adds model
**D**, Vaulthalla Desktop with VL-managed storage and no server: device-held keys, the Mac writing the same bucket
format, previews decrypted in the browser. It has no column and no allowed wording until its own design is approved
and it ships; until then §6 allows nothing for it.

### 3.1 Recovery service tiers

"Tier" here is the recovery service; the letters A-C′ above are deployment models.

| | Tier A: Self-Managed Recovery | Tier B: Vaulthalla Cloud Assisted Recovery | Tier C: Vaulthalla Cloud Custodial Recovery |
|---|---|---|---|
| Status | **the design in these specs** | **BEING BUILT, NOT OFFERED**: the product owner approved the customer-key-controlled design on 2026-11-10 (§3.2); vaulthalla.cloud isn't open | **PLANNED / NOT IMPLEMENTED**; needs its own approved security architecture, custody model, threat model, incident response and disclosure process before any implementation |
| Account / payment | none | a vaulthalla.cloud account; no payment method for the free allowance (10 vaults, product owner 2026-11-06), a commercial agreement beyond it | an account, an active paid arrangement and explicit enrollment in custody |
| Who holds recovery material | the customer only (kit, exports) | the customer; recovery can stay entirely customer-key-controlled | Valkyrian Labs may hold protected recovery material or take part in threshold recovery |
| What VL can do | nothing: no unilateral decryption authority | orchestration, encrypted backup management, disaster-recovery assistance | depending on the model, possibly recover plaintext; the exact keys or shares held, what they permit and whether VL can decrypt alone are documented per customer |
| Depends on VL infrastructure | no | for the assistance only; Tier A recovery stays available | for the custodial path; Tier A recovery stays available |
| Enrollment | default | voluntary, revocable; amended 2026-11-12: a managed vault is enrolled automatically, as part of the managed storage the customer chose, and only to the account recovery key a person pinned on the server | voluntary, explicit, separately authorized, revocable |

Separation rules (binding now, for any future work):

- A payment method is a commercial prerequisite, never cryptographic authorization or consent. Custody needs its
  own explicit authorization (with step-up, #325 / #359).
- Creating an account, adding a payment method, subscribing to managed B2 storage or upgrading Vaulthalla never
  uploads keys or enrolls anyone in custody. No existing vault's recovery properties change silently. Amended
  2026-11-12: a vault's automatic Tier B enrollment is stated when it is created as, or converted to, a managed
  vault, and shown in its status; a vault that isn't managed is never enrolled automatically.
- Disabling self-managed recovery or replacing customer-held keys is never a prerequisite for buying anything.
- Managed storage and managed recovery are separate capabilities: buying one never implies the other. Amended
  2026-11-12 (product owner, plan revision 4 §3.1 item 3): managed storage includes Tier B for its own vaults,
  "included and automatic". It never implies Tier C, and Tier B for other vaults never requires managed storage.
- Leaving Tier B or C (cancellation, failed payment, expiry, or Valkyrian Labs ceasing operations) never traps a
  customer or leaves them unable to recover: Tier A recovery remains intact throughout. **Proposed 2026-11-12,
  awaiting the maintainer:** for a vault whose only recipient is the account recovery key, this holds only while an
  offline copy of that key exists, so managed onboarding is not complete until one does: the key recovery code, if
  it is made to work without the service (the cloud's `key-manager.md` open question 1), or Desktop's export of the
  key as a recovery kit (1Password or print). A server with no record of an offline copy says so in status and the
  console; it never blocks a vault that already runs (`design/cloud/key-manager.md`).
- Revoking a custodian's access to a key it already held does not revoke historical access; cutting it off needs a
  rotation and, for data it could already read, re-encryption (spec 03 §5.7).

The recipient formats are ready for separately authorized recipients and threshold participants without a
redesign (spec 03 §5.7), and nothing more for Tier C: no APIs, tables, billing hooks or scaffolding exist for it.

**Automatic enrollment of managed vaults is Tier B, not Tier C** (amended 2026-11-12). The account recovery key
(the cloud's `docs/design/key-manager.md`; this repository's `design/cloud/key-manager.md`) is a recovery seed made
on a customer device. Servers receive only its public half, pinned after a person confirms its fingerprint, and wrap
vault keys to it as ordinary customer-class (`0`) KEV1 envelopes. The cloud stores those envelopes and the seed only
wrapped under secrets it never receives: a passkey's PRF output, or a transfer from a customer device. The key
recovery code is shown once on the customer's device and never sent to the cloud. So Valkyrian Labs holds no material it can open alone, which is Tier B's defining property; what
the enrollment changes is only who triggers it. It would become Tier C (and lose every "operator-blind" and "E2EE"
claim) if any of these held:

- the seed, or a wrap of it, under a secret the cloud can derive or reset: the account password, email, the sign-in
  recovery codes, TOTP seeds, or a key the cloud keeps (a KMS key, a "convenience" escrow);
- a recipient Valkyrian Labs holds, whatever class the envelope declares (spec 03 §5.5), or a server that wraps to
  an account key nobody confirmed (a substituted key receives every vault key the server wraps);
- an unlock that succeeds without a customer factor, or Valkyrian Labs taking a share of a threshold scheme.

A malicious portal release could read a seed the browser unlocks; that is the vendor risk of §4 conditions 3 and 5,
not custody by design, and it is disclosed with the claim (§6).

### 3.2 Tier B as approved (product owner, 2026-11-10)

Customer-key-controlled cloud recovery: the cloud keeps an independent copy of a vault's recovery records and relays
restores, and can never decrypt them alone. On the server (`vh cloud recovery enroll|status|unenroll`,
`ops::cloud_recovery`; the cloud's `docs/design/recovery-enrollment.md` and `recovery-restore.md`):

- **Explicit, per vault.** A linked server (`vh cloud link`), a super admin or the export encryption keys permission,
  the local CLI or a paired device with the vault-bound keys step-up, never the browser or an agent. Linking, an
  account, a payment or managed storage never enrolls a vault. **Amended 2026-11-12:** this stays the rule for BYOS
  and local vaults. A managed vault is the one exception: the server enrolls it automatically when it becomes managed
  (its attach reaching `done`), after each rotation and whenever coverage falls behind, sending only envelopes
  wrapped to the account key a person pinned (`design/cloud/key-manager.md`). Linking, an account or a payment alone
  still enrolls nothing.
- **What is sent:** the vault's existing KEV1 envelopes, read byte for byte from its bucket and checked against their
  records, wrapped only to customer-class recipients the customer enrolled (for a managed vault, the pinned account
  key); the key checks, attestations, attestation public keys and manifest checkpoint (public, as in a recovery
  kit). Never a vault key, a seed, a kit or an export. Enrollment is refused unless every needed key version has an
  envelope.
- **Revocable.** `vh cloud recovery unenroll` deletes every record the cloud holds for the vault. That doesn't undo
  past disclosure: a recipient whose key leaked keeps the versions it covered until a rotation (spec 03 §5.7).
- **Tier A is unchanged.** A vault in cloud recovery is still recovered from the customer's kit or export without
  Valkyrian Labs, and the claims of §4 still hold (VL receives no vault keys, exports, seeds or kits).
- **Claims:** until vaulthalla.cloud opens, §6's row for cloud recovery still applies to product text.

**Open questions for the maintainer (§3.1, §3.2; not changed above).**

1. **The offline-copy condition** proposed in the separation rules above. Without it, if every unlock of the account
   key is a wrap the cloud stores (passkey, key recovery code), the seed is unreachable without the service once the
   server is gone, and Tier A independence fails for vaults whose only recipient is that key. *Recommendation:
   adopt it as written; the cloud's open question 1 (recovery code as a wrap secret or as the seed) decides whether
   the code alone satisfies it.*
2. **Unenrolling a managed vault.** Revocable is part of Tier B. *Recommendation: allowed with a warning (the
   cloud's `account-model.md` open question 2); the server then stops re-enrolling it automatically, and the
   bucket's own envelopes keep D2 satisfied.*

## 4. Conditions behind "operator-blind to Valkyrian Labs" (A′)

1. The customer runs the daemon on infrastructure VL does not administer, and VL holds no admin account, SSH access,
   device pairing or API key to it.
2. VL receives no vault keys, exports, recovery seeds or kits (Tier A, or Tier B kept customer-key-controlled; a
   Tier C configuration that lets VL recover plaintext ends this claim). Amended 2026-11-12: the account recovery
   key's seed reaches the cloud only wrapped under secrets it never receives (§3.1), which is not receiving it.
   Managed storage credentials are scoped to the customer's bucket and can't read the daemon's database.
3. The customer controls updates (can pin a version: `apt-mark hold vaulthalla`; macOS: a fixed cask version).
   Valkyrian Labs remains in the threat model **as software vendor**: a malicious update could exfiltrate keys.
   Mitigations to state, not to overclaim: signed APT repository and packages, notarized macOS builds, published
   source (AGPL); reproducible builds are future work.
4. Support access, if any, follows §5.
5. Amended 2026-11-12: **the portal caveat is stated wherever portal access is offered** (`app.vaulthalla.cloud`
   through the relay, plan revision 4 §3.2). The page's code is served by Valkyrian Labs on every visit, so a
   malicious or compromised portal release could use a paired browser's key, or an account key unlocked in that
   browser, while the page is open, and read what that browser's user can read. This is a vendor risk like
   condition 3, not a pairing VL holds; it is limited as the cloud's `docs/design/relay.md` says ("The portal's
   code is served by us"). Desktop and the server's own web console don't depend on it, and the portal is optional.

If any condition fails, the claim falls back to "provider-blind".

**Why the relay keeps condition 1** (amended 2026-11-12). Valkyrian Labs relays the portal's connection and never
pairs (plan revision 4 §3.2, the cloud's `docs/design/relay.md`):

- The pairing key is the browser's: a non-extractable P-256 key per browser and deployment, kept in that browser's
  IndexedDB. The cloud registers only its public key's hash, so a ticket can name it but nothing at VL can sign with
  it.
- Pairing is the device protocol unchanged: TLS 1.3 end to end inside the relayed stream, the server pinned by its
  key, a SAS the server's owner confirms in their own console, and the same `device.trust` step-up. A relay that
  terminates both legs gets a different SAS on each.
- A ticket the cloud signs admits a stream to pairing only; the server re-checks it and closes a stream whose client
  key isn't the ticket's. A compromised cloud reaches the pairing screen, not a session.
- Relayed sessions can't export keys, register approval keys, rotate the device identity or satisfy a step-up
  without a person's passkey approval in the server's console.

Condition 1 breaks, and A′ loses "operator-blind" and "self-hosted E2EE", if any of these changes: the cloud or relay
keeps or can use a browser's private key (server-side storage, key sync or backup, a hosted "web device"); the cloud
is itself a paired device or service account on the customer's server; relayed pairing is approved without the
owner's SAS confirmation, or a ticket alone authorizes a session; the inner TLS is terminated at the relay, or the
portal accepts a server key other than the pinned one; relayed sessions gain key export, approvals or step-ups; or
the browser end moves to certificates for hostnames VL controls (the relay design's option (d)) without this section
being reviewed again.

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
| A′ (self-hosted + VL-managed B2) | "Valkyrian Labs stores only data your own server encrypted, with keys we never receive. We can't read your files or their names." with the vendor footnote: "You control your server and its updates." | "Nobody can read your data"; "end-to-end encrypted" without the qualifiers of the next row |
| A′, end to end (amended 2026-11-12; product owner, plan revision 4 §1 and §3.1) | "End-to-end encrypted: your files are encrypted on your own server and devices, with keys that never leave hardware you control. Neither Backblaze nor Valkyrian Labs can read them." Only for a self-hosted server on VL-managed storage, `opaque_v1` (which managed storage enforces), Tier A or B, and §4's conditions. Required with it, in the same block: the vendor footnote "You control your server and its updates."; the portal caveat wherever portal access is offered, "If you open your files at app.vaulthalla.cloud, that page's code is served by Valkyrian Labs. Vaulthalla Desktop and your server's own web console don't depend on it."; and, wherever cloud key backup is described, that the keys are stored only wrapped to a recovery key that only your devices can unlock. Usable from the launch of managed storage; until then no product text describes managed storage | "zero-knowledge"; "nobody can read your data", "only you can read", or naming any party beyond Backblaze and Valkyrian Labs; "operator-blind" (the cloud repository's rule: the service is never called operator-blind); the sentence without its footnote or, where the portal is offered, its caveat; the claim for BYOS (model A, not decided), `path_v0`, a VL-hosted daemon, Tier C or Desktop-only vaults |
| B (VL-hosted, server vaults) | "Managed, encrypted: files are encrypted on the server and in storage. Valkyrian Labs operates the server that holds the keys; support access requires your approval and is logged." No such offering is planned (amended 2026-11-12); the row stays as it is | "zero-knowledge", "we can't access your data", "end-to-end encrypted" |
| Desktop-only (D, a later wave; amended 2026-11-12) | nothing until its own design is approved and it ships | any claim, including the plan's proposal that the A′ sentence also holds for it |
| Sealed vaults (any model) | "End-to-end encrypted: files and names are encrypted on your devices. The server and storage hold only ciphertext and wrapped keys, so neither we nor your provider can read them. Previews, search, the S3 gateway and share links aren't available in sealed vaults." | "anonymous", "metadata-free"; omitting the unavailable features |
| "Zero-knowledge" | only for sealed vaults, and only with the metadata sentence: "The server still sees file sizes, counts and activity times." | anywhere else |
| Recovery (Tier A) | "Restore from your bucket and your recovery kit into a server you run, even if ours is gone. No account or payment needed." | "Valkyrian Labs can recover your data"; "we can restore your keys"; any suggestion that recovery needs VL |
| Cloud recovery (Tiers B, C) | nothing while they are planned; at most "planned" in roadmap material, with no availability, pricing or capability claims | "available", "included", or any description of Tier B or C as a current feature; any wording that ties managed storage, an account or a payment method to custody |
| A vault in Tier C (once it exists) | exactly which keys or shares Valkyrian Labs holds, what they permit, and whether VL can decrypt on its own | "operator-blind", "zero-knowledge" or "only you can decrypt" when VL can recover plaintext |
| Compliance | "Designed to support the technical safeguards in <framework>; see <doc>." | "HIPAA compliant", "certified" (compliance is a property of the customer's organization and agreements, not of software) |

Never: "military-grade", "unbreakable", "unhackable", "bank-level".

**Open questions for the maintainer (§6; not changed above).**

1. **The same sentence for BYOS (model A).** With `opaque_v1` it is true there with fewer parties (no VL at all), but
   the decision of 2026-11-12 names managed storage only. *Recommendation: allow it for A with "your storage
   provider" in place of "Backblaze" and without "Valkyrian Labs", once A′'s wording ships.*
2. **"Keys that never leave hardware you control"** is true of usable keys; wrapped copies do leave (the bucket's
   envelopes, the cloud's backup). *Recommendation: keep the plan's sentence and rely on the required backup
   qualifier above; if that qualifier is too heavy for short surfaces, use "keys that are never readable outside
   hardware you control" instead.*
3. **Where the portal caveat must appear.** *Recommendation: as a footnote next to the vendor footnote on every
   surface that offers portal access, rather than on every occurrence of the claim, so the lint can check it as a
   paragraph qualifier.*

## 7. Current text that must change

| Where | Today | Action |
|---|---|---|
| `docs/vaults/encryption.md:89-94` | lists provider-visible names correctly | done (#371): the `opaque_v1` sentence for new vaults, the `path_v0` caveat for older ones |
| `docs/vaults/secrets-and-key-export.md:180` | "Restoring a vault from its encrypted files alone … is not possible" | done (#371): "Restore A Vault From Its Bucket" (bucket + kit) |
| Website and README feature lists | (not in this repo) | audit against §6 before any managed-storage or hosted offer launches |

No product text promises a capability before it ships (`.claude/context/docs-authoring.md`: never imply a full
backup/restore that doesn't exist).

## 8. Test and review plan

- A docs lint (contract test) that fails on the disallowed phrases in `docs/`, `web/src` strings and `README.md`
  unless the line carries an approved qualifier.
- Each feature PR that changes a cell in §3 updates this matrix and the operator docs in the same change.
- Amended 2026-11-12: the lint (`tools/contracts/encryption_claims.py`) stays as it is until managed storage
  launches; it is stricter than §6's A′ end-to-end row, and nothing user-facing may use that row before launch. It
  changes in the launch PR, with this section's rows and the docs.

## 9. Future workstream: Vaulthalla Cloud Recovery (Tiers B and C)

Tier B's customer-key-controlled design was approved on 2026-11-10 (§3.2). Tier C is not designed here and not to be
implemented until a separate design is approved by the product owner. Its scope must cover at least:

- enrollment and disclosure (what is held, what it permits, whether VL can decrypt alone);
- MFA and step-up before enrolling in or changing custody (#325 framework, #359);
- identity verification at recovery time;
- custody access controls, separation of duties and emergency procedures;
- audit and customer notifications (the #323 audit trail);
- revocation, rotation and cancellation (revocation doesn't undo past disclosure: rotation or re-encryption);
- failed payment, expiry and company shutdown, none of which may strand a customer;
- removing Valkyrian Labs from a recovery configuration.

Threshold recovery (no single party, Valkyrian Labs included, can recover alone) is worth exploring as possibly
preferable to sole custody; it is not committed to.

## 10. Proposed implementation issues

- **WS5-a. Claims in docs and console.** Wording per §6 for `path_v0` now; the matrix page when `opaque_v1` ships;
  the disallowed-phrase contract test.
- **WS5-b. Support grants.** Customer-created, scoped, expiring, audited support access (§5). Depends on #325.
- **WS5-c. Managed-storage guardrails.** Managed (VL B2) credentials scoped per customer bucket; `encrypt_upstream`
  and `opaque_v1` enforced; refusal of `transparent`. Depends on WS1-b.
