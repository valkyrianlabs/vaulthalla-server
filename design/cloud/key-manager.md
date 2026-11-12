# Vaulthalla Cloud: the account recovery key on the server

The server's side of vaulthalla.cloud as key manager: how a linked server fetches, verifies and pins the account
recovery key, uses it as a recovery recipient of its vaults, enrolls managed vaults with the cloud automatically,
and restores with it. It does not cover the key's creation, unlock methods or storage in the cloud (the cloud's
`docs/design/key-manager.md`), provisioning buckets (`managed-remotes.md`) or attaching a remote to a local vault
(`design/storage/attach-remote.md`). A server that never links works exactly as today.

## Decided and proposed

Decided (product owner, 2026-11-12, managed storage plan revision 4 §3.1 item 3): vaulthalla.cloud is the preferred
key manager, with one recovery key per account across all deployments and no per-vault or per-server ceremony; what
is stored is the vault keys themselves, every version, each wrapped to the account key; a server fetches only its own
vaults' wrapped keys and a linked Desktop all of the account's; 1Password remains for installs without an account or
as a second copy; it is included and automatic for managed storage. Also decided (§3.1 item 2): the server is the hub
and holds the vault keys. Everything else here is a proposal; choices are under Open questions.

## Today

| Fact | Source |
|---|---|
| Linking makes an Ed25519 identity key sealed to this host (KeyProvider slot `cloud_identity`); `cloud_link` is one plain row with the cloud's numeric `account_id`, the installation id and the public key | `core/src/cloud/Identity.cpp`, `deploy/psql/134_cloud_link.sql` |
| Link, status and unlink are super-admin-only, never an agent, and `vh cloud link` and `unlink` are excluded from MCP | `core/src/ops/Cloud.cpp` (`require`), `docs/admin/mcp-and-agents.md` |
| A recovery recipient is a `vault_recovery_grant` row (class `customer` by CHECK, suite 1, X25519 public key, `authorized_by` = `user:<id> via cli` or `via device`); every retained and future key version gets a KEV1 envelope in the vault's bucket | `deploy/psql/127_recovery_recipients.sql`, `core/src/vault/RecoveryEnvelopes.cpp` |
| Adding a recipient needs the encryption-key Export permission, the CLI or a paired device, a vault-bound keys step-up; browser sessions get `recipient_requires_device`, agents are denied; local vaults are refused (no bucket) | `core/src/ops/RecoveryRecipients.cpp` |
| Cloud recovery enrollment is explicit per vault (super admin or Export, CLI or device, keys step-up, never an agent), sends every usable grant's envelopes read back from the bucket, and refuses vaults without a bucket | `core/src/ops/CloudRecovery.cpp`, `deploy/psql/135_cloud_recovery.sql` |
| Restore from the cloud is `vh vault recover --from-cloud`: a temporary key in memory, a restore code, D1 verification against the bucket | `core/src/ops/CloudRestore.cpp`, `design/cloud/server-link.md` |

## Fetching and pinning

**Fetch.** Right after a link is claimed, and then from the background cloud service (`CloudStorageService`,
`managed-remotes.md`, which hosts this check; daily, and on demand), the server signs `GET /v1/keys/account`
(`cloud::Client::signedCall`). The answer is the current key statement and the chain of earlier ones, in the format
of the cloud's `key-manager.md`. Never on FUSE, sync or ws hot paths: a failed fetch changes nothing and is retried.

**Verify.** Every statement must parse exactly (six lines, `vhc-account-key-v1`, canonical base64url, no trailing
data); `public_id` must equal the account the claim reported (a new `cloud_link.account_public_id` column: the cloud
now returns its public id, and the numeric id is internal to it); generations start at 1 and increase by one; each
statement is signed by its own Ed25519 key, and from generation 2 also by the previous generation's, whose
fingerprint it names. The fingerprint is computed here, never taken from the answer.

**Pin.** A verified statement the server has not pinned is stored as `pending`. It becomes `pinned` only when a
person confirms its fingerprint, because a self-signed chain can't tell the customer's key from a substitute the
cloud made, and a substitute would receive every vault key this server wraps:

- **At `vh cloud link`.** After `Linked`, the command prints the recovery key fingerprint (eight groups of four hex
  digits) and asks the super admin to compare it with the one Vaulthalla Desktop's Cloud section or the account page
  on vaulthalla.cloud shows, then to type it or `yes`. `--json` and `--finish` leave it `pending`; it is confirmed
  later with `vh cloud key confirm <fingerprint>`, which refuses a mismatch.
- **From Desktop.** A Desktop that holds the account key derives the fingerprint itself and offers "Use this
  account's recovery key on *nas*". It sends `cloud.key.confirm {fingerprint}` over its paired connection, so no
  digits are compared by eye. A device needs the keys step-up (`cloud.key.confirm`, #359).
- **In the console.** The fingerprint and its state are shown, read-only, with the two ways above. Confirming in a
  browser session is refused (`cloud_key_requires_device`), as adding a recipient is today.

**Where the pin lives: a sealed cloud configuration.** A new table `cloud_account_key` (the next free migration when
it lands; wave 1 lands spec 06's probe columns, then attach-remote, then these pin tables, then managed remotes)
holds one row per generation: `generation`, `fingerprint`, `x25519_public`,
`ed25519_public`, the statement and signatures, `state` (`pending`, `pinned`, `superseded`, `refused`),
`confirmed_by` (`user:<id> via cli|device`, or `chain:<generation>`), `confirmed_at`, and `mac`. The MAC is
HMAC-SHA-256 over the account public id and every other column, under a 32-byte key sealed in a new KeyProvider slot
`cloud_account_pin`, beside `cloud_identity`. A database writer can therefore not swap the pinned key: every wrap
checks the row's MAC first. The slot survives `vh cloud unlink`, so a server that links again to the same account
compares against its old pin instead of asking again; `vh cloud key forget` (super admin, CLI) destroys it.

**Rotation** (a generation signed by the pinned one). The service verifies the chain and accepts it with
`confirmed_by = chain:<n>`, no person needed. For every vault holding the old generation's grant it adds one for the
new key, wraps every retained version (`vault::envelopes::ensure`), and revokes the old grant once the new one covers
every needed version; the old row becomes `superseded`. Old envelopes stay in the bucket, which is harmless while the
old key is the customer's (open question 4).

**Replacement** (a new generation not signed by the pinned one: the cloud's `POST /v1/keys/account/replace`). The
server stores it as `refused`, keeps wrapping to the pinned key, reports health `cloud_account_key_change_pending`
and asks for a confirmation exactly like the first pin. Writes and rotations never wait for it.

**The server refuses:** a statement for another account; a broken or reordered chain; a generation lower than or
equal to the pinned one with different keys; any use of a `pending` or `refused` key; an X25519 key of the wrong
length or a low-order point; a confirmation through the console or an agent; and a row whose MAC fails, which is
also reported as health `cloud_account_key_tampered` and stops every automatic grant.

## The account key as a recovery recipient

The pinned key enters spec 03's model as an ordinary grant: class `customer`, suite 1, its X25519 public key,
label `Vaulthalla Cloud recovery key (generation n)`, `authorized_by` naming the confirmation it rests on
(`account_key:<n> confirmed by user:<id> via cli|device`, or `via chain:<n-1>`). One new nullable column,
`vault_recovery_grant.account_key_generation`, marks it; the CHECK on `class` is unchanged. Wrapping every existing
and new key version and writing envelopes to the bucket (`.vaulthalla/key/<kid>`, `If-None-Match: *`, listed in the
root's `recovery_policy`) are today's code paths; the one addition is that before wrapping to a grant with
`account_key_generation` set, `vault::envelopes::put` checks that its public key is the MAC-verified pinned key of
that generation, and skips it otherwise.

**When the server adds it on its own:** only to a vault becoming managed (spec 03 §5.5 as amended 2026-11-12), and
only to a `pinned` key. Managed vaults are created local and attached once their bucket exists (`managed-remotes.md`),
so the grant is added in the attach's `preparing` step and re-checked at cutover (`attach-remote.md` precondition
6). In this document "a managed vault is created" means that attach reaching `done`. Without a pin, the vault stays
`waiting` with `account_key_unconfirmed` (`managed-remotes.md` step 3) unless another customer recipient covers it.

**How that stays within "human-only".** Today a recipient is added only by a person, never an agent, never through
MCP, because a recipient is a decryption path. The automatic grant keeps that intent: the decryption path is chosen
once, by a super admin confirming the account key's fingerprint on this server (CLI or a paired device with step-up,
never an agent or MCP). The system then applies exactly that choice where D2 requires a recipient anyway. It never
picks a key, never grants a key nobody confirmed, never adds one to a BYOS or local vault, and an agent that creates
a managed vault chooses nothing about its recipients. Every automatic grant is audited with the confirmation it
rests on.

**BYOS and local vaults stay explicit.** `vh vault keys recipient add <vault> --account-key` (and
`vault.keys.recipients.add {vault_id, account_key: true}`) adds the pinned key with today's permission, channels
and step-up. Any other customer recipient (a kit, another admin) still works beside it.

## Enrolling with the cloud

**Managed vaults: automatic** (spec 05 §3.2 as amended 2026-11-12). `CloudStorageService` calls
`ops::cloud_recovery::enrollAutomatic(vault, reason)` when a vault's attach reaches `done` (`managed-remotes.md` step
6), after each committed rotation, and when `status` finds it `behind` or `missing`. It runs as `system:cloud`,
needs no step-up (no person is present; the authorization is the pin and the managed choice), and sends only the
envelopes of the account-key grant, read back from the bucket and checked against their records as
`bucketEnvelopes` does today. Vault creation and writes
never wait for it: D2 is met locally by the grant and the bucket's envelopes, and an unreachable cloud only leaves
the vault `behind`, reported in status and, after a day, as health `cloud_recovery_behind`. Status marks such a
vault `automatic`, and the console states it when a vault is switched on for managed storage or an offer accepted.

**BYOS and local vaults: explicit**, as today (super admin or Export, CLI or device, keys step-up, never an agent).
`vh cloud recovery enroll <vault> --account-key` adds the account-key grant and enrolls in one step, under one
step-up, still one person's decision per vault. They count against the cloud's free allowance.

## Local vaults

A local vault has no bucket, so today it can't hold envelopes or be enrolled. Proposed:

- **Where the envelopes live:** in the database, in a new nullable `vault_key_envelope.envelope BYTEA` filled for
  vaults without a bucket. `vault::envelopes::storeFor` returns a database-backed store for them, so `put`,
  `ensure`, rotation and salvage work unchanged, and `RecoveryRecipients::add` stops refusing local vaults.
- **How they reach the cloud:** the same `PUT /v1/recovery/vaults/{uid}` body; the server reads them from its rows
  and checks each as it checks bucket objects (kid, vault uid, version).
- **What they are for, stated plainly:** a lost `vault_master` on the same host (`vh vault keys import
  --recovery-kit`, or a cloud restore into the existing vault), and conversion to a remote, where attach-remote
  copies them into the new bucket before the vault flips. They don't recover a local vault whose disk is gone: the
  content was only on that disk.

## Scoped fetch, restore, and the private half

- **Scoped fetch.** The cloud's `GET /v1/keys/vaults/{uid}/envelopes` answers a server only for vaults its deployment
  replicates. The server never needs it to operate; `vh cloud recovery status --verify` uses it to compare the
  cloud's kids with its own records. Desktop and the portal are the readers that matter.
- **Restore onto a new server.** Link the new server and confirm the account key's fingerprint, then run
  `vh vault recover --from-cloud` exactly as today (`server-link.md`). The deliverer opens the account-key envelopes
  and re-wraps each version to the server's temporary key: **Vaulthalla Desktop** holding the key, or **the portal**
  in a browser that unlocked it (the cloud's `POST /v1/account/restores/{id}/deliver`; the portal's code is served by
  Valkyrian Labs, spec 05 §4 condition 5). The restore code is compared on both screens, D1 is verified against the
  bucket, nothing changes in the server's import. The restored root's account-key grant is kept as such only if its
  key equals this server's pin; otherwise it is kept as an ordinary customer grant and the admin is told.
- **The server never holds the private half.** No cloud route gives a server installation a wrap, and no server
  command accepts the account seed except as a recovery kit in a restore the customer runs (`--kit`, read by `vh`,
  never stored; spec 03 §6.4).

## 1Password and kits

Unchanged. Desktop's per-vault 1Password item and kit, `vh-recovery kit create` and `vh vault keys export` work as
today and coexist with the account key as separate grants; any one satisfies D2. The account key is itself a valid
kit seed (the cloud's `key-manager.md`), so Desktop's 1Password copy of it opens every vault wrapped to it with
`vh vault recover --kit`, with no cloud involved.

**The offline copy** (amended 2026-11-12; proposed in spec 05 §3.1, awaiting the maintainer). Managed onboarding is
complete only once an offline copy of the account key exists: Desktop's export of it as a recovery kit (1Password or
print; Desktop is the exporter), or the key recovery code if the cloud makes it work without the service. The server
can't see either, so it reads what the cloud records: the answer to `GET /v1/keys/account` carries the offline copies
known for the account (kind and date, never the copy), which the cloud's design has to add. With none recorded,
`vh cloud key status`, `cloud.key.status` and the console show `offline_copy: none` and the next step ("export the
recovery key from Vaulthalla Desktop"), and health reports `cloud_account_key_no_offline_copy` (info, only while a
managed vault exists). Nothing is blocked: running vaults keep running and syncing, and attaches proceed.

## Replicated vaults (wave 3): what `mirrors.md` needs from this design

- **A joining server confirms its own pin** before its join's restore request: linking server B follows "Pin"
  above, and B wraps nothing to an account key it hasn't pinned.
- **Handed-over grants.** The join is a restore (`ops::vault_recover`), and replicas apply each other's root grants
  (`mirrors.md`, "What the first version adds" item 4). An account-key grant arriving either way is kept as one
  (`account_key_generation` set) only if its public key equals B's own MAC-verified pin of that generation;
  otherwise it stays an ordinary customer grant and B's admin is told.
- **Rotation across replicas** uses per-replica keys, which are `mirrors.md`'s proposal (its open question 3) and
  kept outside `vault_recovery_grant`. The rotation owner wraps the new version to the account key like any recipient,
  so cloud coverage follows from the owner's automatic enrollment.

## Surfaces

| Operation | CLI | ws | Who | Channels |
|---|---|---|---|---|
| status | `vh cloud key status [--json]` | `cloud.key.status` | super admin or encryption-key View | any, agents included (public keys only) |
| confirm | `vh cloud key confirm <fingerprint>` (also inside `vh cloud link`) | `cloud.key.confirm {fingerprint}` | super admin | CLI, or a paired device with the keys step-up (Desktop, over its pinned device connection, deriving the fingerprint itself); console `cloud_key_requires_device`; agents denied |
| refresh | `vh cloud key refresh` | `cloud.key.refresh` | super admin | CLI, device, console |
| forget | `vh cloud key forget` | (none) | super admin | CLI only |
| add as recipient | `vh vault keys recipient add <vault> --account-key` | `vault.keys.recipients.add {…, account_key: true}` | as recipient add | as recipient add |
| enroll explicitly | `vh cloud recovery enroll <vault> --account-key` | (as today) | as enroll | as enroll |
| offline copy | (none: Desktop exports the kit; the server only shows `offline_copy` in status) | (in `cloud.key.status`) | as status | as status |

`cloud.key.confirm`, `cloud.key.forget`, recipient add and enroll are excluded from MCP and added to
`docs/admin/mcp-and-agents.md` when this ships. The ws commands sit behind a `meta.hello` capability
(`cloud.account_key`, beside `managed-remotes.md`'s `cloud.storage.managed_remotes`) and the console page behind it,
hidden until launch (`tools/contracts/encryption_claims.py`).

**Audit events:** `cloud.key.pending` (a verified generation stored; fingerprint), `cloud.key.confirm` (success or
denied on mismatch; by whom, channel), `cloud.key.chain` (a signed rotation accepted), `cloud.key.change_refused` (an
unsigned replacement seen), `cloud.key.forget`; `vault.recovery.recipient.add` and `.revoke` gain
`automatic: true` and `account_key_generation`; `cloud.recovery.enroll` gains `automatic: true` and the reason.
**Health:** `cloud_account_key_unconfirmed` (only while managed storage is enabled),
`cloud_account_key_change_pending`, `cloud_account_key_tampered`, `cloud_recovery_behind`,
`cloud_account_key_no_offline_copy`.

## Tests

- **vl-keykit vectors**, shared byte for byte with the cloud and Desktop (`KeykitVectors`): the key statement and
  fingerprint for generations 1 and 2; negatives (another `public_id`, an altered line, a missing previous signature,
  a previous fingerprint that doesn't match, a skipped generation, non-canonical base64url, a trailing newline); the
  vault label sealing (`vh.vault-label.v1`, the cloud's `account-model.md`).
- `AccountKeyPin.*`: verify, pending, confirm, mismatch refused, MAC tamper detected, another account refused,
  re-link compares against the old pin, `forget`.
- `AccountKeyRecipient.*`: default grant at the managed attach, every version wrapped before any content PUT, the
  vault `waiting` without a pin, last recipient not removable, a grant whose key isn't the pinned one is never
  wrapped to, a handed-over grant that doesn't match the pin kept as ordinary.
- `AccountKeyRotation.*`: chained rotation re-wraps and revokes; replacement waits for a person; writes never block.
- `CloudEnrollAutomatic.*` (fake cloud): only account-key envelopes sent; a down cloud blocks neither creation nor
  writes; BYOS and local vaults never enrolled automatically.
- `RecoveryNoSilentCustody.*` extended as spec 03 §8 now words it; `LocalVaultEnvelopes.*`; an MCP exclusion contract.
- The drill (`vhh drill recover`): lose a managed server, restore from the account key through a fake Desktop and a
  fake portal deliverer.

## Work items

Landing order (wave 1): spec 06's probe columns, attach-remote, items 2, 3 and 6, then managed remotes with 4 and 5.

1. **vl-keykit:** statement codec, fingerprint, chain check and vectors (and KAK1 and label sealing for the cloud and
   Desktop).
2. **Pin:** `cloud_link.account_public_id`, `cloud_account_key`, slot `cloud_account_pin`, fetch and verify, `vh
   cloud key …`, ws commands, audit, health.
3. **Recipient:** `account_key_generation`, the wrap guard, the default grant in the managed attach (with
   `attach-remote.md` and `managed-remotes.md`), `--account-key`.
4. **Automatic enrollment** in `CloudStorageService`, and the offline-copy status.
5. **Rotation and replacement.**
6. **Local vault envelopes**, recipients and enrollment.
7. **Drill** extension.

## Open questions

1. **Folding the fingerprint into the link code** (the cloud's `key-manager.md` open question 3): a
   password-authenticated exchange keyed by the link code, so one comparison covers both the server and the account
   key. *Recommendation: design it later; until then the confirmation is required before any automatic use, and
   Desktop's confirmation (no digits compared) is the default path, which keeps the per-server step to one click.*
2. **Confirming in the console** with a passkey step-up. *Recommendation: no, as for recipients; revisit with #361.*
3. **Who confirms:** super admins only, or also holders of the Export permission. *Recommendation: super admins,
   since one confirmation reaches every managed vault on the server.*
4. **Routine rotation and `rotation_needed`.** Revoking the old generation's grant raises `rotation_needed` on every
   vault today (`RecoveryGrants::revokedWithAccess`). *Recommendation: not for a chained rotation; only for a
   replacement the customer marks as a compromise, which then also asks every vault to rotate its key.*
5. **Automatic enrollment sends only account-key envelopes,** not the vault's other recipients'. *Recommendation:
   keep it so; the explicit enroll still sends all.*
6. **Local vault envelopes now or later.** *Recommendation: with attach-remote, which needs them to convert a local
   vault without a gap in coverage.*
7. **Whether attaches wait for an offline copy.** *Recommendation: no; holding back backups would leave data local.*
8. **Elsewhere:** unenrolling a managed vault and the offline-copy condition (spec 05 §3.1, §3.2); local-first
   managed vaults before their bucket exists (spec 03 §5.5).
