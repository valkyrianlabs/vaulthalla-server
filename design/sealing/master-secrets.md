# Master secrets: sealing posture, fail-closed rules, rotation (#326)

Status: design note, approved direction (maintainer decision on #326, 2026-11-05). Part 1 ships with this note.
Principle: **installation master keys protect a host; vault keys protect a customer's files.** Recovery must not
depend on preserving the original host or its TPM.

## 1. Inventory: every sealed slot and what depends on it

| Slot | Wraps / is | Dependents in the database | If the sealed blob is lost | Regenerate? |
| --- | --- | --- | --- | --- |
| `vault_master` | every vault key version | `vault_keys`, `vault_keys_trashed`, `vault_deletion_key` | every wrapped vault key is undecryptable; recover by importing per-vault key backups (Desktop/1Password, `vh vault keys export`) under a new master | **never** while dependents exist (`MasterSecretLost`) |
| `ak_master` | provider API key secrets | `api_keys.encrypted_secret_access_key` | upstream credentials unreadable; re-enter them | **never** while dependents exist |
| `s3gw_master` | S3 gateway credential secrets | `s3_gateway_credentials.encrypted_secret_access_key` | gateway credentials unusable; reissue them | **never** while dependents exist |
| `master` | `internal_secrets`: the JWT signing secret, `mfa_seal`, `mfa_pepper`, the share-token pepper, email provider credentials | `internal_secrets` rows other than `jwt_secret` (and the plaintext pre-#322 pepper) | the daemon refuses to start (`MasterSecretLost`, #393): restore the state directory, or give the listed secrets up explicitly (docs: A Lost Host Master); the JWT secret alone regenerates | **never** while dependents exist (`initGuarded`, #393); the JWT secret inside it: yes, `vh secret jwt rotate` (#353) |
| `key_attest` | the Ed25519 attestation seed | public keys stay in `key_attestation_keys` | new key; old attestations and signed audit heads still verify | yes (by design) |
| `device_tls` | the device-listener identity (versioned since #353: `device_tls.vN`) | pairings pin its SPKI | paired devices see a new identity and must re-pair | yes (devices fail closed); `vh secret device-identity rotate` also revokes every paired device (#353) |
| `psql` | the PostgreSQL password | none | set again from the installer / `vh secret set db-password` | from the installer only |
| `share.token.pepper.sealed.v1` | the share-token pepper (#322) | share links | existing links stop resolving | migration-managed (#322) |

Backups are separate on purpose:
- Vault-content recovery uses the independently exportable per-vault key versions and their attestations, resealed under a **new** installation master.
- `vh secret export` (GPG-encrypted, operator-run) is the separate route for the internal secrets.
- Neither preserves sessions, upstream credentials or the server's device identity, and the docs must not imply that they do.
- `vault_master` is never synced or exported automatically, to 1Password or anywhere else.

## 2. Part 1 (this change)

1. **Never silently regenerate.** `KeyProvider::initGuarded(dependents)` is used for `vault_master`, `ak_master` and `s3gw_master`, and since #393 for `master` too (`dependents::internalSecrets()`: every `internal_secrets` row but `jwt_secret` and the plaintext pre-#322 pepper).
   - With no sealed blob to unseal and dependent rows present, it throws `MasterSecretLost`. The message names the slot, the count, and the three ways back: restore the state directory with its TPM, import the vault key backups, or use `vh secret`.
   - Before this change, `init()` generated a fresh secret and every existing key became undecryptable without a word.
   - The import path (`ops::vault_keys` seal) deliberately stays unguarded. Importing backups under a new master is the approved recovery route, and it makes nothing readable become unreadable.
2. **macOS fails closed.**
   - Without a usable Secure Enclave, the daemon refuses to seal or unseal; `backend` reports `unavailable`.
   - The plain-file backend is used only when chosen explicitly: by the build (`-Ddarwin_sealer=file`) or by `secrets.allow_development_file_backend: true` in config.yaml, which is documented as development-only.
   - Existing file-sealed secrets are not touched. A Mac that gains a Secure Enclave context still migrates them on first unseal.
3. **Posture is observable.** Health (`deps.secrets_posture`), `vh status` and the console show the posture:
   - `hardware`: a TPM device or the Secure Enclave;
   - `software`: swtpm, with no hardware binding (its state on disk is effectively the key);
   - `development`: files;
   - `unknown`: an explicit TCTI override.
4. **Protected deployments: `secrets.require_hardware: true`.** Every seal and unseal refuses unless the posture is `hardware`. It is read from config.yaml only, never from the console, so a console session cannot weaken it.

## 3. Threat model by posture

| Posture | Defends against | Does not defend against |
| --- | --- | --- |
| hardware TPM, no PCR policy (today) | copying the state directory or disk to another machine | root on this host (it can ask the TPM to unseal); an attacker who boots this machine into another OS |
| hardware TPM + PCR 7 (opt-in, part 3) | the above, plus booting another OS or a modified Secure Boot configuration on this machine | root on the running, legitimately booted host; firmware updates that change PCR 7 (see part 3) |
| Secure Enclave | copying the state off the Mac; processes outside the daemon's launchd context | root on the running Mac acting as the daemon |
| swtpm (software) | casual reads of the sealed blobs alone | anyone who can read both the swtpm state and the blobs, which includes disk theft and backups of the whole disk |
| files (development) | nothing beyond file permissions | anyone who can read the files |

## 4. Part 2: memory hygiene (`SecretKey` for masters)

Status: implemented (#350). `SecretKey` is fixed at 32 bytes for vault keys, while the provider's slots include the DB
password and other variable-length values, so `KeyProvider` uses `crypto::SecretBytes`, its variable-length sibling with
the same lock-and-wipe behavior (`crypto/SecretBytes.hpp`, which also holds `WipedKeyCopy`).

- `KeyProvider` holds the master in a `crypto::SecretKey` (locked, zeroized on destruction) instead of a `std::vector`. `getMasterKey()` returns a `std::span<const uint8_t>`.
- Callers that copy it into vectors (`encrypt_aes256_gcm(..., master, ...)`, `Retention::retainedKey`, `EncryptionManager::mintSalvageKey`, `APIKeyManager`, `CredentialManager`) take spans, so no long-lived aliases remain.
- Short-lived copies made by dependent APIs are wrapped in `WipedKeyCopy`.
- Tests:
  - the provider's buffer is zero after destruction (a test hook);
  - error paths (throw mid-unseal) leave no copy (an ASan/UBSan run on dev);
  - `getMasterKey()` callers compile only with spans.

## 5. Part 3: PCR 7 policy (opt-in, never silent)

- `secrets.tpm_pcr_policy: none | pcr7` (default `none`) applies only when an operator reseals explicitly: `sudo vh secret reseal --pcr7`. Existing blobs are never rebound behind the operator's back.
- `vh secret reseal --pcr7` refuses unless:
  - every vault's current and historical key versions have a confirmed backup (`vault.keys.status`);
  - a `vh secret export` was taken in the last 24 hours;
  - a hardware TPM is present.
- The reseal is staged and verified: write the new blob beside the old, unseal it, compare, then rename.
- The firmware-update hazard: a firmware or Secure Boot change alters PCR 7, and unseal fails until the secrets are restored from the exports.
  - The docs give the recovery drill: export, update, then import, or `vh secret reseal --pcr7` before rebooting into new firmware.
  - Health turns `warning` when the posture is PCR-bound and no export is newer than 30 days.

## 6. Part 4: versioned master-key rewrap (`vault_master` first)

Status: parts 4a (#352) and 4b (#353, §6.5) implemented: migrations 121 and 124, the registry
(`crypto/secrets/Versioned.hpp`; `vault/Master.hpp` is its vault_master view), the engine
(`crypto/secrets/Rewrap.hpp`; `vault/MasterRewrap.hpp`), `ops::master_secrets` and `vh secret master
status|rotate|finalize|rollback [--slot ...]`. As built for 4a (the state now lives in `master_secret_state`):
- The state is the singleton `vault_master_state` (`version`, `staging_version`, `previous_version`, `window_until`,
  `highest_version` so numbers are never reused, `discard_versions` for slot deletions a crash interrupted). Every key
  row carries `master_version`; unwraps use the row's version, wraps happen inside a `vault::master::Writer` (the
  switch waits for every Writer), and trigger `vh_vault_master_guard` refuses a row that declares another master.
- A write that changes a row's wrapped bytes (a key rotation, an import) drops its staged and retained wraps; the
  switch stages such rows inside its own locked transaction, and a rollback rewraps them under the previous master.
- Rotation refuses a row that doesn't unwrap under the current master (import its keys first) and a second rotation
  while a window is open. Rollback while staging abandons the staging.
- Accepted consequence: a database backup from before a rotation needs the previous master; once the window ends,
  it restores only through the vault key exports (documented, and named in the rotate confirmation).

Goal: replace `vault_master` without re-encrypting any file body.

1. **Stage.** Generate the new master and seal it as `vault_master.v<N+1>` beside the current one. For every dependent row (`vault_keys`, `vault_keys_trashed`, `vault_deletion_key`), write the new wrap into staging columns (`encrypted_key_next`, `iv_next`, `master_version_next`) in batched transactions, which can resume after a crash.
2. **Verify.** Unwrap every staged row under the new master and compare its key check with the row's recorded key check (migration 113). Any mismatch aborts before anything switches.
3. **Switch.** One transaction swaps the staged columns into place and records `vault_master_version = N+1`. The daemon loads the master by version, so a crash on either side of the commit is consistent.
4. **Recovery window.** The old sealed blob stays for a bounded window (default 7 days; `vh secret master finalize` ends it sooner). Rollback within the window reverses the switch from a retained copy of the old columns. After the window both the old blob and the old columns are deleted, verified first.
5. **Other slots.** `ak_master` and `s3gw_master` use the same machinery over their own tables. `master` (JWT) and `device_tls` rotate by regeneration, with explicit consequences: everyone signs in again, and devices re-pair. Each is its own command with its own warning.

### 6.5 Part 4b as built (#353, migration 124)

- **One registry, one engine.** `crypto/secrets/Versioned.hpp` holds every data-wrapping master by version (slot ids
  `vault_master`, `ak_master`, `s3gw_master`; v1 the original sealed name, vN `<slot>.vN`), and
  `crypto/secrets/Rewrap.hpp` is the #352 engine taking the slot. Each slot names its tables, key columns and wrapped
  fields: `api_keys` has two (the S3 secret, and the provider token, which may be NULL and is NULL in every form);
  `s3_gateway_credentials` one. Verification compares every field under the new master with the field under the current
  one; vault keys also compare the key check. `vault_master_state` moved into `master_secret_state` (one row per slot).
  Guard triggers on both tables refuse a write that declares another master and drop staged/retained wraps when the
  wrapped bytes change; the rewrap's own transactions are exempt for their slot only (`vh.master_rewrap`).
- **Consumers.** `APIKeyManager` and `s3::CredentialManager` unwrap each row under the version it names and write
  inside a `Writer` (the switch waits for it), declaring `master_version`. Every window ends from the retention loop.
- **Accepted consequence.** After a window ends, a database backup from before the rotation needs its API keys entered
  again and its gateway credentials reissued: unlike vault keys, these have no per-row export (they are re-creatable at
  the provider and the gateway). Named in the confirmation, the docs and the release note.
- **JWT (`vh secret jwt rotate`).** Not the `master` slot: it wraps the MFA keys and the share pepper, which can't be
  regenerated (§1). Only the `jwt_secret` row changes: one transaction stores a fresh secret and revokes every refresh
  token; then every live session (web, device and share sockets) is invalidated and closed and the cached refresh
  validations dropped. Share sessions are not JWT-signed and stay. No rollback.
- **Device identity (`vh secret device-identity rotate`).** Versioned like the masters (state row `device_tls`, only
  `version`/`highest_version`/`discard_versions`), so a crash never leaves a half-written key in the loaded slot. The
  new key is sealed as the next version and read back; one transaction then revokes every paired device and switches;
  the certificate is written and the old key deleted (a crash before the switch: the next start deletes the unused
  key; after it: the next start reissues the certificate). Pairing windows and requests are dropped, the listener
  swaps its TLS context for new connections and every device connection is closed. No device is trusted under the new
  key without pairing again (pairing always uses a fresh device key). No rollback.

| Slot | Crash point | State after | Recovery |
| --- | --- | --- | --- |
| ak_master / s3gw_master | staging recorded, sealed, any batch, verified | still on vN, rows unchanged | rerun `rotate --slot ...` resumes |
| ak_master / s3gw_master | switched (committed) | on vN+1, window open, `*_prev` kept | `rollback` / `finalize` / expiry |
| ak_master / s3gw_master | finalize or rollback committed, slot not yet deleted | consistent, slot in `discard_versions` | next finalize / retention pass deletes it |
| ak_master / s3gw_master | new master lost inside the window | `MasterSecretLost` naming `rollback --slot ...`; finalize refused | `rollback --slot ...` from the retained wraps |
| JWT | before the transaction commits | old secret, sessions valid | rerun |
| JWT | after the commit, before the sessions close | new secret; every stored refresh token revoked, every old token fails its signature | a crash restarts the daemon, which drops every socket; a failure is audited, and a rerun ends the sessions |
| device_tls | after sealing, before the switch | old identity, no device revoked | next start deletes the unused key; rerun |
| device_tls | after the switch, before the certificate | new identity, every device revoked | next start reissues the certificate |

Tests before rollout:
- interrupted staging, at every batch boundary and between verify and switch;
- an old/new master mismatch;
- TPM loss mid-window;
- restore on a new host from the database, the vault-key exports and the attestation public records;
- live, retired and deleted vault keys;
- explicit rollback inside the window.

## 7. swtpm state encryption: the one open decision

Encrypting the swtpm state (`swtpm --key`) protects only if the key is not stored beside the state. On a host without a hardware TPM there is no local place that is independent of the disk: `systemd-creds` without a TPM keeps its host key on the same disk.

Options:
- **(A) Recommended.** Protected deployments require hardware (`secrets.require_hardware: true`). swtpm stays a homelab and development backend, reported as `software`, never as sealing.
- **(B)** An operator-supplied key at boot (a passphrase or a key file on removable media through `systemd-ask-password`). This breaks unattended restarts, and the daemon blocks until it is unlocked.
- **(C)** A key fetched from an external KMS. This adds a network dependency and a custody question for whoever runs the KMS.

Recommendation: (A) now. (B) as an opt-in later if a customer needs software-only hosts.

## 8. Implementation issues (to open)

1. Part 2: `SecretKey` for master secrets (#350, done).
2. Part 3: PCR 7 opt-in with reseal, health warning and drill docs.
3. Part 4a: versioned rewrap engine with staging columns and the `vault_master` rotation command (#352, done).
4. Part 4b: `ak_master` and `s3gw_master` rewrap, and JWT and device-identity rotation commands (#353, done).
5. swtpm state key, if option (B) is chosen.
