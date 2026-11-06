---
title: Secrets And Key Export
description: Export vault keys and internal secrets safely, and seed database or JWT secrets from operator-controlled files.
order: 250
status: published
tags:
  - secrets
  - keys
  - recovery
---

# Secrets And Key Export

Vaulthalla separates vault encryption keys from internal runtime secrets. Export both before storing critical data and whenever your recovery plan changes.

:::toc[On this page]{depth="3" theme="compact"}
:::

## What To Export

| Material | Command family | Why it matters |
| --- | --- | --- |
| Vault keys | `vh vault keys export` | Required to recover encrypted vault content outside the original TPM context. |
| Database password | `vh secret export db-password` | Required to reconnect services to an existing PostgreSQL database. |
| JWT secret | `vh secret export jwt-secret` | Required to preserve token/session behavior across recovery where applicable. |
| MFA seal | `vh secret export mfa-seal` | The key that seals TOTP authenticator seeds (base64). Exists once someone has enrolled a TOTP factor. Without it, TOTP factors stop working and must be reset; passkeys are unaffected. |
| MFA pepper | `vh secret export mfa-pepper` | The key that hashes recovery codes (base64). Exists once a recovery code batch has been generated. Without it, recovery codes stop working. |
| All internal secrets | `vh secret export all` | Convenient recovery bundle for internal non-vault secrets. |

## Export Vault Keys

Export all vault keys with GPG encryption:

```bash
vh vault keys export all \
  --recipient <gpg-fingerprint> \
  --output vaulthalla-vault-keys.json.gpg
```

Export a single vault:

```bash
vh vault keys export archive \
  --recipient <gpg-fingerprint> \
  --output archive-vault-key.json.gpg
```

If you omit `--recipient`, Vaulthalla warns and writes unencrypted JSON to the output file or stdout.

Vaulthalla records every export of a vault's current key version. Deleting a vault whose key was never exported warns you, and deleting an S3 vault that keeps encrypted objects in its bucket asks you to accept that the data cannot be decrypted without the key. A key rotation makes earlier exports stale: export again.

### Every Key Version A Vault Still Needs

An export carries every key version the vault still needs, not only the current one:

- **The outgoing key of an unfinished rotation.** `vh vault keys rotate` switches new writes to a new key at once, but the sync pass re-encrypts existing files gradually. Until it has finished, the previous key still decrypts the files it hasn't reached.
- **Retired keys that recovery data references.** A rotation re-encrypts a vault's live files, but never its recovery data: snapshots, local versions and provider object versions keep the key version they were sealed with. Vaulthalla keeps every retired key version sealed by the host, and refuses to delete one while recoverable data still references it.

Those versions are listed under `historical_keys`, in the same encoding as the current key, each with its [key check](#key-checks), its [attestation](#key-attestations) and the reason it is needed (`rotation` or `recovery`):

```json
{
    "vault_id": 12,
    "vault_name": "archive",
    "key": "<base64 current key>",
    "key_check": "3d1f…",
    "attestation": { "key_id": 1, "signature": "<base64>" },
    "key_info": { "key_version": 3, "key_check": "3d1f…", "attestation": { "...": "..." }, "...": "..." },
    "historical_keys": [
        { "key_version": 2, "key": "<base64>", "key_check": "9a07…", "attestation": { "...": "..." }, "reason": "rotation", "created_at": "...", "retired_at": "..." },
        { "key_version": 1, "key": "<base64>", "key_check": "c4e2…", "attestation": { "...": "..." }, "reason": "recovery", "created_at": "...", "retired_at": "..." }
    ]
}
```

`historical_keys` appears only when a vault needs more than its current key. If the vault needs a version it no longer holds, the export lists it under `missing_key_versions` instead of inventing a key.

An export is recorded against the current key version, so a rotation makes it stale. Export again after a rotation.

A deleted vault's key stays exportable with the same command (use the vault id) until `vaults.tpm_retention_window` ends: `90d` by default, `180d` for S3 vaults. See [Deleting And Restoring Vaults](/vaults/deleting-vaults). That export carries the versions the vault still needs as well. See [File Recovery](/vaults/recovery#keys-and-rotation).

## Check Key Backup Status

`vh vault keys status` shows, for every vault (or one), whether its key is backed up, without printing any key material:

```bash
vh vault keys status all
vh vault keys status archive --json
```

For each vault it reports the current key version with its key check and attestation, the last exported version and when (stale after a rotation), whether a rotation is under way, and every version the vault still needs with its key check, and the vault's last [salvage](#salvage-unverified-keys) if there was one. Deleted vaults whose key is still retained are included and marked. It needs the permission to view encryption keys, the same as `vh vault keys inspect`.

### Key Checks

A key check identifies one key version without revealing it, so you can verify that a backup holds the key the server uses: compute the check from the backed-up key and compare it with the server's.

```text
key_check = BLAKE2b-128(key = the 32 key bytes,
                        message = "vh-key-check-v1" ‖ vault_id ‖ UInt32BE(version))
```

The output is 16 bytes, written as 32 lowercase hex digits. `vault_id` is the vault's numeric id written as ASCII decimal (`42`), and the version is the last 4 bytes, big-endian. This is libsodium's `crypto_generichash` with a 16-byte output, or `hashlib.blake2b(message, digest_size=16, key=key)` in Python. Test vector: with the key bytes `00 01 02 … 1f`, vault 42 and version 3, the key check is `72e4c8b7f8ab43b8ed8869a57cef1703`.

A key check is a keyed hash of the key (a PRF output): it identifies the key version and reveals nothing usable about the key itself. The server records the key check of every key version it creates, and of older ones the next time it reads them.

### Key Attestations

Every export also carries, for each key version, the server's **attestation**: a signature by this server over the version's key check, proving the key is one this server created or held. It is what lets `vh vault keys import` restore the key later (see [Restore Vault Keys](#restore-vault-keys)). Like the key check it is public and reveals nothing about the key.

```text
attestation = Ed25519(server signing key,
                      "vh-key-attest-v1" ‖ node_id ‖ UInt64BE(vault_id) ‖ UInt32BE(version) ‖ key_check (16 bytes))
```

In the export it appears as `"attestation": {"key_id": 1, "signature": "<base64>"}` next to each `key_check`. `node_id` is this installation's id (the one paired devices record); `key_id` names which of the server's signing keys signed. The signing key is created on first use, sealed by the host (TPM2 or `swtpm` on Linux, the Secure Enclave on macOS), and never leaves it. If it can no longer be unsealed (for example after the TPM state was reset), the server creates a new one and keeps the public half of every old one, so attestations in older exports still verify. Test vector: signing seed `00 01 02 … 1f`, node id `00000000-0000-4000-8000-000000000001`, vault 42, version 3 and the key check above give the public key `03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8` and the signature `fbda258fa125ef4237a54b7cde732c073ba598fa4a1a782226aa82514ee5c36a3ad452e6d36593337dc1619e61391c6ae20685155b11cc2b6deaf637e893840c`.

Exports taken before attestations existed have none. Export your vault keys again after upgrading so every backup can be restored.

## Back Up Keys With Vaulthalla Desktop

A Mac paired with Vaulthalla Desktop can back vault keys up to 1Password over its paired connection. It reads the key status, exports the keys it needs, and confirms each backup by its key check after 1Password stored it; only then does the server record the vault as exported. A confirmation is refused when the vault rotated its key in the meantime, so a backup is never recorded for a key it doesn't hold.

Keys leave and enter the server only through the local `vh` CLI or a paired device. The web console never receives or sends key material, and AI agents (MCP) can read key status but never export or import keys. A paired device needs the same permission to export keys as the CLI.

## Export Internal Secrets

```bash
vh secret export all \
  --recipient <gpg-fingerprint> \
  --output vaulthalla-secrets.json.gpg
```

Single-secret examples:

```bash
vh secret export db-password --recipient <gpg-fingerprint> --output db-password.json.gpg
vh secret export jwt-secret --recipient <gpg-fingerprint> --output jwt-secret.json.gpg
```

When `--recipient` is used, provide `--output` so the encrypted result lands in a file.

## Seed Internal Secrets

Set the database password from a file:

```bash
vh secret set db-password /root/vaulthalla-db-password
```

Set the JWT secret from a file:

```bash
vh secret set jwt-secret /root/vaulthalla-jwt-secret
```

The CLI reads and trims the file contents. Protect the source file and remove temporary copies after use.

## Permissions

Key and secret exports require elevated Vaulthalla permissions. Super admins can export; other users need the appropriate encryption-key export permission.

Exports are audit-sensitive operations. Treat them as operational events, not routine casual diagnostics.

## How Secrets Are Sealed

Vaulthalla seals its master secrets to the machine: a TPM on Linux, the Secure Enclave on macOS. `vh status` and **Health › Runtime** show the backend and what actually protects it:

| Posture | Means |
| --- | --- |
| `hardware` | A hardware TPM or the Secure Enclave. The sealed files are useless on another machine. |
| `software` | swtpm, a software TPM. The files have no hardware binding, and anyone who can read the swtpm state and the sealed files can unseal them. |
| `development` | Plain files, for development only. |

For hosts that hold regulated data, require hardware sealing in `config.yaml`:

```yaml
secrets:
  require_hardware: true
```

With this setting, Vaulthalla refuses to seal or unseal anything unless a hardware TPM or the Secure Enclave protects it. The setting is read from `config.yaml` only; the console cannot change it.

On macOS, Vaulthalla refuses to start its sealing when the Secure Enclave can't be used (an Intel Mac without a T2 chip, or a daemon not running under launchd). Earlier versions silently fell back to plain files instead. A development machine may opt in to the file backend with `secrets.allow_development_file_backend: true`.

:::callout[A lost master secret is never replaced silently]{variant="warning"}
If the sealed master that protects vault keys, provider API keys, S3 gateway credentials or the internal secrets ([A Lost Host Master](#a-lost-host-master)) is missing while those records still exist, Vaulthalla refuses to create a new one, because a new one could never decrypt them. Inside a rotation's recovery window, the log names the rollback command that restores the rows from the previous master. The affected vaults don't start, and the log says why. Restore the state directory (with the same TPM or Secure Enclave), or import the vault key backups ([Restore Vault Keys](#restore-vault-keys)) and the internal secrets ([Seed Internal Secrets](#seed-internal-secrets)).
:::

### A Lost Host Master

The host master (`master`, `.sealed_master.blob` in the state directory) wraps the internal secrets: the JWT secret, the MFA keys that seal TOTP seeds and hash recovery codes, the share-link pepper and email provider credentials. When its sealed blob is missing while any of those (other than the JWT secret) are in the database, Vaulthalla refuses to start and names them in the log. That happens when the state directory is lost, or when a database is restored onto a new host.

First, restore the state directory with the blob, on the same TPM or Secure Enclave. Everything then opens again as it was.

If the old host master is gone for good, those secrets are gone with it. Give them up explicitly, with the daemon stopped:

```bash
sudo -u postgres psql vaulthalla <<'SQL'
BEGIN;
DELETE FROM internal_secrets WHERE key NOT IN ('jwt_secret', 'share.token.pepper.v1');
DELETE FROM totp_factors;    -- every TOTP factor is enrolled again
DELETE FROM recovery_codes;  -- every recovery code batch is issued again
COMMIT;
SQL
```

Then start Vaulthalla. It creates a new host master, and with it a new JWT secret (everyone signs in again), new MFA keys and a new share-link pepper. Users enroll TOTP and print recovery codes again, existing share links stop resolving (create or rotate the ones you still need), and email provider credentials have to be entered again. Vault keys are not affected: they have their own master and their own exports ([Restore Vault Keys](#restore-vault-keys)).

## Rotate The Vault Master

The vault master is the installation secret that wraps every vault key. Rotating it replaces that secret without re-encrypting a single file: only the wraps of the vault keys change, and the vault keys themselves stay the same. Rotation is for super admins, from a terminal; agents and the web console can't do it.

```bash
vh secret master status               # version, sealing, any rotation in progress or recovery window
sudo vh secret master rotate          # asks to confirm; --yes without a terminal
vh secret master rollback             # inside the recovery window: return to the previous master
vh secret master finalize             # end the recovery window now
```

What `rotate` does:

1. **Stage.** It seals a new master (`vault_master.v2`, `.v3`, ...) beside the current one, then writes the new wrap of every key row (live vaults, retired key versions, and the retained keys of deleted vaults) in batches. If it is interrupted (a crash, a restart, a power cut), run it again: it continues where it stopped. Nothing switches while staging, and every vault keeps working on the current master.
2. **Verify.** It unwraps every staged row under the new master and checks that it is the same key as under the current one, and that it matches the key's recorded [key check](#key-checks). Any mismatch stops the rotation before anything switches.
3. **Switch.** One step moves every row to the new master. Rows written while the rotation ran (a new vault, a key rotation) are rewrapped and verified in the same step.
4. **Recovery window.** The previous master and every row's previous wrap are kept for 7 days (`--window-hours` sets 1 hour to 90 days). Inside the window, `rollback` returns every key to the previous master. When the window ends, by itself or with `finalize`, every row is verified under the new master again, and only then is the previous master deleted.

A rotation refuses to start while a recovery window is still open, and when a key row doesn't unwrap under the current master (import that vault's keys first). Every step is recorded in the audit trail (`secrets.master.rotate`, `secrets.master.rollback`, `secrets.master.finalize`), refusals included.

:::callout[Database backups from before a rotation]{variant="warning"}
A database backup taken before a rotation holds key rows wrapped by the previous master. Once the window has ended and that master is deleted, such a backup restores only through the vault key exports ([Restore Vault Keys](#restore-vault-keys)). Export the vault keys (or let Vaulthalla Desktop back them up) before rotating, and take a fresh database backup after the window closes.
:::

### Recovery Window Drill

Practice this on a test host before you rely on it in production:

1. `vh vault keys status all`: every vault's needed versions have a confirmed backup.
2. `sudo vh secret master rotate`, then `vh secret master status` shows `recovery_window` and the date it ends.
3. Check that the vaults still read: open a few files, and run `vh status`.
4. Roll back: `vh secret master rollback`. Status shows the previous version again, and the files still read.
5. Rotate again and let the window run out, or `vh secret master finalize`. Status shows no rotation in progress.

If the new master is lost inside the window (a TPM reset, a damaged state directory), the vaults don't start and the log names `vh secret master rollback`: the rollback needs only the previous master and puts every key row back. If both masters are lost (a new host, or the whole TPM state), restore the vault keys from their exports onto the new host's master ([Restore Vault Keys](#restore-vault-keys)). The exports and the server's attestation records in the database are enough; the old host and its TPM are not needed.

## Rotate The API Key And S3 Gateway Masters

Two more installation masters work exactly like the vault master, with their own recovery window: the **API key master** (`ak_master`) wraps every provider API key's secret and Cloudflare provider token, and the **S3 gateway master** (`s3gw_master`) wraps every S3 gateway credential's secret. Rotating one replaces only the wrap: the secrets themselves don't change, nothing is sent to the providers, and S3 clients keep their access keys and secrets. Name the master with `--slot`:

```bash
vh secret master status --slot all                 # every master: version, sealing, rotation or window
sudo vh secret master rotate --slot api-keys       # asks to confirm; --yes without a terminal
vh secret master rollback --slot api-keys          # inside the window: return to the previous master
vh secret master finalize --slot s3-gateway        # end the S3 gateway master's window now
```

Staging, verification, the switch, the recovery window and its automatic end are the same as for the vault master: an interrupted rotation resumes when run again, every staged wrap is checked against the secret under the current master before anything switches, and a rollback inside the window needs only the previous master. A rotation refuses to start while a row doesn't unwrap: enter that API key's secret again in the console (or remove it with `vh api-key delete`), or revoke that gateway credential and issue a new one. The audit trail records each step as `secrets.master.*` with the `slot` it rotated.

:::callout[Database backups from before a rotation]{variant="warning"}
Once the window has ended and the previous master is deleted, the API keys in an older database backup have to be entered again, and its gateway credentials reissued. Neither is recoverable from the vault key exports: those only cover vault keys.
:::

## Rotate The JWT Secret

The JWT secret signs every session token. Rotate it when you suspect it leaked, or to sign everyone out at once:

```bash
sudo vh secret jwt rotate     # asks to confirm; --yes without a terminal
```

**Everyone signs in again.** In one database transaction a fresh secret replaces the old one and every stored refresh token is revoked, so no token signed before verifies again. Every open console connection is then closed. Paired devices reconnect by themselves with their device keys, and share-link visitors keep their share sessions (they aren't signed with the JWT secret). There is no rollback: the old secret is discarded. The rotation is recorded as `secrets.jwt.rotate`.

Only the JWT secret changes. The host master that wraps the internal secrets (the JWT secret, the MFA keys, the share-link pepper, email provider credentials) is not replaced, so TOTP factors, recovery codes and share links keep working.

## Rotate The Device Identity

The device listener's identity is the TLS key that every paired Vaulthalla Desktop pins. Rotate it when you suspect the key leaked:

```bash
sudo vh secret device-identity rotate     # asks to confirm; --yes without a terminal
```

**Every paired device pairs again.** The new key is sealed beside the old one and read back first. Then one database transaction records it and revokes every paired device: their pairing was bound to the old key, so none of them is ever trusted under the new one. Open pairing windows and requests in flight are dropped, every device connection is closed, the listener presents the new identity right away, and the old key is deleted. Each Desktop then reports that the node's identity changed and pairs again with a fresh key and a new pairing code ([Paired Devices](/admin/devices)). There is no rollback. The rotation is recorded as `secrets.device_identity.rotate` with the old and new key fingerprints.

If the rotation is interrupted before that transaction, nothing changed and the next start deletes the unused new key; after it, the new key is in effect and the next start writes its certificate if it is missing.

## Storage Rules

Use these rules for recovery material:

- Encrypt exports to an operator-controlled GPG recipient.
- Store exports outside the Vaulthalla host.
- Keep at least one offline or separately administered copy.
- Do not store key exports in the same bucket they protect unless additional independent encryption is applied.
- Document which export belongs to which Vaulthalla version and database backup.

## Restore Vault Keys

`vh vault keys import` is a **recovery mechanism**: it puts back key versions a vault already had, when this host can no longer use them. It cannot be used to set your own key or to add a key version: it restores only versions the server's own records show the vault had, proven by the server's [attestation](#key-attestations) in the export. Use it when:

- the host's master key was lost or replaced, for example after restoring the database onto a new host or reinstalling the TPM or `swtpm` state, so the vault's sealed keys no longer unseal and the vault can't start;
- the database was restored from a backup older than a key rotation, so a key version the vault's files still need is missing;
- a deleted vault that can still be restored (pending deletion).

The vault itself (its database records and its encrypted files on this host) must still exist. Restoring a vault from its encrypted files alone, after the database is lost, is not possible: file names, folders and the per-file encryption details live only in the database. Restore the database first, then import the keys.

```bash
vh vault keys import archive --file archive-keys.json
gpg --decrypt archive-keys.json.gpg | vh vault keys import archive --file - --confirm-name archive
```

`vh` reads the file on your side and sends its contents; the server never opens a path you name. Decrypt a GPG export first, ideally into a pipe as above so the keys never touch disk.

Each key version in the export gets one of these outcomes:

| Outcome | When |
| --- | --- |
| `restored` | The vault's records reference the version, and the export's attestation for it verifies as this server's signature over this vault, version and key (or the key matches one the server still holds). The key is re-sealed under this host's master key. |
| `unchanged` | The server already holds exactly this key. Nothing is written. |
| `needs_salvage` | The vault had this version, but nothing proves the key in the export is it: an export from before attestations, a signature by another server, or a key check that doesn't match the server's record. Nothing is written for it. |
| `refused` | The vault has no record of this version. An import never introduces a key version, and never moves the vault's current version. |

A key that this host can still unseal is never replaced: if the export holds different bytes for it, the whole import is refused (is the export from another node?). An export whose key doesn't match its own key check is damaged and refused as a whole. Restored keys are written in one step, the vault starts again, and a rotation that was under way continues.

### Salvage Unverified Keys

For versions answered `needs_salvage`, `--salvage` makes a best effort without ever trusting the supplied key:

```bash
vh vault keys import archive --file old-export.json --salvage
```

The server creates a fresh key of its own as the vault's next key version, then, for every file sealed under the unverified version, checks whether the supplied key decrypts it. Files it decrypts are re-encrypted under the fresh key (with the same crash-safe steps a key rotation uses; an interrupted salvage resumes when you run it again with the same key). Files it doesn't decrypt (damaged, or not this key's) are reported as unrecoverable. The supplied key is held in memory only for the pass and is never stored. Files whose only copy is in an S3 bucket are downloaded once through the vault's price budget and request limits; if the budget refuses, they are reported as skipped with the estimate, and running the salvage again later retries them.

Salvage asks you to type the vault's name, prints a report (files re-encrypted, unrecoverable, skipped, deferred because they were open for writing, failed) and records it in the audit log and in `vh vault keys status`. What it guarantees: every file it re-encrypted authenticated under the supplied key and is now under a key this server created; nothing it couldn't decrypt was changed; the supplied key is not kept. What it doesn't: files sealed under the version that didn't decrypt stay unreadable, and recovery data (snapshots, local versions, provider versions) sealed under that version stays unreadable. A deleted vault must be restored before it can be salvaged.

### A Vault Whose Key Is Missing

Vaulthalla never creates a new key for a vault that already holds encrypted data on its own: a new key could decrypt none of it. If a vault's key record is missing, its key doesn't unseal on this host, or a key version its files are sealed under is gone (for example after restoring an older database), the vault does not start. `vh status` reports degraded and names the vault, the console's health turns degraded, `vh vault keys status` shows the key as unavailable with the reason (`key_missing`, `key_unsealable` or `version_missing`), and the daemon log says which command restores it. Import the keys and the vault starts again (or salvage them, which starts it on a fresh key). A new or empty vault still gets its first key automatically.

Writing asks you to type the vault's name; without a terminal, pass it with `--confirm-name`. The import needs the same permission as export. A Mac paired with Vaulthalla Desktop restores keys from 1Password the same way over its paired connection. Neither the web console nor AI agents can import keys.

Test the restore path before relying on it: keep database backups, Vaulthalla state, TPM or `swtpm` state (Linux), and encrypted key exports together as a recovery set.
