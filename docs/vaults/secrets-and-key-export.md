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

Those versions are listed under `historical_keys`, in the same encoding as the current key, each with its [key check](#key-checks) and the reason it is needed (`rotation` or `recovery`):

```json
{
    "vault_id": 12,
    "vault_name": "archive",
    "key": "<base64 current key>",
    "key_check": "3d1f…",
    "key_info": { "key_version": 3, "key_check": "3d1f…", "...": "..." },
    "historical_keys": [
        { "key_version": 2, "key": "<base64>", "key_check": "9a07…", "reason": "rotation", "created_at": "...", "retired_at": "..." },
        { "key_version": 1, "key": "<base64>", "key_check": "c4e2…", "reason": "recovery", "created_at": "...", "retired_at": "..." }
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

For each vault it reports the current key version and its key check, the last exported version and when (stale after a rotation), whether a rotation is under way, and every version the vault still needs with its key check. Deleted vaults whose key is still retained are included and marked. It needs the permission to view encryption keys, the same as `vh vault keys inspect`.

### Key Checks

A key check identifies one key version without revealing it, so you can verify that a backup holds the key the server uses: compute the check from the backed-up key and compare it with the server's.

```text
key_check = BLAKE2b-128(key = the 32 key bytes,
                        message = "vh-key-check-v1" ‖ vault_id ‖ UInt32BE(version))
```

The output is 16 bytes, written as 32 lowercase hex digits. `vault_id` is the vault's numeric id written as ASCII decimal (`42`), and the version is the last 4 bytes, big-endian. This is libsodium's `crypto_generichash` with a 16-byte output, or `hashlib.blake2b(message, digest_size=16, key=key)` in Python. Test vector: with the key bytes `00 01 02 … 1f`, vault 42 and version 3, the key check is `72e4c8b7f8ab43b8ed8869a57cef1703`.

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

## Storage Rules

Use these rules for recovery material:

- Encrypt exports to an operator-controlled GPG recipient.
- Store exports outside the Vaulthalla host.
- Keep at least one offline or separately administered copy.
- Do not store key exports in the same bucket they protect unless additional independent encryption is applied.
- Document which export belongs to which Vaulthalla version and database backup.

## Restore Vault Keys

`vh vault keys import` puts a vault's keys back from an export (or a Vaulthalla Desktop backup) when this host can no longer use them:

- the host's master key was lost or replaced, for example after restoring the database onto a new host or reinstalling the TPM or `swtpm` state, so the vault's sealed keys no longer unseal and the vault can't start;
- the database was restored from a backup older than a key rotation, so a key version the vault's files still need is missing;
- a deleted vault that can still be restored (pending deletion).

The vault itself (its database records and its encrypted files on this host) must still exist. Restoring a vault from its encrypted files alone, after the database is lost, is not possible: file names, folders and the per-file encryption details live only in the database. Restore the database first, then import the keys.

```bash
vh vault keys import archive --file archive-keys.json
gpg --decrypt archive-keys.json.gpg | vh vault keys import archive --file - --confirm-name archive
```

`vh` reads the file on your side and sends its contents; the server never opens a path you name. Decrypt a GPG export first, ideally into a pipe as above so the keys never touch disk.

Before anything is written, every key version in the export is verified:

1. When the export carries a [key check](#key-checks) for the version, the key must match it.
2. The key must decrypt this vault's data: Vaulthalla authenticates a sample of the vault's files sealed under that version (all of them when there are few) with the key. A key that decrypts none of them is refused, and nothing is written.
3. A version with nothing on this host sealed under it can't be verified and is skipped.

A key that this host can still unseal is never replaced: if the export holds different bytes for it, the import is refused (is the export from another node?). Importing a key the host already holds unchanged does nothing. Verified keys are re-sealed under this host's master key in one step, and the vault starts again. A rotation that was under way continues.

Writing asks you to type the vault's name; without a terminal, pass it with `--confirm-name`. The import needs the same permission as export. A Mac paired with Vaulthalla Desktop restores keys from 1Password the same way over its paired connection. Neither the web console nor AI agents can import keys.

Test the restore path before relying on it: keep database backups, Vaulthalla state, TPM or `swtpm` state, and encrypted key exports together as a recovery set.
