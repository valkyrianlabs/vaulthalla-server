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

### Retired Keys For Recovery Data

A key rotation re-encrypts a vault's live files, but never its recovery data: snapshots, local versions and provider object versions keep the key version they were sealed with. Vaulthalla keeps every retired key version sealed by the host, and refuses to delete one while recoverable data still references it.

An export therefore also carries the retired key versions that recoverable data still needs, under `historical_keys`, in the same encoding as the current key:

```json
{
    "vault_id": 12,
    "vault_name": "archive",
    "key": "<base64 current key>",
    "key_info": { "key_version": 3, "...": "..." },
    "historical_keys": [
        { "key_version": 1, "key": "<base64>", "created_at": "...", "retired_at": "..." }
    ]
}
```

The existing fields don't change. `historical_keys` appears only when recoverable data references a retired version; a vault without recovery data exports exactly as before. If recovery data references a version the vault no longer holds, the export lists it under `missing_key_versions` instead of inventing a key.

An export is recorded against the current key version, so a rotation still makes it stale. Export again after a rotation: the new export carries the current key, and the retired one under `historical_keys` while recovery data needs it.

A deleted vault's key stays exportable with the same command (use the vault id) until `vaults.tpm_retention_window` ends: `90d` by default, `180d` for S3 vaults. See [Deleting And Restoring Vaults](/vaults/deleting-vaults).

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

## Import Boundary

The current operator-facing CLI documents export and rotation flows. Do not assume a one-command vault-key import workflow exists for disaster recovery. Keep database backups, Vaulthalla state, TPM or `swtpm` state, and encrypted exports together as a recovery set, and test the restore path before relying on it.
