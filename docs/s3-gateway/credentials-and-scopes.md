---
title: S3 Gateway Credentials And Scopes
description: Manage inbound gateway credentials, effective principals, vault roles, and path overrides for downstream S3 clients.
order: 30
status: published
tags:
  - s3-gateway
  - credentials
  - scopes
  - access-control
---

# S3 Gateway Credentials And Scopes

Gateway credentials are inbound downstream S3 credentials issued by Vaulthalla. They are not upstream provider credentials and should not reuse AWS, Cloudflare R2, or other provider keys.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Credential Types

| Credential | Used by | Purpose |
| --- | --- | --- |
| Gateway credential | Downstream S3 clients -> Vaulthalla | Authenticate AWS CLI, rclone, MinIO mc, SDKs, and apps to S3 Gateway. |
| Upstream provider credential | Vaulthalla -> upstream provider | Let Vaulthalla access an upstream S3/R2 bucket for an S3/R2 vault. Created with `vh api-key`. |

The gateway secret access key is shown only when created. It is encrypted at rest and later used by Vaulthalla for SigV4 verification.

## Scope Modes

Gateway credentials authenticate as an effective Vaulthalla principal user. The principal user's normal RBAC is always the ceiling. For role-based gateway credentials, the key-level default vault role is the aperture, per-vault roles are exceptions, key-level overrides apply broadly, and per-vault overrides apply narrowly.

```text
allowed = principal RBAC allows the action
          and scope-mode rules allow the bucket/vault/path/action
          and gateway budget preflight allows estimated cost
```

| Scope | Behavior |
| --- | --- |
| `user_access` | Personal-key mode. No gateway vault role, default role, or selected vault list is configured. After the principal user's normal RBAC allows an action, the credential may proceed, still subject to enabled state, expiry, budgets, and credential identity. |
| `vault_allowlist` | App/service-key mode. Requires a key-level default vault role and selected vaults. The default role and key-level overrides apply to every selected vault. Optional per-vault role assignments and per-vault overrides replace or narrow behavior for one selected vault. |
| `global` | Admin/service-key mode. Requires an admin/service principal and a key-level default vault role. The default role applies across gateway bucket bindings. Optional per-vault role assignments and overrides handle exceptions. Principal RBAC remains the ceiling. |

:::callout[Secure default]{theme="warning"}
For `vault_allowlist` and `global`, credentials without an enabled default vault role are denied even when the principal user has normal vault access. For `vault_allowlist`, a vault must also be selected. For `user_access`, the principal's Vaulthalla RBAC is enough and no gateway role row is expected.
:::

## Vault Roles And Overrides

Each role-based gateway credential has one default vault role. The role uses the same filesystem permission model as ordinary Vaulthalla vault roles. Optional default/key-level overrides apply to every selected vault for `vault_allowlist` and every gateway bucket binding for `global`.

Per-vault role assignments are optional exceptions. If a selected or globally bound vault has an enabled per-vault assignment, that role replaces the key default role for that vault. Per-vault overrides apply after key-level overrides; when the same permission and glob appear in both places, the per-vault override wins.

| S3 action | RBAC-style permission gate |
| --- | --- |
| List buckets, head bucket, list objects | Vault list permission on the bucket root or requested prefix. |
| HEAD/GET object and copy source | Vault read permission on the object path. |
| PUT, copy destination, multipart write/complete | Vault write or overwrite permission on the object path. |
| Delete object and multi-delete | Vault delete permission on each object path. |

Deny overrides win according to the filesystem policy evaluator. The principal user's normal RBAC is always evaluated separately, so a gateway key role cannot widen the user's own Vaulthalla authority.

## Principal Assignment

Non-admin users can create gateway credentials only for themselves. Creating or updating a credential whose principal differs from the actor requires the explicit `admin.s3_gateway.assign_principal` permission; super-admins have it through the built-in full S3 Gateway permission set.

## CLI Examples

Create credentials:

```bash
# Personal full-access key, bounded by the user's normal vault permissions.
vh s3-gateway creds create laptop --scope user-access --json

# Single-bucket backup key. The default role applies to the selected vault.
vh s3-gateway creds create backup \
  --scope vault-allowlist \
  --default-role contributor \
  --selected-vault archive \
  --json

# Multi-vault read-only analytics key.
vh s3-gateway creds create analytics \
  --scope vault-allowlist \
  --default-role reader \
  --selected-vault photos \
  --selected-vault reports \
  --json

# Global admin service key. Requires admin permission and a default role.
vh s3-gateway creds create gateway-ops --scope global --user admin --default-role reader --json
```

Inspect, update, and revoke:

```bash
vh s3-gateway creds list
vh s3-gateway creds scope backup show
vh s3-gateway creds scope backup set --scope vault-allowlist
vh s3-gateway creds scope backup allow-vault archive --read --write
vh s3-gateway creds scope backup revoke-vault archive
vh s3-gateway creds revoke VH...
```

Shorthand grants always include listing and reading; `--write`, `--delete` and `--admin` add to them. Only admins can grant `--admin` (role administration), and a grant never exceeds what the principal can already do on that vault. Naming vaults without `--scope` creates a vault-allowlist credential. Asking for `--scope user-access` while naming vaults is refused, not silently changed. `revoke-vault` removes both the vault selection and any per-vault role.

The `allow-vault` shorthand and boolean create flags are compatibility paths. At save time, Vaulthalla converts them into selected vaults, a default role when it can infer one, and per-vault role exceptions only when needed. New automation should use the default-role and selected-vault model, with `creds role assign` only for per-vault exceptions.

Assign per-vault role exceptions and path overrides:

```bash
vh s3-gateway creds role assign backup --vault archive --role reader
vh s3-gateway creds role list backup
vh s3-gateway creds role override add backup \
  --vault archive \
  --pattern "/exports/private/*" \
  --permission download \
  --effect deny
vh s3-gateway creds role override list backup --vault archive
vh s3-gateway creds role override remove backup --vault archive 42
vh s3-gateway creds role revoke backup --vault archive
```

Overrides need both `--effect allow|deny` and `--pattern` (or `--path`); there is no default that grants everything. Revoking a role or removing an override that doesn't exist is an error. A vault named without `--owner` must be your own, or the only vault with that name; an ambiguous name is refused.

The role commands write `s3_gateway_credential_vault_role_assignment` and `s3_gateway_credential_vault_role_override` rows directly. They are exception tools, not the primary selected-vault list. Boolean create flags and `creds scope allow-vault` are CLI/API shorthand that writes the selected-vault, default-role, and per-vault exception tables.

Local/cache budget accounting is off by default. Enable it only when a gateway credential should consume key budgets for pure local buckets, metadata-only requests, cache hits, and sync-deferred local-first writes/deletes:

```bash
vh s3-gateway creds create backup --enforce-budget-for-local-requests
vh s3-gateway creds scope backup set --enforce-budget-for-local-requests
vh s3-gateway creds scope backup set --no-enforce-budget-for-local-requests
```

## What A Credential's CreateBucket Creates

By default a bucket an S3 client creates with a gateway credential is a local vault. A credential can instead create its buckets in a provider account, through an [upstream profile](/s3-gateway/buckets#upstream-profiles):

```bash
vh s3-gateway creds scope backup set --upstream vl-b2            # an upstream profile
vh s3-gateway creds scope backup set --upstream server-default   # the server's default profile
vh s3-gateway creds scope backup set --upstream local            # local vaults again
vh s3-gateway creds scope backup set --allow-upstream r2-edge    # a profile its client may also select, by region
vh s3-gateway creds scope backup set --reapply off               # its buckets keep their sync settings when the profile changes
vh s3-gateway creds scope backup show
vh s3-gateway creds scope backup show --json
```

`show` reports the setting under `new buckets`, and under `upstream` with `--json`: the source (`local`, `profile` or `server_default`), the profile with its provider credential, encryption, sync strategy, conflict policy and bucket prefix, whether the credential's buckets follow later changes of the profile, and the allowlist (`may also select`, `allowed_profiles`): the other profiles a client may [name per request](/s3-gateway/buckets#selecting-a-profile-per-request). A profile that is neither the credential's own nor on its allowlist is out of its reach.

These settings can let a credential create buckets, and so spend, on a provider account. Giving a credential a profile, as its own or on its allowlist, needs management of the credential plus `admin.upstream.provision` and permission to use the profile's provider credential, both for the person making the change and for the credential's principal. Going back to `local`, shortening the allowlist, and `--reapply`, need only management of the credential.

## Web Console Workflow

In the console's **S3 gateway** page:

1. Open the credentials section.
2. Create a credential and choose the effective principal, description, expiry, and scope mode.
3. Copy the secret access key immediately; it is revealed only once.
4. Save scope edits after changing mode, expiry, description, or local budget enforcement.
5. For `vault_allowlist`, choose a default vault role and select one or more vaults.
6. For `global`, choose a default vault role; selected vaults are hidden because gateway bucket bindings define the vault set.
7. Add default path overrides when every selected/bound vault should share the rule.
8. Add per-vault role exceptions or per-vault path overrides only when one vault should differ.
9. Under **New buckets**, choose what a `CreateBucket` made with the key creates: a local vault, an upstream profile, or the server default.
10. Revoke keys that should no longer authenticate downstream S3 clients.

Upstream profiles are created and edited on the page's **Upstream** tab.

The web console exposes **Count local/cache hits against gateway request budgets** for the same `enforce_budget_for_local_requests` setting.
