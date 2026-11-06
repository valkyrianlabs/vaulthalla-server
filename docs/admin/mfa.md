---
title: Multi-Factor Sign-In
navTitle: Multi-Factor Sign-In
description: Require passkeys or authenticator apps for administrators, set the policy and defaults, configure passkeys, understand step-up confirmation, recover a lost second factor, and what Desktop approvals and key-backup grants do.
order: 6
status: published
tags:
  - admin
  - security
  - mfa
  - passkeys
  - cli
---

# Multi-Factor Sign-In

Vaulthalla asks for a second factor after the password: a **passkey** (a security key, your device's passkey manager,
or a password manager such as 1Password) or a code from an **authenticator app** (TOTP). On new and upgraded installs
the super admin and every administrator who can change accounts, roles, settings or encryption keys must use one.
Sensitive changes in the web console ask you to confirm it's you again right before they run (**step-up**), and a
lost second factor has a recovery path that leaves a trail in the [audit trail](/admin/audit-trail).

This page is for operators. It describes what the server enforces; it does not make an organization compliant with
anything (see [HIPAA And Other Frameworks](#hipaa-and-other-frameworks)).

:::toc[On this page]{depth="3" theme="compact"}
:::

## Policy And Defaults

Set the policy under **Settings › Security › Multi-factor sign-in** or in `config.yaml`
(see [Configuration](/reference/configuration#multi-factor-sign-in-mfa)):

```yaml
auth:
  mfa:
    policy: admins                 # optional | admins | all
    admin_webauthn_only: false
    admin_device_bound_only: false
    recovery_cooldown_hours: 24    # 1..168
    step_up_ttl_seconds: 300       # 60..900
```

| Setting | Default | What it does |
| --- | --- | --- |
| `policy` | `admins` | `admins`: the super admin and every account whose admin role can manage users or admins, roles, settings, or export or rotate encryption keys. `all`: every account. `optional`: nobody, except accounts you mark **Require MFA**. |
| `admin_webauthn_only` | `false` | The accounts the `admins` policy names may use passkeys only. Authenticator apps are not accepted for them. Needs passkeys configured. |
| `admin_device_bound_only` | `false` | Those accounts may use only passkeys that never leave their device (security keys, platform passkeys that don't sync), not synced ones such as 1Password or iCloud Keychain. Implies `admin_webauthn_only`. |
| `recovery_cooldown_hours` | `24` | How long sensitive changes wait after a recovery-code sign-in or an MFA reset (below). |
| `step_up_ttl_seconds` | `300` | How long a confirmation covers similar changes in one browser tab. |

- An account that has a factor is **always** asked for it, whatever the policy.
- `vh user mfa require <user>` (or **Users › a user › Require MFA**) requires it for one account whatever the policy.
- **Raising the policy** (or an upgrade onto `admins`) signs out sessions that signed in with a password alone, at their
  next request. Nothing is grandfathered: those accounts go through the guided setup at their next sign-in.
  Paired Desktop devices are not affected and never ask for a second factor.
- **Weakening it** (a lower policy, an admin flag turned off, a changed `rp_id`) is recorded in the audit trail
  (`auth.mfa.policy.change`) and emailed to `operator_emails.recipients.security`.
- Turning on `admin_webauthn_only` or `admin_device_bound_only` without passkeys configured is refused, because no
  administrator could sign in. An administrator whose only factor stops being allowed is signed out and sets up a
  passkey at the next sign-in.
- The local `vh` CLI is trusted as the server's own account and never asks for a second factor.

### First sign-in

After the password, an account that must use MFA and has no factor chooses **Create passkey** (recommended) or **Use an
authenticator app**. It then saves ten recovery codes, shown once, and confirms it did; only then is the sign-in
complete. Adding a second passkey (another device, or 1Password) is suggested. Until the second step succeeds nothing
is signed in: the half-finished sign-in can't be refreshed, reopened in another tab or used for downloads, and it ends
after 5 minutes (10 while setting up), after 5 wrong attempts, or when the page closes.

## Passkeys

Passkeys are bound to the host name people open the console at. Set it explicitly in **Settings › Security › Passkeys
/ security keys** or `config.yaml`:

```yaml
auth:
  webauthn:
    rp_id: vault.example.com
    rp_name: Vaulthalla
    origins:
      - https://vault.example.com
```

- `rp_id` is a host name, never an IP address, and it is never derived from request headers. `origins` are exactly
  `https://host[:port]` under it (`http://localhost:<port>` for development). The daemon refuses to start, and the
  settings page refuses to save, when the rules are broken. Details: [Configuration](/reference/configuration#passkeys-webauthn).
- **A console reached by an IP address can't use passkeys.** Browsers refuse passkeys for IP addresses, so a host that
  is only reachable as `https://192.168.1.20` has no valid `rp_id`. Give it a host name (a local DNS name works) with a
  certificate the browser trusts, or use authenticator apps there. Leave `rp_id` empty and passkeys are simply
  unavailable; authenticator apps and the password sign-in keep working.
- Passkeys are checked with user verification: the passkey must be unlocked with a PIN or biometric. Supported
  keys are ES256, Ed25519 and RS256 (2048 bits or more).
- **Sign in with a passkey alone:** the sign-in page has **Sign in with passkey**, and browsers that support it offer
  your passkeys in the username field. It needs no username or password and counts as a full second-factor sign-in.
- **Changing `rp_id`** leaves passkeys registered for the old one unusable (kept, not deleted); their owners sign in
  another way and register new ones. The settings page warns before saving such a change.
- A passkey whose signature counter goes backwards is suspended as a possible clone, and the account and the
  security recipients are emailed.
- Keep the recovery codes somewhere other than your passkey manager: if the manager is the thing you lost, the codes
  are the way back in.

## Authenticator Apps And Recovery Codes

- **TOTP:** the QR code is drawn in the browser; the secret is a 160-bit seed, six digits, 30-second steps, with the
  step before and after accepted. Seeds are stored sealed under the internal key `mfa_seal`, bound to the account and
  factor they belong to.
- **Recovery codes:** ten per batch, each usable once, stored only as keyed hashes under the internal key `mfa_pepper`.
  Replacing the batch (**Account › Security**) voids the old one.
- Neither key is ever regenerated while anything depends on it. If one can't be unsealed (a database restored without
  this host's sealed master), only that kind of factor stops working. Passkeys are unaffected, and so is the local
  `vh` CLI. Back both keys up with the other internal secrets: `vh secret export mfa-seal` and
  `vh secret export mfa-pepper` (included in `vh secret export all`).
- **Moving to a new host:** a database restored without the old host master loses the two keys. `vh secret set
  mfa-seal|mfa-pepper` imports them from the export, so TOTP factors and recovery codes keep working without
  re-enrolling. See [A Lost Host Master](/vaults/secrets-and-key-export#a-lost-host-master) for the current steps.
- A TOTP code is phishable, a passkey is not. For administrators, `admin_webauthn_only` removes the phishable option.

## Lockout

- A pending sign-in ends after 5 wrong second factors. Start again with the password.
- After 5 failed second factors on an account within 15 minutes, its next attempt waits 1 minute, then 2, 4, 8 and at
  most 15 minutes. The account is **never locked** outright, because an attacker could use that to lock a real user
  out. The 10th failure emails the account and the security recipients.
- The count and the delay are per account, whatever the source address. The password sign-in keeps its own rate limit.

## Step-Up Confirmation

Right before a sensitive change in the web console, a dialog asks for your passkey, or your password together with a
code from your authenticator app. The changes are grouped into *families*:

| Family | Examples of what asks | How long it covers |
| --- | --- | --- |
| `account.credentials` | Changing a password, adding or removing a passkey or authenticator app, replacing recovery codes, resetting another account's MFA | `step_up_ttl_seconds` |
| `identity.admin` | Creating, deleting or changing accounts, roles, groups and their members; requiring MFA for an account | `step_up_ttl_seconds` |
| `secrets` | API keys, the email provider's credentials, S3 gateway credentials, turning on provider administration | `step_up_ttl_seconds` |
| `settings` | Any **Settings** change, including `auth.webauthn` and `auth.mfa`, and the email configuration | `step_up_ttl_seconds` |
| `device.trust` | Approving a new device, turning on remote device connections, key-backup grants | One change |
| `keys` | Exporting or importing vault keys outside a paired device's key-backup grant, recovery recipients, `vault.recover` | One change |
| `data.destroy` | Deleting a vault or a recovery point, suspending provider versioning, cleaning up, unprotecting or setting a destructive lifecycle rule on a bucket | One change |

- Confirming covers similar changes in that browser tab for `step_up_ttl_seconds` (5 minutes by default; reloading the
  page asks again). The last three families confirm exactly one change each time, for the exact target.
- Signing in with a passkey or an authenticator code counts as a confirmation for the first four families for the
  next 5 minutes.
- An account that doesn't need MFA and has no second factor confirms with its password, but never for `device.trust`,
  `keys` or `data.destroy`: add a passkey or an authenticator app for those.
- Recovery codes, a remembered session and Vaulthalla Desktop's connection never count as a confirmation. Five failed
  confirmations within 15 minutes sign that browser out.
- **Not affected:** the local `vh` CLI, and Desktop's sync and key backup inside a [key-backup grant](#key-backup-grants).
  Agent tools (`/mcp`, `vh mcp`) can't confirm and are refused these actions.

## Recovery

| What was lost | The way back |
| --- | --- |
| One factor, another remains | Sign in with the other, remove the lost one in **Account › Security**, and revoke a lost Mac in **Devices**. |
| Every factor, recovery codes kept | Password plus a recovery code (below). |
| Every factor, another administrator exists | **Users › a user › Sign-in factors › Reset MFA** with a reason, by an administrator who may reset the account's password. A super admin's MFA only another super admin resets. |
| Every factor, sole super admin | `vh user mfa reset <user>` on the server (below). |
| The password | Unchanged: another administrator, or `vh setup set-super-admin-password`. A password reset never touches factors. |

There is no email reset.

### Signing in with a recovery code

A recovery code works once and has these effects:

- Every other browser session of the account is signed out.
- The key-backup grants of the account's paired devices are revoked, and **Account › Security** lists the devices so
  you can revoke any you lost. The devices stay paired and keep syncing. Nothing is revoked for you.
- You must set up a new factor and new recovery codes. The number of codes left is shown.
- The account and the security recipients are emailed.
- The **recovery cooldown** starts.

### Recovery cooldown

For `auth.mfa.recovery_cooldown_hours` (24 by default) after a recovery-code sign-in or an MFA reset, the `keys`,
`device.trust`, `identity.admin`, `secrets` and `settings` families are refused for that account (`recovery_cooldown`):
no key export, device approval, account and role administration, API keys and other secrets, or settings changes. A
passkey or authenticator app set up during the recovery doesn't count as a confirmation for those until the cooldown
ends. The local `vh` CLI is not held back. `account.credentials` and `data.destroy` are not cooldown families.

The one exception is a paired Mac that backs keys up: during the cooldown the same Mac can turn its key backup back on
with Touch ID, for the same vaults only, if its approval key was registered before the recovery.

### Admin reset and the CLI

```bash
vh user mfa status alice
vh user mfa require alice            # whatever the policy says; --off to undo
vh user mfa reset alice --reason "lost phone, verified by phone call"
```

- `status` shows whether the account must have MFA and why, its factors (never secrets), the recovery codes left and
  the cooldown. `--json` is available.
- `reset` disables the account's passkeys and authenticator apps (kept for the audit trail), voids its recovery codes,
  signs every session out and revokes the key-backup grants of its paired devices (they stay paired and keep syncing).
  It sets up a new factor at its next sign-in, and the same cooldown applies.
- Run `vh user mfa` as the Linux user bound to your own account (for yourself) or to an account that may reset the
  target's password. **Never with `sudo`**: root is refused. This is the documented way back for a sole super admin
  who lost every factor. `vh user mfa require` can't change your own account.
- Every recovery can be followed in the audit trail alone: `vh audit list --action auth.mfa.` and
  `vh audit verify`. See [Reconstruct an MFA recovery](/admin/audit-trail#reconstruct-an-mfa-recovery).

## Desktop Approvals And Key-Backup Grants

A paired Mac proves **which device** is connecting, never that a person is there. Routine traffic (sync, file access,
transfers) never asks for anything. The actions in the `device.trust` and `keys` families need a person's approval:

- **Touch ID on the Mac,** through a second key Desktop keeps in the Secure Enclave (its *approval key*), for vault-key
  operations and approving devices only. Each approval is signed for one action and one target and expires after two
  minutes.
- **A passkey in the web console,** for anything else Desktop asks for. The request shows up for every console tab the
  account is signed in to, and only a passkey can approve it (an authenticator code or a password can't). An
  account without a passkey does the action in the console instead.
- A new Mac can be approved from a Mac you already paired, with Touch ID, instead of from the console.

Automatic 1Password key backup is a **key-backup grant** you can see and turn off. It lets one paired Mac back up the
keys of the vaults it names with no prompt; any other export from the Mac needs approval each time. See
[Key-Backup Grants](/admin/devices#key-backup-grants) for managing them and
[Device Approvals](/reference/device-approvals) for the protocol. Every approval, refusal and grant change is in the
audit trail (`device.approval.`, `auth.approval.`, `keys.backup.`).

The server can't verify that the approval key really asks for Touch ID. It trusts the key because a person registered
it through an approved action, it can't be exported, and every signature is bound to one action; so an approval key
approves only `keys` and `device.trust`.

## HIPAA And Other Frameworks

45 CFR §164.312(d) (person or entity authentication) requires procedures to verify that a person seeking access to
electronic protected health information is who they claim to be. It does not name multi-factor authentication.
Vaulthalla gives a covered entity technical controls it can use for that safeguard: second-factor sign-in for the
accounts you choose (`policy: all` for every account), enforcement for administrators, step-up confirmation for
privileged actions, and audit events that can support the audit controls of §164.312(b).

Vaulthalla is designed to support the technical safeguards in HIPAA; see this page and the [audit trail](/admin/audit-trail).
Whether an organization is compliant depends on its own risk analysis, policies, agreements and operation of the
whole system, not on software. Proposed changes to the Security Rule are not law until final; check their status
before relying on them.

## What This Does Not Cover

- **The host.** Someone with root on the server can read the daemon's memory and the database. The local CLI is
  trusted as the host account.
- **Malware in a signed-in browser.** It can do what the user can without step-up, and it can prompt the user to
  confirm something. A passkey signs the challenge, not the dialog text.
- **An authorized administrator.** MFA resets are audited and need a step-up; they are not prevented.
- **The first factor of a new account.** Whoever first completes enrollment with the correct password owns that
  factor. Keep the generated super-admin password file private.
- **What a device does with keys it receives.** The server can't prove Desktop stored an exported key in 1Password.
