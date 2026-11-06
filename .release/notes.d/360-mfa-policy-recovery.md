## Security

- **Multi-factor sign-in policy is now a setting** (**Settings › Security › Multi-factor sign-in**, `auth.mfa.policy`):
  `admins` (the default, unchanged), `all` (every account) or `optional` (nobody, except accounts you require). Raising it
  signs affected password-only sessions out at their next request; they set up a factor at their next sign-in.
  Weakening it is recorded in the audit trail and emailed to the security recipients
  (`operator_emails.recipients.security`).
  - New: hold administrators to **passkeys only** (`admin_webauthn_only`), or to **device-bound passkeys only**
    (`admin_device_bound_only`: security keys, not synced passkeys). Both need passkeys configured. An administrator
    whose only factor is no longer allowed is signed out and sets up a passkey at the next sign-in.
  - **Require MFA for one account** whatever the policy: on the account's page in **Users**, or `vh user mfa require
    <user>`.
- **Resetting a lost second factor.** An administrator who may reset an account's password can now reset its MFA
  (**Users › a user › Sign-in factors › Reset MFA**, with a reason; a super admin's only another super admin). On the
  server, `vh user mfa reset <user>` does the same, run as the Linux user bound to your own account or to one allowed
  to reset the target's password, never with `sudo`: it is the way back in for a sole super admin who lost every factor.
  A reset disables the account's passkeys and authenticator apps, voids its recovery codes, signs every session out
  and revokes its paired devices' key-backup grants (the devices stay paired and keep syncing). The account sets up a
  new factor at its next sign-in. A password reset never touches factors.
- **Signing in with a recovery code** now also revokes the key-backup grants of your paired devices, and lists them
  in **Account › Security** so you can revoke any you lost (nothing is revoked for you). Every other browser is still
  signed out.
- **Recovery cooldown:** for 24 hours after a recovery-code sign-in or an MFA reset (`auth.mfa.recovery_cooldown_hours`,
  1 to 168), key export, device approval, account and role administration, API keys and other secrets, and settings
  changes are refused for that account. A passkey or authenticator app set up during the recovery doesn't count as a
  confirmation for those until it ends. The local `vh` CLI is not held back.
- **Repeated wrong codes:** after 5 failed second factors in a row an account waits 1 minute before the next attempt,
  then 2, 4, 8 and at most 15 minutes. It is never locked. The 10th failure emails the account and the security
  recipients.
- **Emails:** the account (when it has an email address) and the security recipients are told about recovery-code
  sign-ins, MFA resets, repeated failures and suspended passkeys; the account alone about factors added, renamed or
  removed and new recovery codes. Operator email must be configured.
- Every recovery can be followed in the audit trail alone (`vh audit list --action auth.mfa.`), and `vh audit verify`
  checks it. See **Audit trail › Reconstruct an MFA recovery**.
