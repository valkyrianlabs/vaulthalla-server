## Security

- **Sensitive changes in the web console now ask you to confirm it's you (step-up).** Right before the change runs, a
  dialog asks for your passkey, or your password together with a code from your authenticator app. What asks:
  - changing accounts, roles, groups and their members, and creating or deleting accounts;
  - changing passwords, adding a second passkey or authenticator app, removing one (new: **Account › Security ›
    Remove**), and replacing recovery codes;
  - API keys, the email provider's credentials, S3 gateway credentials and turning on provider administration;
  - any **Settings** change (including the passkey settings `auth.webauthn`);
  - approving a new device and turning on remote device connections;
  - deleting a vault or a recovery point, suspending provider versioning, cleaning up, unprotecting or setting a
    destructive lifecycle rule on a bucket;
  - exporting or importing vault keys outside a paired device's automatic backup.
- Confirming covers similar changes in that browser tab for 5 minutes (`auth.mfa.step_up_ttl_seconds`, 60 to 900; reloading the page asks again). Device approvals, key
  operations and data removal confirm exactly one change each time. Signing in with a passkey or an authenticator code
  counts as a confirmation for the next 5 minutes.
- An account that doesn't need MFA and has no second factor confirms with its password, but never for vault keys,
  device approvals or removing data: add a passkey or an authenticator app for those.
- Recovery codes, a remembered session, and Vaulthalla Desktop's connection never count as a confirmation. Five failed
  confirmations within 15 minutes sign that browser out.
- **Not affected:** the local `vh` CLI (it is trusted as the server's own account) and Vaulthalla Desktop's sync and
  automatic 1Password key backup. Actions above that Desktop starts itself (removing a vault, importing keys) are
  refused until device approvals arrive in a later release; do them in the web console or with `vh`. Agent tools
  (`/mcp`, `vh mcp`) can't confirm and are refused these actions.
