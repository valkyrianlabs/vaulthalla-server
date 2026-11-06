## Security

- **Vaulthalla Desktop can get your approval for sensitive actions (device approvals, server side).** A paired Mac's
  connection still never counts as you being there. What counts:
  - **Touch ID on the Mac**, through a second key Desktop keeps in the Secure Enclave (its *approval key*), for
    vault-key operations and approving devices only. Each approval is signed for one action and one target, and expires
    after two minutes.
  - **Your passkey in the web console**, for anything else Desktop asks for: the request shows up for every console tab
    you're signed in to, and only a passkey can approve it (an authenticator code or a password can't).
- **Approve a new Mac from a Mac you already paired**, with Touch ID, instead of from the web console. Pairing from the
  console and with `vh device pair` (including `--json`) works as before.
- Desktop's sync, file access and automatic 1Password key backup still never ask for anything.
- Every approval, refusal and decision is recorded in the audit trail (`vh audit list --action device.approval.` and
  `--action auth.approval.`).
- The Desktop side (Touch ID prompts, registering the approval key, the console's Pending approvals list) ships in
  Vaulthalla Desktop and a later console update. Until then, do these actions in the web console or with `vh`.
