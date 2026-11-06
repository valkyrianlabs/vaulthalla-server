---
title: Device Approvals
navTitle: Device Approvals
description: How a paired device such as Vaulthalla Desktop gets a person's approval for a sensitive action - the approval key, its signed single-use challenges and canonical payload, and approvals made with a passkey in the web console.
order: 725
status: published
tags:
  - reference
  - protocol
  - security
  - desktop
---

# Device Approvals

A paired device's mutual-TLS key proves **which device** is connecting. It never proves that a person is there. A
routine connection, a device reporting that the operating system checked a fingerprint, or any flag a client sets
never counts as a person's approval. Routine traffic (sync, the file provider, transfers, reads, key backup inside the
device's [key-backup grant](#key-backup-grants)) never asks for one.

A few actions need a fresh approval by a person: the step-up families (their contract entries carry `step_up`,
see [WebSocket Protocol](/reference/ws-protocol)). On a paired device's session such a command answers
`step_up_required` with `methods` saying how this device can get it approved:

| Method | What it is | Families |
| --- | --- | --- |
| `device_approval` | A signature by the device's **approval key** over a server challenge | `keys`, `device.trust` (the key-backup grant commands are `device.trust`) |
| `console_approval` | A person approves the device's request in the web console **with a passkey** | any family |

Either way the approval becomes a grant on **the device session that asked**, never on another session, for the
family and (for `keys`, `device.trust` and `data.destroy`) the exact target the refusal named. A target-bound grant is
spent by one use; every grant ends after `auth.mfa.step_up_ttl_seconds` (300 by default) or with the session. The
device then sends the refused request again.

:::toc[On this page]{depth="2" theme="compact"}
:::

## The approval key

A second P-256 key per device, separate from the mTLS key (which must work unattended). Vaulthalla Desktop keeps it
in the Secure Enclave with an access control that needs Touch ID or the Mac password for every signature. The server
stores the public key only (`device_approval_keys`, one per device).

It is registered in one of two ways:

- **With the pairing request:** `device.pair.request` carries `approval_key`, the key's SubjectPublicKeyInfo (91 bytes
  of DER: id-ecPublicKey, prime256v1, an uncompressed point) in standard base64. The request shows
  `approval_key_present`, and approving the pairing registers the key with the device.
- **Later, once, for a device paired without one:** `device.approval.key.register {public_key_spki_b64}`. A person
  approves it in the web console: the command answers `step_up_required` (`device.trust`, target
  `device.approval.key.register:<device row>:<key SPKI SHA-256>`) until a console approval for exactly that target.

An approval key is never the device's mTLS key and never a key this node already knows. Revoking the device revokes
its approval key.

The server can't verify that the key really asks for Touch ID: macOS gives it no attestation of that. The key is
trusted because a person registered it through an approved action, it can't be exported, and every signature is
bound to one action. That is weaker than a passkey's user-verification flag, so an approval key approves only `keys`
and `device.trust` (decision D6).

## Challenge and signature

1. `device.approval.challenge {family, target}` (`family` is `keys` or `device.trust`; `target` is the refusal's)
   answers `{challenge_id, challenge, payload_b64, family, target, expires_at}`. The challenge is 32 random bytes,
   single use, valid 120 seconds and bound to this device session, the family and the target. Families the key
   can't approve answer `console_approval_required`; a device without a live key `approval_key_unavailable`.
2. The device checks the payload against what it knows, asks for Touch ID, and signs it with ECDSA P-256 over SHA-256.
3. `device.approval.submit {challenge_id, signature_b64}` (the DER signature, standard base64). The challenge is spent
   whatever the answer; on success the grant is on the session.

The payload, byte for byte:

```text
"vh-device-approval-v1" 0x00
node_id 0x00
server_spki_sha256[32]
approving_device_spki_sha256[32]
challenge[32]
family 0x00
target 0x00
UInt64BE(expires_at)
```

| Field | Value |
| --- | --- |
| `node_id` | The node id `device.pair.status` and `device.endpoints` report |
| `server_spki_sha256` | SHA-256 of the SubjectPublicKeyInfo of the certificate the device listener presents (the pin) |
| `approving_device_spki_sha256` | SHA-256 of the approving device's own mTLS key SPKI (its device id) |
| `challenge` | The 32 challenge bytes |
| `family`, `target` | As in the challenge: no NUL bytes |
| `expires_at` | Unix seconds, 64-bit big-endian |

The server verifies against the payload as it computes it at submit time: a signature over another node, server key,
device, family, target, challenge or expiry never verifies, and neither does one by another key or a revoked one.

The shared test vector, with negatives that change one field each, is
`core/test-assets/device/approval-vectors.json` in the server repository (test keys only). Clients assert the same
bytes; `tools/dev/device_approval_vectors.py --check` verifies the file.

## Console approvals

For a device without an approval key, or a family the key can't approve:

1. The device sends `device.approval.request {family, target, summary}` on its own session and gets
   `{approval_id, state: "pending", expires_at, ...}`. A request lives 5 minutes. A device may have at most 3 open and
   make 10 an hour (`rate_limited`).
2. The account's signed-in console sessions receive `{"command": "auth.approval.pending", "data": {approval_id, device:
   {id, name}, family, target, summary, expires_at}}`; `auth.approval.list` lists the open requests.
3. A person approves with a **passkey**: `auth.approval.approve {approval_id}` returns the WebAuthn request options (a
   challenge bound to that console session and this request), and `auth.approval.approve {approval_id, credential}`
   verifies an assertion with user verification. Nothing else approves: a TOTP code or a password is refused, and an
   account without a passkey gets `passkey_required` (it does the action in the console instead). Or the person
   declines with `auth.approval.deny`.
4. The device polls `device.approval.status {approval_id}` on the same session (every 2 seconds). Once approved, the
   first answer leaves the grant on that session.

A device can't answer its own request or any other: the `auth.approval.*` commands are refused on device sessions.

## Approving a new device from a paired one

`device.pairing.approve` needs `device.trust` with the target `device.pairing.approve:<request>:<new key>:<code
digest>`. On an already-paired Desktop: open the window (`device.pairing.open`), read the request with
`device.pairing.pending`, let the person pick the code the new device shows, send `device.pairing.approve` (it answers
`step_up_required` with the target), approve it with the approval key, and send `device.pairing.approve` again. From
the web console the same approval is a passkey or password plus TOTP step-up, and `vh device pair` on the node needs
none.

## Key-backup grants

Vaulthalla Desktop backs up the keys of your vaults to 1Password in the background. A **key-backup grant** is what lets
one paired device do that without asking you each time: it is bound to that device and your account, and it names its
vaults one by one. A key export from the device for a vault its grant names needs no approval, on every reconnect and
after every key rotation. Any other export (another vault, an export of all vaults, a suspended grant) needs your
approval for that one export: `step_up_required` with family `keys` and target `vault.keys.export:<vault id>`.

| Command | What it does | Approval |
| --- | --- | --- |
| `device.backup.grant.list` | Your grants (on a device's own session, that device's only) | none |
| `device.backup.grant.create {vault_ids, device_id?}` | Turns backup on for a device (on a console session, name it with `device_id`) | `device.trust`, target `device.backup.grant.create:<device row>:<vault ids>` |
| `device.backup.grant.extend {grant_id, vault_ids}` | Adds vaults (a new vault) | `device.trust`, target `device.backup.grant.extend:<grant>:<vault ids>` |
| `device.backup.grant.confirm {grant_id}` | Confirms a migrated grant, or resumes a suspended one | `device.trust`, target `device.backup.grant.confirm:<grant>` |
| `device.backup.grant.revoke {grant_id}` | Turns backup off for the device | none |

Vault ids in a target are ascending and comma-separated; a list longer than the target limit is named by
`sha256:` and the first 32 hex digits of that list's SHA-256. You need the export encryption keys permission (or super
admin), and every vault must be one you may export. One live grant per device: extend it rather than creating another.

- **The cap.** More than 60 vault key exports in an hour under one grant suspends it, and you get a notice. Exports
  then need your approval until you confirm the grant again. A Mac exporting every key in a burst is what a thief does.
- **Automatic revocation.** A grant ends when its device is revoked, your account is deactivated or deleted or loses
  the export permission, your MFA is reset, you sign in with a recovery code, or the device hasn't connected for 90
  days. You can turn it off any time in **Devices › My devices** (the Key backup column) or from Desktop.
- **After a recovery-code sign-in**, while the recovery cooldown runs, the same device may re-create its grant with its
  approval key, only if that key was registered before the recovery, and only for vaults the revoked grant named. A
  passkey added during the recovery, a console approval or another device can't.
- **Upgrading.** Devices paired before key-backup grants existed keep backing up: each got a `migrated` grant over
  exactly the vaults its user could export at that moment. The console asks you to confirm or turn it off; nothing is
  interrupted meanwhile, and a vault created later is added only by `extend`.

Every grant change is in the audit trail (`keys.backup.grant.create`, `.extend`, `.confirm`, `.migrate`, `.suspend`,
`.revoke` with its reason), and so is every export under a grant (`keys.backup.export`, with the grant and the key
versions).

## Audit

Every submission and console decision is in the audit trail (`vh audit list`): `device.approval.submit` (success,
failure, denied), `auth.approval.request`, `auth.approval.approve` (success, failure, denied), `auth.approval.deny`,
and `device.approval.key.register`. Details carry the family, target, request id and device row, never signatures,
assertions or codes.
