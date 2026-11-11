# Vaulthalla Cloud: linking a server (operator page, held until launch)

> **Not published.** vaulthalla.cloud isn't open yet, and the claims spec (`design/encryption/05-claims-and-custody.md`
> §3.1, enforced by `tools/contracts/encryption_claims.py`) allows no product text that describes it as available.
> This is the operator page for `docs/admin/cloud.md`, ready to move there (with the command and configuration
> reference entries) when the service opens. The commands below exist in the server already.

Vaulthalla never needs vaulthalla.cloud. A self-hosted server works the same with or without it, and nothing contacts
the cloud until a super admin runs `vh cloud link`. Linking makes this server an installation of your
vaulthalla.cloud account, so that cloud services you choose later (starting with cloud recovery of vault keys) know
which account it belongs to.

## Link this server

Run this in a terminal on the server, as a super admin:

```bash
vh cloud link --name "home server"
```

It prints a code and this server's key fingerprint, then waits:

1. Sign in on vaulthalla.cloud and choose **Link a server**.
2. Enter the code (it lasts 10 minutes).
3. Check that the fingerprint vaulthalla.cloud shows is the one in your terminal, then approve. vaulthalla.cloud asks
   for a fresh second factor first.

The terminal then says `Linked`. If you stopped waiting (Ctrl-C, or `--json`), `vh cloud link --finish` picks the
request up again. A denied or expired request leaves nothing behind.

:::callout[Compare the fingerprint]{variant="warning"}
Someone who gets you to type *their* code would link *their* server to your account. The fingerprint is how you tell:
approve only when the one vaulthalla.cloud shows matches the one on your own screen.
:::

## What linking does

- **An identity key for this server.** `vh cloud link` creates an Ed25519 key pair and seals the private key to this
  machine like the server's other secrets (the TPM on Linux, the Secure Enclave on macOS; slot `cloud_identity`).
  vaulthalla.cloud receives only the public key.
- **Signed requests.** Every request this server makes as your installation is signed with that key (VHC1-Ed25519):
  it is bound to its method, path, body and time, and can't be replayed. There is no password or token to steal from
  the server or from vaulthalla.cloud.
- **Nothing else, yet.** Linking sends no vault data, keys or recovery material. Cloud recovery will be a separate,
  explicit step per vault.

## Cloud recovery of a vault's keys

Once linked, a vault can be enrolled in cloud recovery, explicitly and one vault at a time:

```bash
vh cloud recovery enroll photos --owner alice
vh cloud recovery status
vh cloud recovery unenroll photos --owner alice
```

- **What is sent.** The vault's recovery envelopes, exactly as they are in its bucket. They are wrapped to the
  recovery recipients *you* enrolled (`vh vault keys recipient add`), so vaulthalla.cloud can't open them. Alongside
  them go the public facts a restore checks against: each key version's key check and this server's attestation, the
  attestation public keys, and the manifest checkpoint. Never a vault key, a recovery seed, a kit or an export.
- **When it is refused.** Without a link, without a recovery recipient, while a needed key version has no envelope
  yet (the next sync pass writes it), or when an object in the bucket isn't the envelope this server wrote.
- **After a key rotation.** `vh cloud recovery status` says `behind`; run `vh cloud recovery enroll` again.
- **Undo.** `vh cloud recovery unenroll` deletes every record vaulthalla.cloud holds for the vault. Your recovery kit
  or export recovers the vault exactly as before, with or without the cloud.
- **Who.** Super admins or users with the export encryption keys permission, in a terminal on the server or from a
  paired device (with its approval), never through the browser or an agent.

## Check and undo

```bash
vh cloud status
vh cloud unlink
```

`vh cloud status` shows the account and installation, and whether vaulthalla.cloud still accepts this server.
`vh cloud unlink` revokes the link in vaulthalla.cloud (your account's owner is emailed) and deletes the identity key
here. If vaulthalla.cloud can't be reached, the link stays; `vh cloud unlink --force` forgets it here anyway, and you
revoke the server on vaulthalla.cloud. You can also revoke it there at any time: `vh cloud status` then says
`revoked`.

## Who can do it

Super admins, in a terminal on the server. Agents can't: `vh cloud link` and `vh cloud unlink` are not available
through `vh mcp` (see `docs/admin/mcp-and-agents.md`). Every request, link, denial and unlink is in the
audit trail (`cloud.link.request`, `cloud.link`, `cloud.unlink`).

## Configuration

```yaml
cloud:
  endpoint: https://api.vaulthalla.cloud   # https, or http only to localhost (development)
```

Read from `/etc/vaulthalla/config.yaml` only; the console's settings never change it. The default is the production
service, and you only change it to test against a staging or local cloud.
