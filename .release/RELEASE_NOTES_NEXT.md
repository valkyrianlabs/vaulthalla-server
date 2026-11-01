<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# macOS: Secure Enclave key sealing

## Master keys on macOS are sealed with the Secure Enclave

The macOS server now seals its master keys (the vault master key, the database password, API-key, S3 gateway and
device secrets) with the Mac's Secure Enclave, and `vh status` reports `secrets backend: secure-enclave`. Until now
they were plain `0600` files in the state directory, protected only by permissions and FileVault.

- **Upgrading keeps everything.** On its first start after the upgrade the daemon moves each existing key file into
  the Secure Enclave and deletes the plaintext file. No action is needed.
- **Only the daemon can open the keys**, and only on this Mac: they are bound to the context launchd starts it in, so
  not even root can open them from a terminal or `sudo`. Copying the state directory to another Mac no longer carries
  the keys with it; GPG-encrypted vault key and secret exports are the way to move or recover them. See macOS Key
  Recovery in the backup docs.
- **Restarts with FileVault on:** a cold boot waits at the FileVault login before any service runs. For an unattended
  restart use `sudo fdesetup authrestart`; Vaulthalla then starts at the login window, before anyone logs in.
- If the Secure Enclave can't be used (the daemon checks at startup), it keeps using key files, logs why, and
  reports `secrets backend: file`.

Linux TPM2 sealing is unchanged.

## Change feed for sync clients

Every change to a vault's files and folders is now recorded in a change journal, in the same database transaction as
the change itself, whichever way it was made: the mounted filesystem, uploads, the web console, sync, recovery or a
manual database edit. A new WebSocket command, `fs.changes.list`, returns what changed in a vault since a revision,
oldest first, so sync clients such as Vaulthalla Desktop's Finder integration can follow a vault without listing its
folders again.

- Anyone who can browse a vault can follow it, and sees only changes to entries they are allowed to see. A rename or
  move into or out of what they can see reads as a create or a delete.
- When a role, group membership or permission override changes what someone may see in a vault, their cursor
  expires and their client lists the vault again. So does a cursor older than the journal's retention (7 days or the
  last million changes).
- Clients can subscribe instead of polling: `fs.changes.subscribe` makes the server tell a connected session when a
  vault it follows has changed (`fs.changed`). Events are merged per vault for slow clients, and a subscription
  ends when its user loses access to the vault.
- The journal adds one row per change. The database migration (115) is safe on upgraded installs.

## Fixes

- **Health dashboard: FUSE permission denials are no longer errors.** A system process with no Vaulthalla account
  that looks at the mount (an ssh login's MOTD scripts, for example), or a user refused by RBAC, is the filesystem
  enforcing access as designed. These now count as expected errors, so they no longer raise "FUSE alertable error
  rate is above 10%". They still appear under all errors and errors by errno.
