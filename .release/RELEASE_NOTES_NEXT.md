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

## Vaulthalla Desktop sets up this Mac's server on its own

`brew install --cask valkyrianlabs/tap/vaulthalla` now ends with Vaulthalla Desktop open and already connected to
the server on the same Mac. There is no pairing code to compare: your macOS account is the proof. Desktop (0.5.0 and
later) pairs through the server's own `vh` as you, so the device acts as the Vaulthalla user your account is bound to
(the person who installed the server is `admin`), and it shows up in your device list like any other.

- The meta cask opens Desktop once, on its first install; upgrades don't open it again. Desktop also does this
  whenever it starts, or when a server is installed on its Mac while it runs, so installing the two casks separately
  works too. A Mac with only one of them is unchanged.
- Nothing on the network is trusted more than before: it is the same number-matched pairing you could run in
  Terminal, approved over the local `vh` socket, and the connection is pinned to the server key `vh` reports.
- New for scripts: `vh device pair --json` opens your pairing window without waiting and prints its expiry, the
  device port, the node id and the server key.

## Fixes

- **Health dashboard: FUSE permission denials are no longer errors.** A system process with no Vaulthalla account
  that looks at the mount (an ssh login's MOTD scripts, for example), or a user refused by RBAC, is the filesystem
  enforcing access as designed. These now count as expected errors, so they no longer raise "FUSE alertable error
  rate is above 10%". They still appear under all errors and errors by errno.
