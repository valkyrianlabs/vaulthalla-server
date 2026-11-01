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
- A Mac without a Secure Enclave (a virtual machine) keeps using key files, logs that it does, and reports
  `secrets backend: file`.

Linux TPM2 sealing is unchanged.
