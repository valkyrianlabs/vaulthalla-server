<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Pair Vaulthalla Desktop with your node

## Paired devices

The daemon now serves Vaulthalla Desktop through its own **device listener** on port 36971: TLS 1.3 with a
certificate on both sides, each side pinning the other's key. No browser cookie, nginx or certificate authority is
involved. The listener answers on **loopback only** until a super admin runs `vh device remote enable`, which opens
it to the network at once (no restart) and keeps it that way across restarts and upgrades; `vh device remote
disable` closes it again.

Any signed-in user can pair a Mac with their own account: `vh device pair` opens a 10-minute pairing window, lists
the Mac when it asks, and offers three codes. Pick the one the Mac shows; a wrong pick denies the request. A paired
device acts as its account with that account's permissions, and follows it: role changes apply at once,
deactivation refuses it, and a password reset or role change closes its open connections. Manage devices with
`vh device list | rename | revoke` (super admins: `vh device list --all`). Revoking is final: the device's
connections close immediately and its key is never accepted again.

### In the web console

**Devices** (in the main navigation and the account menu) lists your paired Macs with their platform, app version,
when they were paired and last seen, the last address and the device id, and lets you rename or revoke them. **Pair a
device** is one click: the dialog opens a pairing window, shows the Mac's request with three codes as large buttons,
and you click the one the Mac shows. A wrong click declines the request; if another user is pairing on the node at
the same time, the dialog says so and leaves their window alone. Closing the dialog closes your window.

Super admins also get **Devices → All devices**: every user's devices with their owners, and a **Remote connections**
card with the listener's live status (address, port, connections, any bind error, the server key fingerprint) and an
on/off switch. Settings → Device listener links there.

**macOS:** the package's bundled PostgreSQL uses port 36971, so the device listener doesn't start on macOS in this
release.
