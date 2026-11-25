## Linked servers (experimental, off by default)

Two Vaulthalla servers can be paired with each other and keep one mutually authenticated connection: the first step
towards mirroring a vault on two servers. It is **experimental and off by default**: nothing changes unless you set
`peers.experimental: true` in `/etc/vaulthalla/config.yaml` and restart the daemon on both servers. No vault data,
keys or accounts travel over the link yet.

- **Pairing.** On one server `vh peer pair` opens a 10-minute window; on the other `vh peer link <address>` dials it
  (the device port, 36972 by default) and shows a six-digit code, which a super admin picks among three on the first
  server. `--fingerprint <key>` on either side refuses any other server key. One window at a time is shared with
  device pairing.
- **The link.** Each server pins the other's key (no certificate authority, no trust store), either side dials, the
  link reconnects by itself after a restart or a network loss, and `vh peer list` shows its health.
- **Unlinking.** `vh peer unlink <peer>` refuses the other server's key from then on and closes the link; the other
  server is told and unlinks too.
- **Identity rotation.** `vh secret device-identity rotate` now tells connected linked servers of the new key first
  (signed by the old one), and they keep their links; servers that weren't connected are unlinked and must be linked
  again. `--revoke-peers` is the emergency rotation: it tells no one and drops every link.
- **Who may.** Super admins only, on the server's `vh`, in the web console (with the device-trust confirmation; no
  console page yet) or from a fully trusted Vaulthalla Desktop connected directly. Agents, devices with limited
  access and connections through Vaulthalla Cloud can't.

Requires migration 157 (a new `peer` table; additive). A linked server's key can never be paired as a device, and a
device's key can never link.
