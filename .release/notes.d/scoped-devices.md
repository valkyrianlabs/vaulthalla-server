## Devices

- **Paired devices can have limited access.** When you approve a pairing (in the console's pairing dialog or with
  `vh device approve --scope read|write`), you can now limit the device to reading, or to reading and changing, within
  your account's rights; a device can also ask for less when it pairs. `vh device list` and the console's device list
  show each device's access, and `vh device scope <device> <scope>` changes it (giving more access asks for
  confirmation). A limited device can't pair or approve other devices, back up or import vault keys, or manage remote
  connectors. Every existing pairing keeps full access. Vaulthalla Desktop support for choosing a scope for the AI apps
  it pairs comes in its own release.
- **Every scoped device is accountable in the audit trail.** The trail records the access a device asked for and was
  given, every change to it, the scope each of its actions ran under and every request its scope refused.
  `vh audit list --device <n>` shows one device's history, and `vh device scopes` lists exactly what each scope allows.
