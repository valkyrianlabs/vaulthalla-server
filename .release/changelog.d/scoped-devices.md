- Scoped devices: migration 152 adds `devices.scope` (read | write | destructive, default destructive: every existing
  device unchanged). `device.pair.request` and `device.pairing.approve` take an optional `scope` (bound into the
  device.trust target when narrower), `device.list` shows it, `device.scope.set` changes it. Every ws command declares
  an `effect` in the contract; a scoped device's ws commands, HTTP lanes and `/mcp` are held to its scope (ERROR
  `device_scope`), and it never pairs, approves, steps up, handles vault keys or manages connectors. Capability
  `device.scope`. `vh device approve --scope`, `vh device scope`.
- Scoped devices are audited in the existing trail: approvals record the scope asked for and given, scope changes
  record from/to, a scoped device's lines carry `scope <scope>` in their origin, and refusals are recorded as
  `device.scope.refused` (throttled per device, with a count). `vh device scopes` lists what each scope allows; `vh audit
  list --device <n>` and `--grant <id>` (ws `audit.list {device_id, grant_id}`) filter the trail to one device or grant.
