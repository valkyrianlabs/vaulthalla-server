- Groundwork for reaching a linked server through Vaulthalla Cloud, which isn't offered yet (design/cloud/relay.md,
  "As built"). Migration 144 adds `devices.paired_via` (`listener` for every existing device) and `cloud_relay` (the
  local switch, off). `CloudRelayService` contacts nobody unless the server is linked, a super admin switched the relay
  on (`vh cloud relay status|enable|disable`; ws `cloud.relay.*` behind the `cloud.relay` capability; enabling is a
  device.trust step-up; both switches are excluded from `vh mcp`) and the device listener is enabled.
- The device listener accepts relayed streams from that service only: a TLS context without a client certificate and a
  key proof bound to the TLS exporter before any request; the network listener still requires a certificate. A
  relayed or relay-paired device is held to a read-only set (ws ERROR `relay_read_only`; GET/HEAD `/preview` and
  `/download` only). `device.pairing.pending` requests carry `via`, `Device` carries `paired_via`; approvals are
  audited `device.pairing.approve` with `via`.
