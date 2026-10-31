<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Vaulthalla Desktop connects directly

Vaulthalla Desktop can now find the fastest way to reach a node on its own. A paired Mac asks the node where it can be
reached (`device.endpoints`): its addresses on this machine, the local network and VPNs such as Tailscale or
WireGuard, `<hostname>.local` where mDNS runs, and any names an operator lists under the new
`device_server.advertise` section of `config.yaml` (port forwards, tunnels, TLS passthroughs). The node never asks an
outside service for its public address. The web console's "Pair a device" dialog gets the same list, the node id and
the server key fingerprint, so a pairing link can carry them.

With remote connections on, the device listener now accepts IPv6 as well as IPv4 (`[::]`, falling back to
`0.0.0.0` where IPv6 is disabled); loopback-only listens on `::1` too. For super admins, `device.remote.status` adds
diagnostics: every bound address, the addresses devices are told, a read-only look at the host firewall (ufw,
firewalld, nftables, the macOS application firewall; "unknown" rather than a guess) and when a device last
connected from a public address. Paired devices can measure a route's throughput with the new `/transfer` probe,
sink and source lanes on the device listener; nothing they send is stored.
