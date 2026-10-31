---
title: Direct Device Connections
navTitle: Direct Connections
description: How Vaulthalla Desktop finds and verifies the fastest route to a node, and how to let it connect from outside your network over port 36972 or a TLS passthrough on 443, with firewall, DNS, Cloudflare and security guidance.
order: 41
status: published
tags:
  - admin
  - devices
  - networking
  - security
---

# Direct Device Connections

Vaulthalla Desktop talks to a node through the **device listener** (port `36972`), not through the web console's
reverse proxy. It works out the best route on its own: the same machine first, then your local network, a VPN, the
internet, and finally a TLS passthrough on port 443. This page covers how that works and what an operator sets up so
Desktop can also connect from outside the network. Pairing, revoking and the remote-connections switch are covered
in [Paired Devices](/admin/devices).

:::toc[On this page]{depth="3" theme="compact"}
:::

## Why Desktop For Large Transfers

Browser uploads go through the web console's origin, in parts of at most 64 MiB, up to three at a time (see
[Uploads](/web-console/uploads)). Desktop is the better client for large uploads and downloads, and for files you
transfer again and again:

- **Direct first.** Desktop connects straight to the device listener over the best route it can verify. When that
  route is the LAN or a VPN, nothing leaves your network. A CDN or reverse proxy is never involved, so their
  request-size limits and timeouts don't apply.
- **Verified routes.** Every route is checked with a full TLS 1.3 handshake. Desktop presents its device certificate,
  and the node must present the key Desktop pinned when it paired. An address that answers with a different key is
  ignored. An open TCP port alone is never trusted.
- **Adaptive parts.** Desktop measures throughput as it uploads. It sizes each part to take about two seconds and
  keeps one to four parts in flight, backing off when the node is busy or the link drops packets. The node caps parts
  at `transfer.max_part_bytes` on the device listener (512 MiB by default), compared with 64 MiB for browsers.
- **Resumes.** Acknowledged parts are stored on the node and survive dropped connections, network changes, quitting
  Desktop and daemon restarts. Desktop sends only the missing bytes.

## How Desktop Picks A Route

Desktop collects candidate addresses for a node from several sources:

1. `127.0.0.1` and `::1` at the listener's port, for every node. The pinned key decides whether the server that
   answers is this node.
2. The address you entered when you added the node.
3. The addresses the node advertises (`device.endpoints`), asked for after each connection and cached.
4. The last address that worked.
5. Bonjour (`_vaulthalla._tcp`), only when everything above has failed, and only for a service whose `node_id` matches.

It probes up to four candidates at once, best class first, with three seconds per probe and six seconds in all. It
then picks the best class that verified:

| Class (as Desktop shows it) | Addresses |
| --- | --- |
| Localhost | `127.0.0.1`, `::1`: Desktop and the node on the same Mac |
| LAN | Private IPv4 ranges (RFC 1918), IPv6 ULA (`fc00::/7`), `<hostname>.local`, names under `advertise.hostnames` |
| VPN | `100.64.0.0/10` (Tailscale) and addresses on `tailscale*`, `wg*`, `zt*` and `utun*` interfaces |
| Direct WAN | Public addresses: an interface's global address, or `advertise.public` entries (`kind: wan`, the default) |
| Passthrough | `advertise.public` entries with `kind: passthrough`: an SNI router on port 443 in front of the listener |

A host name is classified by the address it resolves to, so split-horizon DNS works. If `device.example.com` resolves
to `192.168.1.10` at home and to your public address elsewhere, Desktop treats it as LAN at home and as Direct WAN
outside.

Desktop chooses again when it connects, when the Mac's network changes, after two failed reconnects in a row, when a
transfer loses its connection, and every 30 minutes while it is on a route worse than LAN, so it can move back to a
better one. Uploads, downloads, previews and MCP all use the selected route.

### What The Node Advertises

The node lists:

- its interface addresses, classified by range. Loopback-only listeners list loopback addresses only. Container and
  bridge interfaces are skipped (`docker*`, `br-*`, `veth*`, `virbr*`, `podman*`, `cni*`, `flannel*`, `lxc*`), as are
  link-local addresses;
- `<hostname>.local`, where an mDNS responder runs (always on macOS; on Linux when avahi is running);
- the names and addresses you configure under `device_server.advertise` (see
  [Configuration](/reference/configuration#service-endpoints)).

The node never asks an outside service for its public address. List port forwards, tunnels and passthroughs yourself
under `advertise.public`. Only paired devices and signed-in users opening a pairing window see the list: a
connection that can only pair never receives it.

:::callout[Bonjour]{variant="note"}
The server doesn't register a Bonjour service yet. Desktop browses for `_vaulthalla._tcp` as a last resort and uses a
result only when its `node_id` matches. Without one, Desktop relies on the advertised addresses (which include
`<hostname>.local` where mDNS runs).
:::

### Pairing Links

The web console's **Pair a device** dialog lists the addresses this node can be reached on, with a copy button, and
offers **Open in Vaulthalla Desktop**. That link (`vaulthalla://pair?node=…&spki=…&endpoints=…`) fills in Desktop's Add
Node sheet with the node id, the server key fingerprint and the addresses. Desktop probes the addresses and refuses a
pairing connection to a server whose key differs from the link's.

The link only saves typing. **The six-digit code is still the proof** that the Mac is pairing with this node: compare
it every time, as described in [Pair a device](/admin/devices#pair-a-device).

## Reaching The Node From Outside

Desktop on the same network needs only `vh device remote enable` (a super admin command) and, if the host runs a
firewall, a rule for `36972/tcp`. To connect from elsewhere, pick one of these:

| Option | What you set up | Use it when |
| --- | --- | --- |
| VPN (Tailscale, WireGuard, ZeroTier) | The VPN on the node and the Mac. Nothing is exposed. | You already run one. This is the safest choice. |
| Direct WAN on port 36972 | Remote connections on, a firewall rule, a router port forward, a DNS-only record, `advertise.public` | The node has (or can forward) a public address. |
| TLS passthrough on port 443 | An SNI router (nginx `stream`) in front of the listener, a DNS-only record, `advertise.public` with `kind: passthrough` | Port 36972 is blocked on the networks you connect from, or you want a single public port. |

A VPN needs no node configuration. Its addresses are advertised automatically as the VPN class.

## Direct WAN On Port 36972

:::steps

### Turn on remote connections

```bash
vh device remote enable
```

The listener then accepts IPv4 and IPv6 on every interface. Super admins can also use **Devices → All devices →
Remote connections** in the web console.

### Open the port in the host firewall

Allow `36972/tcp` inbound. The commands are listed in [Host Firewalls](#host-firewalls).

### Forward the port on your router

Forward TCP port `36972` from the router's public address to the node's LAN address, also on `36972`. Give the node a
fixed LAN address (a DHCP reservation) so the forward keeps pointing at it.

With IPv6 there is no NAT. Instead, the router's IPv6 firewall must allow inbound `36972/tcp` to the node's global
address. That address is advertised automatically as Direct WAN.

### Create a DNS-only record

Point a name such as `device.example.com` at your public address with an `A` record (and `AAAA` for IPv6). If your
DNS is on Cloudflare, the record **must be DNS-only (grey cloud)**: see [Cloudflare](#cloudflare). If your public
address changes, keep the record current with dynamic DNS.

### Advertise it

In `config.yaml` (`/etc/vaulthalla/config.yaml` on Linux, `/Library/Application Support/Vaulthalla/config.yaml` on
macOS):

```yaml
device_server:
  advertise:
    public:
      - {host: device.example.com, port: 36972}
```

Restart the daemon (`sudo systemctl restart vaulthalla`, or `sudo launchctl kickstart -k system/sh.vaulthalla.server`
on macOS). Paired Macs pick the new address up the next time they connect on any route.

### Prove it from outside

Take the Mac off your network (a phone hotspot works) and check Desktop's connection panel: see
[Check That It Works](#check-that-it-works).

:::

The DNS name can be the console's own name only when that record is also DNS-only. If the console sits behind
Cloudflare's proxy, use a separate DNS-only name for the device listener.

## TLS Passthrough On Port 443

A passthrough shares port 443 with the web console. A layer-4 router reads the server name in the TLS ClientHello
(SNI) and hands connections for the device name, still encrypted, to the device listener. Everything else goes to the
console. Nothing in between terminates TLS: Desktop's client certificate and the node's pinned key travel end to end.

- **nginx on Linux:** use a `stream {}` server with `ssl_preread`. The complete configuration is in
  [Share Port 443 With Vaulthalla Desktop](/https/nginx#share-port-443-with-vaulthalla-desktop).
- **Caddy on macOS:** Caddy's HTTP server can't pass TLS through. Layer-4 routing needs the third-party `caddy-l4`
  plugin, which the bundled Caddy doesn't include and `vh setup caddy` doesn't configure. On macOS, use a VPN or
  direct WAN. See [Caddy](/https/caddy#vaulthalla-desktop-and-port-443).

Port 443 must reach the host from outside, as it already does for a public console (a router port forward behind
NAT). Advertise the passthrough with its own kind, and use a host name, not an IP address: the SNI router routes by
the name.

```yaml
device_server:
  advertise:
    public:
      - {host: device.example.com, port: 443, kind: passthrough}
```

What changes with a passthrough:

- The SNI router connects to the listener over loopback, so a passthrough works **with remote connections off**. Port
  36972 then stays closed to the network, and only 443 is public. Macs learn the passthrough address from the
  pairing link or after any connection, or you can add the node in Desktop as `device.example.com`, port 443.
- The node sees every passthrough connection as coming from `127.0.0.1`. That address appears as the device's last
  address and on pairing requests. The per-address pairing rate limit is shared by every passthrough client, and
  passthrough connections never count as proof of a direct public connection (`last_remote_device_at`).
- `vh device remote disable` doesn't close passthrough connections, because they arrive over loopback. To stop the
  passthrough, remove the device name from the SNI router, or revoke the device.

## Host Firewalls

Open `36972/tcp` for direct LAN or WAN connections. A passthrough needs only 443, which the console already uses.

:::tabs{default="ufw"}

:::tab[ufw]{value="ufw"}
```bash
sudo ufw allow 36972/tcp                                              # from anywhere
sudo ufw allow from 192.168.1.0/24 to any port 36972 proto tcp        # or: your LAN only
sudo ufw status
```
:::

:::tab[firewalld]{value="firewalld"}
```bash
sudo firewall-cmd --permanent --add-port=36972/tcp
sudo firewall-cmd --reload
sudo firewall-cmd --list-ports
```
:::

:::tab[nftables]{value="nftables"}
Add a rule to the `input` chain in `/etc/nftables.conf` (table and chain names vary by distribution), then check the
file and load it:

```text
tcp dport 36972 accept
```

```bash
sudo nft -c -f /etc/nftables.conf     # check only
sudo nft -f /etc/nftables.conf
```
:::

:::tab[macOS]{value="macos"}
The macOS application firewall filters by program, not by port. When it is on, allow incoming connections for
`vaulthalla-server` in **System Settings → Network → Firewall → Options**, or:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/local/bin/vaulthalla-server
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /usr/local/bin/vaulthalla-server
```

**Block all incoming connections** overrides per-app rules. pf, if you have configured it, is separate.
:::

:::

Cloud servers usually have a provider firewall (a security group) in front of the host as well. Open the port there
too.

## Cloudflare

The device listener can't run behind Cloudflare's proxy. A proxied (orange-cloud) record sends clients to Cloudflare,
which terminates TLS at its edge and opens its own connection to your origin. Desktop's client certificate never
reaches the node, and Desktop would see Cloudflare's certificate instead of the node's pinned key. Both checks fail
by design, so a proxied device name never works. Cloudflare's proxy doesn't carry port 36972 either.

**The device host name must be DNS-only (grey cloud).** This is true for direct WAN on 36972 and for a passthrough on
443. The console can stay proxied under its own name. Its limits (request size per plan, response timeouts) are
described in [Cloudflare In Front Of The Console](/https#cloudflare-in-front-of-the-console).

## Check That It Works

What the node can tell you:

- `vh device remote status` and the web console's **Remote connections** card show whether the listener is
  listening, on which addresses, and the server key fingerprint.
- For super admins, the ws `device.remote.status` answer adds diagnostics: every bound socket, the addresses devices
  are told, a read-only look at the host firewall (ufw, firewalld, nftables, the macOS application firewall; "unknown"
  when it can't tell without root), and `last_remote_device_at` / `last_remote_device_ip`.

These checks only inspect the node itself. They can't see your router, your ISP or a cloud firewall, so they can't
prove that the node is reachable from the internet. The proof is a Desktop connecting from outside:

- In Desktop, the node's **Overview → Connection** panel shows the active route class (Localhost, LAN, VPN, Direct
  WAN, Passthrough), the endpoint and address reached, the verified key, the round-trip time and the transfer
  throughput. For every candidate that wasn't used, it says why, with a technical detail line. **Test Connection**
  runs a fresh selection and measures throughput without writing anything on the node.
- On the node, `last_remote_device_at` records the latest paired-device connection from a public address. It covers
  public addresses only: LAN, VPN (`100.64.0.0/10`) and passthrough connections don't count. It is kept in memory and
  cleared by a daemon restart.

## Troubleshooting

| Desktop shows for a candidate | Likely cause | Fix |
| --- | --- | --- |
| "a different server answered there" (`identity_mismatch`) | Another server or another node answers at that address: a stale DNS record, a reused LAN address, a port forward pointing at the wrong host, a TLS-terminating proxy (a proxied Cloudflare record), or, on a passthrough, an SNI router that sends the name to the console (the name is missing from its map). | Fix the record or the forward. Make the device name DNS-only. Desktop ignores that candidate and doesn't ask to pair again. |
| "no answer in time" (`timeout`) | A firewall drops the packets: the host firewall, a cloud security group, a missing router forward, or a network that blocks outbound 36972. | Open the port at every layer ([Host Firewalls](#host-firewalls)), add the forward, or use a passthrough on 443. |
| "nothing is listening there" (`refused`) | The listener is loopback-only (remote connections off) or not running, or nothing listens on that port. | `vh device remote status`, then `vh device remote enable`. |
| "the secure connection failed" (`tls_error`) | Something answered but isn't the device listener, or it isn't TLS 1.3 end to end (a proxy in the path). On a passthrough, the SNI router accepted the connection but couldn't reach the listener. | Check what owns the port and that nothing terminates TLS in front of the listener. For a passthrough, check that the daemon is running and the nginx error log. |
| "the name doesn't resolve from this Mac" (`unresolved`) | No DNS record for that name, or a LAN-only name used outside the LAN. | Create the record. LAN names (`.local`, `advertise.hostnames`) only work inside the network. |
| Works on the LAN, not from outside | No port forward, `advertise.public` missing, a proxied (orange-cloud) record, or the ISP uses carrier-grade NAT. | Add the forward and the `advertise.public` entry, make the record DNS-only. If the router's WAN address is in `100.64.0.0/10` or differs from your public address, port forwarding can't work: use a VPN. |
| The Direct WAN candidate fails at home but works outside | The router doesn't loop traffic back to its own public address (no NAT hairpin). | Nothing to fix: Desktop uses the LAN route at home. |
| Every candidate shows `identity_mismatch` | The node's key changed (for example, its state was restored without the sealed secrets). | Pair again. See [Paired Devices](/admin/devices#troubleshooting). |

## Security

Turning on remote access exposes the device listener's address. Weigh what that means:

- **Every connection needs a client certificate.** The listener refuses any TLS connection that doesn't present one.
  A certificate that isn't a paired device can only ask to pair. Pairing works only while a user has a pairing window
  open (10 minutes, one window per node, at most 5 pending requests), at most 10 requests per address per minute,
  and a request is approved only when a person picks the six-digit code the Mac shows.
- **The origin's address becomes public.** A DNS-only record publishes your public IP address, and nothing like
  Cloudflare's DDoS protection stands in front of that port. If the console relies on Cloudflare's proxy to hide
  the origin, a device name points straight past it. A passthrough on 443 also opens 443 to everyone, so it doesn't
  fit an origin that only accepts Cloudflare's addresses. Direct WAN on 36972 leaves 443 alone.
- **Keep remote connections off when you don't need them.** `vh device remote disable` closes every non-loopback
  device connection at once. A VPN gives remote Macs the same direct route without exposing anything.
- **Advertise only what's needed.** Every name under `advertise.public` is told to every paired device. Leave out
  addresses you don't want devices to use, and exclude interfaces with `advertise.exclude_interfaces`.
- **Limit who can reach the port.** Where only known networks connect, restrict the firewall rule to them.
- **Revoke lost or retired Macs.** `vh device revoke <id>` (or **Devices** in the console) closes the device's
  connections and refuses its key from then on. See [Manage devices](/admin/devices#manage-devices).
