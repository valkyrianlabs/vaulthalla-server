<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Direct device connections and resumable uploads

## Vaulthalla Desktop connects directly

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

## Web console

- **Large uploads survive interruptions.** On servers that offer resumable uploads, the console sends files in parts
  of up to 64 MiB (under Cloudflare's 100 MB request limit), up to three at a time, each checked with a SHA-256
  digest on HTTPS. A dropped connection, a busy server or a daemon restart no longer restarts the file: the console
  waits, asks the server which bytes it already has and sends only the rest. After a page reload, choosing the same
  file again in the same place picks up where it stopped ("Resuming … already on the server"). Shared upload links
  get the same behavior. Older servers keep the previous whole-file uploads.
- When some files of a batch fail, the transfers panel now names each one and why (already exists, no room left in
  the vault, the vault key changed so the file must be uploaded again, and so on).
- **Pair a device** lists the addresses this server can be reached on (copyable) and offers **Open in Vaulthalla
  Desktop**, which fills in Desktop's Add Node sheet with those addresses and the server key. The six-digit code match
  stays the proof that you are pairing with the right server.

## Uploads resume where they stopped

Vaulthalla now offers resumable uploads (`/upload/sessions`, capability `http.upload.resumable`) on the web console
listener and on the Vaulthalla Desktop device listener, share links included. A client uploads a file in parts, in
any order and in parallel; every acknowledged part is durable, survives a dropped connection or a daemon restart,
and a client resuming asks which byte ranges the server holds and sends only the gaps. Resending a part is
harmless (same bytes are accepted, different bytes are refused), and an optional `Content-Digest` catches corruption
in transit.

- Files may now be as large as the vault format allows (about 64 GiB per file) instead of 8 GiB.
- Nothing is stored in plaintext while an upload is in flight: each part is encrypted the moment it arrives, and the
  server seals the file in the background as its parts come in, so finishing a large upload takes seconds instead of
  re-encrypting the whole file.
- Create-only and compare-and-swap replacement work per file, exactly as on `PUT /upload/content`; a file that
  appears at the target before the upload commits is reported, never overwritten or silently dropped.
- Sessions expire 24 hours after their last part (at most 7 days after they began) and their temporary data is
  removed. New `transfer:` settings in `config.yaml` tune part sizes and limits; out-of-range values are refused.

The existing upload lanes keep working unchanged for older clients.

