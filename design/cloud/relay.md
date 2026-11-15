# Vaulthalla Cloud relay: the server's side (wave 2, as built)

How a linked server lets a browser on `app.vaulthalla.cloud` reach it through one outbound connection to
`relay.vaulthalla.cloud`, which forwards bytes it cannot read: the outbound service, the relayed streams on the
device listener, the browser's key proof, pairing a browser, and the read-only set. The protocol is the cloud's
`docs/design/relay.md`, "As built" (valkyrianlabs/vaulthalla-cloud); this note says what the server does with it,
where it had to fix a detail, and what the portal implements against it. Held here, never published, until
vaulthalla.cloud opens (the claims lint allows no product text about it).

## Decided

- **Opt-in per server**, by a super admin, off by default (Cooper). The account holder has a switch at the cloud too;
  both must be on (a ticket answers 403 `relay_disabled` while the cloud's is off).
- **Option (c)** (Cooper, 2026-11-15): inside each relayed stream the browser runs TLS 1.3 with a mature library,
  authenticates the server by its pinned SPKI hash and presents no certificate, then proves its own key in an
  application-level challenge signed with WebCrypto. The device listener gains a second way to authenticate a peer,
  used only on relayed streams.
- **A browser pairs like a device:** a pairing window, the SAS compared by number matching, the owner's approval
  (`device.trust` step-up), a `devices` row bound to one user and that user's RBAC. The cloud never pairs.
- **Wave 2 is read-only:** browse, thumbnails, previews and downloads. The server enforces it.

## Invariants (each has a test)

- Nothing runs, and nobody is contacted, unless the server is linked, the local switch is on for this installation
  and `device_server.enabled` holds (`NothingRunsUntilTheSwitchIsOn...`). A self-hosted server never needs the cloud.
- The second authentication path is unreachable from the network listener: `Listener` connections always use
  `makeServerContext` (a client certificate required, verified after the handshake) and carry no `RelayedOrigin`;
  only `startRelayedConnection` builds a relayed connection, and only `CloudRelayService` calls it, with a socketpair
  end (`TheNetworkListenerNeverAdmitsAPeerWithoutACertificate`).
- A relayed peer that has not completed the key proof can do nothing: no HTTP byte is read before the proof
  verifies (the 10 s handshake deadline covers TLS, the proof and the request).
- A paired browser has at most its user's rights, narrowed to the read-only set, on every connection: the rule
  follows `Peer.relayed` (this connection came through the relay) **or** `Peer.pairedViaRelay`
  (`devices.paired_via = 'relay'`), never the platform string.
- Refused, each with a test: a ticket for another server (`dep`) or account (`acct`), an expired or not-yet-valid one,
  one signed by a key the ticket answer didn't list, a server ticket, an extra claim, a replayed `jti`; a proof by
  another key, a proof from another TLS session (exporter), a proof replayed against a new challenge, a malformed
  record; a revoked browser key (pairing-only again, `device_unknown`).

## The outbound connection (`cloud/RelayService`, runtime service `CloudRelayService`)

Started after `DeviceServer`, stopped before it. Two threads of its own, never a FUSE, ws or HTTP thread:

- **The service thread** decides, every 250 ms (the switch and link from the database every 10 s or when woken): off,
  `not_linked`, `listener_off`; otherwise it fetches a ticket (`POST /v1/relay/server-tickets`, VHC1-signed with the
  installation key through `cloud::signedCall`; blocking, bounded by the http client), checks the answer
  (`relay_url` is `wss://host[:port]`, or `ws://` to a loopback host for development; `deployment_id` is this link's;
  at least one 32-byte ticket key), and hands it to the I/O thread. At `renew_after` it fetches a fresh ticket and
  sends RENEW, retrying every 30 s until `renew_by` (the relay closes the connection then).
- **The I/O thread** runs the socket: WebPKI TLS to the relay (system trust store, SNI, host name verification), the
  WebSocket upgrade to `/v1/server`, TICKET, CHALLENGE, PROOF (`Ed25519(seed, "vhc-relay-connect-v1\n" + jti + "\n" +
  base64url(challenge))`; the seed is dropped right after), WELCOME (`renew_by`, `window`), all within 15 s. Beast
  keep-alive pings after 20 s of silence and drops the socket after 40 s (the relay pings every 30 s).
- **Backoff:** 1 s to 5 minutes with full jitter, reset after a connection that stayed up 60 s. Ticket refusals:
  401, 404 or another 403 stop the service (`stopped`) until the switch is switched on again or the link changes;
  403 `relay_disabled`, 402 and 503 are `waiting`, retried every 5 minutes; 429 and anything else back off (429 at
  least 60 s).
- **Status never fakes state:** `connected` only after WELCOME and until the socket ends; `vh cloud relay status`,
  ws `cloud.relay.status`: `state` (`off`, `not_linked`, `listener_off`, `connecting`, `connected`, `backoff`,
  `waiting`, `stopped`), the switch and who set it, `relay_url`, `connected_since`, `renew_by`, `last_ticket_at`,
  `next_attempt_at`, `last_error`, open, accepted and refused streams.
- **Shutdown:** a close frame (4009 at daemon shutdown, 1000 when switched off), every relayed session closed
  (`closeRelayedDeviceSessions`), the I/O thread joined within the 10 s exit bound.

## A relayed stream

On OPEN `{ticket, remote}` the I/O thread re-checks the browser ticket (`cloud/RelayProtocol`,
`verifyBrowserTicket`): signature first (any key of the latest ticket answer), exactly the browser claims, `typ`
browser, `aud` the audience of this server's admission, `acct` and `dep` this link's, valid from `iat - 30 s` to
before `exp`, at most 300 s long, `jti` once (an in-memory ledger kept until `exp`, bounded, failing closed). It
creates a local `socketpair`, keeps one end (DATA from the relay written into it, CREDIT sent once written; read up
to the remaining credit and sent as DATA of at most 64 KiB), and hands the other to
`DeviceServer::acceptRelayed`, which runs the listener's own `Connection` over it on the listener's io_context (a
device connection slot, the same certificate and pin a Desktop sees). Any refusal sends CLOSE `refused` and is
audited (`cloud.relay.refused`, actor `system`, `reason`, `remote`, `browser_key`: at most 20 a minute, the rest
counted in the log). Failed proofs and refused tickets count against the browser key hash (5 a minute) and in all
(30 a minute); past either, OPENs are refused `rate_limited`. A relay-reported `remote` that is loopback or
unspecified is recorded as `unknown`: a relayed peer is never loopback, stays open when remote connections go off,
and is closed when the relay goes off.

Chosen over a stream adapter: a socketpair keeps `TlsTransport`, `ws::Session`, `http::Session` and their
deadlines unchanged, bounds what is buffered by the kernel's socket buffers plus one window, and carries no identity
(that travels in `RelayedOrigin`).

### The key proof (normative for the portal)

After the inner TLS 1.3 handshake (the browser checks the server certificate's SPKI SHA-256 against its pin; at first
pairing it has none, and the SAS binds the server key), before any HTTP byte:

```
server -> browser   0x01 ‖ nonce[32]                                   33 bytes, a fresh CSPRNG nonce per stream
browser -> server   0x01 ‖ spki[91] ‖ signature[64]                    156 bytes

spki       the browser key's SubjectPublicKeyInfo, DER: WebCrypto exportKey("spki") of its P-256 key (91 bytes,
           uncompressed point); SHA-256 of it must equal the ticket's `spki`
signature  ECDSA P-256 / SHA-256, raw r ‖ s (WebCrypto's output, 32 + 32 bytes), over the UTF-8 bytes of
           "vhc-relay-browser-proof-v1\n" + jti + "\n" + base64url(nonce) + "\n" + base64url(exporter)
jti        the browser ticket's `jti`, as in the ticket
exporter   TLS 1.3 exporter (RFC 8446 7.5) of this session: label "EXPORTER-vhc-relay-browser-v1", no context (the
           same as an empty one in TLS 1.3), 32 bytes
base64url  without padding
```

No acknowledgement: on success the stream is a listener connection (the browser sends its HTTP request, normally the
`/ws` upgrade, right after the proof); on failure the server closes it and sends CLOSE `refused`, which the browser
sees as WebSocket close 4007. The proven key then authorizes exactly like a client certificate's: a live `devices`
row (current or previous key) gives a Device session as that row's user, anything else a pairing-only session.

## Pairing a browser

The Desktop ceremony over a relayed stream (`docs/pairing.md` in vaulthalla-desktop, section 3), unchanged except:
the request's `via` is `relay` (from the connection), the row's `paired_via` is `relay` (migration 144), a relayed
request carrying `approval_key` is `invalid` (#361: approvals happen in the console), the approval is audited as
`device.pairing.approve` with `via`, and a relay-paired device never gets a key-backup grant. The owner sees the
request in `device.pairing.pending` (`via: relay`) and the device in `device.list` (`paired_via: relay`);
`vh device revoke` or ws `device.revoke` from the console unpairs it and closes its sessions. Pairing attempts keep
the existing limits (5 per window, 10 a minute per address) and need an open window and the owner's code choice.

## The read-only set

`Router::isRelayedReadCommand` is an allowlist, checked in `classifyCommand` for every Device session whose peer is
`readOnly()` (refused ERROR `data.code: relay_read_only`): `meta.hello`, `meta.contract.get`, `storage.vault.list`,
`storage.vault.accessible.list`, `storage.vault.get`, `fs.list`, `fs.dir.list`, `fs.metadata`,
`fs.download.start|chunk|cancel`, `fs.changes.list|subscribe|unsubscribe`, `device.list`. A pairing-only relayed
session keeps the pairing set (`device.pair.*`, `meta.*`). On the HTTP lanes `http::Session::serve` allows such a
peer only `GET`/`HEAD` on `/preview*` and `/download*`, per request (a keep-alive connection's later requests too);
`/upload*`, `/transfer*` and `/mcp` answer 403 `relay_read_only`. `CloudRelayReadOnly.Every...` walks every
registered ws command on a relayed super admin's session.

## The switch

`vh cloud relay status|enable|disable` and ws `cloud.relay.status|enable|disable` (capability `cloud.relay`;
`ops::cloud_relay`). Status: super admins or the admin cloud View permission. Enable and disable: super admins, never
an agent (`vh mcp` excludes both); enabling is a `device.trust` step-up (like remote device connections) and needs a
link (`conflict` otherwise). Stored in `cloud_relay` (migration 144): one row naming the installation it was enabled
for, so relinking leaves the relay off. Audited `cloud.relay.enable` / `.disable`. Switching off closes the connection
and every relayed session at once; paired browsers stay paired.

## Decisions made here (compatibility policy rule 5: the simplest secure option)

1. **The exporter is required**, not "when the library exposes one". Without it a relay that terminates the inner
   TLS (possible before the browser holds a pin) could forward the server's nonce to the browser and its proof back
   to the server, and be admitted as that key. Undo: none advisable; a portal library without RFC 8446 exporters
   is not usable.
2. **Fixed binary records** (33 and 156 bytes, version byte 0x01) and a raw `r ‖ s` signature: what WebCrypto emits,
   no parser on either side. A new version byte is how it changes.
3. **No acknowledgement** of the proof; a refusal is CLOSE `refused`.
4. **Wave 2 read-only as an allowlist** rather than the relay design's denylist; `/upload` is not exposed yet.
   Undo/extend: add commands to `isRelayedReadCommand` and lanes to `isReadOnlyDeviceRequest`, with the test's
   reviewed set.
5. **`device.revoke` is not in the read-only set**, so the portal cannot clean up stale browser devices itself yet
   (a super admin's relayed session could revoke anyone's device). Undo: allow it restricted to the caller's own
   web devices.
6. **A relay-paired device is read-only on every connection**, the network listener included.
7. **Server-side failure limits:** 5 failed proofs or refused tickets a minute per browser key hash, 30 in all;
   refusal audits capped at 20 a minute.
8. **403 `relay_disabled` waits** (retried every 5 minutes) instead of stopping the service: the account holder may
   switch it on at any time. 401, 404 and any other 403 stop it until the switch is turned on again.
9. **Liveness:** pings after 20 s of silence, dropped after 40 s (the cloud's text says 60 s for both ends; the relay
   pings every 30 s, so either works).
10. **No new configuration:** intervals and limits are constants; the switch is in the database.
11. **No new TLS or WebSocket library:** Boost.Beast/Asio and OpenSSL, already linked, do both ends.

## What the cloud's `docs/design/relay.md` must change

- "As built: The channel inside", step 2: drop "when the library exposes a TLS exporter"; the exporter is
  mandatory, with no context; replace "Proposed message, for the server and portal designs to fix" by the records
  above (version byte, 91-byte SPKI, raw 64-byte signature, no acknowledgement, refusal = CLOSE `refused`).
- "The server's connection", step 5, and "Close codes", last paragraph: a 403 `relay_disabled` on a ticket waits and
  retries; 401, 404 and other 403s stop the service. Liveness: the server drops a socket silent for 40 s.
- "What the server exposes over the relay": wave 2 exposes `/ws` (pairing-only, or a Device session held to the
  read-only allowlist above) and `GET`/`HEAD` `/preview` and `/download`; `/upload`, `/transfer` and `/mcp` answer
  403; the denylist paragraph becomes the allowlist; `device.revoke` is not available to a relayed session yet.
- "Re-pairing": the portal can list (`device.list`) but not revoke stale web devices in wave 2.
- "Pieces for the server and portal designs": the 413 cap on `/download` is not built (the relay's `CLOSE limit`
  enforces `lim.stream_bytes`).

## For the portal

1. **Keys.** One non-extractable P-256 key per browser and deployment; register it (`POST /v1/relay/browser-keys`).
2. **A stream.** `POST /v1/relay/browser-tickets {browser_key_id}`; `wss://<relay_url>/v1/browser`, TICKET first;
   after WELCOME, DATA and CREDIT carry the inner stream (window 256 KiB each way, DATA at most 64 KiB).
3. **Inner TLS 1.3** with no client certificate; accept the server certificate only if its SPKI SHA-256 equals the pin
   (no pin yet: accept and note it; the SAS binds it). Then read 33 bytes, send the 156-byte proof, then HTTP/1.1.
4. **Pairing** (no pin yet): the owner opens a window on the server (console, `vh device pair` or Desktop). Over the
   stream: `/ws` upgrade, `meta.hello`, `device.pair.request {name, platform: "web", app_version, commitment =
   hex(SHA-256("vh-pair-commit-v1" ‖ device_spki_sha256 ‖ nonce_device))}` (no `approval_key`), then
   `device.pair.confirm {request_id, nonce_device}`; show the six digits of
   `SHA-256("vh-pair-v1" ‖ server_spki_sha256 ‖ device_spki_sha256 ‖ nonce_device ‖ nonce_server)` (first 8 bytes
   big-endian mod 10^6, shown "482 913"), and poll `device.pair.status {request_id}` until `approved`, then store the
   pin (`server_spki_sha256`) and the device id with the key. `device_spki_sha256` is SHA-256 of the same 91-byte
   SPKI the proof carries.
5. **A paired session:** a new stream; the same proof now gives a Device session as the owner. Allowed: `meta.hello`,
   `meta.contract.get`, `storage.vault.list`, `storage.vault.accessible.list`, `storage.vault.get`, `fs.list`,
   `fs.dir.list`, `fs.metadata`, `fs.download.start|chunk|cancel`, `fs.changes.list|subscribe|unsubscribe`,
   `device.list`; previews and downloads as `GET`/`HEAD` on `/preview*` and `/download*` (one stream each, or a small
   pool). Anything else answers `relay_read_only` (ws) or 403 (HTTP). Check `meta.hello`'s capabilities for
   `cloud.relay`.
6. **Errors to show:** WebSocket close 4007 (`refused`: a bad proof, a revoked or unknown key on a paired path, or the
   server's limits), 4006 (`offline`), `device_unknown` (the key isn't paired: pair again with a new key).

## Not built

- The 413 cap on `/download` from the ticket's `lim.stream_bytes` (the relay enforces it with `CLOSE limit`).
- Console UI: the switch on the cloud settings page and "Web browser via Vaulthalla Cloud" in the pairing dialog and
  device list (the ws data is there: `via`, `paired_via`, `cloud.relay.*`).
- Uploads and changes from a relayed session (a later step).
