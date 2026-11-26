# Server link: pairing two Vaulthalla servers

Status: phase 1a built (2026-11-25), experimental and off by default (`peers.experimental` in config.yaml): pairing,
the link, unlinking and the announced identity rotation, and the console's Linked servers page; not Desktop's brokered
flow. What the
build changed or decided is in "As built (phase 1a)" at the end; the rest of this text is the design. It covers how two
servers pair, how they authenticate each other afterwards, what a linked server may call, and how the link is
unlinked and rotated. It does not cover what travels over the link for a mirrored vault ([`mirror.md`](mirror.md)) or
how accounts are shared ([`identity.md`](identity.md)). No part of it needs vaulthalla.cloud.

## Decided and given

- **Servers pair with each other directly, or through a Desktop that is paired with both** (Cooper, 2026-11-25). The
  link is a long-lived, mutually authenticated channel like Desktop and server have, and it is the only path two
  servers sync through.
- **A linked server may receive vault keys over the link;** the compared pairing code is the proof of provenance
  (Cooper, 2026-11-25, decision 1). The keys this needs are therefore bound into the pairing transcript (below).
- **Desktop-brokered linking needs only super-admin rights on both nodes,** no step-up (Cooper, 2026-11-25, decision
  2, extending the 2026-11-23 rule that a paired Desktop is gated by RBAC alone).
- **From the existing device pairing** (`docs/pairing.md` in vaulthalla-desktop, decisions D2 and D3 there): no
  certificate authority; each side pins the other's SPKI hash and never consults a trust store; a short
  authentication string (SAS) compared by number matching closes the trust-on-first-use gap.

## What exists and is reused

| Piece | Where | Reused as |
|---|---|---|
| Device listener: TLS 1.3, client certificate required, ECDSA P-256 with SHA-256 only, the peer authorised by its key at the handshake | `core/src/protocols/device/Listener.cpp`, `core/src/device/Peer.cpp` | The accepting end of a link |
| The server's identity: a self-signed P-256 certificate whose key is sealed through `KeyProvider` (slot `device_tls`, versioned) | `core/include/device/ServerIdentity.hpp` | Both ends: the listener's certificate and the dialling side's client certificate |
| Pairing windows and requests, in memory only: 10-minute window, commitment, nonces, the SAS and its two decoys | `core/include/device/Pairing.hpp`, `core/src/device/Pairing.cpp:231-262` | The pairing state machine, with a second transcript domain |
| Endpoint advertisement and selection (loopback, LAN, VPN, WAN, passthrough) | `core/include/protocols/device/Endpoints.hpp` | How a server finds its peer again |
| Desktop brokering a second key onto a node | vaulthalla-desktop `Sources/VHNodes/AgentPairing.swift` | The shape of Desktop-brokered linking |

What does not exist:

1. **An outbound client that presents a certificate.** The server's outbound connections today are to the cloud:
   `cloud::RelayService` (a websocket client using the system trust store and hostname verification) and
   `cloud::Client` (curl with signed requests). Neither pins a key or presents the server's identity.
2. **A principal that is not a person.** `devices.user_id` is NOT NULL (`deploy/psql/112_devices.sql`); a device
   session acts as its user with that user's RBAC and is granted the key-export channel
   (`core/src/protocols/ws/handler/vault/Keys.cpp:29-33`).
3. **A second server key for unwrapping.** The identity key signs; nothing wraps to a server.

## The peer principal

A linked server is a **peer**: its own kind of principal, in its own table. It is never a row in `devices` and never
acts as a user.

```sql
peer (
  id                  serial primary key,
  node_id             text not null unique,      -- the peer's device_node.node_id
  name                text not null,             -- shown in every UI; editable locally
  spki_sha256         text not null unique,      -- the pin
  next_spki_sha256    text,                      -- announced by peer.identity.rotate, not yet in use
  attest_public_keys  jsonb not null,            -- Ed25519: the peer's key-attestation keys, current and retired
  wrap_public_key     bytea not null,            -- X25519: vault keys for this peer are wrapped to it
  endpoints           jsonb not null,            -- what the peer advertised; refreshed over the link
  sharing             text not null,             -- 'identities' | 'full' (identity.md)
  approved_by         integer references users,  -- who approved it here
  linked_at           timestamptz not null,
  last_seen_at        timestamptz,
  revoked_at          timestamptz                -- unlinked; the row is kept for the audit trail
)
```

As built (`deploy/psql/157_peers.sql`): node_id and spki_sha256 are unique among live rows only (partial indexes), so
that "linking the same server again writes a new row" holds; and four more columns: `rotate_counter` (the last
rotation announcement accepted), `compared_by` (person | desktop), `peer_protocol` and `product_version` (the card's,
then each peer.hello's).

- **What a peer session may call:** `peer.*` wire commands, `meta.hello` and `meta.contract.get`. Nothing else: no
  filesystem, vault, key, device, settings or account command. `Router::classifyCommand` gains a `PeerSession` branch
  that fails closed, the way a scoped device's does today (`core/src/protocols/ws/Router.cpp:279-292`).
- **What it is not given:** the key-export channel, any step-up family, the HTTP `/preview`, `/download`, `/upload`
  and `/mcp` lanes. The link gets lanes of its own (`mirror.md`).
- **How it is authorised for a vault:** by holding a vault role on that vault, checked on every change it submits
  (`identity.md`). A peer with no vault role on any vault can do nothing but stay connected.
- **In RBAC** it is a principal next to users and groups, so a vault's access list can name it. It can hold vault
  roles only: never an admin role.

## Keys

| Key | Type | Slot | Purpose |
|---|---|---|---|
| Identity | ECDSA P-256 | `device_tls` (exists) | TLS in both directions. One fingerprint per server, the same one a Desktop already sees |
| Attestation | Ed25519 | `key_attest` (exists) | Signs key-version attestations. Pinned by the peer at pairing, which is what makes a key version delivered over the link provable (decision 1) |
| Peer wrap | X25519 | `peer_wrap` (new) | The peer wraps vault keys and shared secrets to it. Sealed like the other slots; created when the first link is made |

One identity key for both the listener and the client is deliberate: an admin compares one fingerprint per server,
and the listener already limits client signatures to that key type. The cost is that rotating it touches links,
handled under "Rotation".

## Pairing

The handshake is the device handshake with its own domain separation, so a code shown for one can never be accepted
for the other.

1. **B opens a window** (`peer.pairing.open`, a super admin). It returns B's node id, SPKI hash and advertised
   endpoints, and lives 10 minutes. It shares the node-wide "one window at a time" rule with device pairing.
2. **A dials B** (`peer.link.start {endpoints, expect_spki?}`, a super admin on A). A connects with its identity
   certificate. With `expect_spki` (the brokered path) A refuses any other key at the handshake; without it A trusts
   on first use, guarded by the code in step 4.
3. **A sends `peer.pair.request`:** its peer card and a commitment to its nonce,
   `SHA-256("vh/peer/commit/v1" ‖ spki_A ‖ nonce_A)`. B answers with its own card and
   nonce; A reveals its nonce (`peer.pair.confirm`). A **peer card** is
   `{node_id, name, attest_public_keys[], wrap_public_key, peer_protocol, product_version}`. The attestation keys are
   every key the server has attested a vault key with, current and retired (`key_attestation_keys`), because an old
   key version carries an old key's signature.
4. **Both compute the code:**
   `sas = SAS(H("vh/peer/sas/v1" ‖ spki_B ‖ spki_A ‖ nonce_A ‖ nonce_B ‖ H(card_A) ‖ H(card_B)))`.
   Binding the cards is what authenticates the attestation and wrap keys: change either and the codes differ.
   `H(card)` is SHA-256 over `"vh/peer/card/v1" ‖ LP(node_id) ‖ LP(name) ‖ UInt32BE(n) ‖ attest_key[32] × n ‖
   wrap_key[32] ‖ UInt32BE(peer_protocol) ‖ LP(product_version)` (LP = UInt32BE byte length ‖ UTF-8), and `SAS` is
   device pairing's: `UInt64BE(digest[0..8]) mod 10^6`, six digits. The fixed vector Desktop implements against is
   `core/test-assets/peer/pairing-vectors.json` (code `227515`), recomputed independently by
   `tools/dev/peer_pairing_vectors.py`.
5. **A shows its code** to the super admin who started the link (`peer.link.status`). **B offers three choices**
   (`peer.pairing.pending`), as device pairing does.
6. **B's super admin picks the matching one** (`peer.pairing.approve {request_id, code, expect_spki?}`). B writes its
   `peer` row. A learns the outcome (`peer.pair.status`) and writes its own.
7. Both sides audit it. The window closes.

A failed or expired request leaves nothing on either side. The limits on requests per window and per address are the
device pairing's (`Pairing.hpp:35-36`).

### Three ways to drive it

| Path | Who compares the code | Trust on first use? |
|---|---|---|
| **Terminal:** `vh peer pair` on B, `vh peer link <address>` on A | A person, reading A's terminal and choosing on B's | Yes, closed by the code |
| **Web console:** "Accept a link" on B, "Link a server" on A | A person, across two browser tabs | Yes, closed by the code |
| **Desktop paired with both** | Desktop | No |

**Desktop-brokered, in full.** Desktop holds an authenticated, pinned session with each server, as a super admin on
each. It therefore already knows both servers' SPKI hashes.

1. Desktop calls `peer.pairing.open` on B.
2. Desktop calls `peer.link.start` on A with B's endpoints and `expect_spki` = Desktop's own pin for B.
3. Desktop reads A's code (`peer.link.status`) and B's pending request (`peer.pairing.pending`).
4. Desktop calls `peer.pairing.approve` on B with the request, A's code, and `expect_spki` = its pin for A. B refuses
   if the requesting key is not that one.
5. The person saw one sheet: "Link vps and Mac Studio? Each will be able to receive the vaults you mirror to it."

Nothing in this path trusts a key on first use, and no number is read by a person.

### Who may link servers

| Caller | May open, start or approve a link |
|---|---|
| Super admin on the host's control socket (`vh`) | Yes |
| Super admin in the web console | Yes, with the console's existing step-up for trusting a device |
| Super admin on a full-access, directly connected Desktop | Yes, on RBAC alone (decision 2) |
| Scoped device, AI app pairing, relayed browser, agent over MCP, share session | Never. The MCP catalog omits `peer.*`; the router refuses the rest |

Linking is not delegated below super admin in the first version. A "manage linked servers" admin permission can
follow once the feature has been used.

As built: the console's step-up (device.trust, target-bound) is asked by the two commands that make a link,
`peer.pairing.approve` and `peer.link.start`; opening a window, listing, renaming and unlinking ask none. On a
full-access, directly connected device the same two run on RBAC alone, but not during the account's recovery
cooldown. The refusal for the callers in the last row is `peer_forbidden` (ops), on top of the router's and the
MCP catalog's.

## The connection

- **One persistent websocket per pair** carries control and notices in both directions. Bulk data uses separate
  connections to the same listener with the same pins (`mirror.md`).
- **Either side dials.** Each tries the other's endpoints in the usual order (last good, LAN, VPN, WAN). If both
  connect at once, the connection dialled by the lower node id is kept.
- **Both ends check the pin on every connection.** The dialler verifies the listener's SPKI against `peer.spki_sha256`
  and nothing else; the listener looks the client's SPKI up in `peer` (not revoked) after looking in `devices`.
- **`peer.hello`** exchanges `peer_protocol` and the product version. A peer speaking an older major protocol stays
  connected, and every mirrored vault pauses with the reason "upgrade <server>". Nothing is guessed across versions.
- **Reconnect** with capped, jittered backoff. `peer.ping` every 30 s; three misses mark the link down.
- **Health** is reported by `peer.list`: connected or not, since when, which side dialled, round-trip time, the
  peer's version.

### Reachability

One of the two servers must accept inbound connections on its device listener: on a LAN, over a VPN, or through a
forwarded port or SNI passthrough (`docs/admin/direct-connections.md`). The other needs only outbound access. Two
servers that are both behind NAT need a VPN. A relay through vaulthalla.cloud is out of scope here; if built it must
carry the TLS stream unopened, so that the company holds no pairing and can read nothing
(`design/encryption/05-claims-and-custody.md` §4).

Linking does not require `device_server.remote` on both servers, only that one of them is reachable by the other.

## Unlinking and revocation

- **Either side unlinks** (`peer.unlink`, a super admin). The local row gets `revoked_at`, live connections close at
  once, and the peer is told if it is reachable. Telling it is a courtesy: a revoked key is refused at the handshake
  whether or not the notice arrived.
- **What unlinking does to mirrored vaults** is in `mirror.md`: it is refused while this server is the mirror of a
  vault, until each such vault is detached or deleted here; on the core it ends the mirror.
- **The peer still holds whatever keys it was given.** Unlinking offers a key rotation for each vault it mirrored
  (`mirror.md`).
- **Linking the same server again** needs a new pairing with a new code. Unlike a device key, a server's identity is
  not disposable, so a previously unlinked key is not banned; its old row stays revoked and a new row is written.

## Rotation

- **Today** rotating the identity revokes every paired device (`ServerIdentity.hpp:74-79`), because a device's pairing
  is bound to the old key.
- **For peers** the server announces the new key first: `peer.identity.rotate {next_spki, proof}`, where the proof is
  a signature by the current identity key over `"vh/peer/rotate/v1" ‖ next_spki ‖ peer_spki ‖ node_id ‖ counter`. A
  connected peer stores it as `next_spki_sha256` and accepts either key until it has seen the new one in use, then
  drops the old. As built: `node_id` is length-prefixed (UInt32BE), `counter` is UInt64BE and is the identity's new
  version, and the announcing server revokes, in the rotation's switch transaction, every link that did not store
  it.
- **A peer that is offline at the rotation** never received the announcement and must be linked again. Failing
  closed is intended.
- **An emergency rotation** (`vh secret device-identity rotate --revoke-peers`) skips the announcement and drops every
  link. Use it when the identity key may be compromised.
- The attestation and wrap keys rotate by the same announcement, carrying the new public keys under the same proof.
  A new attestation key is added to the peer's pinned set; none is removed while a key version it signed is in use.

## Commands

Management, for a person (super admin; console, `vh`, or a full-access Desktop):

`peer.status` (as built: whether the switch is on) · `peer.pairing.open` · `peer.pairing.close` · `peer.pairing.pending` · `peer.pairing.approve` · `peer.pairing.deny` ·
`peer.link.start` · `peer.link.status` · `peer.link.cancel` · `peer.list` · `peer.get` · `peer.rename` ·
`peer.unlink`

Wire, on a pairing connection (a key not yet known): `peer.pair.request` · `peer.pair.confirm` · `peer.pair.status`

Wire, on a peer session: `peer.hello` · `peer.ping` · `peer.endpoints` · `peer.identity.rotate` · `peer.unlinked`,
and the `peer.mirror.*` and `peer.identity.*` families defined in the other two documents.

CLI: `vh peer pair`, `vh peer link <address> [--fingerprint <hex>]`, `vh peer list`, `vh peer info <peer>`,
`vh peer rename`, `vh peer unlink <peer>`; as built also `vh peer pending`, `vh peer approve <request> --code <code>
[--fingerprint <hex>]` and `vh peer deny <request>`, the non-interactive halves of `vh peer pair` (as `vh device` has).

## Audit events

`peer.pairing.open`, `peer.link.request`, `peer.link` (both sides, with the peer's node id and fingerprint, how
the code was compared: person or Desktop, and as built whether a key was pinned), `peer.link.denied`, `peer.unlink`,
`peer.identity.rotate`, `peer.connection` (up or down, at most one per minute per peer).

## Invariants (each gets a test)

1. A peer session can call no command outside the peer set, whatever its vault roles are.
2. A key in `peer` is never accepted as a device, and a key in `devices` is never accepted as a peer.
3. A code computed for a device pairing is never valid for a peer pairing, and the reverse.
4. Changing any field of either peer card after the request changes the code.
5. The dialling side never completes a handshake with a key other than its pin (or `expect_spki` while pairing).
6. Nothing dials, and no peer key is accepted, on a server with no `peer` rows.
7. A revoked peer is refused at the handshake, and its open connections are closed in the unlinking transaction's
   wake.
8. No scoped device, relayed session, share session or MCP caller can reach a `peer.*` management command.

## Work items

1. The outbound pinned client: a `makeClientContext(identity)` beside `makeServerContext`
   (`core/src/protocols/device/Listener.cpp:287-304`), TLS 1.3 only, presenting the `ServerIdentity` certificate; a
   verify callback comparing `device::crypto::p256KeyOf(peer).spkiSha256` with the pin in place of the trust store;
   the Beast websocket and HTTP client code factored out of `cloud::RelayService`; an accessor for the identity that
   `protocols::device::Service` keeps private today.
2. Migration: `peer`, the `peer_wrap` slot, the principal kind in RBAC tables.
3. `device::Peer` lookup and the `PeerSession` router branch.
4. The pairing transcript and the `peer.pair.*` and `peer.pairing.*` handlers.
5. The link service: dial, tie-break, hello, ping, reconnect, health.
6. Unlink and rotation.
7. `vh peer …`, the console's Linked servers page, the ws contract and its generated clients.
8. Desktop: the brokered flow, and links in All Nodes.
9. Operator page `docs/admin/linked-servers.md`; Tier A tests for the invariants; a two-daemon Tier B scenario.

## Open

- **More than two servers.** Nothing above limits a server to one link. `mirror.md` limits a vault to one mirror in
  the first version.
- **A "manage linked servers" permission** below super admin: later, once there is a reason.

## As built (phase 1a, 2026-11-25)

Work items 1 to 7 and 9 without the console page, the operator page and Desktop (8). Decided while building (under
the owner's instruction to build without waiting for review; compatibility policy rule 5):

- **The switch.** `peers.experimental: false` (config.yaml only, like `cloud`). Off: the link service closes every link
  and dials nothing, the listener never looks a key up in `peer`, and every `peer.*` command and `vh peer` answers
  `peers_experimental`.
- **Unique among live rows** (schema above), and the extra columns.
- **The commitment** has its own domain, `vh/peer/commit/v1` (device pairing's is `vh-pair-commit-v1`); the card has an
  exact encoding (Pairing, step 4).
- **The pairing connection.** A's connection to B's window is a pairing-only connection on B (device pairing's rules:
  one live request per key, 5 per window, 10 per minute per address, 5-minute requests inside a 10-minute window).
  A writes its row only once `peer.pair.status` says approved; if A cannot write it then (a crash, a conflict), B keeps
  a row A doesn't have, and an admin unlinks it on B. B closes the window when it approves.
- **The brokered check on B** (`expect_spki` on `peer.pairing.approve`) is applied before the code: another key denies
  the request whatever the code.
- **`compared_by` follows the channel, not the pin.** It records who compared the code, from the session of the call
  that made the link on each side (`peer.pairing.approve` on the accepting side; `peer.link.start` on the dialling side,
  carried on the attempt until its row is written): `desktop` over a full-access device session (the brokered path,
  where Desktop makes both calls), `person` from the console or the host socket, also when that person pinned the
  other key. Whether a key was pinned (`expect_spki`) is recorded only in the `peer.link` audit event's details as
  `pinned`. No column for it.
- **Who dials.** Both ends dial a live row's endpoints when it has no connection, loopback included (two servers on one
  host); a row with no endpoints yet (the accepting side before the first peer.endpoints) waits to be dialled. Backoff
  1 s to 2 min with full jitter. A newer connection from the same dialler replaces the older one (it reconnected); the
  lower-node-id rule decides between the two dialling directions. Both ends ping.
- **Wire shapes.** `peer.hello {node_id, name, peer_protocol, product_version}` both ways (the node id must be the
  row's; the side that loses the tie-break answers `conflict` and closes); `peer.endpoints {endpoints}` answers the
  receiver's own; `peer.ping` answers `{time}`; `peer.unlinked` makes the receiver revoke its row too (a notice that
  is a courtesy for the key, and saves the other side from dialling a server that refuses it).
- **Rotation.** The identity key's announced rotation is built. The attestation and wrap keys have no rotation path
  today (the wrap key never rotates; the attestation key is replaced only when it no longer unseals), so nothing
  announces them yet: when either gets one, the announcement gains their public keys under the same proof (a
  `peer_protocol` bump). A new attestation key reaches a peer only by linking again until then.
- **The websocket client** is a new reusable dialler (`protocols::ws::client::dial`: resolve, connect, the TLS client
  handshake with a caller's certificate check, the upgrade, one deadline), used by the link for both directions'
  dialling side. `cloud::RelayService` keeps its own (it also speaks plain ws to a loopback relay over a
  `beast::tcp_stream`); only its reconnect backoff moved to the shared `concurrency::jitteredBackoff`.
- **Not built in phase 1a:** the principal kind in RBAC tables and vault roles for peers (built since, migration 162:
  identity.md "As built: the mirror server's vault role"), bulk lanes (built since, below), any `peer.mirror.*` or
  `peer.identity.*` command, and Desktop's brokered flow (built since, in vaulthalla-desktop).
- **Bulk lanes** (mirror phase 2 wave 2): the sealed lane, `GET /peer/object/…` on the same listener over separate
  connections with the same pins (`mirror.md` "As built: sealed contents"). A linked key gets it and nothing else over
  HTTP; unlinking closes its connections with the websocket (invariant 7). The dialling side's pin check is one function
  for both (`peer::pinnedKeyOf`).
- **The console page** (built after phase 1a, same day): `/linked-servers` for super admins, shown only while the switch
  is on. The console learns the switch from `peer.status {enabled}`, the one management command that answers while it
  is off (the same callers as the rest), so no page load provokes `peers_experimental` and nothing advertises a
  switched-off feature; a server without the command leaves the page out too. It drives the commands above, never the
  wire set.
