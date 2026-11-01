---
title: WebSocket Protocol Compatibility
navTitle: WebSocket Protocol
description: How Vaulthalla clients and servers released on their own schedules agree on a protocol version and detect features - the meta.hello handshake, capabilities, error codes and what counts as a breaking change.
order: 720
status: published
tags:
  - reference
  - protocol
  - websocket
  - desktop
---

# WebSocket Protocol Compatibility

The server, the web console and Vaulthalla Desktop release independently. A client may connect to a server that is newer or older than the one it was built against, so every WebSocket session can start with a handshake that settles which protocol version the two speak and which features the server has.

This page is the policy behind that handshake. It applies to the WebSocket API on the web socket (`/ws`, the console and API clients) and on the device listener (paired Desktop clients). The server's contract document (`vh_usage --json`) publishes the same facts under `protocol` and `capabilities`.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Three Different Versions

| Version | Example | What it says |
| --- | --- | --- |
| Product version | `1.19.0` | The Vaulthalla release. Informational: never decide compatibility from it. |
| Protocol version | `1` | What the WebSocket API's shapes are. Negotiated per session. |
| Contract document version | `3` | The layout of the `vh_usage --json` document itself, not API compatibility. |

The contract hashes (`contract_hash`, `ws_hash`, `models_hash`) identify an exact build of the command book. They change on any edit, descriptions included, so they tell a client that something differs, not whether it still works.

## The Hello Exchange

Send `meta.hello` first thing after connecting, or on the web socket right after signing in. It follows the same rule as `meta.contract.get`:

- a signed-in web session (with a valid access token), a paired device and a device that is not paired yet may send it;
- an anonymous web socket and a share session get `UNAUTHORIZED`. The server doesn't tell anyone its version or contract before they sign in.

Every member of the payload is optional:

```json
{
  "command": "meta.hello",
  "requestId": "1",
  "payload": {
    "client": { "name": "Vaulthalla Desktop", "version": "0.9.0" },
    "protocol": { "min": 1, "max": 1 }
  }
}
```

The answer:

```json
{
  "server": { "name": "vaulthalla", "version": "1.19.0" },
  "protocol": { "version": 1, "min": 1, "max": 1 },
  "capabilities": ["device.lanes.download", "errors.unknown_command_code", "fs.entry.metadata_version"],
  "commands": ["auth.login", "fs.dir.list", "meta.contract.get", "meta.hello"],
  "contract": { "contract_version": 3, "contract_hash": "…", "ws_hash": "…", "models_hash": "…" }
}
```

`capabilities` and `commands` are complete and sorted in a real answer (shortened here). `client.name` and `client.version` are at most 64 printable ASCII characters each. The server keeps them on the session for its logs, and a paired device's `client.version` becomes the app version shown in the device list.

### Negotiation

The session speaks the newest version both sides speak:

- `version = min(server max, client max)`.
- If `version` is below `max(server min, client min)`, there is no overlap: the server answers `ERROR` with `data.code` `protocol_unsupported`, and `data` carries `server_min`, `server_max` and `server_version` so the client can tell the user which side to upgrade. The session's version doesn't change.
- A missing bound is the server's own. A hello without `protocol` (and a session that never says hello) speaks the server's minimum.

The session remembers its version until it closes. Saying hello again negotiates again.

### Servers Without The Handshake

A server older than the handshake answers `meta.hello` with `ERROR` `"Unknown command"` (a device that isn't paired yet gets `device_unknown`). Treat that as protocol 1 with no capabilities, and detect commands as before.

## Capabilities

A capability is a feature a client must detect that the `commands` list cannot show: a new member in an existing answer, an HTTP lane, a behavior. Command presence is never a capability: check `commands` for that.

Names are stable dotted lower-case identifiers (`fs.entry.metadata_version`). A capability is never renamed, reused or removed while the protocol lasts: a server that stops offering a feature does so in a new protocol version.

| Capability | Since | Meaning |
| --- | --- | --- |
| `device.endpoints` | 1.20.0 | `device.endpoints` (paired devices), plus `node_id`, `server_spki_sha256` and `endpoints` in `device.pairing.open` and `diagnostics` in `device.remote.status` (transfer protocol §1). |
| `device.lanes.download` | 1.16.0 | The device listener serves `/download/content` (Range, conditional requests) as the device's user. |
| `device.lanes.preview` | 1.16.0 | The device listener serves `/preview` as the device's user. |
| `device.lanes.transfer` | 1.20.0 | The device listener serves `/transfer/probe`, `/transfer/sink` and `/transfer/source` (throughput calibration; transfer protocol §4). |
| `device.lanes.upload` | 1.16.0 | The device listener serves the `/upload` session lane as the device's user. |
| `device.mcp` | 1.16.0 | The device listener serves remote MCP at `POST /mcp`. |
| `device.server.identity` | 1.16.0 | A paired device can read the server key's pin over its own session. |
| `errors.unknown_command_code` | 1.19.0 | Unknown commands carry `data.code` `unknown_command`. |
| `fs.entry.content_version` | 1.17.0 | Entries carry `content_version`, equal to the download ETag. |
| `fs.entry.metadata_version` | 1.17.0 | Entries carry `metadata_version`, which changes on rename and move. |
| `fs.entry.stable_id` | 1.17.0 | An entry keeps its id across rename and move. |
| `http.upload.content` | 1.17.0 | `PUT /upload/content`: a streaming conditional create or replace. |
| `http.upload.resumable` | 1.20.0 | `/upload/sessions`: resumable uploads with idempotent parts (transfer protocol, section 3). |
| `ws.envelope.optional_payload` | 1.16.0 | A request without `payload` reads as `{}`. |

## Error Codes

A typed refusal is an `ERROR` answer whose `data.code` a client can act on without reading the message. Codes any command may answer with are listed in the contract's `envelope.error_codes`; a command's own codes are in its `refusal_kinds` and `confirmations`.

| Code | When |
| --- | --- |
| `unknown_command` | No command by that name on this server. Sent to signed-in web sessions and paired devices; the message stays `Unknown command` for clients that match the text. An anonymous web socket is refused with `UNAUTHORIZED` first, and a device that isn't paired gets `device_unknown`. |
| `protocol_unsupported` | `meta.hello` found no protocol version in common. `data` adds `server_min`, `server_max` and `server_version`. |
| `device_unknown` | The device listener: this key is not a paired device. It may only pair and say hello. |
| `denied`, `not_found`, `invalid`, `conflict` | The generic refusals. |

## Following Changes

A sync client follows a vault with `fs.changes.list` instead of listing its folders again. The server records every change to the vault's entries, whichever way it was made, and numbers the changes in commit order.

1. Take an anchor: `fs.changes.list` with `vault_id` and no `since` answers the current `revision`.
2. List the vault (`fs.dir.list`).
3. Ask for changes since the anchor, and from then on since the `revision` of the last answer. Ask again at once while `more` is true.
4. When the answer says `expired`, list the vault again and continue from the `revision` it carries.

Instead of asking on a timer, a client can subscribe: `fs.changes.subscribe` with `vault_ids` makes the server send an unsolicited frame `{"command": "fs.changed", "data": {"vault_id": 3, "revision": 1042}}` after changes to one of those vaults commit. The frame has no `requestId` and carries no changes: it means "ask again" (step 3). Events for one vault are merged while the client is slow to read. A vault the caller can no longer see is dropped from the subscription with a last event carrying `"subscribed": false`. `fs.changes.unsubscribe` stops them; closing the session ends every subscription.

Changes are `create`, `update`, `rename`, `move` and `delete`, keyed by `entry_id`, which stays the same across rename and move. A caller sees only changes to entries it can see: a rename or move into its view reads as `create`, out of it as `delete`. A cursor expires when it is older than the journal's retention, when it doesn't come from this server, or when an authorization change may have changed what the caller sees in the vault.

## Breaking And Additive Changes

Within one protocol version the WebSocket API only grows.

Additive changes ship any time without a bump:

- new commands;
- new optional request fields;
- new response fields;
- new enum values;
- new models, capabilities and error codes.

Clients must ignore response members they don't know and must not fail on an enum value they don't know.

Breaking changes need a new protocol version:

- removing a command;
- making a request field required (or adding a required one), removing it, or changing its type;
- removing a response field or changing its type;
- making a required response field optional;
- removing a response enum value;
- removing a model that is still referenced;
- removing an error code or a capability.

Descriptions, client timeouts and other prose are not part of the protocol.

### How A Bump Works

1. Raise `kProtocolVersion` in `core/usage/include/WsProtocol.hpp`.
2. Freeze the new surface: `python3 tools/contracts/protocol_compat.py --write --vh-usage build/core/vh_usage` writes `core/usage/protocol/v<N>.json`. Keep the older baselines.
3. Decide `kProtocolMin`. Keep the old version while handlers still answer older sessions in their shapes (a handler reads the session's negotiated version). Raise it only when those shapes are dropped. Clients whose range ends below it get `protocol_unsupported`.

The overlap is what lets clients and servers upgrade in any order: a server that speaks versions 1 and 2 serves both old and new clients while they move.

### The Compatibility Check

Every build runs `tools/contracts/protocol_compat.py --check` (the meson test `protocol_compat`). It compares the server's WebSocket surface with the frozen baseline of the current protocol version and fails on any breaking change, listing each one and the steps above. Additive changes pass; `--write` freezes them into the baseline, and it refuses to overwrite a baseline with a breaking change.
