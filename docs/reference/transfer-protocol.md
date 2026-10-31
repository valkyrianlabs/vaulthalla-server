# Transfer protocol: direct endpoints and resumable uploads

Normative for the daemon (`core/`), the web console (`web/`) and Vaulthalla Desktop
(`valkyrianlabs/vaulthalla-desktop`). "MUST", "SHOULD" and "MAY" are normative. Sizes are bytes; "MiB" is 2^20,
"MB" is 10^6. Every size and offset on the wire is an unsigned 64-bit integer (JSON numbers ≤ 2^53, which every
legal value is).

Capabilities (`meta.hello` → `capabilities`, `core/usage/src/contract/protocol.cpp`):

| Capability | Since | Meaning |
|---|---|---|
| `device.endpoints` | 1.20.0 | ws `device.endpoints` (Device sessions) and `endpoints` in `device.pairing.open` |
| `device.lanes.transfer` | 1.20.0 | device-listener `/transfer/probe`, `/transfer/sink`, `/transfer/source` |
| `http.upload.resumable` | 1.20.0 | `/upload/sessions` (this document, §3), on both listeners |

A client MUST gate every feature here on its capability and keep the older path for servers without it.

## 1. Endpoint advertisement

### 1.1 `device.endpoints` (ws, Device sessions only)

Request `{}`. Never answered on pairing-only or console sessions (no address disclosure before a device is trusted).

```json
{
  "node_id": "<server install id, as device.pair.status node_id>",
  "port": 36972,
  "remote": true,
  "listening": true,
  "generated_at": 1793453809,
  "candidates": [
    {"host": "127.0.0.1",        "port": 36972, "kind": "loopback",    "source": "interface", "interface": "lo"},
    {"host": "::1",              "port": 36972, "kind": "loopback",    "source": "interface", "interface": "lo"},
    {"host": "10.0.0.11",        "port": 36972, "kind": "lan",         "source": "interface", "interface": "enp3s0"},
    {"host": "fd00::11",         "port": 36972, "kind": "lan",         "source": "interface", "interface": "enp3s0"},
    {"host": "vh-storage.local", "port": 36972, "kind": "lan",         "source": "mdns"},
    {"host": "nas.home.arpa",    "port": 36972, "kind": "lan",         "source": "config"},
    {"host": "100.101.1.2",      "port": 36972, "kind": "vpn",         "source": "interface", "interface": "tailscale0"},
    {"host": "device.example.com","port": 36972,"kind": "wan",         "source": "config"},
    {"host": "device.example.com","port": 443,  "kind": "passthrough", "source": "config"}
  ]
}
```

- `kind` ∈ `loopback | lan | vpn | wan | passthrough`. Interface addresses are classified by range:
  loopback (127/8, ::1); `lan` = RFC 1918, 100.64/10 is `vpn`, IPv6 ULA fc00::/7; `wan` = other global unicast
  (IPv4 outside 0/8, 169.254/16 and 224/3; IPv6 2000::/3). IPv4-mapped IPv6 is classified as its IPv4 address.
  IPv4 link-local (169.254/16) and IPv6 link-local (fe80::/10) are never advertised (scope ids don't travel), nor
  are unspecified, multicast or reserved addresses. Interfaces matching `device_server.advertise.exclude_interfaces`
  (globs, fnmatch(3)) are skipped; `vpn` also covers every non-loopback address on interfaces named `tailscale*`,
  `wg*`, `zt*`, `utun*`.
- `source` ∈ `interface | config | mdns`. `mdns` is `<hostname>.local` (the host name's first label), advertised
  only where an mDNS responder is known to run (macOS always; Linux when `/run/avahi-daemon/pid` exists).
  `interface` (the interface name) is present only on `source: interface` entries.
- When the listener is loopback-only (`remote: false`) only `loopback` candidates are listed (so no `mdns` entry).
  Configured candidates are listed whatever `remote` says (a reverse tunnel or port forward may reach a loopback
  listener). `hostnames` entries are `lan` on the listener's port; `public` entries default to `wan` and the
  listener's port.
- IPv6 interface addresses (`::1` included) are left out when `advertise.include_ipv6` is false, and when the
  listener is bound but has no IPv6 socket (§1.4 fell back to `0.0.0.0`): an address no socket answers on is not
  advertised. With `advertise.interfaces: false` no interface address is listed at all.
- The list is computed on every call (`getifaddrs`, interfaces that are up), de-duplicated by `(host lowercased,
  port)` keeping the first, stably ordered loopback, lan, vpn, wan, passthrough (within a kind: interface, mdns,
  config, in that order), and capped at 32 entries.
- `port` is the port actually bound (it differs from `device_server.port` only when that is 0, as in tests), else
  the configured port; `listening` says whether the listener is bound right now.
- The server MUST NOT discover its public address by contacting a third party. Public addresses come from
  configuration (`device_server.advertise.public`) or from a global address on an interface.

### 1.2 Pairing bootstrap

`device.pairing.open` (an authenticated human's console session) adds `endpoints` (the §1.1 object without
`node_id`), `server_spki_sha256` (null until the listener has loaded its identity) and `node_id` (top level, beside
`endpoints`: the link below needs it). The web "Pair a device" dialog shows them and a link
`vaulthalla://pair?node=<node_id>&spki=<hex>&endpoints=<host:port,host:port,…>` (hosts with `:` bracketed,
the list percent-encoded). Desktop treats the link as untrusted input: it prefills the Add Node sheet, probes the
endpoints like §2, and if `spki` is present it refuses a pairing connection whose server SPKI differs. The SAS
(docs/pairing.md in the Desktop repo) stays authoritative; the link only saves typing and narrows TOFU.

### 1.3 Diagnostics (`device.remote.status`, super admins)

The existing answer gains:

```json
"diagnostics": {
  "bind": ["0.0.0.0:36972", "[::]:36972"],
  "ipv6": true,
  "candidates": [ /* §1.1 list */ ],
  "firewall": {"detected": "ufw|firewalld|nftables|pf|alf|none|unknown", "active": true|false|null,
               "hint": "human readable, or null"},
  "last_remote_device_at": 1793453809 | null,
  "last_remote_device_ip": "203.0.113.7" | null
}
```

`diagnostics` sits beside `status` in the `device.remote.status` answer (`{status, diagnostics}`);
`device.remote.enable|disable` answer `{status}` as before. `bind` lists every listening socket, `ipv6` says
whether one of them is IPv6.

`last_remote_device_*` is the latest Device-session handshake (ws or HTTP lane) whose source address is neither
loopback nor private, i.e. classifies as `wan` (100.64/10 and VPN ranges don't count): proof that a remote client
reached the listener directly. It is kept in memory only, so a daemon restart forgets it (null until the next one).

Firewall inspection is read-only (config files and state files the daemon can read; no commands needing root, no
rule changes) and reports `null` rather than guess. What is detected today:

- Linux: `ufw` when `/etc/ufw/ufw.conf` says `ENABLED=yes` (active, hint `sudo ufw allow <port>/tcp`); else
  `firewalld` when its pid file or `/run/firewalld` exists (active, hint `firewall-cmd --permanent
  --add-port=<port>/tcp` + reload); else `nftables` when `nftables.service` is enabled and `/etc/nftables.conf` is
  non-empty (`active: null`: the loaded ruleset needs root to read); else `ufw` with `active: false` when ufw is
  installed but disabled; else `unknown`. Linux never reports `none`: plain iptables rules can't be seen without
  root.
- macOS: `alf` (the application firewall) from `socketfilterfw --getglobalstate`, which answers any user, bounded
  to 2 s; else `unknown`. pf's state needs root and is never reported.
- `pf` and `none` stay reserved values.

### 1.4 Listener binding

`device_server.remote: true` binds `[::]:<port>` dual-stack (IPV6_V6ONLY off). If that fails (IPv6 disabled), it
binds `0.0.0.0:<port>`. Loopback-only binds `127.0.0.1` and, when available, `[::1]` on the same port. IPv4 clients
of the dual-stack socket are seen as their IPv4 address (not `::ffff:a.b.c.d`) everywhere: `last_ip`, pairing rate
limits, the loopback test that decides which sessions turning remote off closes. A bind failure is retried every
30 s as before; `status.address` is the first bound socket (`[::]:36972`, `127.0.0.1:36972`).

## 2. Desktop endpoint selection

Candidate sources, merged and de-duplicated by `(host lowercased, port)`:
1. `127.0.0.1:<port>` and `[::1]:<port>` for every node (cheap; the pin decides whether that server is this node).
2. The user-entered `Node.endpoint`.
3. The server's last `device.endpoints` answer (cached in the node record, `endpoints`).
4. Endpoints that succeeded before (`lastGood`, with time).
5. Bonjour `_vaulthalla._tcp` results whose TXT `node_id` equals the node's `serverNodeID` (only after 1–4 fail).

Priority by the class of the address actually connected to (a host name is classified by what it resolved to, so
split-horizon DNS works): loopback 0, lan 1, vpn 2, wan 3, passthrough 4. Within a class: last-good first, then
server order.

Probing:
- A probe is a TLS 1.3 handshake with the device identity and the node's pin (current or next) on a fresh
  connection, then close. TCP connect alone proves nothing. A pin mismatch on a candidate other than the
  user-entered endpoint marks only that candidate `identity_mismatch` (a different server lives there); it never
  starts the re-pair flow. A mismatch on every reachable candidate keeps today's behavior.
- At most 4 probes in flight, started in priority order 150 ms apart (or immediately when the previous one fails),
  3 s per probe, 6 s overall. After the first success the selector waits up to 250 ms for a higher-priority probe
  still in flight, then picks the best success.
- The outcome per candidate (`ok(rtt)`, `refused`, `timeout`, `identity_mismatch`, `tls_error(text)`,
  `unresolved`) is kept for the status view.
- Selection runs on connect, when the network path changes, when the ws connection drops twice in a row, and every
  30 min while connected on a class worse than lan (to move to a better route). It never runs more often than every
  5 s.
- Every lane (uploads, downloads, previews, MCP, File Provider) uses the selected endpoint. A lane failure with a
  connection-class error triggers re-selection; requests in flight are retried on the new endpoint.
- The app (credential owner) persists `endpoints` and `lastGood`; the File Provider extension and the MCP helper
  read them and select on their own, without writing.

## 3. Resumable uploads (`http.upload.resumable`)

Served on the device listener (device principal) and the web listener (cookie, or `?share=1` + `share_refresh`).
Every route is under `/upload`, so nginx and Caddy need no new prefix. Authorization, quota, RBAC, share scope and
overwrite rules are those of `/upload/session` and `PUT /upload/content` today. The older lanes stay as they are.

### 3.1 Create: `POST /upload/sessions`

```json
{
  "vault_id": 7,
  "files": [
    {"file_id": "f0", "path": "/photos/a.mov", "size": 12884901888, "mime_type": "video/quicktime",
     "duplicate_policy": "reject"},
    {"file_id": "f1", "path": "/docs/b.txt", "size": 1200, "if_match": "<content_version>"},
    {"file_id": "f2", "path": "/docs/c.txt", "size": 0, "if_none_match": "*"}
  ]
}
```

- One vault per session (`vault_id`; a share session's vault is the link's, and `vault_id` is ignored there).
- `file_id`: `[A-Za-z0-9_-]{1,96}`, unique in the session; default a UUID. `path` names a file inside the vault (a
  share session: relative to the share root); `/`, a trailing `/` and paths escaping the vault are 400.
- Per file at most one of: `duplicate_policy: "reject"` (default; the `/upload/session` rule: the target must not
  exist), `if_none_match: "*"` (create only: the `/upload/content` rule), `if_match: "<content_version>"`
  (replace: `Need::Overwrite`, compare-and-swap at commit). Two of them, or another value, is 400.
- Checked at create, each refusal naming the `file_id` in the body: Write on the path (`if_match`: Overwrite on the
  file, and its current version must equal `if_match`, else 412 `precondition_failed` + `ETag`; a file open through
  the mount is 412 too); something at the path: `reject` → 409 `already_exists`, `if_none_match` → 412
  `precondition_failed` + `ETag`, not a file → 409 `conflict`.
- At most `transfer.max_session_files` files (default 4096). Each `size` ≤ `transfer.max_file_bytes` (default 0 =
  no limit beyond the format) and ≤ 68 719 476 704 (the AES-GCM single-message limit, 2^36 − 32; larger files are
  refused with 413 `file_too_large`). Sum of sizes plus the bytes promised to the vault's other open sessions ≤ the
  vault's `freeSpace()` (507 `insufficient_storage`).
- Shares: `reject` or `if_none_match` only (`if_match` is 403: shares never replace); the link's limits
  (`max_upload_size_bytes`, file count and total, MIME and extension rules) are applied by `startUpload` and refuse
  with 403 `forbidden`.
- 201:

```json
{
  "upload_id": "…", "resumable": true, "expires_at": 1793540209, "state": "open",
  "part": {"default_bytes": 67108864, "min_bytes": 1048576, "max_bytes": 536870912, "max_in_flight": 4},
  "files": [ /* §3.2 file objects */ ]
}
```

`part.max_bytes` is `transfer.max_part_bytes` on the device listener and `min(that, transfer.http.max_part_bytes)`
on the web listener (default 64 MiB there, so a request stays under Cloudflare's 100 MB body limit);
`default_bytes` is `min(transfer.part_default_bytes, max_bytes)`. `min_bytes` binds every part except a file's
last. `max_in_flight` bounds concurrent part requests per session; more get 429.

### 3.2 Status: `GET /upload/sessions/<id>`

```json
{
  "upload_id": "…", "state": "open|finalizing|complete|failed", "expires_at": 1793540209,
  "part": { … as above … },
  "files": [
    {"file_id": "f0", "path": "/photos/a.mov", "size": 12884901888, "state": "receiving",
     "received_bytes": 1073741824, "ranges": [[0, 536870912], [1073741824, 1610612736]],
     "error": null, "entry": null}
  ]
}
```

- `ranges`: sorted, coalesced, half-open `[start, end)` byte ranges the server has **durably** stored. A client
  resuming sends exactly the gaps.
- Session `state`: `open` while any file is `receiving`, `finalizing` while any is `sealing`/`committing`, then
  `complete` or (any file failed) `failed`. A cancelled or expired session is gone (404).
- File `state`: `receiving` → `sealing` (all bytes present, the sealing cursor is finishing the file's stream and
  tag) → `committing` → `committed` (`entry` = the file's entry JSON, as `PUT /upload/content` answers; a share
  session gets `{id, path, transfer_id}` with the share-relative path) | `failed` (`error` = `{code, message}`;
  codes: `already_exists`, `precondition_failed` (+ `etag`), `conflict`, `forbidden`, `key_rotated`, `integrity`,
  `internal`). Share sessions' files also carry `transfer_id` (the `share_upload` id).

### 3.3 Part: `PUT /upload/sessions/<id>/files/<file_id>?offset=<n>`

- Headers: `Content-Length` (required, 411 otherwise), optional `Content-Digest: sha-256=:<base64>:` (RFC 9530;
  other algorithms in the header are ignored, a malformed `sha-256` member is 400).
- Rules, all checked before a body byte is read (refusal closes the connection):
  - `offset` present, `length > 0`, `offset + length ≤ size`, `length ≥ part.min_bytes` unless `offset + length ==
    size` (each 400 `bad_request`); `length ≤ part.max_bytes` (413 `part_too_large`); an unknown `file_id` is 404.
  - The range is disjoint from every stored range and every part in flight, **or** it equals a stored part exactly
    (same offset and length): then the body is read and compared byte for byte with the stored part (decrypted in
    memory), and the answer is 200 (idempotent) or 409 `part_conflict` (different bytes; nothing changes).
  - Partial overlap (with a stored part or one in flight): 409 `part_overlap`. File not `receiving`: 409
    `file_state`. Over `max_in_flight`: 429 `too_many_parts_in_flight` with `Retry-After`. More than 64 part bodies
    being received by the whole server: 503 `busy` with `Retry-After`.
  - The vault key is no longer the version the file was created under: the file fails with `key_rotated` and the
    part gets 409 `file_state`.
- The server streams the body (bounded buffers), encrypts it as its own AES-256-GCM message (§3.5), writes it to an
  attempt file in the spool, `durable::sync`s it, renames it into place, syncs the directory, records the part (and
  for a share session `recordUploadChunk`), and only then answers. A `Content-Digest` that doesn't match: 400
  `digest_mismatch`, and the part is not recorded. A part whose connection drops is not recorded either.
- 200 (`sha256` is the SHA-256 of the part's plaintext as received, computed in memory; no plaintext digest is
  stored):

```json
{"file_id": "f0", "offset": 536870912, "length": 536870912, "sha256": "<hex>",
 "received_bytes": 1610612736, "ranges": [[0, 1610612736]], "state": "receiving"}
```

  `Server-Timing: recv;dur=<ms>, write;dur=<ms>, sync;dur=<ms>` reports where the server spent its time (reading
  the body, encrypting and writing it, flushing and recording it).
- When the last gap closes the file moves to `sealing` and then `committing` on its own (§3.4); the answer to that
  part carries the new state.

### 3.4 Finalization

- Files seal and commit independently as soon as they are complete, on a bounded worker pool
  (`transfer.commit_workers`, default 2), never on a request thread. Commit = the sealing cursor's tag appended and
  `durable::sync`ed, then `Filesystem::createFile` with the `sealed` writer (the sealed spool file becomes the
  backing file: a hard link, copied where linking is impossible, so the spool keeps it until the commit is
  recorded), with the file's precondition (reject / create-only / compare-and-swap), authorized again as the caller
  is at that moment (a user: its current roles, and an account that stopped authorizing fails `forbidden`; a share:
  the share session's principal re-resolved, scope and target re-checked, committed as the link's creator). A target
  that appeared since create fails the file (`already_exists`, or `precondition_failed` + `etag`); it is never
  silently skipped. A file is never visible before its bytes and tag are durable.
- `POST /upload/sessions/<id>/finish`: idempotent. 200 `{state: "complete", files: [...]}` once every file is
  `committed`; 202 `{state: "finalizing", files: [...]}` + `Retry-After: 1` while any is `sealing`/`committing`
  (the server waits up to 5 s for that before answering, without doing any of the work itself); 409 `incomplete` +
  the status while any file is still `receiving`; 200 with `state: "failed"` once every file is terminal and any
  failed. Finish never re-encrypts and never holds the request for the commit.
- Commit state is in the database, so a restart resumes it (§3.6); re-running a commit is idempotent (a file row
  carrying the upload's IV at the target path is the committed result). A share session's commit resumes after a
  restart on that share session's next request (status, part or finish), because only it can provide the principal.

### 3.5 Encryption of parts (no plaintext at rest)

The vault file format is unchanged: AES-256-GCM over the whole file, body ‖ 16-byte tag, one IV per file, empty
AAD. At create the server picks the file's IV and the vault key version and stores both.

Parts are **not** written under the file's keystream. A part attempt that fails half way (the connection drops, the
digest is wrong, the daemon dies before the part is recorded) is not recorded, and the range may later be filled
with different bytes (the client's file changed, or a bug). Had the attempt's ciphertext been written at its offset
under the file's IV, two different plaintexts would have been encrypted under the same CTR keystream positions,
and both versions can survive on disk (copy-on-write file systems, snapshots, SSD remapping): their XOR is the XOR of
the plaintexts. So each part attempt is its own AES-256-GCM message under the same vault key version with a fresh
random IV, written to `<ordinal>.<offset>.<random>.tmp` and renamed to `<ordinal>.<offset>.part` when durable; the
part row records that IV. No keystream is ever used twice, and every stored part is authenticated.

A per-file sealing cursor builds the vault-format file: it reads the stored parts in order as the contiguous prefix
grows, decrypts and authenticates each (a failure fails the file with `integrity`), and re-encrypts the plaintext
through the file's own GCM stream into `<ordinal>.sealed`, feeding the BLAKE2b content hash at the same time
(`createFile` then doesn't read the file back). Plaintext exists only in bounded memory buffers. The durable sealed
prefix is flushed and recorded (`sealed_bytes`) at least every 256 MiB and at the end of every pass; parts below it
are then deleted. The cursor lives in memory; after a restart it is rebuilt by reading the sealed prefix back
(decrypted at its offset and re-encrypted, which must reproduce it byte for byte) and the file is cut to that
prefix. Positions of the sealed file only ever receive the decided bytes, so rewriting a prefix after a restart
writes the same ciphertext again.

The vault key version must still be the current one when a part arrives and when the file commits; otherwise the
file fails with `key_rotated` and the client uploads it again (a rotation re-keys only committed files, so a file
committed under an outgoing version after the rotation pass had run would become unreadable).

### 3.6 Persistence, expiry, cleanup

- Sessions, files and parts are rows (migration 114); spool files live in `<backing>/.upload-spool/<upload_id>/`
  (0700, outside the FUSE mount and every vault tree, ciphertext only): `<ordinal>.<offset>.part` stored parts,
  `<ordinal>.sealed` the file being sealed. Nothing else (FUSE, snapshots, versions, archives, copy, sync) reads
  them. Restart keeps both; at startup attempt files, parts without a row and session directories without a session
  are removed, and part rows above the sealed prefix whose file is gone are dropped (they become gaps again).
- Disk use: a file's stored parts plus its sealed prefix, at most about twice the parts not yet sealed.
- A session expires `transfer.session_idle_ttl_hours` (default 24) after its last part, and at the latest
  `transfer.session_max_age_hours` (default 168) after creation; the DB janitor deletes expired sessions' rows and
  spool files (and spool directories without a row). `DELETE /upload/sessions/<id>` cancels at once (204; committed
  files stay; files of a share session that never committed are cancelled in `share_upload`).
- Shares: `?share=1` sessions also write the `share_upload` row (`startUpload` / `recordUploadChunk` once per stored
  part / `finishUpload`) and keep the link's `max_upload_size_bytes`; a share session is bound to its share session
  (another share session, a human or a device gets 404). The share manager's stale-upload sweep (6 h without a chunk)
  still applies to the `share_upload` row: a share session idle longer than that loses the file.

### 3.7 Errors

JSON `{error: {code, message}}` with the status (412 adds `error.etag` and the `ETag` header; refusals about one
file of a create carry its `file_id`; 409 `incomplete` carries the §3.2 status); never status-by-substring.
400 `bad_request`/`digest_mismatch`, 401 `unauthorized`, 403 `forbidden`, 404 `not_found` (unknown, expired,
cancelled or someone else's session: no oracle), 405 `method_not_allowed`, 409 `part_overlap`/`part_conflict`/
`file_state`/`incomplete`/`already_exists`/`conflict`, 411 `length_required`, 412 `precondition_failed` (+ `ETag`),
413 `file_too_large`/`part_too_large`, 429 `too_many_parts_in_flight`, 503 `busy`, 507 `insufficient_storage`.

## 4. Device transfer lanes (`device.lanes.transfer`, device listener only)

- `GET /transfer/probe` → `{node_id, server_time_ms, capabilities: [...]}`: cheap, no I/O (the node id is read
  from the database once per process).
- `POST /transfer/sink` with a body ≤ 256 MiB: read and discarded; answers `{bytes, server_ms}` (time from the
  first to the last body byte, integer milliseconds; `Server-Timing: recv;dur=<ms with 3 decimals>` carries it
  precisely).
- `GET /transfer/source?bytes=<n>` (0 ≤ n ≤ 256 MiB, decimal): streams n pseudo-random bytes (SplitMix64; not
  cryptographic, not compressible), `Content-Type: application/octet-stream`, through the same bounded,
  backpressured stream path as downloads.
- Nothing is written to disk. At most 2 calibration requests (sink, source) per device at once; the probe doesn't
  count. Answers are `Cache-Control: no-store`; keep-alive works across them.
- Refusals are JSON `{error: {code, message}}`: 400 `bad_request` (missing or out-of-range `bytes`), 404
  `not_found` (another `/transfer/*` path), 405 `method_not_allowed`, 413 `too_large` (a `Content-Length` or a
  chunked body over 256 MiB; the connection closes), 429 `too_many_requests` with `Retry-After: 1`. A pairing-only
  connection gets 403 `device_unknown` like every other lane. The lanes exist only on the device listener (never
  on the web listener or behind nginx).

## 5. Configuration (`/etc/vaulthalla/config.yaml`)

```yaml
device_server:
  remote: false
  advertise:
    interfaces: true              # advertise interface addresses
    include_ipv6: true
    exclude_interfaces: ["docker*", "br-*", "veth*", "virbr*", "podman*", "cni*", "flannel*", "lxc*"]
    hostnames: []                 # extra LAN names, e.g. ["nas.home.arpa"] (kind lan)
    public: []                    # [{host: device.example.com, port: 36972}, {host: device.example.com, port: 443, kind: passthrough}]
                                  # per entry: host (name or IP; IPv6 may be bracketed), port (absent/0 = the listener's),
                                  # kind lan|vpn|wan|passthrough (default wan)
transfer:
  part_default_bytes: 67108864    # 64 MiB
  part_min_bytes: 1048576         # 1 MiB
  max_part_bytes: 536870912       # 512 MiB, device listener
  max_parts_in_flight: 4          # per session
  max_file_bytes: 0               # 0 = only the format limit
  max_session_files: 4096
  commit_workers: 2
  session_idle_ttl_hours: 24
  session_max_age_hours: 168
  http:
    max_part_bytes: 67108864      # web listener cap; keep ≤ 95 000 000 behind Cloudflare Free/Pro (100 MB)
```

`device_server.advertise` validation: every host is a DNS name or IP literal (letters, digits, `.-_:`, at most 253
characters; no scheme, path or spaces), every `kind` is one of the four, no glob is empty. A malformed entry
refuses to start (config load) and `settings.update` refuses it with `invalid`. Absent keys keep the defaults
above; the section round-trips through `Config::save` and the settings JSON.

Validation: `1 ≤ part_min_bytes ≤ part_default_bytes ≤ max_part_bytes ≤ 4 GiB`, `part_min_bytes ≤
http.max_part_bytes ≤ max_part_bytes` (a listener whose cap is below the minimum could never take a full part),
`1 ≤ max_parts_in_flight ≤ 16`, `1 ≤ commit_workers ≤ 8`, `1 ≤ max_session_files ≤ 65536`, both TTLs ≥ 1 hour.
Out of range: the daemon refuses to start with a clear message (config load), and `settings.update` refuses with
`invalid`. Nothing is clamped; a key left out keeps its default.
