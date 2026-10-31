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
    {"host": "100.101.1.2",      "port": 36972, "kind": "vpn",         "source": "interface", "interface": "tailscale0"},
    {"host": "vh-storage.local", "port": 36972, "kind": "lan",         "source": "mdns"},
    {"host": "nas.home.arpa",    "port": 36972, "kind": "lan",         "source": "config"},
    {"host": "device.example.com","port": 36972,"kind": "wan",         "source": "config"},
    {"host": "device.example.com","port": 443,  "kind": "passthrough", "source": "config"}
  ]
}
```

- `kind` ∈ `loopback | lan | vpn | wan | passthrough`. Interface addresses are classified by range:
  loopback (127/8, ::1); `lan` = RFC 1918, 100.64/10 is `vpn`, IPv6 ULA fc00::/7; `wan` = other global unicast.
  IPv4 link-local (169.254/16) and IPv6 link-local (fe80::/10) are never advertised (scope ids don't travel).
  Interfaces matching `device_server.advertise.exclude_interfaces` (globs) are skipped; `vpn` also covers
  interfaces named `tailscale*`, `wg*`, `zt*`, `utun*`.
- `source` ∈ `interface | config | mdns`. `mdns` is `<hostname>.local`, advertised only where an mDNS responder is
  known to run (macOS always; Linux when `/run/avahi-daemon/pid` exists).
- When the listener is loopback-only (`remote: false`) only `loopback` candidates are listed. Configured candidates
  are listed whatever `remote` says (a reverse tunnel or port forward may reach a loopback listener).
- The list is computed on every call (`getifaddrs`), de-duplicated by `(host, port)`, ordered loopback, lan, vpn,
  wan, passthrough, and capped at 32 entries.
- The server MUST NOT discover its public address by contacting a third party. Public addresses come from
  configuration (`device_server.advertise.public`) or from a global address on an interface.

### 1.2 Pairing bootstrap

`device.pairing.open` (an authenticated human's console session) adds `endpoints` (the §1.1 object without
`node_id`) and `server_spki_sha256`. The web "Pair a device" dialog shows them and a link
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

`last_remote_device_*` is the latest Device-session handshake whose source address is neither loopback nor private:
proof that a remote client reached the listener directly. Firewall inspection is read-only (config files and state
files the daemon can read; no commands needing root, no rule changes) and reports `null` rather than guess.

### 1.4 Listener binding

`device_server.remote: true` binds `[::]:<port>` dual-stack (IPV6_V6ONLY off). If that fails (IPv6 disabled), it
binds `0.0.0.0:<port>`. Loopback-only binds `127.0.0.1` and, when available, `[::1]`.

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
overwrite rules are those of `/upload/session` and `PUT /upload/content` today.

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

- `file_id`: `[A-Za-z0-9_-]{1,96}`, unique in the session; default a UUID.
- Per file exactly one of: `duplicate_policy: "reject"` (default; the `/upload/session` rule: the target must not
  exist), `if_none_match: "*"` (create only: the `/upload/content` rule, 412 when something is there),
  `if_match: "<content_version>"` (replace: `Need::Overwrite`, compare-and-swap at commit).
- At most `transfer.max_session_files` files (default 4096). Each `size` ≤ `transfer.max_file_bytes` (default 0 =
  no limit beyond the format) and ≤ 68 719 476 704 (the AES-GCM single-message limit, 2^36 − 32; larger files are
  refused with 413 `file_too_large`). Sum of sizes ≤ the vault's `freeSpace()` (507 `insufficient_storage`).
- 201:

```json
{
  "upload_id": "…", "resumable": true, "expires_at": 1793540209,
  "part": {"default_bytes": 67108864, "min_bytes": 1048576, "max_bytes": 536870912, "max_in_flight": 4},
  "files": [ /* §3.2 file objects */ ]
}
```

`part.max_bytes` is `transfer.max_part_bytes` on the device listener and `min(that, transfer.http.max_part_bytes)`
on the web listener (default 64 MiB there, so a request stays under Cloudflare's 100 MB body limit). `min_bytes`
binds every part except a file's last. `max_in_flight` bounds concurrent part requests per session; more get 429.

### 3.2 Status: `GET /upload/sessions/<id>`

```json
{
  "upload_id": "…", "state": "open|finalizing|complete|failed|cancelled", "expires_at": 1793540209,
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
- File `state`: `receiving` → `sealing` (all bytes present, integrity tag being finished) → `committing` →
  `committed` (`entry` = the file's entry JSON, as `PUT /upload/content` answers) | `failed` (`error` =
  `{code, message}`; codes: `already_exists`, `precondition_failed` (+ `etag`), `conflict`, `forbidden`,
  `quota_exceeded`, `key_rotated`, `integrity`, `internal`).

### 3.3 Part: `PUT /upload/sessions/<id>/files/<file_id>?offset=<n>`

- Headers: `Content-Length` (required, 411 otherwise), optional `Content-Digest: sha-256=:<base64>:` (RFC 9530).
- Rules, all checked before a body byte is read (refusal closes the connection):
  - `offset + length ≤ size`; `length ≤ part.max_bytes`; `length ≥ part.min_bytes` unless `offset + length ==
    size`; `length > 0`.
  - The range is disjoint from every stored range and every part in flight, **or** it equals a stored part exactly
    (same offset and length): then the body is read, its SHA-256 compared with the stored part's, and the answer is
    200 (idempotent) or 409 `part_conflict` (different bytes; nothing changes).
  - Partial overlap: 409 `part_overlap`. File not `receiving`: 409 `file_state`. Over `max_in_flight`: 429 with
    `Retry-After`.
- The server streams the body (bounded buffers), encrypts it at its offset (§3.5), hashes it, writes it to the
  spool, `durable::sync`s, records the part, and only then answers. A `Content-Digest` that doesn't match: 400
  `digest_mismatch`, and the part is not recorded.
- 200:

```json
{"file_id": "f0", "offset": 536870912, "length": 536870912, "sha256": "<hex>",
 "received_bytes": 1610612736, "ranges": [[0, 1610612736]], "state": "receiving"}
```

  `Server-Timing: recv;dur=<ms>, write;dur=<ms>, sync;dur=<ms>` reports where the server spent its time. When the
  server's write path is saturated it answers 503 `busy` with `Retry-After` before reading the body.
- When the last gap closes the file moves to `sealing` and then `committing` on its own (§3.4); the answer to that
  part carries the new state.

### 3.4 Finalization

- Files commit independently as soon as they are complete, on a bounded worker pool (`transfer.commit_workers`,
  default 2), never on a request thread. Commit = finish the GCM tag, `durable::sync`, then
  `Filesystem::createFile` with the `sealed` writer (the spool file becomes the backing file: rename, copy on
  EXDEV), with the file's precondition (reject / create-only / compare-and-swap). A file is never visible before
  its bytes and tag are durable.
- `POST /upload/sessions/<id>/finish`: idempotent. 200 `{state: "complete", files: [...]}` once every file is
  `committed`; 202 `{state: "finalizing", files: [...]}` + `Retry-After: 1` while any is `sealing`/`committing`
  (the server waits up to 5 s for that before answering); 409 `incomplete` + the status while any file has gaps;
  200 with `state: "failed"` once every file is terminal and any failed. Finish never re-encrypts and never holds
  the request for the commit.
- Commit state is in the database, so a restart resumes it (§3.6); re-running a commit is idempotent (a file row
  carrying the upload's IV at the target path is the committed result).

### 3.5 Encryption of parts (no plaintext at rest)

The vault file format is unchanged: AES-256-GCM over the whole file, body ‖ 16-byte tag, one IV per file, empty
AAD. At create the server picks the file's IV and the vault key version and stores both. GCM's body is CTR mode,
so the ciphertext of any part is computable at its offset (counter = 2 + block index, `crypto/util/Gcm.hpp`):
parts are encrypted on arrival and written at their offset in the spool file. The tag needs GHASH over the
ciphertext in order: a per-file sealing cursor feeds it while the contiguous prefix grows (a part landing at the
cursor is fed from memory; parts that landed ahead are read back from the spool when the gap before them fills).
The cursor lives in memory; after a restart it is rebuilt by reading the spool from 0. The content hash (BLAKE2b
of the ciphertext) is computed by the same cursor. A resubmitted part is accepted only with identical bytes
(§3.3), so a keystream position is never used for two different plaintexts. If the key version is retired before
commit, the file fails with `key_rotated` and the client re-uploads it.

### 3.6 Persistence, expiry, cleanup

- Sessions, files and parts are rows (migration 114); spool files live in `<backing>/.upload-spool/<upload_id>/`
  (0700, outside the FUSE mount, ciphertext only). Restart keeps both.
- A session expires `transfer.session_idle_ttl` (default 24 h) after its last part, and at the latest
  `transfer.session_max_age` (default 7 days) after creation; the DB janitor deletes expired sessions' rows and spool
  files. `DELETE /upload/sessions/<id>` cancels at once (204; committed files stay).
- Shares: `?share=1` sessions also write the `share_upload` row (`startUpload` / `recordUploadChunk` /
  `finishUpload`) and keep the link's `max_upload_size_bytes`; a share session is bound to its share session.

### 3.7 Errors

JSON `{error: {code, message}}` with the status; never status-by-substring. 400 `bad_request`/`digest_mismatch`,
401, 403 `forbidden`, 404 `not_found` (unknown or someone else's session: no oracle), 409 `part_overlap`/
`part_conflict`/`file_state`/`incomplete`, 411, 412 `precondition_failed` (+ `ETag`), 413 `file_too_large`/
`part_too_large`, 429 `too_many_parts_in_flight`, 503 `busy`, 507 `insufficient_storage`.

## 4. Device transfer lanes (`device.lanes.transfer`, device listener only)

- `GET /transfer/probe` → `{node_id, server_time_ms, capabilities: [...]}`: cheap, no I/O.
- `POST /transfer/sink` with a body ≤ 256 MiB: read and discarded; answers `{bytes, server_ms}` (time from the
  first to the last body byte).
- `GET /transfer/source?bytes=<n>` (n ≤ 256 MiB): streams n pseudo-random bytes.
- Nothing is written to disk. At most 2 calibration requests per device at once (429 beyond).

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

Validation: `part_min_bytes ≤ part_default_bytes ≤ max_part_bytes ≤ 4 GiB`, `http.max_part_bytes ≤
max_part_bytes`, `1 ≤ max_parts_in_flight ≤ 16`, `1 ≤ commit_workers ≤ 8`. Out of range: the daemon refuses to start
with a clear message (config load), and `settings.update` refuses with `invalid`.
