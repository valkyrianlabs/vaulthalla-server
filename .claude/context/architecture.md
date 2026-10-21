# Architecture: core daemon, protocols, runtime

Verified against `main` @ 1.6.6 (2026-09-30). Merges the old `.codex` repo-overview,
core-backend, and protocol-map docs, with stale claims corrected.

## Build graph

- Root `meson.build` holds `project('vaulthalla', 'cpp', version: '1.6.6')`: `cpp_std=c++23`,
  `unity=on`, `unity_size=9`, `warning_level=3`, `werror=false`, `prefix=/usr`, meson >= 1.3.0.
  It enters C++ via `subdir('core')` and also installs `deploy/lifecycle` → `/usr/lib/vaulthalla/lifecycle`.
- `core/meson.build`: deps `libsodium libcurl boost(filesystem) libpqxx-vh pdfium yaml-cpp spdlog fmt openssl>=3
  libmagic libjpeg libturbojpeg pugixml zlib threads`, plus `fuse3` when the kernel bridge is built (`-Dfuse`, auto:
  required on Linux, off on macOS) and the Linux-only `uuid tss2-esys tss2-tctildr tss2-rc`.
  OS-specific code lives only in `core/src/platform/{linux,darwin}/` behind `core/include/platform/*.hpp` (see
  `macos.md`); source discovery adds the host's directory and, without FUSE, swaps the four libfuse sources for
  `fuse/unbuilt/Service.cpp`.
  The two Vaulthalla-built SDKs come only from apt.vaulthalla.sh: `libpqxx-vh-dev` (libpqxx 8, a **static** archive
  under its own pkg-config name `libpqxx-vh`, so servers need only `libpq5`) and `libpdfium-dev` (Chromium-tracking
  PDFium, runtime `libpdfium<branch>`, e.g. `libpdfium8059`). The pdfium dependency carries a version window
  (`>=155.8059`, `<1000`) because the retired `20250629` fork snapshot sorts higher; `tools/contracts` pins both.
  libpqxx stays out of the -O0 PCH (GCC drops its `#pragma GCC diagnostic` fences there).
  It generates `paths.h` (config/runtime/mount/state/log/psql paths, lines ~35-44).
- Artifacts: `vaulthalla-server`, `vaulthalla-cli` (links `vhusage` for `vh mcp` / `vh skill`), `vh_usage` (manpage markdown generator),
  static libs `vaulthalla`, `vhseed`, `vhusage`, `vhusage-native`; tests `vh_unit_tests`, `vh_integration_tests`.
- `meson.options`: `manpage` (true), `install_data` (true), `build_unit_tests` (false),
  `integration_tests` (false), `systemd_system_unit_dir` (`/lib/systemd/system`), `udev_rules_dir`, `tmpfiles_dir`.
- Vendored code lives in `core/vendor/`. Seed data is in `core/seed/`, and test fixtures are in `core/test-assets/`.

### Unity-build hygiene (invariant)

Unity builds concatenate `.cpp` files, so file-scope `using namespace` leaks into neighbours. The
CI-only `reference to 'Vault' is ambiguous` failures came from filesystem-order-dependent grouping.
- Source discovery in `core/meson.build` is piped through `LC_ALL=C sort`. Keep it that way.
- **Don't add file-scope `using namespace` in `core/src/**/*.cpp`.** Wrap definitions in their
  namespace, or use narrow aliases. About 340 file-scope directives remain, so don't make it worse.
  A newer one is at `db/query/sync/RemoteObjectIndex.cpp:13`.
- Never weaken the unity, warning, or werror settings to get a build green.

**Forward declarations.** Each subsystem that other code refers to by pointer or reference has a declaration-only
`Fwd.hpp` (`identities/`, `auth/`, `storage/`, `vault/`, `fs/`, `rbac/`, `share/`, `sync/`, `crypto/`,
`protocols/ws/`, `protocols/shell/`; earlier: `rbac/resolver/*/Fwd.hpp`). Include the narrowest one instead of
writing `namespace vh::x { struct Y; }` again, and `db/Fwd.hpp` for libpqxx classes (it adds libpqxx 8's `row_ref`/`field_ref`
to `<pqxx/types>`). Keep them declarations only:
no includes of definitions, no aliases, one subsystem each (no global fwd header). Add a type to its subsystem's
Fwd.hpp once it's forward-declared in more than one place. The `vh_usage` library (`core/usage`) can't see
`core/include` and keeps its own declarations.

## Process model

`core/main/main.cpp` boot sequence: config + log registries → DB init + prepared statements +
optional seed → runtime deps → storage wiring (+ derived-cache startup sweep) → `runtime::Manager` start → wait
for SIGINT/SIGTERM. Shutdown: `Manager::stopAll` → `preview::derive::Queue::shutdown()` → thread pools.
Shutdown is bounded and fast (restart ≈1 s; guard: `test_shutdown_bounds.cpp`): the SIGTERM/SIGINT handler only sets
an atomic and notifies a `platform::Waker` (eventfd on Linux, self-pipe on macOS); a watcher thread (started before startup) wakes main and `_Exit`s 10 s after the first
signal whatever main is doing; a second signal exits at once. `stopAll` calls `requestStop()` on every service but FUSE
(non-blocking: flag + cv notify + `onStop()`), joins them, then stops FUSE last. Services sleep with `lazySleep` (cv,
woken by stop), never `sleep_for` loops. FUSE `onStop()` lazily unmounts, ends the session, and after 1 s aborts the
fusectl connection (minor from `/proc/self/mountinfo`) if the mount is still referenced. Thread pools never lend
workers; `ThreadPoolManager::shutdown` requests every pool's stop, then joins all against one 3 s deadline (stragglers
are detached; workers hold only shared state).

`core/src/runtime/Manager.cpp` owns the service lifecycle. It runs a watchdog every 2s and restarts
a service after 500ms. Start order:

```
FUSE → IdentityWatcher → SyncController → UpstreamEventService → DBJanitor → VaultRetentionService →
LogRotationService → StatsSnapshotService → OperatorEmailService → ConnectionLifecycleManager → ProtocolService →
DeviceServer → S3GatewayService (+ ShellServer)
```

Stop order is the reverse, with the ShellServer stopped right after ProtocolService.
ShellServer is not created in test mode (`paths::testMode`).

## Protocol surfaces (`core/src/protocols/`)

| Surface | Code | Default bind (shipped `deploy/config/config.yaml`) |
|---|---|---|
| WebSocket `/ws` | `ws/Server.cpp`, `ws/Router.cpp`, `ws/Handler.cpp`, `ws/handler/*`, `ws/Session.cpp` | `0.0.0.0:36969` |
| HTTP preview/download/upload/auth | `http/Server.cpp`, `http/Session.cpp`, `http/Router.cpp`, `http/Access.cpp`, `http/handler/*`, `http/upload/Coordinator.cpp` | `0.0.0.0:36970` (fresh installs: `127.0.0.1`) |
| S3 gateway (SigV4, multipart) | `s3/*` (`GatewayService`, `SigV4`, `ObjectStore`, `MultipartStore`, `CredentialManager`) | `0.0.0.0:39000`, disabled by default |
| Shell/CLI control | `shell/Server.cpp`, `shell/Router.cpp`, `shell/commands/*` | unix socket `/run/vaulthalla/cli.sock` |
| Device listener (Vaulthalla Desktop, mutual TLS) | `device/Service.cpp`, `device/Listener.cpp` (`/ws` → the ws Router) | `127.0.0.1:36972`; `0.0.0.0` once `device_server.remote` (absent section = these defaults) |

> `core/include/config/Config.hpp` compiled-in defaults are **33369/33370**, but the shipped config,
> web fallbacks, and Caddyfile all use **36969/36970**. Trust the config file, and treat that
> header/config mismatch as a known wart.

### Shell CLI flow

`vh` / `vaulthalla` are symlinks to `vaulthalla-cli` (created by `bin/setup/install_dirs.sh` and the Debian payload).
1. `core/main/cli.cpp` normalizes args and connects to `/run/vaulthalla/cli.sock`.
2. It sends a JSON frame `{cmd, args, line, interactive}`.
3. `shell/Server.cpp` authenticates the peer by UID/group (the `vaulthalla` group plus the app-user UID mapping), answers
   with a `{"type":"hello"}` frame, then dispatches the frame. Each client runs on its own thread (cap 16, extra
   clients get exit 75 "busy"); request reads time out after 10s, prompt answers after 15 min, sends after 30s, and
   writes use `MSG_NOSIGNAL`. `status`/`version` skip the DB user lookup so they work while the DB is down.
4. `shell/Router.cpp` with `core/include/protocols/shell/Parser.hpp` tokenizes the line and runs the handler; output frames stream back.
   Before dispatch the Router rejects options the usage definitions don't declare: each option must be declared by
   a node on the path the positionals select (argument words are skipped), or match a declared `option_prefixes`
   family (role commands' generated `--allow-*`/`--deny-*`). `--help`/`-h` are always accepted.
   `test_cli_options.cpp` keeps definitions honest: every documented example must pass this check, and every
   subcommand name a handler dispatches on must be defined.
5. Usage/help comes from `core/usage/*` (root alias hard-coded as `vh`). The same code drives the `vh_usage` manpage
   generator and the integration-test command models, so CLI UX changes ripple into man pages and tests.
   Every leaf declares `effect` (`CommandEffect::Read|Write|Destructive`, `types.hpp`; destructive = deletes, purges,
   revokes, rotates keys or can't be undone); `McpCatalog.EveryLeafDeclaresAnEffectAndOnlyLeaves` refuses a leaf
   without one, and `vh_usage --json` exports it.

Invariants: the **daemon owns `/run/vaulthalla/cli.sock`** (binds it itself; every ~1s it checks the path still points
at its listener and rebinds if something replaced it). `deploy/systemd/vaulthalla-cli.{socket,service}` are obsolete
(`vaulthalla-cli --systemd` never existed as a mode; the unit connected to its own socket and hung) and should not be
shipped. The client waits at most `VAULTHALLA_CLI_TIMEOUT` (default 10s) for the first frame and exits 69 (no daemon),
75 (not responding), 77 (not in the `vaulthalla` group), 76 (reply without exit status). `vh status` exits 0/1/2 for
healthy/degraded/critical and includes a live `SELECT 1` DB probe.

**File transfer (`vh fs ls|get|put`, #229). Interim:** retire it once a macOS FUSE identity adapter maps local
uids to Vaulthalla users on the mount (#221); don't grow it into a second file API. Bytes ride the same length-prefixed JSON frames, never a second channel
(`protocols/shell/Transfer.hpp`, header-only and shared with the client): the request carries `"transfer": {"v":1}`
(`put_size` for put), the daemon answers `transfer`/`transfer-ready`, then `data` frames (`seq`, base64 of at most
256 KiB) and `transfer-end`/`transfer-abort`, then the usual `result`. Limits are checked before allocation: 512 KiB
per frame during a transfer (the server's general request limit is 1 MiB), 64 MiB for any reply on the client.
Transfers are never interactive (they keep the 10s read timeout), at most 4 gets and 2 puts run daemon-wide, 6h max.
Authorization is `http::access::resolveUserPath`/`requireUser` (the HTTP lanes' evaluator, taking the peer-mapped
`User` instead of a session), re-evaluated with the user reloaded every 32 chunks of a get and before a put commits.
A put is staged in `<backing>/.cli-staging/put-*.part` (0600 in 0700, swept at CLI-server start since it is plaintext)
and committed by `fs::Filesystem::createFile` with `source_path` (streaming seal; overwrite is CAS on the authorized
generation). The client reads/writes local files itself (get `-o` = temp sibling + rename only on an ok result with
every byte; stdout via write(2), refused to a TTY without `-o -`); `planLocal` mirrors the daemon's tokenizer so both
agree which positional is the local file. Tests: `test_cli_fs.cpp` (DB, socketpair), `core/tests/cli/test_fs_client.py`
(meson `cli_fs_client`, real `vaulthalla-cli` against a scripted daemon).

### MCP and agent skills (`vh mcp`, `vh skill`)

One catalog, two transports. `core/usage/{include/Mcp.hpp,src/mcp/}` (`vh::mcp`) holds the tool catalog
(`Catalog`), the JSON-RPC 2.0 handler (`Server`: initialize with version negotiation 2025-11-25 → 2025-06-18 →
2025-03-26, ping, tools/list, tools/call) and the skill text. It lives in the usage module because it needs only the
usage book and the operation catalog and no daemon types, so the client links it directly; the daemon links it too
(remote `/mcp` on the device listener runs `Invocation::line` through `Router::executeLine(line, deviceUser)`; see
"Device listener and pairing").
- Compiled into `vaulthalla-cli` rather than fetched from the daemon: `tools/list` and `vh skill install` work with the
  daemon down, there is no new socket command, and skew fails closed (an older daemon rejects options it doesn't
  declare; `mcp`/`skill` reaching a daemon get "runs in the vh client", `commands/client.cpp`).
- Tools: `vh_help {path}` (usage book as JSON), `vh_read {command, confirm?}` (read-effect leaves only, readOnlyHint),
  `vh_run {command, confirm?}` (any agent-available leaf, destructiveHint: annotations are per tool, so the read/any
  split is how a leaf's effect reaches the client), and one typed tool per `OperationSpec` with a CLI binding (name =
  id with `_`, schema from `FieldSpec`s, line from `field_to_entry`/`fixed`, annotation = stronger of op `effect.kind`
  and the leaf's effect).
- `vh_run` commands are tokenized with a mirror of `Token.hpp`/`Parser.hpp`, resolved like the Router (plural → list,
  positionals descend), checked, and re-rendered from the tokens, so the daemon parses exactly what was checked
  (`McpCatalog.RunLinesParseAsCheckedForEveryDocumentedExample`). Refused before running: unknown commands, groups,
  `--`, odd option spellings, confirmation flags in the command, and `mcp::exclusions()` (one list: `vault key export`,
  `secrets export|update`, `setup`, `teardown`, `fs get|put`, `mcp`, `skill`, `device pair|approve|deny`,
  `device remote enable|disable`; also checked case-insensitively).
- Confirmations: a leaf's gates are its flags spelled `yes`/`accept-*`/`adopt-bucket` and the `confirm-token` option.
  Tools never add them on their own (typed bindings' `fixed` `flag:yes` is dropped) and the schema has `confirm`
  (`{"yes": true}`, `{"confirm-token": "<t>"}`). Independently, every call that resolves to an `effect: destructive`
  leaf (typed effect = stronger of op and leaf) is refused before execution without `confirm: {"destructive": true}`
  (an MCP-layer acknowledgement, never rendered as a flag). Refusals for want of a confirmation: handlers call
  `shell::noteConfirmationNeeded(code, flags)` (thread-local) right before refusing; `Router::executeLine` attaches it
  to the failed `CommandResult::confirmation`, and `shell/Server.cpp` sends it as the result frame's optional
  `confirmation {code, flag, flags}` (the CLI ignores it). `Catalog::finish` maps those flags to the leaf's gates; only
  without the member (older daemons) does it fall back to the text ("re-run …/pass --<gate>"). Either way the result
  is `isError` + `structuredContent {needs_confirmation, confirm_options, code?, message, how_to_confirm}`. `--json` is appended where the
  leaf has it; stdout is the text content; stderr and the exit code go into an `isError` result otherwise.
- `vh mcp` (`core/main/cli_mcp.cpp`): newline-delimited JSON-RPC on stdin/stdout (stdout only protocol messages,
  invalid UTF-8 replaced, writes serialized), each call one `vh::cli::runCaptured` (`interactive:false`, same peer-UID
  authorization; 69/75/77 come back as tool errors). `tools/call` runs on its own thread (at most 8 in flight), so
  ping/cancel/other requests are answered meanwhile; `notifications/cancelled` shuts the call's socket down
  (`CallControl`) and its response is suppressed (exit 130 internally); `VAULTHALLA_MCP_TIMEOUT` (default 600 s, 0 =
  none) abandons a call (exit 124). An abandoned or cancelled call is not undone in the daemon. `vh skill install` (`cli_skill.cpp`): `SKILL.md` (hand-written,
  `src/mcp/Skill.cpp`) + `references/commands.md` (`Catalog::commandReference`) into `~/.claude/skills/vaulthalla` /
  `~/.agents/skills/vaulthalla` (project: `.claude/skills`, `.agents/skills`); registers via `claude mcp add --scope
  user|project` / `codex mcp add` when on PATH, else prints it (Codex TOML stanza written only with `--force`);
  identical skill = no-op, a changed one only with `--force`. Tests: `test_mcp_catalog.cpp` (DB-free),
  `core/tests/cli/test_mcp_client.py` (meson `cli_mcp_client`: real client, scripted daemon, temp HOME).
  Operator doc: `docs/admin/mcp-and-agents.md`.

### WebSocket flow

**Connection cap (#164).** `ws::Server::onAccept` takes a `ConnectionSlot` (`protocols/ws/ConnectionLimit.hpp`)
under `websocket_server.max_connections` (read per accept, default 1024, 0 acts as 1); over the cap the socket gets
a raw `503` + `Retry-After: 1` without reading the upgrade request, and a warning at most once a minute with the
refused count. The session holds the slot and gives it back on its first `close()` (or destruction); connections
that fail before the websocket handshake (header read, hydration, handshake error) now `close()` at once instead of
lingering in the session manager until the lifecycle sweep.

The web client builds `ws(s)://<host>/ws` in `web/src/util/getUrl.ts` (overridable with `NEXT_PUBLIC_VAULTHALLA_WS_ORIGIN`).
`web/src/stores/useWebSocket.ts` handles reconnect, the pending-request map keyed by `requestId`, and token injection.
Router allowlists are **exact and per session mode**: unauthenticated, human, pending-share, ready-share, and on the
device listener device and device-pairing (see "Device listener and pairing" below).
Only the session-lifecycle commands (`auth.login`, `auth.logout`, `auth.refresh`, `auth.isAuthenticated`) skip
access-token validation (`isSessionLifecycleCommand`, mirrored by the web's
`SESSION_LIFECYCLE_COMMANDS`). Every other `auth.*` command (register, user update/delete/get/list, password change)
is account management and goes through `RequireHumanAuth`. A `starts_with("auth")` rule used to let unauthenticated
sockets reach handlers that dereference `session->user` (a remote daemon segfault); `WsAuthRouting.*` guards it.
There is no password gate (removed in 1.8.0, with the universal default password): a valid session is fully
authenticated. The super admin's initial-credential posture is advisory only: `auth.security.status` (human auth,
read once per page load) returns the initial password file path for `admin` while the generated password is in use
and the file exists; the web shows `InitialPasswordWarning`. Credential lifecycle: `core/auth/Bootstrap.hpp`
(see "Super-admin initial credential" below). `auth.login` is rate-limited per IP + account
(`ShareRateLimit.cpp`). The Router's debug log redacts credentials (`LogRedaction.cpp`); never log a raw ws message.
Refused requests (unauthorized, rate limited) warn once per client + command per 60s and count the rest
(`RefusalLogThrottle`, bounded map + overflow bucket, summary "suppressed N more in Ns"); per-request detail is
debug only, and client-invented command names share one label so they can't mint a warning each (#135).
See `link-sharing.md`.

### Device listener and pairing (Vaulthalla Desktop, S1a)

Normative protocol: `docs/pairing.md` in `vaulthalla/desktop` (its §8 test vectors are asserted in
`test_device_crypto.cpp`). Decisions D1-D3 in that repo's `docs/architecture.md` §8.
- **Listener** (`protocols/device/`): runtime service `DeviceServer` (after ProtocolService) with its own io_context
  (4 threads + work guard). Boost.Asio `ssl::stream`, TLS 1.3 only, no tickets/session cache, client certificate
  required with a verify callback that accepts any chain (dates, EKU, self-signature unchecked: TLS 1.3
  CertificateVerify proves possession), client sigalgs `ECDSA+SHA256`. After the handshake the leaf must be EC
  P-256; its SPKI SHA-256 (DER exactly as in the certificate) is authorized **once, at handshake time**
  (`device::authorize`): a live `devices` row (current or previous key) → Device session as that row's user (the
  canonical `identities::Manager` object); anything else (unknown, revoked, owner gone) → pairing-only. A handshake
  with a rotated device's new key clears `previous_spki_sha256`. Then the HTTP request is read and dispatched by path
  in `Connection::dispatch` (only the header is read; an upload body is the session's): `/ws` upgrades into
  `ws::Session::acceptDevice`; `/preview*`, `/download*`, `/upload*` and `/mcp` hand the TLS stream to an
  `http::Session` (below); anything else is 404. Cap
  `device_server.max_connections` (own `ConnectionSlot::Pool::Device`; over it the socket is closed, a TLS client
  can't read a 503), 10 s handshake and request deadlines. A bind failure never stops the daemon: it is in
  `listenerStatus()` and retried every 30 s.
- **HTTP lanes and remote MCP (S1b).** `http::Session` runs over a `ByteStream`: `TimedStream` (the plain socket,
  poll + deadline) or `TlsStream` (the device TLS stream: each blocking call starts one async op on the stream's strand
  and waits against the deadline, cancelling the socket's I/O when it passes; bytes go through op-owned buffers so an
  abandoned op never touches freed memory). A device connection runs on its own thread like the web side's, holds its
  `ConnectionSlot` (device pool), and serves only `/preview*`, `/download*`, `/upload*` and `/mcp` (pairing-only
  connections get 403 `device_unknown`). Its principal is a stream-less Device `ws::Session`
  (`Session::devicePrincipal`) registered with the session manager, so revocation, `revokeSessions`, remote-off and
  the sweeper close it; its close hook cancels the HTTP session, which also stops between requests and between
  chunks. Requests run under `access::DevicePrincipalScope` (thread-local): `access::authenticate` and the upload
  coordinator take the principal instead of a cookie, refuse the share lanes (`?share=1`: 403), and the usual
  `Need` → RBAC mapping applies as the device's user; audit lines carry `[via device <id16>]`. `/mcp`
  (`protocols/device/Mcp.cpp`): Streamable HTTP, POST only (GET/DELETE 405: no SSE, no MCP session id), JSON
  responses (202 for notifications), `Origin` present → 403, unknown `MCP-Protocol-Version` → 400, JSON content type
  required, batches refused; the `vh mcp` catalog and `mcp::Server` with an executor running
  `shell::Router::executeLine(line, deviceUser, nullptr)` on its own thread, abandoned after 10 min (the command is
  not interrupted). Same exclusions (key/secret export unreachable, D4), destructive gate and structured confirmation.
  DeviceServer shutdown waits up to 3 s for device HTTP sessions before stopping its io_context (else keeps it).
- **Server identity** (`device/ServerIdentity`): P-256 scalar sealed through `KeyProvider("device_tls")`
  (`test_device_tls` in test mode), generated on first start; self-signed certificate (serverAuth, 20 years) kept as
  `<state>/device_server_certificate.pem` and re-issued for the same key when missing or mismatched (the pin is the
  key's SPKI hash, so that is invisible to clients). Server-key rotation (spec §5) is minimal: `device.server.identity`
  returns the current SPKI only, never a next one.
- **One `ws::Session` for both transports.** The websocket lives behind `Session::Stream` (a plain
  `websocket::stream<tcp::socket>` or a `TlsTransport`, visited with a generic lambda), so every handler and the
  Router are unchanged; `TlsTransport.hpp` keeps Asio's SSL headers out of `Session.hpp`. Chosen over a socketpair
  handoff: no second hop, no out-of-band identity channel, and the session holds the device identity
  (`devicePeer()`) itself.
- **Session modes** `Device` / `DevicePairing` (`SessionMode`). Device: no tokens (`session::Manager::validate` is
  true while the user is `authorizing()` and the session open), `rbacActor()` = `human(user)`, classify = the Human set
  minus `auth.login|logout|refresh|register` and the share-recipient commands, plus `device.*`; deactivation or
  deletion is seen on the next command. Pairing: only `device.pair.*` and `meta.contract.get`; anything else is ERROR
  `data.code: device_unknown` (same for unknown and revoked keys). `device.identity.rotate` /
  `device.server.identity` only in Device mode; `device.pair.*` never on console sessions. Contract auth levels
  `pairing` and `device` (`human` commands also run in Device mode). The sweeper keeps Device sessions while their
  user may sign in (no refresh token to expire) and closes pairing-only ones after 15 minutes (`DeviceEnded`).
  `auth::Manager::revokeSessions` closes Device sessions (they have no token to revoke); revocation closes the
  device's sessions (`protocols::device::closeDeviceSessions`; a device revoking itself gets its reply first,
  `Session::closeAfterReply`). `last_seen_at/last_ip` are written at the handshake and at most every 5 min per
  session (`device::touch`). Audit lines written while a device's command runs end with `[via device <id16>]`
  (`log::AuditOrigin`, a thread-local read by the audit sink's `%*` flag).
- **Pairing state is in memory** (`device::Pairing`, process singleton): windows (10 min, **one per node**, reopening
  extends; another user's open is `conflict`; closing is the owner's, `{any: true}` / `vh device pair --close --any`
  lets a super admin close anyone's; `open` and `pending` carry `server_time`, `open` the listener's `port` and
  `remote`), requests (commit-then-reveal; 5 min after confirm, never past the
  window; one live request per key; ≤ 5 per window and ≤ 10/min per source IP → `rate_limited`), outcomes kept 10
  min for `device.pair.status`. Nonces and codes never touch disk; a restart only makes Desktop start over. Number
  matching: `pending` offers three codes (one SAS, two decoys fixed per request), `approve` compares in constant time
  and any other code denies. No long poll on `device.pair.status` (answered at once).
- **ops::devices** (`ops/Devices.cpp`): D3, no new permission bits: any signed-in user opens windows and approves for
  their own account; list/rename/revoke own devices (others' are `not_found`); super admins list (`--all`) and revoke
  every device. Rotation checks in the spec's order (current key, P-256 cert, never-seen key, ±300 s, signature under
  the connection's key and this server's SPKI); a retry from the previous key naming the same new key succeeds
  again, another key is `conflict`. Remote connections (D1): `ops::config::setDeviceRemote` (super admins, like
  `settings.update`) writes `device_server.remote` through the settings commit, which calls
  `DeviceServer::applyConfig()`: the listener rebinds in place, and turning remote off closes non-loopback device
  sessions. `ops::Refused{code}` carries the pairing codes (`no_pairing_window`, `rate_limited`, `device_unknown`).
- **Table** `devices` (migration 112): `spki_sha256` UNIQUE, previous key unique (partial index), `user_id` CASCADE,
  `approved_by` SET NULL; revoked rows stay (a revoked key never pairs again). `device_node` holds the node id
  Desktop records (created on first use).
- Port 36972 (36971 is the macOS package's bundled PostgreSQL; the dev instance shifts both by +100).

### Super-admin initial credential

No universal default password. `seed::initAdmin` (fresh DB only: `initDB` seeds when no `admin` row exists) calls
`auth::bootstrap::issueInitialCredential()`: 16 CSPRNG bytes as 32 hex characters, hashed normally, plaintext written
atomically (temp + rename, 0600, daemon user) to `<backing path>/super_admin_initial_password`
(`/var/lib/vaulthalla/...`), and `auth_bootstrap_state.super_admin_password_generated = TRUE` (singleton row, migration
098). Nothing re-issues it while the `admin` row exists: restarts, upgrades, reinstalls (adopt) and a deleted file
keep the password. Any change of admin's password (`auth::Manager::changePassword/resetPassword`) marks it rotated and
removes the file; a failed removal is logged and reported, never rolled back. `vh setup set-super-admin-password` is a
daemon shell command (`setup/superAdminPassword.cpp` → `ops::users::setSuperAdminPassword`) restricted to the caller
whose UID is bound to `admin` (root/system/sudo refused). Startup `retireLegacyDefaultPassword()` replaces a pre-1.8.0
`vh!adm1n` with a generated one (file written, admin's refresh tokens revoked). `vh setup nginx` (lifecycle Python)
warns while generated + file present and offers rotate / delete file / continue / cancel; non-TTY warns and continues.

### Refresh tokens and the web auth gate

Refresh tokens (human and share) are HS256 JWTs minted by `auth::session::Issuer`: a libuuid random `jti` plus an
HMAC-SHA256 signature keyed by the daemon's JWT secret (64 CSPRNG characters). Because they are high-entropy and
server-minted, `refresh_tokens.token_hash` stores `crypto::hash::tokenDigest()` = `sha256:<64 lowercase hex>`, not a
password hash. `crypto::hash::verifyToken()` accepts that digest (constant-time compare) or a legacy libsodium Argon2
string written before #171; `auth::session::Validator::verifyStoredRefreshTokenHash` (used by both the ws handshake
and the HTTP `validateRawRefreshToken` path) rewrites a legacy row to the digest after a successful verify
(conditional `UPDATE`, a failed rewrite only logs). (Argon2 used to cost ~0.57 s per check on every page load and
every HTTP preview/download.) User passwords still use `crypto::hash::password()` (Argon2). No migration: the column
is `TEXT`. Guard: `RefreshTokenDigest*` unit tests. A cookie-authenticated HTTP request without a live ws session
rehydrates from the stored row on every request (one `Transactions::read`, so revocation is immediate); the owner is
`refresh_tokens.user_id` resolved through `identities::Manager` (a deleted account is a non-authorizing tombstone),
and the JWT secret is cached in `crypto::secrets::Manager` (written only through it, which republishes).

**Identities (`identities::Manager`, `core/{include,src}/identities/`).** One canonical `User`/`Group` object per id,
handed out as the same `shared_ptr` everywhere (sessions, engines, FUSE, HTTP, S3). Each holds an immutable
`UserState`/`GroupState` in an `std::atomic<std::shared_ptr<const ...>>`; the Manager never replaces the object, it
publishes a new state into it, so every holder sees a committed change on its next read. Readers take one state per
logical check (`User::state()`, or `User::authz()` for the user plus its live groups, read under a seqlock so a
multi-object publication is seen whole or not at all). `authorizing()` is false for deactivated accounts and for
tombstones (deleted accounts keep their object, with no roles); every resolver, the FUSE identity step and the ws
router check it. Group membership lives on the member's state (`groups`, `joinedAt`); a group's own state has no
member list, so a group-level change reaches members through the canonical group. State never carries a password
hash. Writes: `createUser/updateUser/deleteUser/setPasswordHash/recordLogin/bindLinuxUid`, group CRUD and
membership, and `mutate(Touched, fn)` for everything else (vault role assignments, overrides, role templates in
`ops::roles`); each runs its statements, then reloads what it touched in one REPEATABLE READ snapshot
(`db::query::identities::Loader`, ~8 statements for any number of identities) and publishes before returning.
Ordering: migration 108's triggers bump `identity_revision` once per writing transaction (row lock = commit order)
and log `(rev, entity, id)` in `identity_change_log` (`last_login`/`password_hash` changes excluded); every state
carries the revision it was read at and an older read never replaces a newer state. Out-of-band writes (psql,
tests) are applied by `identities::RevisionWatcher` (runtime service, polls every second; the trigger also
`NOTIFY vh_identity`s) into the existing objects; `Manager::reconcile()` does one round (tests call it after raw
SQL). Lookups: `preload()` at startup loads everything; misses go to the database once (single-flight) and are
remembered negatively until the next publication. The test schema reset calls `Manager::reset()`. Guard:
`tools/contracts/test_identity_writes_contract.py` (identity row writers only in Manager.cpp, RBAC writers only
inside `mutate`), `IdentitiesManagerDbTest`.

**HTTP auth hot path.** Media seeking fires many small requests, so `session::Manager` skips the refresh-token DB
lookup for 30 s after a successful validation of the same in-memory session (`validatedAt_` keyed by jti, dropped
with the session's indexes on logout/invalidation/`revokeSessions`, so revocation stays immediate).
`rbac::policyEpoch()` is bumped by share link update/revoke/token rotation and every vault role template,
assignment and override mutation; short-lived authz caches treat an older epoch as a miss. The HTTP access layer
caches a resolved share principal for 15 s under that epoch.

`web/middleware.ts` only checks that a `refresh` cookie is present (no upstream call); the websocket session gate
decides validity (see `web-client.md`). The daemon's HTTP `GET /auth/session` remains for other clients.
(`NEXT_PUBLIC_SERVER_ADDR` no longer exists.)

### HTTP lanes (`protocols/http/`)

Routes (nginx prefixes `/preview`, `/download`, `/upload` only; never add prefixes), all cookie-authenticated
(`refresh`, or `share_refresh` with `?share=1`; no tokens in URLs): `GET /preview?vault_id&path&size&page`
(RenderedImage plans only, JPEG; `size` clamped 16-2048, default 1024; `page` 0-based; `X-Vaulthalla-Page-Count`
for PDFs; `scale` accepted and ignored), `POST /preview/batch` (≤ 200 items, per-item RBAC, readiness from one index query per engine (`ready` / `queued` /
`failed` (final: the source doesn't render) / `missing` / `unsupported`), never opening or decrypting an artifact,
`ready|queued|missing|unsupported|error`, never fetches remote-only files), `GET|HEAD /download/content` (original
bytes, inline by default), `GET|HEAD /download` (files stream with no size cap; directories stream a STORE ZIP,
see "Folder ZIPs" below), `GET /preview/derived?kind=&variant=` (200 artifact | 202 queued + Retry-After |
415 | 422 `conversion_failed` | 503 `converter_unavailable`/`busy`), `PUT /upload/text`, `GET|HEAD /download/conflict?
conflict_id&side=local|remote` (#187, humans only: `ops::conflicts::previewTarget` = resolve_conflicts + filesystem Read;
409 when the conflict is closed; local side served like `/download/content` with remote fetch off; remote side fetched
on demand by `sync::ConflictResolver::fetchRemoteForPreview`: price preflight `conflict_preview`, a usage capture of
1 HEAD + 1 GET + the cap, If-Match the HEAD's ETag, decrypted in memory, never stored, ≤ 32 MiB (413 `too_large`),
Range ignored; HEAD answers from the recorded artifact without contacting the bucket).
- **Server.** One thread per connection, capped by `http_preview_server.max_connections` (over the cap: raw `503` +
  `Retry-After: 1`). `TimedStream` polls a non-blocking socket against real deadlines (idle keep-alive 20 s,
  read/write inactivity 60 s); `SO_RCVTIMEO` was ignored by Asio. Long streams never occupy a shared pool slot.
- **Access layer** (`Access.cpp`) is the only place a route's `Need` (Preview, Download, Overwrite) maps onto RBAC:
  humans via the vault resolver (Preview and Download → filesystem Read, + List for directory ZIPs; Overwrite →
  `FilesystemAction::Overwrite`), shares via `share::TargetResolver` with the share op. Runs before any cache lookup,
  decrypt or render; HEAD = GET. Typed `Unauthorized/Forbidden/NotFound/BadRequest` → 401/403/404/400 (no
  status-by-substring). A missing path is 404 only for callers with Read on the vault root, else 403 (no existence
  oracle). Share accounting (`recordShareAccess`) is coalesced: one audit event, and for Download needs one
  `max_downloads` unit (`share::Manager::consumeDownload`, a conditional UPDATE; refusals audited as
  `share.download.limit`, HTTP 403 `max_downloads_reached`), per share session × entry × source id × event type per
  30 min. HEAD and 304 never count. Human accesses go to the audit log channel, coalesced the same way.
- **Serving** (`handler/Common.cpp` `serve`): strong generation ETag
  (`"g<file_id>-<hex16(sha256(sourceId|key_version|size))>"`), 304, one Range (206/416, `If-Range`; multi-range or
  malformed → 200 full), open-ended ranges capped at 16 MiB for inline media, HEAD writes headers only and never opens
  the reader. Bodies are `StreamResponse`s pulled in 256 KiB chunks from a `PlaintextReader` (TCP backpressure; a
  write error stops decryption; an integrity failure mid-body truncates and closes). Every original-bytes response
  sets `X-Accel-Buffering: no`, `nosniff`, a sandbox CSP and `Cross-Origin-Resource-Policy: same-origin`; non-media
  originals are served inline as `application/octet-stream`. Fresh nginx sites also set `proxy_buffering off` +
  `proxy_max_temp_file_size 0` on `/preview` and `/download`; upgrades keep the old site and rely on the header.
- **Folder ZIPs** (`handler/Archive.cpp`, #143). `archive::plan` walks the folder first (one `fsCache->listDir` /
  share `listChildren` per directory, name-sorted) and authorizes every entry exactly as before (human: Read on files,
  Read + List on dirs via `access::requireHumanChild`; share: List per dir via `resolve`, Download per entry via
  `TargetResolver::resolveListedChild`: the same scope/entry/RBAC checks without reloading root and entry per entry,
  parity-tested against `resolve`; one denial → 403 for the whole archive). It reads no bytes, skips symlinks and `.upload-http-*.part` staging, and caps the plan at
  `archive::kMaxEntries` (50,000 → 413 `limit_exceeded`: bounds the walk, done for HEAD and GET, and the
  plan's ~1 KiB/entry); there is no byte cap. Members are STOREd with data
  descriptors (CRC-32 computed while streaming), ZIP64 where a size, offset or the entry count needs it, UTF-8 names
  (bit 11; invalid UTF-8, `\`, control bytes → `_`; never absolute or `..`), DOS + UT mtime. STORE + plaintext
  `files.size_bytes` make the length exact up front: GET and HEAD carry `Content-Length`, HEAD stops after the plan.
  The body is `archive::stream`, a sequential `PlaintextReader` the session pulls like a file: one member open at a
  time (≤ 1 MiB members read in one authenticated pass, larger ones streamed and `requireAuthenticated()` before
  their descriptor, so a CRC never vouches for unverified bytes); a member that fails integrity, changed size or is
  unavailable (remote-only + policy) throws mid-body → truncated response + closed connection. Share archives count
  one `max_downloads` unit per logical download on GET (never HEAD), coalesced like files (key `dir`).
- **Text saves** (`handler/Text.cpp`): human only (shares 403), TextDocument plans only, `If-Match` required (428
  without, 412 + current ETag on mismatch), UTF-8 without NUL, ≤ `preview.text.max_edit_bytes` (413). Re-seals through
  `Filesystem::createFile(overwrite, expected_source_id)`, which takes a per-file content lock
  (`contentWriteMutex(fuse_path)`) so the check is a true CAS, and throws `ContentConflict` (→ 412) when the source id
  moved or the file has an open FUSE working copy.

### Byte-serving spine, integrity and derived artifacts

- **Positioned reads.** `storage::Engine::openPlaintextReader(file, ReaderOptions)` is the single funnel for every
  byte consumer (HTTP, media, models, text, thumbnails, converter input). `storage::Generation` identifies one content
  version: `sourceId()` = IV (changes on every write; rename/move keep it), `plain:<size>:<updated_at>` for
  unencrypted legacy/empty files. `GcmFileReader` preads only the requested ciphertext and decrypts with the GCM CTR
  keystream (`crypto::util::gcmCtrDecryptAt`: plaintext offset o ↔ ciphertext offset o, counter IV‖BE32(2+o/16)).
  Keys come from `EncryptionManager::keySnapshot(version)` (immutable `crypto::SecretKey`, mlocked, wiped; rotation
  swaps pointers under a shared_mutex). `readAll()` does one authenticated pass and records the verdict.
- **Verify-once integrity.** `crypto::IntegrityRegistry` keys a verdict on (domain, IV, key version, dev, ino, size,
  mtime_ns) and runs one streaming tag check per key on 2 workers (capacity 8192 settled verdicts). `optimistic`
  (default, `preview.media.integrity`) serves at once and every live reader throws `IntegrityError` on its next read
  after a failed verdict; `strict` waits for the verdict. Failure is sticky for that key (later opens fail fast;
  logged on the crypto channel); a replacement during verification is `Superseded`, not corruption.
- **Remote-only files** (cloud vaults without a local copy) follow `preview.media.remote`: `hydrate` (default: whole
  object once, metered/budgeted, verified, local ciphertext kept), `ranged` (opt-in metered ranged GETs pinned to the
  object version, no per-range authentication), `off` (`storage::ContentUnavailable` → HTTP 503
  `content_unavailable`). Grid thumbnails always use `off`. Chunked AEAD at rest would only be needed for
  *authenticated* random access to remote-only objects.
- **Derived cache** (`preview::cache::Store`, `cache_index` rows `type='derived'`, migration 103). One encrypted,
  disposable cache for thumbnails (`thumbnail`/`<size>`), sheet and PDF page renders (`render`/`p<page>-s<size>`),
  posters, probes, GLB, transcodes. File: `<cacheRoot>/derived/<file_id>/<kind>.<variant>.vhd` = 64-byte header
  (`VHDERIV1`, header version, key version, IV) ‖ AES-256-GCM(vault key, fresh IV, AAD = header ‖
  `"<vault>/<file>/<kind>/<variant>/<source_id>/<generator_version>"`) ‖ tag; 0600 temp, rename (fsync + dir fsync
  only for `Durability::Durable` artifacts: derive-queue outputs; thumbnails and page renders are `Disposable`, a
  crash only loses or tears one and every read detects that). Valid only for the current source id, generator
  version and a resolvable key version; anything else is deleted on sight. Small artifacts are served by
  `Store::read` (one index read via `Transactions::read`, one open, one authenticated decrypt); hits are recorded in
  memory and `last_accessed` is written in batches (`Store::flushTouches`, from the periodic eviction). PDF renders
  carry the document's page count in their row (`cache_index.page_count`, migration 109; older rows fall back to the
  `pdf-info` artifact). `Store::status` answers readiness for many keys from the index alone (`/preview/batch`).
  Failures are negative-cached (`preview.derive.failure_ttl_hours`, or until the source changes). LRU eviction to
  `caching.max_size_mb`, idle expiry `caching.thumbnails.expiry_days`, per-file/vault purge, retired-key purge after
  rotation, startup sweep. Not charged to vault quotas (`Engine::getCacheSize` excludes `derived/`); never synced,
  never visible over FUSE.
- **Render pipeline** (`preview::render::{Raster,Service}`). Header-checked decodes against
  `preview.max_render_pixels` and `http_preview_server.max_preview_size_mb`; TurboJPEG DCT-scaled decode, stb from
  memory otherwise; PDF pages behind one process-wide PDFium lock (`PdfiumLibrary` is the one init/teardown, held by
  `main` and test suites), rendered by PDFium straight into the packed RGB raster (24bpp + `FPDF_REVERSE_BYTE_ORDER`); output edges ≤ 2048, never upscaled. One decode
  per source generation and page at a time (single flight, shared by on-demand renders and thumbnail tasks); a decode
  emits every missing `caching.thumbnails.sizes` entry (16-2048) at or below the size it renders, resizing down a
  chain. An on-demand render returns once its requested size is stored; the smaller sizes are finished on the
  thumbnail pool from the same raster while the task holds the flight (`OutputTail`), so a thumbnail request
  meanwhile waits instead of decoding again (`render::waitForFlightsForTesting` for tests). Two render gates of `clamp(cores/4,1,4)` slots each (interactive renders, background thumbnailing), so
  imports never hold the slots a viewer needs (`render::Busy` → 503 + Retry-After). Thumbnail-sized outputs (≤ 512)
  use the fast IDCT and 4:2:0 chroma; images with alpha are composited over white (generator version 3). Uploads hand their in-memory plaintext to thumbnailing. A derived-cache outage
  degrades to uncached renders. Preview plans (`preview::classify`, file JSON `"preview"`, see `web-client.md`) decide
  which files render at all; `caching.thumbnails.formats` is no longer read.
- **Derive queue** (`preview::derive::Queue`, HTTP `/preview/derived`): bounded (`preview.derive.max_queue`),
  `max_concurrency` workers, deduplicated per artifact key, feeding `Runner` (below) into a `Store::Writer`.

### FUSE

`core/src/fuse/Service.cpp` validates the mountpoint, mounts a low-level session with `allow_other,auto_unmount`
(subtype `vaulthalla-fuse`), and dispatches to a thread pool. Mount path: `/mnt/vaulthalla` (prod/dev),
`/tmp/vh_mount` (integration harness).
- **FUSE ops still hit the DB for content and metadata writes**, but no longer for identity: the caller (by uid), its
  groups and the vault owner come from `identities::Manager` in memory (see Identities below). If the DB pool wedges,
  writes, opens of uncached entries and anything else that queries still hang. See P0 in `production-hardening.md`.
- HTTP uploads stage `.upload-http-<id>-<file>.part` next to the target *through FUSE*, then rename
  from `fuse_from` to `fuse_to` (`http/upload/Coordinator.cpp`). This is intentional. Don't move staging out of
  FUSE to reduce sync churn; fix duplicate sync triggers or backing-path resolution instead.
- **Vault bytes are always ciphertext at rest; the mount is the decrypting view (#173).** Every backing file (local
  vaults and cloud vaults' local copies) is AES-256-GCM body‖16-byte tag, IV and key version in `files`, and
  `files.size_bytes` is the *plaintext* size. Derived preview artifacts are encrypted too (`VHDERIV1`, see
  "Byte-serving spine"); the legacy plaintext `<cacheRoot>/thumbnails` and `<cacheRoot>/files` trees are deleted by
  `preview::cache::Store::sweep` at startup. The HTTP lanes never write plaintext. FUSE `open` decrypts into a
  per-inode working copy
  (`fuse/WorkingCopies`, 0600 under `<backing>/.fuse-plaintext`, shared by every handle on the inode); reads and
  writes go to it; `flush` (so `close(2)` returns with the change on disk), `fsync` and the last `release` seal it
  back (new IV, fsynced temp + rename). `setattr` size works on the copy. Copies that fail to seal move to
  `.fuse-plaintext/unsaved/`; stale copies are deleted at mount. A same-vault rename only moves the bytes (no
  re-encryption).
- **Rename over an existing entry replaces it (editor saves; `FsRenameDbTest`, Tier A CRUD + "Rename Over Needs
  Delete").** `Filesystem::rename(..., RenameMode)`: `NoReplace` (default: ws rename/move, uploads,
  RENAME_NOREPLACE) answers -EEXIST; `Replace` (FUSE rename without flags, only after the Bridge resolved Delete on
  the destination, like unlink) trashes a replaced file in the rename's own transaction
  (`File::markFileAsTrashed(txn, ...)`), deletes a replaced symlink or empty folder, then removes its backing bytes
  and derived artifacts after commit. rename(2) refusals come first: EISDIR, ENOTDIR, ENOTEMPTY, EINVAL (into
  itself), EBUSY (vault root). The rename works on clones of the cached entries and records each backing move in a
  `RenameJournal`; it publishes the clones to the cache only after commit and rolls the journal back on any failure.
  Before, it mutated cached entries in place and moved bytes before the commit, so a failure (any rename over an
  existing name hit UNIQUE(parent_id, name)) stranded the bytes and corrupted the cache. RENAME_EXCHANGE is still
  refused (EINVAL). `Filesystem::repairAtRest` (first sync pass per vault per start) seals plaintext left by older
  builds and corrects ciphertext-length sizes.
- **Vault key rotation is failure- and crash-safe (`sync/rotation/`).** `vh vault keys rotate` only prepares a new
  key; the sync pass re-encrypts. Per file: new ciphertext → `<backing>.vh-rotate` (O_EXCL, fsync file + dir) →
  (cloud, encrypt upstream) PUT with its own IV/version metadata → compare-and-set the `files` row on the old
  IV/version → rename over the backing file + dir fsync → fs cache refreshed. Recovery (each pass, and once per vault
  per start before `repairAtRest`) keeps whichever of sidecar/backing authenticates under the row (streaming GCM
  verify, no plaintext written) and leaves both if neither does. Remote-only files are re-encrypted remotely, never
  written locally; an uploaded-but-uncommitted object is adopted from its metadata. The rotation finishes (old key
  dropped) only when no file failed, no sidecar is unresolved and re-querying `getFilesOlderThanKeyVersion` (rows
  with an IV only: empty/legacy-plaintext files are excluded) is empty; otherwise both keys stay loaded and the next
  pass retries. Files open in FUSE are deferred. `fs::ops::replaceFileAtomic`/`writeFileAtomic` (temp + fsync +
  rename + dir fsync) back `Filesystem::createFile`'s overwrite branch. A copy (ws `fs.entry.copy`) copies the sealed
  bytes with their IV under the same content lock (see "Delete keeps folders; copy is deep" below).
- No writeback cache (`FUSE_CAP_WRITEBACK_CACHE` off): with it the kernel owns `i_size` and ignores getattr sizes,
  so out-of-band changes showed stale `stat` sizes. Handles are `direct_io` anyway.
- `forget` does not evict the metadata cache (it is seeded at startup and updated by the daemon's own changes);
  evicting a vault root used to make the whole vault ENOENT until restart.
- The RBAC gate is unchanged in shape: `open` needs Read for readable handles and Write for writable or `O_TRUNC`
  ones (both for `O_RDWR`); `write` and size changes check Write *before* touching the copy. A working copy is only
  reachable through a handle that passed the resolver.
- **Denied means hidden unless visible (#170).** `fuse::resolver::deniedErrno` answers a denial with ENOENT when the
  caller cannot Lookup the target (the parent for a create of a new name) and EACCES when it can see it but lacks
  the action; the mount root is never hidden. The answer must not depend on which op reaches the daemon first.
  An ENOENT answer to a revalidating lookup (or unlink) makes the kernel invalidate that shared dentry, so allowed
  users re-look it up, and a process whose cwd was that dentry gets ENOENT from getcwd.
- **No kernel metadata caching (#183).** The kernel dentry/attr cache is shared across uids and the mount has no
  `default_permissions`, so anything cached is answered for any caller without the daemon. Every reply uses
  `kKernelMetadataTimeout` = 0 (Bridge.cpp; pinned by `tools/contracts/test_fuse_cache_timeout_contract.py`), so each
  lookup/getattr is authorized for the calling uid. Before, a denied uid could `stat` a path another uid had just
  resolved (up to 60 s after a create). Size coherence doesn't need kernel caching: `statFromEntry` reports an open
  working copy's size. The harness passing "override allow: read secret" had relied on that cache: a file Lookup
  maps to Preview, so a download-only grant was hidden; `Evaluator::resolveStage` now lets a denied file Lookup fall
  back to the Read decision (seeing a file is implied by being allowed to download it).

## Database

- PostgreSQL via libpqxx. The schema is `deploy/psql/000…112_*.sql`, applied in order (all in ONE transaction by `core/seed/include/SqlDeployer.hpp`) and installed to `/usr/share/vaulthalla/psql`.
  New migrations take the next number and must be idempotent against upgraded installs. SqlDeployer records sha256(raw bytes)
  per file and refuses to start on a mismatch, so **never edit a shipped migration**: 020/060/082 were edited in place and
  bricked upgrades (1.5.x→1.6.x crash loop on 060). Reviewed exceptions live in `kHistoricalMigrationChecksums` (accepted, recorded
  hash rewritten to current, not re-run; a forward migration owns the delta). `core/seed/shipped_migrations.lock` pins every hash;
  `tools/contracts/test_migration_checksums_contract.py` enforces it (plus every local v* tag).
- `core/include/db/DBPool.hpp` is a fixed pool of 4 connections (config `database.pool_size` is **not** wired to it)
  handed out as RAII `DBPool::Lease`s (FIFO) that always return the slot. A dead connection is replaced on
  `acquire()` (reconnect + re-prepare, pool-wide backoff 250ms→5s, callers inside the window get
  `DatabaseUnavailable`). "Dead" also covers a session poisoned by a libpqxx error
  (`pqxx::failure::poisons_connection()`: unknown COMMIT outcome, protocol violation), which `Transactions::exec`
  marks. `acquire()` throws `PoolAcquireTimeout` after 30s. `db::Connection` hands libpq keyword/value parameters
  (no assembled or URI-escaped connection string): `connect_timeout=10`, `application_name=vaulthalla`, and TCP
  keepalives (30s idle, 10s × 3) + `tcp_user_timeout=60000`, so a server that stops answering surfaces as a broken
  connection within about a minute.
- libpqxx 8 rows: models and mappers take `pqxx::row_ref` / `pqxx::field_ref` **by value**; they are views into a
  `pqxx::result` and never keep it alive. Name the result before taking a row from it (`const auto res =
  txn.exec(...); res.one_row_ref()`); a `row_ref` from `txn.exec(...)[0]` in a declaration dangles. Only an owning
  `one_row()` may outlive its result. `db/Rows.hpp` maps results (`db::sharedRows<T>`, `db::rowsAs<T>`,
  `db::mapRows(res, fn)`); enums bound as parameters go through their SQL text (`to_string`).
  `core/include/db/Transactions.hpp` has `Transactions::exec(ctx, fn)`, the only path to a `pqxx::work`. It
  reconnects and retries once only when BEGIN fails on a dead connection (before `fn` runs); later failures
  surface. Pool state is in `SystemHealth.database` (`vh status`, stats ws, watchdog). Queries live in
  `core/src/db/query/<domain>/`, prepared statements in `core/src/db/preparedStatements/`.
- **Time zones (#157):** every daemon session runs with `TimeZone=UTC` (`db::Connection::configureSession`, on connect
  and reconnect) and records the zone it started in as `vaulthalla.database_timezone`. Migration 100 converted every
  `timestamp` column to `timestamptz`, reading old values in that recorded zone (manual psql runs fall back to the
  session zone); columns a view depends on are skipped with a warning. New columns must be `TIMESTAMPTZ`. Text output
  is `YYYY-MM-DD HH:MM:SS[.ffffff]+00`, which `db::encoding::parsePostgresTimestamp` handles. Guard: `DbTimezoneTest`.
- `db::Janitor` handles sweeps (DB cleanup every `services.db_sweeper.sweep_interval_minutes`, derived-artifact
  eviction and local-version retention every 15 min, the recovery store's orphan sweep at startup and daily; see
  `recovery.md`). Stats rollups read from `file_activity`, `files_trashed`, `operations`, `share_*`.

## Subsystem directory map (`core/src`, mirrored in `core/include`)

`auth` sessions/tokens · `concurrency` thread pools · `config` YAML registry · `crypto` AES-GCM, TPM2/swtpm
key provider, secrets · `db` · `email` providers (Resend, SES v2) · `fs` · `fuse` · `identities` users/groups ·
`log` spdlog registries + rotation · `notifications` operator emails · `preview` plans (`Plan.cpp`), in-memory
renders (`render/`: pdfium, turbojpeg, stb), the encrypted derived cache (`cache/Store.cpp`) and the
converter-helper runner/queue (`derive/`, below) · `protocols` · `rbac` roles/permissions/resolver/actor · `runtime` Manager · `share` link
sharing · `stats` dashboard telemetry + snapshots · `storage` local + S3 backends, remote index · `sync`
controller, strategies `cache|sync|mirror`, cost guardrails · `vault` vault model, slugs, FUSE names ·
`recovery` file recovery: local snapshots/versions, provider versioning, usage ledger, cost model (below) ·
`ops` actor-authorized operations shared by the CLI and ws handlers (below) · `device` paired devices: protocol
crypto, server identity, in-memory pairing, handshake authorization (the listener itself is `protocols/device`).

**Config keys renamed or moved (#164).** `config.yaml` is never rewritten on upgrade, so `loadConfig` keeps reading
the old spellings: `sharing.enable_public_links` → `sharing.enable_email_validated`, and
`s3_gateway.default_remote_{sync_strategy,conflict_policy}` → `vaults.s3.*` (new key wins; an invalid old value is
ignored; an invalid new value refuses to start). It collects one message per old key and `main.cpp` logs them via
`config::Registry::deprecations()` after the log registry is up (config loads before logging). `Config::save`
writes only the new keys, so a console save migrates the file. The settings JSON accepts the old spellings when the
new ones are absent. `ops::vaults::create` starts S3 policies from `vaults.s3.*` (CLI interactive prompts offer the
same defaults); gateway remote-cache buckets stay explicit `cache` + `keep_local`. Since #187 the remote default is
`ask` (conflicts are resolvable; see "Sync conflicts" below); existing vaults keep their stored policy.
`settings.policy.get` (any signed-in user) returns `{policy: {sharing, vaults}}`; `settings.get` stays super admin only.

### Converter helpers (`core/tools`, `preview::derive`)

Hostile-file converters never run in the daemon. `core/tools/` builds separate executables (own meson targets,
options `preview_cad`/`preview_media`, packages `vaulthalla-preview-{cad,media}`, installed to
`/usr/lib/vaulthalla/helpers/`); `core/tools/common` (protocol + Landlock/seccomp sandbox, libseccomp) links only
into them. `preview::derive::Runner` (`core/{include,src}/preview/derive/`) spawns one helper per job: fork
(`_Fork`) + async-signal-safe child setup (setsid, PDEATHSIG, NO_NEW_PRIVS, rlimits AS/CPU/FSIZE=0/NOFILE/CORE, fds
0-4 only, empty env), a poll loop that serves range-pull requests on fd 3 from a `storage::PlaintextReader`,
streams fd 1 to a sink, enforces the output cap and wall timeout (SIGKILL of the process group) and reaps.
Helper exit/JSON contract: `core/tools/common/protocol.hpp`. Config: `preview.derive.*`. RLIMIT_NPROC is not
set (per-UID; the daemon's threads would count): process creation is denied by the helper's seccomp filter, the
CAD helper denies clone outright, and the runner SIGKILLs a helper whose thread count (/proc/<pid>/stat, sampled
every 20 ms poll tick) exceeds `Limits::maxThreads` (64; limit_exceeded). Each poll iteration reads a bounded
amount per pipe (stderr/result one chunk, stdout 1 MiB), so a flooding helper cannot starve the deadline checks.
Helpers refuse to run (exit 5, `sandbox_unavailable`, queue reports `converter_unavailable`) without BOTH Landlock
and seccomp; the seccomp filter also limits pid-taking syscalls (prlimit64, setpriority, ioprio_set, sched_set*,
move/migrate_pages) to self, denies fcntl F_SETOWN/F_SETOWN_EX/F_SETSIG/F_SETLEASE and ioctl FIOSETOWN/SIOCSPGRP
(low-32-bit masked), SysV IPC and POSIX mqueues; the CAD `selftest-sandbox` command exercises every vector. Media
hardware devices are opened only after the sandbox (Landlock is per-thread). Trust: `Runner` executes only
root-owned, non-group/world-writable helpers in such directories (canonical path checked and executed;
`setTrustChecksForTesting(false)` in gtest_main, honoured only in testMode); `preview.derive.helper_dir` is
read-only through `ops::config::validateSettings` (settings.update/CLI).
Tests: `test_derive_runner.cpp` (fake helper `core/tests/helpers/fake_derive_helper.cpp`),
`test_preview_cad_helper.cpp` (real helper, skipped when not built).
`RunRequest::stop` (a `std::stop_token`) SIGKILLs the process group on request (`failureReason() == "cancelled"`).

### Derived-artifact cache and derive queue (`preview::cache`, `preview::derive::Queue`)

- One encrypted cache for every derived artifact (thumbnails, page renders, posters, GLB, transcodes):
  `preview::cache::Store`, files `<cacheRoot>/derived/<file_id>/<kind>.<variant>.vhd` (VHDERIV1 header + AES-256-GCM
  under the vault key, identity bound as AAD), rows in `cache_index` (`type='derived'`, migration 103) keyed by
  `(file_id, kind, variant)` and valid only for the source generation (`Generation::sourceId()`, the file IV) and
  generator version. `status='failed'` rows are the negative cache (`preview.derive.failure_ttl_hours`).
- Artifacts are keyed by **file id**, never by path: rename/move need nothing; a file id that ends (delete, trash,
  purge, S3 gateway delete, FUSE unlink) calls `Engine::purgeDerivedArtifacts(fileId)` (best effort, logs); a vault
  removal calls `Store::purgeVault` (`storage::Manager::removeVault`). The old path-keyed
  `Engine::{purge,move,copy}Thumbnails` helpers are gone; don't reintroduce path-keyed cache files.
- `preview::derive::Queue` (`Queue.cpp`) sits in front of Runner + Store: `request(engine, file, kind)` never blocks
  on conversion. Kind table (helper, command, args, generator version) is `queue_impl::kKinds`; bump a kind's
  generator version when its output changes. Flow: kind known + listed in the file's `PreviewPlan::derived` (transcodes
  not with `preview.media.transcode: off`, variant `v1`) else Unsupported → helper executable else Unavailable → `Store::lookup` Ready/Failed → in-flight key ⇒ Queued →
  `preview.derive.max_queue` pending ⇒ Busy → enqueue. `max_concurrency` `std::jthread` workers start lazily.
  A job re-checks the DB generation before opening, streams `openPlaintextReader` into the helper and the helper
  into a `Store::Writer`, and commits only if the generation is still current. Deterministic failures
  (invalid_input, limit_exceeded, unsupported, crashed, timeout) are negatively cached; transient ones
  (content_unavailable, integrity, internal, protocol, cancelled, helper missing) are only remembered for 30 s so
  pollers see Failed instead of polling forever. `Queue::shutdown()` (main, after `stopRuntime`) cancels running
  helpers via the stop token and joins.
- Lifecycle hooks (`preview/cache/Maintenance.hpp`): `applyConfig()` at boot (reader integrity/remote defaults,
  failure TTL); `sweepAtStartup()` after `initStorageEngines()` on every start (deletes legacy plaintext
  `<cacheRoot>/thumbnails`, orphan artifact dirs, temp files); `db::Janitor` runs `evictPeriodic()` every 15 min
  (LRU to `caching.max_size_mb`, idle expiry `caching.thumbnails.expiry_days`) independent of its DB sweep cadence;
  a finished key rotation (`sync::Local::handleVaultKeyRotation`) calls `Store::purgeRetiredKeys`.
- Tests: `test_preview_store.cpp`, `test_derive_queue.cpp` (DB-backed, fake helper symlinked under both helper
  names; real CAD helper when built).

### File recovery (`recovery/`)

Local snapshots, opt-in local versioning and AWS provider versioning behind one model (`recovery/Model.hpp`) and one
authorizing boundary (`ops::recovery`); migration 111. Design of record, as-built notes and open items:
`recovery.md`. Where it hooks into the rest of the daemon:
- **Writers:** every content write retains the prior generation through `recovery::local::versions::retain` before
  its rename (createFile overwrite branch, FUSE seal, deletes, sync DeleteLocal, cache index-only downloads); blobs live
  in `<backing>/.vh-recovery/<alias>`. Invariant: nothing writes a backing file in place
  (`tools/contracts/test_backing_writers_contract.py`). `Engine::freeSpace` counts blob bytes.
- **Upstream:** `CloudEngine::OwnWrite::done()` → `recovery::hooks::afterUpstreamWrite` (version index, usage ledger);
  `sync::tasks::Upload`/`Delete` replay a file's pending local versions first (`backlog::replayBeforeUpload` /
  `replayBeforeRemoteDelete`); the planner's price preflight adds them.
- **Runtime:** `db::Janitor` runs `maintainRecovery` each loop (≤ 15 min: version retention, backlog skips for
  unversioned buckets, the orphaned backlog of deleted files settled (#249, the only Janitor path that sends S3
  requests: under the pass lease, price-preflighted, bounded), plan expiry/purge) and, at startup then daily, the store sweep and interrupted-snapshot cleanup;
  `VaultRetentionService`'s loop calls `recovery::usage::tick` (ledger flush every 60 s, cost alerts hourly);
  `runtime::Manager::stopAll` flushes the ledger after every service stopped; vault purge removes the store directory
  (`vault/Retention.cpp`).

### `ops/`: shared command operations

`core/{include,src}/ops/` holds plain free functions with typed request structs, one file pair per family
(`ops::groups`, `ops::roles`, ...). Each op takes the acting `User` (`ops::Actor`, null → `ops::Denied`), authorizes, looks up,
validates, persists, and returns domain objects. Refusals are typed `ops::Error`s (`Denied`, `NotFound`, `Invalid`,
`Conflict`, and `NeedsConfirmation{code}` for "a person must accept this first", e.g. the encryption waiver). The CLI
handler parses with `CommandUsage` and calls the op through `shell::runOp`, which maps `ops::Error` to exit 2 (CLI
waiver prompts go through `shell::commands::vault::runWithWaiver`). The ws handler maps its payload to the request,
and every ws handler template (`protocols/ws/core/handler_templates.hpp`, `describeCurrentError`) turns the exception into
an `ERROR` response whose `data.code` is stable: `denied`, `not_found`, `invalid`, `conflict`, or the `NeedsConfirmation`
code (the web asks and resends with `accept_encryption_waiver`); a non-`ops::Error` fault has no code. Handler-level
gates (settings/email/pricing admin checks, share upload scope) throw `ops::Denied` so they carry `denied`; every
`stats.*` command authorizes through `ops::stats` (below). Rules: RBAC for an operation lives in the op, never in the frontend as well; code beneath
`ops::` (managers, `db::query`) never authorizes; internal callers use those primitives directly, not ops; no
registry, base class or transport abstraction. Parity is proven by `test_ops_parity_groups.cpp`, which runs each
group operation through both surfaces for every seeded admin role and compares verdicts and DB state.
Migrated families (each with `test_ops_parity_<family>.cpp`): `groups`, `roles`, `api_keys`, `vaults` (lifecycle,
safe deletion/restore, sync policy), `users`, `s3_gateway` (credentials, grants, buckets, credential budgets), `pricing` (price budget
policies), `config` (every settings write: one validation, one apply step that restarts the S3 gateway when
`s3_gateway.enabled` changes), `stats` (authorization only, ws-only: there is no `vh` stats command; `vh status`
is deliberately ungated, see Stats below), `conflicts` (sync conflicts, #187: ws `sync.conflicts.*`, `vh sync resolve` /
`vh resolve`, the HTTP `/download/conflict` lane's authorization), `upstream` (S3/R2 bucket administration and event
sync, #237/#96: ws `upstream.*`, `vh upstream …`; see `upstream-control-plane.md`), `recovery` (file recovery: ws `recovery.*` / `vault.recovery.*`, `vh snapshot|recovery …`, `vh vault recovery …`; see `recovery.md`), `devices` (paired devices: ws `device.*`, `vh device …`; see "Device listener
and pairing"). Still per-surface: the ws-only pricing preflight/override/notification endpoints,
email test-send/history, vault keys/sync diagnostics, and lifecycle commands (`setup`, `teardown`, `secrets`).

Rules the families hold (keep them in ops, never re-add them in a handler):
- **Users:** an account is an *admin identity* when its admin role grants anything outside the self scopes
  (`ops::users::isAdminIdentity`, which counts `admin.stats.view` too); that, not `User::isAdmin()` (a strict "full
  admin" test kept for S3 policy bypass and the resolvers' owner scope), picks admins.* vs users.* identity
  permissions. The ceiling applies to assignment *and* to managing an
  account above you (edit, delete, reset password). Deletion, deactivation, role change and password reset call
  `auth::Manager::revokeSessions` (refresh tokens revoked, live sessions invalidated). Account and role writes go
  through `identities::Manager` (below); credentials (password hashes) are never part of cached identity state:
  login and password checks read them with `Loader::credentialsByName/ById`.
- **API keys:** `update` edits in place (keeps the id, so `s3` rows survive; an empty secret keeps the sealed one;
  `KeyPerm::Edit`), re-validates credentials outside test mode and reloads the engines of the vaults using the key
  (`storage::Manager::reloadEngine`). `remove` refuses (`Invalid`, naming the vaults) while any `s3` row references the
  key, and `ops::users::remove` refuses up front when a surviving vault uses one of the account's keys. Backed by
  `s3.api_key_id ... ON DELETE RESTRICT` (migration 099; it was CASCADE and silently dropped bindings).
- **Vaults:** every change goes through `storage::Manager::updateVault` so the live engine (RBAC's source of the owner)
  follows; owner reassignment needs Create for the new owner; a key change needs Consume; sync settings need vault
  `sync.config.edit`.
- **S3 gateway:** the scope rule that was `CredentialManager::validateScopeMutation` is `requireScopeMutation` in ops;
  `CredentialManager` and `db::query::s3::Gateway` are trusted primitives. Vault names resolve owner-scoped or uniquely,
  never to the first match. Overrides need an explicit effect and pattern. Remote-cache buckets are created through
  `ops::vaults::create` (Consume, waiver) and rolled back if the bind fails.
- **Health:** `stats::model::SystemHealth::snapshot()` takes a bounded live DB probe; an unreachable database is
  critical there, so `vh status` and `stats.system.health` report the same severity.
- **Lists:** `ListQueryParams::sort` must be a column name (`isSortColumn`); it lands in ORDER BY.

**Role permissions (one mechanism).** Every permission change goes through
`PermissionResolver::applyChanges(role, exported, [(qualified, grant)], complete)`, which reports unknown names, missing
snapshot values and unapplicable permissions instead of skipping them. The CLI translates `--allow-*`/`--deny-*`
(the short flags `vh permission` prints, from each set's `flagPrefix()`) into that delta via
`shell/util/permissionFlags.hpp`; the web sends a complete `{qualified, value}` snapshot. The resolver only dispatches
a permission if its target trait (`TargetTraits.hpp`) or context policy (`policy/*.hpp`, included by `EnumPack.hpp`)
is visible; `test_role_permissions.cpp` round-trips every exported permission so a missing trait can't silently
no-op again. `ops::roles` enforces the escalation ceiling: nobody grants an admin permission they do not hold
(`permissionsBeyondActor`). Vault-role overrides persist through `db::query::rbac::permission::Override` on the
subject's assignment; both `vh vault role override ...` and ws `role.vault.overrides.{list,add,update,remove}` call
`ops::roles::*VaultRoleOverride*` (parity in `test_ops_parity_roles.cpp`).

## Subsystem invariants (enforced in code, keep them)

**Filesystem RBAC paths, FS cache and account deletion** (#178–#180, `VaultLifecycleRegressionTest`)
- `rbac::resolver::vault::Context::path` (and `fs::policy::Request::path`) is a **FUSE** path. Callers holding a vault
  path convert it with `engine->vaultPathToFusePath()` first; `share::Manager` once didn't, so only share root `/`
  ever passed and a vault path equal to another vault's FUSE root resolved to that vault. The evaluator refuses an
  entry whose `vault_id` differs from the request's vault (`EntryVaultMismatch`).
- The FS cache is keyed by FUSE path and can only re-hydrate a vault root through `mkVault` (or the rename path in
  `storage::Manager::updateVault`). `storage::Manager` calls `fs::cache::Registry::evictVault` on remove, on rename
  (old and new root, then re-caches the root) and in `addVault` *before* the engine creates the root. Evicting after
  `mkVault` would drop the fresh root and the whole vault would answer ENOENT.
- Every `users(id)` reference has a delete action (migration 104): attribution/audit columns `SET NULL`, while
  `file_locks.locked_by` and `share_link.created_by` `CASCADE` (a deleted account's public links die with it). New
  tables referencing `users` must pick one; a bare `REFERENCES users` blocks `vh user delete`.

**Delete keeps folders; copy is deep and readable at once** (#168, #167; `FsDirStatsDbTest`, `FsCopyDbTest`, harness
stage "Copy And Delete")
- Deleting a file never removes its parent folders, on every path: ws `fs.entry.delete`, FUSE unlink, the S3 gateway
  (DeleteObject, local purge), sync DeleteLocal and trash purge. `File::updateParentStats` only takes the file off
  every ancestor's totals (it was `updateParentStatsAndCleanEmptyDirs`, which deleted ancestors left without files
  except on FUSE calls, so the console and the mount disagreed). The S3 view still loses an implicit prefix with its
  last object: ListObjects derives CommonPrefixes from object keys, not folder rows, and `bucketIsEmpty` counts files
  only. A folder goes only when it is what's deleted. FUSE rmdir refuses a non-empty folder (ENOTEMPTY, including
  children the caller can't see; it used to cascade-delete them) and takes the folder off every ancestor's count.
  Trash purge removes only the file's backing path.
- `Filesystem::copy(CopyContext)`: plan (source subtree from the DB via `Entry::listSubtree`; `Entry::listDir(id, true)`
  returns only direct child files/symlinks and seeds the startup cache in that shape) → `authorize` every entry
  (ws: Copy + Read on each source file, Write/Touch at each destination) → quota (`freeSpace`) → bytes (outside
  `mutex_`): each file's sealed backing bytes are copied as-is to `<dest parent backing>/<new alias>` under the
  source's content lock, with the row snapshot taken under that lock (same IV, key version, plaintext size, content
  hash; no AAD, and any later write draws a fresh IV, so the shared (key, IV) only ever sealed that plaintext; a
  corrupted source stays detectable). Cloud files without a local copy are hydrated first (metered,
  price-preflighted); the next sync uploads the copy as a new object (one PUT each, planned and price-checked like any
  upload). → rows under `mutex_`, shallowest first, so totals build up entry by entry. Any failure takes back rows and
  bytes. The sync pass no longer replays `operations` rows (`Local::processOperations` wrote to the pre-alias
  `BACKING_VAULT_ROOT/<vault path>` layout and nothing had queued a pending row since 2025); the table records activity.

**Safe vault deletion with retention** (#162, migration 106, `vault/Retention.*`, `vault/RetentionService.*`,
`db/query/vault/Deletion.*`, `VaultRetentionTest`, `VaultParityTest.DeletionLifecycleAgreesOnBothSurfaces`)
- A delete is a schedule (`ops::vaults::remove` → `vault::retention::schedule`): one transaction sets
  `vault.deleted_at`, detaches the vault root (`fs_entry.parent_id = NULL`), nulls the vault's inodes, copies every key
  version (still TPM-sealed) into `vault_deletion_key` and writes the `vault_deletion` record (purge_after,
  key_retain_until, delete_upstream); then `storage::Manager::retireVault` drops the engine, evicts the FS cache, purges
  derived artifacts and refreshes sync. Read paths filter deleted vaults: `get_vault*`, `listVaults/listUserVaults`, share
  link statements, S3 gateway bucket resolve/list. `vault_exists`, slug/FUSE-name uniqueness and the `s3` binding still
  see them: **the name, slug, FUSE name and bucket stay reserved until the purge** (`ops::vaults::create` says how to
  restore or purge). Restore (pending only) re-attaches the root and rebuilds the engine (`reinstateVault`; descendants get
  inodes lazily). Restore and the purge claim the same row (`DELETE … WHERE state='pending'` vs `UPDATE … SET
  state='purging'`), so they never both win.
- `VaultRetentionService` (30 s, or at once after "delete now") runs `retention::runPass(now)`: claims due records,
  deletes upstream objects when chosen (≤ 10 LIST pages / 10 000 DELETEs per pass via `Controller::listObjectKeysPage`,
  resumable, refused when the binding is gone or another vault uses the same bucket+endpoint+region: the purge then
  finishes locally with a note), removes the backing and cache dirs through `removeVaultDirectory` (alias must be one
  `[A-Za-z0-9_-]` name, a real directory directly under the resolved root, never a symlink), then deletes the vault row
  (`finishPurge`, only `deleted_at IS NOT NULL`). Failures retry with backoff (30 s → 1 h). Key copies are dropped when
  `key_retain_until` passes; the tombstone row stays. "Delete now" never shortens the key window.
- RBAC: delete, delete now, restore and listing need vault Remove; a deleted vault has no engine, so the admin resolver
  takes `admin::Context::vault` (built from the record's owner). Export tracking: `vault_keys.exported_version/at`
  (set by `vh vault keys export`; a rotation makes it stale). NeedsConfirmation codes `vault_upstream_key_loss` (S3,
  encrypted objects kept, key never exported) and `vault_delete_now`. `storage::Manager::removeVault` stays the
  immediate hard delete (create rollbacks, empty S3-gateway buckets) and now removes the backing dirs too.
- An account whose API keys are bound to any vault (deleted ones included, until purged) cannot be deleted.
- A vault role assigned only on deleted vaults is not in use (`count_vault_role_assignments_by_role_id` joins live
  vaults): deleting it cascades those assignments, and a restore brings the vault back without them.

**Sync conflicts** (#187, migration 107, `sync/model/Baseline.*`, `db/query/sync/Conflict.*`, `sync/ConflictResolver.*`,
`ops/Conflicts.*`; `SyncConflictsTest`, `ConflictParityTest`, `SqlDeployerHistoryDb.SyncConflictMigration*`)
- One open (`resolution = 'unresolved'`) row per file (`uq_sync_conflicts_open_file`). `sync::Cloud::initBins` loads the
  vault's baselines and open conflicts; the Planner decides; `Cloud::flushConflictState` (via `planPass`) writes them
  in one transaction before anything executes. An open row's artifacts are refreshed in place only when a side
  changed. Closed as `kept_local|kept_remote` (a decision, or the policy once it is no longer `ask`), `converged` (both
  sides agree again), `superseded` (remote side gone; duplicates closed by 107). `event_id` is the first run that saw
  it and is `ON DELETE SET NULL` (event retention no longer deletes open conflicts). Auto-resolved conflicts under
  `keep_*` stay per-event history rows (`sync_conflict.upsert`); `Event::upsert` skips unresolved ones.
- **Detection under `ask` is two-sided only.** `files.content_hash` is blake2b of the *sealed* backing file, so a
  download re-sealed under a fresh IV never hashes like the object it came from, and `hasPotentialConflict` (size or
  hash differ) fires on any one-sided edit. `sync_file_baseline` records each side's identity when they last agreed
  (local hash/size; remote index hash, ETag, size), written on agreement (`Cloud::noteInSync`) and after every
  successful upload/download/index refresh (`sync::tasks::recordBaseline`) and resolution. `Baseline::classify`:
  LocalOnly → Upload, RemoteOnly → Download (archive tier skipped), InSync → nothing, Both or Unknown (no baseline) →
  conflict. A baseline written by local versioning's backlog replay (`Baseline::publishing()`, recovery.md) whose
  remote side is unchanged plans an Upload under every policy (finishing an interrupted publication). Every policy
  skips a file whose classification is InSync (#190: under `keep_remote`/`keep_newest` a file
  downloaded from another writer's object used to differ by hash on every pass and be downloaded again). Otherwise
  `keep_*` still treat any difference (one-sided included) as theirs to settle.
- **Resolution** (`ConflictResolver::resolve`, trusted; `ops::conflicts::resolve` authorizes per item): the local row
  must still match the local artifact and one HEAD must still match the remote artifact (ETag, else content-hash
  metadata, else size, + 16 for GCM when encrypted), else `ConflictStale` (status `conflict`). keep_local =
  `CloudEngine::upload` + `applyRemoteIndexMutation`; keep_remote = `fetchRemotePlaintext` (streamObject, If-Match the
  HEAD's ETag, the object's own vh-iv/key version adopted from the HEAD) + `replaceLocalContent` (createFile with
  `expected_source_id` = the checked generation: a true CAS against FUSE/HTTP writes). Price preflight
  `conflict_resolve` (Planner estimate + the HEAD), per-thread `ScopedS3RequestUsageCapture` under the vault's
  request budget (never the engine-wide budget a running pass owns), no FS/DB lock across network work, then one
  transaction closes the row and records the baseline. One in-flight decision per conflict per process.
- **Who:** `vault.sync.action.resolve_conflicts` (sync action bit 2 = mask bit 10) **plus** filesystem Overwrite on the
  file (Read for previews). `ops::conflicts::canResolveIn` = `rbac::resolver::Vault::has`. For sync config/action
  permissions (`VaultResolverMode<E>::vault_roles`) the resolver grants on the admin vault globals (owner self scope,
  admin, user) OR a vault role on that vault, the account's or a group's (#189); role bits only add. Vault-role
  `roles` permissions are deliberately still globals-only: group role assignment has no guardrails yet, so a
  group-held role must not let its members hand out roles. Lists/summary include only vaults the actor can resolve in; deleted vaults are excluded.

**Operator email** (`email/`, `notifications/`, `085_operator_notifications.sql`, `vh email …`)
- Provider secrets are encrypted in `internal_secrets` and entered by hidden prompt. They never go in `.env` or files, and are never logged or rendered.
  Secret reveal was deliberately removed (`a7cc2f4b`).
- If email is disabled, the server must still report healthy. Security alerts are enqueued only after a successful DB write
  and never block the mutation. `Manager::startWatchdog()` stays restart-only.

**Stats / dashboards** (26 `stats.*` ws commands, `dashboard.preferences.*`)
- **Who may read (#166, `ops::stats`).** System stats (overview, severity, health, thread pools, FUSE, DB, operations,
  connections, storage, retention, trends, FS/HTTP caches, system pricing totals) need the admin permission
  `admin.stats.view` (module `admin.stats`, `admin_role.stats_permissions` BIT(8), bit 0; migration 105 added the
  column and granted it to `admin`, `auditor`, `platform_operator`, `super_admin` and any role that passed the old
  `isAdmin()` gate). Vault-scoped stats (`stats.vault.*`, `stats.pricing.budget {vault_id}`) are open to the vault's
  owner or an admin role with `admin.vaults.<scope>.view` + `view_stats` on it; vault-role members who don't own the
  vault are not enough (activity/share/security stats ignore path overrides). Missing and forbidden vaults refuse
  alike. `vh status` is not gated: it skips the DB user lookup so it works while PostgreSQL is down. Guard:
  `test_stats_access.cpp` (`StatsPermission*`, `StatsAccessTest`), `RoleParityTest.StatsView*`,
  `SqlDeployerHistoryDb.StatsPermissionMigration*`.
- **Payload contract (#160).** Trends read `stats_metric_rollup` for every window (5-minute buckets up to 7 d, hourly
  beyond; rollups are upserted with each sample batch), so 24 h never returns more points than 7 d. Overview hrefs are
  console routes (`/health/*`, `/cost#…`); counts carry `numeric_value`; money carries `numeric_value` + the ISO
  currency as `unit`, or `"unknown"`/null when not measured. `PriceBudgetDashboardStats.{current,projected}_monthly_spend`
  are null without a monthly window. A cache with no byte cap (the FS metadata cache) reports
  `capacity_bytes`/`free_bytes` null; the preview cache reports `caching.max_size_mb` from boot. Cards carry at most
  `kDashboardOverviewMaxSeriesPerCard` (3) series of `kDashboardOverviewMaxPointsPerSeries` (64) points.
- The backend owns severity, warning, and error truth. Never show fake integrity, recoverability, or latency badges; report
  unavailable values as `null` / `"not_available"`.
- Stats commands are read-only, and snapshots are background-only. Preferences are scoped to `session->user->id`.
- `stats.dashboard.severity` (nav badge) returns `{stats: {overall_status, error_count, warning_count, checked_at}}` from
  `DashboardOverview::severity()`: the same default cards and aggregation as the overview, without trend series or
  sections, and without serializing cards.
- Rationale history: `history/stats-dashboard.md`.

**S3 pricing / cost estimates** (`core/{include,src}/storage/s3/pricing/`)
- Prices come from the **price bot**, a separate repo (`github.com/vaulthalla/vaulthalla-price-bot`, checked out at
  `/srv/vaulthalla-price-bot`, DB `vaulthalla_price_bot` on dev-db). It fetches official provider pricing, normalizes it,
  and publishes **Ed25519-signed** artifacts (`price-bot publish` / `mirror-artifacts`), served under `/v1/artifacts/`.
- Core `PriceBotClient` fetches `/v1/artifacts/manifest.json` plus the artifacts, verifies signatures with libsodium
  (`verifyEd25519Pem`), and caches under `<backing path>/price-cache`. `PriceCatalogStore` tries the primary source,
  then `fallback_artifact_base_urls`. `PriceEstimate` feeds price budgets (`091`–`094_s3_price_*.sql`).
- Config: `pricing.storage_rates_api` (`base_url: https://storage-rates-api.vaulthalla.cloud`,
  `remote_refresh_enabled: false` in the shipped config, `fail_open: true`, 12h cache/refresh). A local dev price bot
  runs on `127.0.0.1:36933`.
- Alerts live in `operator_notification` (severity `info < warning < error < critical`, the 094 CHECK; ranked by
  `priceBudgetNotificationSeverityRank`). ws `pricing.notifications.list` returns the page (`limit`, newest first) plus
  `summary: {open_count, worst_severity|null}` over every OPEN (unacknowledged, unexpired) alert the caller can see,
  from one `GROUP BY vault_id` aggregate (`PriceBudgetService::summarizeOpenNotifications`) filtered by the same vault
  visibility as the rows, so it never depends on `limit` (#172). The console bell reads its badge from it.
- Invariant: never trust unsigned or unverified price artifacts. Estimates are guidance and `fail_open`; enforcement modes act on
  them, so a pricing outage must not wedge sync.

**S3 cost safety** (sync + S3 gateway + remote-only reads)
- Request budgets (LIST/HEAD/GET/PUT/COPY/DELETE/bytes) and price budgets (`off|report|warn|enforce`,
  global/provider/vault) are separate systems. Don't merge them.
- Usage captures (`ScopedS3RequestUsageCapture`) are thread-local and nest: every capture active on the thread is
  checked and records each request (`Controller::recordRequest`), so a hydrate's own cap inside a gateway request
  is still visible to the gateway's capture. `Controller::streamObject` is the metered streaming GET (optional
  signed `Range` and `If-Match`; 412 → `ConditionalRequestFailed`; the GET is metered before it is sent, body
  bytes as they arrive); fakes override the protected `transportGet(key, versionId, headers, onBody)` seam and keep
  the metering.
- **Provider versions (data plane, `storage/s3/version.cpp`):** `listObjectVersionsPage` (List), `headObjectVersion`
  (Head; 404 → nullopt, delete marker → `delete_marker`, outages throw), `streamObject` with
  `GetObjectOptions::version_id`, `copyObjectVersion` (Copy, directive COPY keeps vh-iv/key-version/hash; > 5 GiB →
  `ObjectTooLargeForCopy` before metering; a 200 carrying `<Error>` fails). They sign with `sigv4::sign` (sorted,
  RFC 3986 query identical in URL and signature: version ids carry `+/=`) and send through `curl::http` (timeouts,
  test transport). Every PUT path records the thread's `lastPutOutcome()` (ETag + `x-amz-version-id`). The legacy
  `buildAuthorizationHeader` sorts the canonical query (it signed `list-type&…&continuation-token` unsorted).
  Test fake: `tests/helpers/versioned_bucket.hpp` (`VersionedBucket`: S3 versioning modes, delete markers, failure
  injection, body-GET counters).
- **Listings are never partial (#246).** `Controller::listObjects` (the full LIST behind `Cloud::initBins` →
  `RemoteObjectIndex::replaceFromListObjects` and `vault sync reconcile`) and `listObjectKeysPage` throw on any
  transport error, non-2xx (403 SignatureDoesNotMatch, 503 SlowDown), cut/non-XML body, or a truncated page without
  an advancing token; callers fail the pass and leave the index untouched. `listObjects` signs with `sigv4::sign` and
  goes through `curl::http` (test transport: `S3ListObjects*`); its result is one ListBucketResult per page, and
  `fs::model::filesFromS3XML` reads every one of them (it used to read only the first: buckets past 1000 objects
  indexed page 1 only).
- **Prefer the local ciphertext copy (D11).** Anything that reads a vault file's bytes goes through
  `Engine::openPlaintextReader`: a cloud file with a backing file reads it in place (zero S3 requests). The ws share
  download/preview lanes and the S3 gateway's file reads (`ObjectStore::readFileObject`, ranges read only their
  bytes) do; the HTTP `/download` lane is the lead's rewrite. `CloudEngine::downloadToBuffer/decryptRemotePayload`
  remain only for HTTP `Router.cpp`, rotation, and gateway objects with no `files` row.
- **Remote-only files (`CloudEngine::openMissingReader`, `preview.media.remote`, process default
  `storage::setDefaultRemotePolicy`):**
  - `hydrate` (default): price preflight (`RemoteFetchGate`, default `priceBudgetRemoteFetchGate`: the
    BudgetConservative estimate + `PriceBudgetService::preflight` sync uses, operation `preview_hydrate`; a refusal
    or a failed preflight → `ContentUnavailable`, nothing sent) → per-hydrate request cap (1 HEAD, 1 GET, object
    bytes) → HEAD (ETag, length, `vh-iv`/`vh-key-version`; a length that disagrees with `files.size_bytes` is
    refused, not fetched) → one GET with `If-Match` streamed into an `O_TMPFILE` next to the backing path (named
    0600 `O_EXCL` `.vh-hydrate-*` sibling where unsupported) → `gcmVerifyFd` over the whole message (failure:
    `IntegrityError`, nothing kept) → fsync → if the IV changes (plaintext-upstream objects are sealed on the fly
    under a fresh IV; an encrypted object normally keeps the row's IV, `indexAndDeleteFile` copied it) the files
    row is compare-and-set *first*, then the copy is linked in without replacing anything (`linkat`, EEXIST: a
    writer won) and the directory fsynced. A crash leaves either no copy (re-hydrated next read) or a verified one.
    Concurrent readers of one file share a single fetch (`hydrating_` futures). The reservation is committed with
    the actual usage. The copy stays: the Cache strategy has no eviction yet.
  - `ranged` (opt-in): `RemoteRangedReader`, aligned 4 MiB windows, LRU of 4, every GET `If-Match` the open-time
    ETag (412 → `IntegrityError`), CTR-decrypt with the *remote* IV, per-reader caps (default 2·windows+8 GETs,
    2·(size+window) bytes; past them `ContentUnavailable`), worst case price-reserved at open and actual usage
    committed on close. Positioned reads are **unauthenticated** (a hostile bucket can flip plaintext bits);
    `readAllAuthenticated` fetches the whole object and checks the tag. Chunked AEAD is the eventual fix.
  - `off`: `ContentUnavailable`.
- Dev R2 dogfooding hits a real bucket. With `dev.init_r2_test_vault`, initdb clears the `VAULTHALLA_TEST_R2_*` bucket.

## Test instances, contracts and the fs actor (2026-10-11)

- `VH_TEST_MODE=1` makes `vaulthalla-server` a private test instance: `runtime/TestInstance.hpp` refuses to start
  (exit 78) unless the DB settings, backing/mount/log/runtime/config paths and `VH_TEST_CLI_SOCKET` all come from the
  environment and are private (paths under `/tmp/`, a `vh_harness_*` or test database). Test mode then serves `vh` on
  that socket (`paths::getCliSocketPath()`); the client honours `VAULTHALLA_CLI_SOCKET`.
- `core/usage` also holds the contract: `FieldGen` generators on CLI usage entries, per-leaf `effect`, `OperationSpec`
  catalog, `WsCommandUsage` book, exported by `vh_usage --json`; and the MCP catalog built from them (above).
- `vh_fs_actor` (`core/tests/helpers/fs_actor.cpp`, `-Dintegration_tests=true`): a single-threaded helper that
  switches to a test uid at startup and serves filesystem ops as JSON lines; used by Tier A and `tools/harness`.

