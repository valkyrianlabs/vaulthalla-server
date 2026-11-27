# Architecture: core daemon, protocols, runtime

Verified against `main` @ 1.6.6 (2026-09-30). Merges the old `.codex` repo-overview,
core-backend, and protocol-map docs, with stale claims corrected.

## Build graph

- Root `meson.build` holds `project('vaulthalla', 'cpp', version: '1.6.6')`: `cpp_std=c++23`,
  `unity=on`, `unity_size=9`, `warning_level=3`, `werror=false`, `prefix=/usr`, meson >= 1.3.0.
  It enters C++ via `subdir('core')` and also installs `deploy/lifecycle` → `/usr/lib/vaulthalla/lifecycle`.
- `core/meson.build`: deps `libsodium libcurl boost(filesystem) libpqxx-vh pdfium yaml-cpp spdlog fmt openssl>=3
  libmagic libjpeg libturbojpeg pugixml zlib threads`, the WebAuthn verifier `vl-webauthn`
  (the pinned subproject: libcbor >= 0.10, OpenSSL, libsodium, the vendored nlohmann), the vault format `vl-vaultfmt`
  (the pinned subproject, `subprojects/vl-vaultfmt.wrap`: OpenSSL, vl-keykit, the vendored nlohmann; #443, below; the
  server builds no fuzz target since its codecs moved to vl-webauthn and vl-vaultfmt), plus `fuse3` when the kernel bridge is built (`-Dfuse`, auto:
  required on Linux; never on macOS, where `-Dfuse=enabled` is a setup error) and the Linux-only `uuid tss2-esys tss2-tctildr tss2-rc`.
  OS-specific code lives only in `core/src/platform/{linux,darwin}/` behind `core/include/platform/*.hpp` (see
  `macos.md`); source discovery adds the host's directory and, without FUSE, swaps the four libfuse sources for
  `fuse/unbuilt/Service.cpp`.
  The two Vaulthalla-built SDKs come only from the Valkyrian Labs APT repository (apt.valkyrianlabs.com, alias apt.vaulthalla.sh): `libpqxx-vh-dev` (libpqxx 8, a **static** archive
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
for SIGINT/SIGTERM. Shutdown: `Manager::stopAll` → `preview::derive::Queue::shutdown()` → thread pools →
`resumable::Service::shutdown()` again (a late device upload could restart its workers; a joinable worker in the
static registry aborts at exit) → `runtime::Deps::releaseSessions()` (the cached ws sessions go before main returns, while the io_contexts their sockets
were bound to still exist; a session destroyed in static destruction crashed at exit, #397/#385). An io_context a
stopped listener keeps for sessions that outlived it (`protocols::retainForProcessLifetime`) is never freed, not even
by static destruction.
Shutdown is bounded and fast (restart ≈1 s; guard: `test_shutdown_bounds.cpp`): the SIGTERM/SIGINT handler only sets
an atomic and notifies a `platform::Waker` (eventfd on Linux, self-pipe on macOS); a watcher thread (started before startup) wakes main and `_Exit`s 10 s after the first
signal whatever main is doing; a second signal exits at once. `stopAll` calls `requestStop()` on every service but FUSE
(non-blocking: flag + cv notify + `onStop()`), joins them, then stops FUSE last. Services sleep with `lazySleep` (cv,
woken by stop), never `sleep_for` loops. FUSE `onStop()` lazily unmounts, ends the session, and after 1 s aborts the
fusectl connection (minor from `/proc/self/mountinfo`) if the mount is still referenced. Thread pools never lend
workers; `ThreadPoolManager::shutdown` requests every pool's stop, then joins all against one 3 s deadline (stragglers
are detached; workers hold only shared state). Pools: fuse, thumb, http, stats, s3 take max(cores x 3, 8) / 6 each (6
on 12 cores); `syncPool()` runs a pass's operations (uploads, downloads, deletes, key-rotation ranges) with
`sync.worker_threads` workers (0: one per core, 4..64); `syncPassPool()` runs the passes themselves
(`sync.max_concurrent_passes`, default 4). A task must never wait on futures of its own pool (no work stealing): passes
and their operations shared the sync pool until 1.25.0, and once every worker held a waiting pass, sync hung for good.
After every run a regular sync task reschedules itself (`Local::finishRun`, a scope guard): SUCCESS and STALLED at the
interval, anything else with backoff (interval x 2^(n-1), capped at max(interval, 1 h)); scoped, interrupted and
replaced tasks are not rescheduled. A stage that fails ends the pass (`Local::runStages`).

`core/src/runtime/Manager.cpp` owns the service lifecycle. It runs a watchdog every 2s and restarts
a service after 500ms. Start order:

```
FUSE → IdentityWatcher → SyncController → UpstreamEventService → DBJanitor → VaultRetentionService →
LogRotationService → StatsSnapshotService → OperatorEmailService → ConnectionLifecycleManager → ProtocolService →
DeviceServer → CloudRelayService → S3GatewayService (+ ShellServer)
```

Stop order is the reverse, with the ShellServer stopped right after ProtocolService.
ShellServer is not created in test mode (`paths::testMode`).

## Protocol surfaces (`core/src/protocols/`)

| Surface | Code | Default bind (shipped `deploy/config/config.yaml`) |
|---|---|---|
| WebSocket `/ws` | `ws/Server.cpp`, `ws/Router.cpp`, `ws/Handler.cpp`, `ws/handler/*`, `ws/Session.cpp` (refuses a browser `Origin` that isn't the requested host or in `websocket_server.allowed_origins`, `ws/OriginPolicy.hpp`, #324) | `127.0.0.1:36969` |
| HTTP preview/download/upload/auth | `http/Server.cpp`, `http/Session.cpp`, `http/Router.cpp`, `http/Access.cpp`, `http/handler/*`, `http/upload/Coordinator.cpp`, `http/upload/Resumable.cpp` | `127.0.0.1:36970` |
| S3 gateway (SigV4, multipart) | `s3/*` (`GatewayService`, `Auth` (SigV4 via vl-sigv4), `ObjectStore`, `MultipartStore`, `CredentialManager`) | `127.0.0.1:39000`, disabled by default (remote clients go through the HTTPS proxy) |
| Shell/CLI control | `shell/Server.cpp`, `shell/Router.cpp`, `shell/commands/*` | unix socket `/run/vaulthalla/cli.sock` |
| Device listener (Vaulthalla Desktop, mutual TLS) | `device/Service.cpp`, `device/Listener.cpp` (`/ws` → the ws Router) | `127.0.0.1:36972` (+ `[::1]` when available); `[::]` dual-stack once `device_server.remote`, `0.0.0.0` where IPv6 is off (absent section = these defaults) |

**S3 gateway authentication** (`protocols/s3/Auth.{hpp,cpp}`): `Router::route` builds a `vl::sigv4::VerificationInput`
with `verificationInput(request, body, sha256)` (Beast adapter; streamed bodies pass the aws-chunked-decoded hash) and
`Authenticator::authenticate` calls `verifySignedRequest`: `vl::sigv4::parseAuthorization` → the gateway's own refusal
of `X-Amz-Security-Token=` anywhere in the target → `vl::sigv4::verify` with a `SecretLookup` (date, skew/presign
window, signed headers, payload hash first; then `CredentialManager::findEnabledSecret`, a DB read plus decryption;
then the constant-time signature). Options (`gatewayVerifyOptions`): service `s3`, any region, ±15 min, presign ≤ 7 d,
no session tokens, host must be signed, scope date = x-amz-date date, implied `content-length: 0` for bodiless
requests a proxy stripped it from. Failures map to AWS's S3 codes and statuses in `sigv4Error`.
**aws-chunked bodies** (`protocols/s3/RequestBody.{hpp,cpp}`): `Session` spools a streamed PUT to a
`crypto::ScratchFile` at `<backing>/.s3-request-body/<uuid>.body` (0700, `requestBodyRoot()`; ciphertext under the process
key, #345; `BodyPayload::file`) and, when `isAwsChunked` (Content-Encoding `aws-chunked`, or any `STREAMING-*`
payload hash: mc signs chunks without Content-Encoding), sets `BodyPayload::aws_chunked_decode_to`. `Router::route`
decodes it with `decodeAwsChunkedBody` (vl-sigv4's `AwsChunkedDecoder`, the only aws-chunked parser): unsigned framing
before authenticating (a hashed payload is compared with the decoded body); signed chunks
(`STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER]`: mc and the Java SDK over plain HTTP) after it, through the
`vl::sigv4::ChunkVerifier` that `authenticate(input, &chain)` hands back once the seed signature verified. Nothing
reaches `routeAuthenticated` (and so no object, budget or metadata write) unless every chunk and trailer verified;
the decoded body is another scratch file (`<uuid>.body.decoded`), and both go with their last reference (`route`
returns, or throws). The body is committed through `fs::sourceOf(ScratchFile)` (`ObjectStore::putObjectFromSource`,
`MultipartStore::uploadPartFromSource`). Signed chunks outside a streamed PUT, and SigV4a streaming, answer
`NotImplemented`. `protocols/s3/SigV4` (the old verifier) has no production callers: it is the goldens'
reference until a release is verified. Tests: `S3GatewayAuth*`, `S3GatewayStreaming*`, `S3GatewayClientCaptures`
(real-client captures incl. mc's signed-chunk and `--checksum` bodies, `tools/dev/sigv4-capture/`),
`S3GatewayDbTest.SignedStreamingUploadsStoreOnlyFullyVerifiedBodies` (socket end to end, tampered/reordered/dropped/
unfinished bodies store nothing), `S3GatewayDbTest.RealMcUploadsOverPlainHttpWhenMcIsInstalled` (skips without mc),
`SigV4Goldens.{VlSigv4Verifier,GatewayVerifier}*`.

**S3 gateway object listing** (`Router` bucket GET → `ObjectStore::listObjects` → `db::query::s3::Gateway::
listObjectStates`): one query for local, `remote_cache` and `remote_proxy` buckets (each LIST first backfills
`s3_gateway_object` from fs entries or `remote_object_index`). Order is S3's, ascending UTF-8 bytes, never the database
collation (en_US on stock Linux clusters, C on macOS): the sort and the page start use PostgreSQL's byte-wise operators
(`ORDER BY … USING ~<~`, `~>~`, `~>=~`), which `idx_s3_gateway_object_vault_key` (`text_pattern_ops`) serves as an ordered
index scan; `COLLATE "C"` would sort the vault's keys on every page. A page starts strictly after
`ObjectListParams::after`: a key (StartAfter, v1 Marker) or the last item of the page before (`next_after`); with a
delimiter, a position that is a common prefix of the listing skips everything under it, any other position is a key
and keys after it still roll up into its prefix. `list-type=2` is ListObjectsV2, anything else ListObjects v1
(`xml::listObjectsV2` / `xml::listObjects`). The v2 continuation token is opaque (`protocols/s3/Listing.hpp`: `vh1.` +
unpadded base64url of the position) and never percent-encoded: `EncodingType=url` covers key fields only, and clients
send tokens back verbatim (boto3 always asks for `url`; an encoded token made page two page one again, v1.23). Unknown
tokens and listing parameters that aren't UTF-8 answer `InvalidArgument`. Bucket subresources (`bucketSubresources`
in Router.cpp: every S3 subresource by name, plus any other parameter without a value; listing, multipart-paging and
signing parameters never count) are configuration calls, routed before CreateBucket/DeleteBucket/listing
(`bucketSubresourceResponse`; only GET `?uploads` and POST `?delete` are served elsewhere): authorised as a listing
(HeadBucket + ListObjects), a GET answers S3's unconfigured-bucket default (`xml::unconfiguredBucketSubresource`:
location, versioning, notification, logging, accelerate, requestPayment) or its 404 (`missingBucketConfiguration`), or
NotImplemented (`?versions`, `?acl`, `?policyStatus`, unknown); every write is NotImplemented. Through v1.24.1 a config
PUT was CreateBucket and a config DELETE was DeleteBucket. Tests:
`S3GatewayListing*` (`test_s3_gateway_listing.cpp`: an SDK-style paginator over the router, every page size, both
encodings, delimiters, all three modes, and the bucket subresource answers, writes and authorisation),
`S3GatewayDbTest.Boto3PaginatorsListABucketLargerThanOnePage` (real boto3, 2,500 keys, skips without boto3),
`S3GatewayDbTest.Boto3HearsS3sAnswersForBucketConfiguration` (real boto3 configuration calls).

> `core/include/config/Config.hpp` compiled-in defaults are **33369/33370**, but the shipped config,
> web fallbacks, and Caddyfile all use **36969/36970**. Trust the config file, and treat that
> header/config mismatch as a known wart. Every listener's compiled-in host is `127.0.0.1` (#324): a config without
> a `host` key never binds all interfaces.

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

**File transfer (`vh fs ls|get|put`, #229).** The CLI file path on hosts without a mount (macOS: the server never
mounts there, and Finder access is Vaulthalla Desktop's File Provider, valkyrianlabs/vaulthalla-desktop#1; #262). No macOS FUSE
identity adapter is coming, so nothing retires it, but don't grow it into a second file API. Bytes ride the same length-prefixed JSON frames, never a second channel
(`protocols/shell/Transfer.hpp`, header-only and shared with the client): the request carries `"transfer": {"v":1}`
(`put_size` for put), the daemon answers `transfer`/`transfer-ready`, then `data` frames (`seq`, base64 of at most
256 KiB) and `transfer-end`/`transfer-abort`, then the usual `result`. Limits are checked before allocation: 512 KiB
per frame during a transfer (the server's general request limit is 1 MiB), 64 MiB for any reply on the client.
Transfers are never interactive (they keep the 10s read timeout), at most 4 gets and 2 puts run daemon-wide, 6h max.
Authorization is `http::access::resolveUserPath`/`requireUser` (the HTTP lanes' evaluator, taking the peer-mapped
`User` instead of a session), re-evaluated with the user reloaded every 32 chunks of a get and before a put commits.
A put is staged in `<backing>/.cli-staging/put-*.part` (a `crypto::ScratchFile`, see "Plaintext in use" below; 0600 in
0700, swept at CLI-server start) and committed by `fs::Filesystem::createFile` with `source` (an `fs::PlaintextSource`;
streaming seal; overwrite is CAS on the authorized
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
- **Effect ceiling** (`withinCeiling`, `parseCeiling`, `ceilingRefusal`; `design/core/mcp-remote-signin.md`): a
  principal's limit, `Read` | `Write` | `Destructive`. `Catalog::tools(ceiling)` lists vh_help and vh_read always, vh_run
  from Write, typed tools by effect; `Catalog::prepare(tool, args, ceiling)` refuses anything above it (a plain tool
  error, before any confirmation is asked for; an unknown effect fails closed below Destructive); `mcp::Server` takes
  it (default Destructive = the catalog without a ceiling, what `vh mcp` and unscoped paired devices get). Tests:
  `McpCatalog.Ceiling*`, `McpServer.ACeilingLimits*`.
- **serverInfo** for clients on 2025-11-25 or later: `icons` (Vaulthalla's logo, 64 and 128 px PNG as `data:` URIs,
  `core/usage/assets/vaulthalla-{64,128}.png` embedded by `tools/dev/mcp_icons.py` into `src/mcp/Icons.cpp`),
  `description` and `websiteUrl` (`https://vaulthalla.io`); an older revision gets none of the three. Tests:
  `McpServer.IconsAreTheAssetsBytes`, `McpServer.IconsDescriptionAndWebsiteOnlyFrom20251125`.
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
  `--`, odd option spellings, confirmation flags in the command, and `mcp::exclusions()` (one list: `vault key export|import`,
  `secrets export|update`, `setup`, `teardown`, `fs get|put`, `mcp`, `skill`, `device pair|approve|deny`,
  `device remote enable|disable`, `cloud link|unlink`, `cloud recovery enroll|unenroll`, `vault remote attach|detach|access`; also checked case-insensitively). Defense in depth for key material:
  `protocols::shell::AgentCallScope` marks a command run for an MCP client (`/mcp`'s executor; a `vh mcp` request
  carries `"agent": true`), and the vault key handlers refuse under it (`key-backup.md`).
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

### Remote connectors (`connector/`, migration 151; `design/core/mcp-remote-signin.md`)

OAuth 2.1 remote sign-in for hosted AI clients (Claude, ChatGPT) and CLIs on other machines, built in steps (the
design's build plan); nothing listens yet (the connector listener is step 5). Decided 2026-11-22: super admins only
grant (`connector::mayGrant`), widest scope `write` unless `connector_settings.max_scope` is raised, grants last
`kGrantLifetime` (90 d) and end after `kRefreshIdle` (30 d), DCR off, any https CIMD host (`client_hosts` empty).
- **Tables:** `connector_settings` (singleton, absent = off; `public_origin`, `max_scope`, `dcr_enabled`,
  `client_hosts`), `connector_clients` (cimd | registered | dcr), `connector_grants` (uuid; user CASCADE; scope read |
  write | destructive; `revoked_reason` final), `connector_refresh_tokens` (`tokenDigest` only, `successor_id`).
  Access tokens and codes are never stored. Query layer `db/query/connector/Connector.hpp` (TEXT[] travel as JSON).
- **`connector::Grants`** (`connector/Grants.hpp`): `create` (audited `connector.grant.create`),
  `issueFirstRefreshToken` (once per grant: a second code redemption gets nothing), `refresh` (one locked transaction,
  `Grants::rotate`: current → successor; a retired token again → `refresh_reuse`, grant and tokens revoked, user
  notified, except once within `kLostResponseAllowance` (10 s) while its successor is unused, which revokes that
  successor and issues another; wrong client changes nothing; expired → `expired`), `revoke*` (audited
  `connector.grant.revoke {reason}`), `endCondition`/`reconcile` (user inactive, not a grantor, past lifetime, idle,
  a code unredeemed after 10 min). Triggers: main.cpp's identity publication hook (with key-backup grants),
  `auth::Manager::revokeSessions` (`sessions_revoked`: sign out everywhere, deactivation, deletion, MFA reset), a
  recovery-code sign-in (`mfa_recovery`), the Janitor. Tokens: `vh_rt_`/`vh_at_`/`vh_ac_` + base64url(32 random
  bytes). Tests: `ConnectorGrantsDb.*`, `SqlDeployerHistoryDb.ConnectorGrantsMigration151*`.
- **`ops::connector`** (`ops/Connector.hpp`; `vh connector …`, ws `connector.*`, models `ConnectorStatus`,
  `ConnectorGrant`, `ConnectorClient`): super admins only, except listing and revoking one's own grants. Switching on
  (`--url`, `connector::urls::canonicalOrigin`: https, a DNS name, port 443), widening the policy and registering a
  client take step-up `connector.trust` (target-bound; targets `connector.enable:<origin>`, `connector.policy:…`,
  `connector.client.add:<digest>`); the CLI is Host (exempt); Channel Agent is refused, and `connector` is an MCP
  exclusion. Off revokes every grant (`switch_off`); a lower `max_scope` ends the grants above it. Audited
  `connector.enable|disable|policy.change|client.add|client.remove`. Tests: `ConnectorOpsDb.*`, `ConnectorUrls.*`.

### WebSocket flow

**Connection cap (#164).** `ws::Server::onAccept` takes a `ConnectionSlot` (`protocols/ws/ConnectionLimit.hpp`)
under `websocket_server.max_connections` (read per accept, default 1024, 0 acts as 1); over the cap the socket gets
a raw `503` + `Retry-After: 1` without reading the upgrade request, and a warning at most once a minute with the
refused count. The session holds the slot and gives it back on its first `close()` (or destruction); connections
that fail before the websocket handshake (header read, hydration, handshake error) now `close()` at once instead of
lingering in the session manager until the lifecycle sweep.

**Envelope.** `ws::Session` checks each text frame before routing (`protocols/ws/Envelope.hpp`): unparsable text or
a frame without a non-empty string `command` (or with a non-string `token`) is answered `parse_error` with `error`,
`message` and the frame's requestId when it has one. Answers (`model::Response::frame()`) echo a string or integer
requestId and omit empty `data`; a fault escaping the router answers `<command>.response` with status ERROR and no
code. Payload handlers read a missing `payload` as `{}`. The contract publishes these rules as `envelope`.

**Protocol negotiation (`meta.hello`).** `core/usage/include/WsProtocol.hpp` holds `kProtocolVersion` (max) and
`kProtocolMin` (both 1), the capability registry (`capabilities()`: `{name, since, description}`, append-only, names
never reused) and `negotiateProtocol` (`min(server max, client max)`, refused below `max(server min, client min)`, no
client range → `kProtocolMin`). `meta.hello` (auth `session`, the same rule as `meta.contract.get`: signed-in web, Device and DevicePairing; never
unauthenticated web or share sessions, bc342115) answers
`{server: {name, version: VH_VERSION}, protocol: {version, min, max}, capabilities, commands (the router's, sorted),
contract}`; no overlap is ERROR `protocol_unsupported` with `{server_min, server_max, server_version}`
(`ws::core::DetailedRefusal`). `ws::Session::protocolVersion()` is what a handler reads to answer an older client in
its shape (`kProtocolMin` until hello); `clientInfo()` (client name/version) shows in router refusal logs, and a paired
device's `client.version` refreshes `devices.app_version` (`Devices::updateAppVersion`). An unknown command on a web
(signed-in) or device session is ERROR `data.code: unknown_command`, text still "Unknown command"
(`Router::unknownCommand`); unauthenticated web stays UNAUTHORIZED, pairing-only stays `device_unknown`. Breaking ws
changes need a protocol bump: `tools/contracts/protocol_compat.py` (meson test `protocol_compat`) checks the surface
against the frozen `core/usage/protocol/v<kProtocolVersion>.json`. Policy: `docs/reference/ws-protocol.md`.

The web client builds `ws(s)://<host>/ws` in `web/src/util/getUrl.ts` (overridable with `NEXT_PUBLIC_VAULTHALLA_WS_ORIGIN`).
`web/src/stores/useWebSocket.ts` handles reconnect, the pending-request map keyed by `requestId`, and token injection.
Router allowlists are **exact and per session mode**: unauthenticated, pending-MFA (#357), human, pending-share,
ready-share, and on the device listener device and device-pairing (see "Device listener and pairing" below).
Only the session-lifecycle commands (`auth.login`, `auth.logout`, `auth.refresh`, `auth.isAuthenticated`, and since
#358 `auth.passkey.options|login`) skip
access-token validation (`isSessionLifecycleCommand`, mirrored by the web's
`SESSION_LIFECYCLE_COMMANDS`). Every other `auth.*` command (register, user update/delete/get/list, password change)
is account management and goes through `RequireHumanAuth` (so are `auth.sessions.list|revoke`, #354). A `starts_with("auth")` rule used to let unauthenticated
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

Normative protocol: `docs/pairing.md` in `valkyrianlabs/vaulthalla-desktop` (its §8 test vectors are asserted in
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
  `ws::Session::acceptDevice`; `/preview*`, `/download*`, `/upload*`, `/transfer*` and `/mcp` hand the TLS stream to
  an `http::Session` (below); anything else is 404. Cap
  `device_server.max_connections` (own `ConnectionSlot::Pool::Device`; over it the socket is closed, a TLS client
  can't read a 503), 10 s handshake and request deadlines. A bind failure never stops the daemon: it is in
  `listenerStatus()` and retried every 30 s. Binding (`docs/reference/transfer-protocol.md` §1.4): `Listener` holds
  one acceptor per socket; remote on = `[::]` with IPV6_V6ONLY off, falling back to `0.0.0.0`; remote off =
  `127.0.0.1` plus `[::1]` on the same port when that binds. `ListenerStatus.bind` lists every socket, `address` is
  the first. The peer address of an IPv4 client on the dual-stack socket is unmapped to IPv4 in
  `Connection::onHandshake`, before `device::authorize`, so `last_ip`, pairing rate limits and the loopback test
  never see `::ffff:` forms.
- **Endpoint advertisement** (`protocols/device/Endpoints.cpp`, transfer-protocol.md §1; capability
  `device.endpoints`): ws `device.endpoints` (auth `device`, `Router::isDeviceOnlyCommand`), the `node_id` /
  `server_spki_sha256` / `endpoints` members of `device.pairing.open`, and `diagnostics` beside `status` in
  `device.remote.status`. `buildCandidates` is pure (classification by range + interface-name globs,
  `device_server.advertise`); interfaces come from `getifaddrs` behind `setInterfaceEnumeratorForTesting`. The
  node id is cached per process (`endpoints::nodeId`, `clearNodeIdForTesting` after a schema reset). The last
  public (`wan`) Device handshake is an in-memory record (`noteDeviceHandshake`, called from the listener), lost on
  restart. Firewall and mDNS-responder detection are `platform/Network.hpp` (Linux: ufw/firewalld/nftables state
  files; macOS: `socketfilterfw --getglobalstate`), read-only and `unknown`/null when they can't tell.
- **Transfer lanes** (`protocols/device/Transfer.cpp` policy, `http::Session::handle_transfer` mechanics; capability
  `device.lanes.transfer`, §4): `GET /transfer/probe`, `POST /transfer/sink` (read and discarded, ≤ 256 MiB),
  `GET /transfer/source?bytes=n` (SplitMix64 `PlaintextReader` through `write_stream`). At most 2 sink/source
  requests per device row at once (in-memory slots, 429). Device listener only; nothing touches disk.
- **HTTP lanes and remote MCP (S1b).** `http::Session` runs over a `ByteStream`: `TimedStream` (the plain socket,
  poll + deadline) or `TlsStream` (the device TLS stream: each blocking call starts one async op on the stream's strand
  and waits against the deadline, cancelling the socket's I/O when it passes; bytes go through op-owned buffers so an
  abandoned op never touches freed memory). A device connection runs on its own thread like the web side's, holds its
  `ConnectionSlot` (device pool), and serves only `/preview*`, `/download*`, `/upload*`, `/transfer*` and `/mcp`
  (pairing-only connections get 403 `device_unknown`). Its principal is a stream-less Device `ws::Session`
  (`Session::devicePrincipal`) registered with the session manager, so revocation, `revokeSessions`, remote-off and
  the sweeper close it; its close hook cancels the HTTP session, which also stops between requests and between
  chunks. Requests run under `access::DevicePrincipalScope` (thread-local): `access::authenticate` and the upload
  coordinator take the principal instead of a cookie, refuse the share lanes (`?share=1`: 403), and the usual
  `Need` → RBAC mapping applies as the device's user; audit lines carry `[via device <id16>]`. `/mcp`
  (`protocols/device/Mcp.cpp` → the shared transport `protocols/mcp/HttpTransport` with a `Principal {user, origin,
  ceiling, ended}`; the device's ceiling is its scope, Destructive unless it is a scoped device): Streamable HTTP, POST only (GET/DELETE 405: no SSE, no MCP session id), JSON
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
- **Session modes** `Device` / `DevicePairing` (`SessionMode`). A scoped device (below, "Scoped devices") is the same
  Device mode and the same RBAC as its user; its scope is only a further ceiling, never a permission. Device: no tokens (`session::Manager::validate` is
  true while the user is `authorizing()` and the session open), `rbacActor()` = `human(user)`, classify = the Human set
  minus `auth.login|logout|refresh|register` and the share-recipient commands, plus `device.*`; deactivation or
  deletion is seen on the next command. Pairing: only `device.pair.*`, `meta.contract.get` and `meta.hello`; anything else is ERROR
  `data.code: device_unknown` (same for unknown and revoked keys). `device.identity.rotate` /
  `device.server.identity` (and #361's `device.approval.*`) only in Device mode; `device.pair.*` never on console
  sessions; `auth.approval.*` never in Device mode. Key material
  (`vault.keys.export|export.confirm|import`) reaches the handler from any signed-in session but `ops::vault_keys` answers
  only Device sessions (`export_requires_device` / `import_requires_device` otherwise, D4). Contract auth levels
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
- **Relayed streams** (`design/cloud/relay.md`, the Vaulthalla Cloud relay, option (c)): the second way to authenticate
  a peer, only through `startRelayedConnection` (`Listener.hpp`), which only `CloudRelayService` calls (via
  `DeviceServer::acceptRelayed`, one end of a local socketpair; the `Listener` never builds one). Its TLS context
  (`makeRelayedServerContext`) is the same identity without a certificate request; before any HTTP byte the server sends
  `0x01 ‖ nonce[32]` and reads `0x01 ‖ spki[91] ‖ raw r‖s[64]`, an ECDSA signature over
  `"vhc-relay-browser-proof-v1\n" + jti + "\n" + b64url(nonce) + "\n" + b64url(exporter)` (TLS exporter
  `EXPORTER-vhc-relay-browser-v1`, 32 bytes), whose key must hash to the browser ticket's `spki`
  (`cloud/RelayProtocol.hpp`, `verifyProof`); then `device::authorize(key, address, relayed = true)`. `Peer.relayed`
  / `.pairedViaRelay` (`devices.paired_via = 'relay'`, migration 144) make `Peer::readOnly()`: the Router allows only
  `isRelayedReadCommand` (an allowlist; ERROR `relay_read_only`) and `http::Session::serve` only GET/HEAD
  `/preview*`/`/download*`, per request. Relayed sessions are never loopback, survive remote-off and close with the
  relay (`closeRelayedDeviceSessions`). A relayed pairing request carries no `approval_key`; pending requests show
  `via`; a relay-paired device gets no key-backup grant. Tests: `test_cloud_relay_protocol.cpp`,
  `test_cloud_relay_db.cpp`.

### Scoped devices (migration 152; `design/core/mcp-remote-signin.md`, "Scoped devices")

A paired device may be held to less than its user's rights: `devices.scope` read | write | destructive (default
destructive = no limit, every pairing before scopes). Vaulthalla Desktop uses it for the pairings it makes for AI apps.
**Rule: a ceiling, never a second permission system.** Every request still runs through the same ops and RBAC as the
device's user, in full; the scope is applied in addition (effective = RBAC ∩ scope): no permission bits, roles,
per-device sets or configurable scope contents, only the three values and the `effect` each command declares in the
contract (ambiguous = the higher effect). The only fixed list (`Router::isScopedDeviceForbidden`) refuses, never grants.
Anything finer stays RBAC's.
- **Audit:** approval details carry `scope` and `requested_scope`; `device.scope.set {from, to}`; origins
  `device <id16>[ mcp] scope <scope>` (unscoped: unchanged; `vh::device::auditOrigin`; grants:
  `connector::auditOrigin`, `connector <id8> scope <scope>`); refusals `device.scope.refused` (outcome denied;
  device, surface ws|http|mcp, command or `(unknown)`, effect, scope; `device::scope_audit`, 5 a minute per device,
  then `suppressed` on the next recorded one); `vh device scopes` reads the effect table, `Router::scopedDeviceMayRun`,
  the MCP catalog's ceiling and `scope::laneClasses()`; `vh audit list --device <n> | --grant <id>` (ws `audit.list
  {device_id | grant_id}`, `ops::audit::forDevice|forGrant`: origin prefixes of the current and previous key, or
  details.device / details.grant_id).
- **Pairing:** `device.pair.request {scope?}` asks (shown as `requested_scope` in `device.pairing.pending`, absent when
  nothing was asked); `device.pairing.approve {scope?}` decides (default: what was asked, else destructive; wider than
  asked is `invalid`). A scope narrower than destructive is appended to the device.trust target
  (`device.pairing.approve:<request>:<spki>:<code digest>:<scope>`), so an approval for one scope never pairs another;
  an unscoped approval's target is unchanged. `vh device approve --scope`.
- **Peer:** `device::authorize` copies the row's scope to `Peer::scope`; `Peer::scoped()`. `device.scope.set {device_id,
  scope}` / `vh device scope` (`ops::devices::setScope`): narrowing by its user or a super admin, no step-up; widening by
  its user only, device.trust `device.scope.set:<row>:<scope>`; refused `device_scope` from a scoped device and from the
  device itself; closes the device's live sessions (they reconnect under the new scope); audited `device.scope.set`.
  `vh device scope` is an MCP exclusion.
- **Enforcement:** ws: every contract command declares an `effect` (`contract::effectTable()`,
  `core/usage/src/contract/ws/effects.cpp`, exported as `effect`; `UsageContract.EveryWsCommandDeclaresAnEffect`);
  `Router::classifyCommand` answers `DenyScope` (ERROR `device_scope {scope, effect}`) for a command above the scope, of
  unknown effect, or in `Router::isScopedDeviceForbidden` (device.pair*, device.approval.*, device.backup.grant.*,
  vault.keys.export|export.confirm|import, connector.*, device.scope.set); `ops::devices::revoke` refuses a scoped
  device unpairing another. Step-up: a scoped device's `stepup::Scope` channel is Agent (never steps up). HTTP lanes:
  `protocols::device::scope::laneEffect` (read: GET/HEAD /preview*, /download*, POST /preview/batch, /transfer*, /mcp;
  write: /upload* and anything else), refused 403 `device_scope`. `/mcp`: the principal's ceiling is the scope.
  Tests: `DeviceScope.*` (DB-free), `ScopedDevicesDb.*`, `DeviceHttpTest.AScopedDeviceIsHeldToItsScopeOnEveryLane`,
  `SqlDeployerHistoryDb.DeviceScopeMigration152*`. Capability `device.scope`.

### Linked servers (`peer/`, migration 157; `design/peers/link.md`)

Two Vaulthalla servers paired with each other keep one mutually authenticated websocket (phase 1a of the server
mirror: the link only; nothing travels over it yet but control). **Experimental and off:** `peers.experimental` in
config.yaml (read-only like `cloud`, never in settings JSON); off = the link service closes every link and dials
nothing, `device::authorize` never looks in `peer`, and every `peer.*` command and `vh peer` refuses
`peers_experimental`, except ws `peer.status` (`ops::peers::enabled`: the same callers, answers `{enabled}`), which
the console reads to leave the Linked servers page out (`web-client.md`, "Linked servers").
- **Principal:** the `peer` table (migration 157; `db::query::peer::Peers`): node_id and spki_sha256 unique among live
  rows only (an unlinked server links again with a new row; the revoked one stays for the audit trail),
  `next_spki_sha256` + `rotate_counter` (rotation), `attest_public_keys`, `wrap_public_key`, `endpoints` (last good
  first), `sharing` (identities), `compared_by` (person | desktop), `peer_protocol`, `product_version`. A peer is never
  a device and never a user: `device::authorize` looks in `devices` first and, only for a key no device ever had (and
  never for a relayed stream), in live `peer` rows (pin or announced next key, which is then promoted). The
  connection becomes a ws `SessionMode::Peer` session (`Session::acceptPeer`, run by `peer::LinkService`); device
  pairing refuses a key in `peer`, `peer.pair.request` a key in `devices`. HTTP lanes answer 403 to a peer key; the
  sealed lane (`/peer/object/…`, below) is the one HTTP route it gets, and nobody else does (404).
- **What a peer session runs:** `Router::isPeerWireCommand` (peer.hello, peer.ping, peer.endpoints,
  peer.identity.rotate, peer.unlinked, peer.mirror.offer|answer|keys|begin|grant|cancel|tree|log|ack|notify|submit) plus meta.hello / meta.contract.get; anything else `Deny` (fail closed). A
  pairing connection this server dialled (`Principal::pairing`) runs nothing. The wire set and `peer.pair.*` are
  refused on every other session kind; `peer.pair.*` runs on pairing-only connections. Answers on a Peer session
  (frames with `status`) go to the link's pending table (`PeerHooks::onResponse`), never to the router; an unknown one
  is dropped. Step-up channel: Agent. The sweeper keeps Peer sessions (the link service owns liveness).
- **Keys:** identity = device_tls both ways (`protocols::device::makeClientContext`: TLS 1.3, the identity certificate
  as client certificate, ECDSA P-256/SHA-256, no trust store); attestation = key_attest
  (`vault::attestation::currentPublicKey`, created for the card if none); peer wrap = X25519 in KeyProvider slot
  `peer_wrap` (`test_peer_wrap`), created by the first `peer.pairing.open`/card, `initGuarded` (never silently replaced
  while live rows pin it) (`peer/Keys.hpp`).
- **Pairing** (`peer::Pairing`, in memory; the window is `device::Pairing`'s with `WindowKind::Peer`: one window at a
  time for devices or a server): `peer/Crypto.hpp` holds the transcript (card encoding, commit "vh/peer/commit/v1",
  SAS "vh/peer/sas/v1" over both SPKIs, both nonces and both card hashes, rotation "vh/peer/rotate/v1"); the fixed
  vector is `core/test-assets/peer/pairing-vectors.json` (`tools/dev/peer_pairing_vectors.py --check`). The window's
  side: `peer.pairing.open|close|pending|approve {expect_spki?}|deny`; the dialling side: `peer.link.start {endpoints,
  expect_spki?}` (a thread per attempt in `LinkService::runAttempt`: dial, request, confirm, code, poll status, write
  its row on approval), `peer.link.status|cancel`. `vh peer pair|pending|approve|deny|link|list|info|rename|unlink`;
  the console's Linked servers page drives the same commands. `compared_by` records who compared the code, from the
  channel of the call that made the link on that side (`peer.pairing.approve` accepting, `peer.link.start` dialling,
  carried on the `LinkAttempt`): `desktop` over a full-access device session, `person` from the console or the host
  socket; whether a key was pinned (`expect_spki`) is only in the `peer.link` audit details as `pinned`.
- **Who may** (`ops::peers`): super admins only; Host free; Web with device.trust on peer.pairing.approve and
  peer.link.start (`stepup::requireForServerLink`); a full-access direct device on RBAC alone (audited
  auth.stepup.grant method device_session, recovery cooldown still applies); Agent (MCP, `vh mcp`, scoped devices,
  peer sessions) and relayed devices `peer_forbidden`; the router's scoped-device forbidden list has `peer.`; the MCP
  catalog excludes `{"peer"}`.
- **The link** (`peer::LinkService`, runtime service "PeerLinks" after DeviceServer; own io_context, 2 threads, own
  Router): either side dials live rows' endpoints (`protocols::ws::client::dial`, pin = spki or next), with backoff
  1 s..2 min (`concurrency::jitteredBackoff`, shared with the cloud relay); the dialler sends peer.hello (node id must
  be the row's) then peer.endpoints; when both connect at once the one dialled by the lower node id is kept (a newer
  one from the same dialler replaces the older); peer.ping every 30 s from both ends, three misses close it; health
  (`peer.list` `health`: connected, since, dialed_by, address, rtt_ms, peer_version, protocol_compatible, last_error,
  next_attempt_at). Unlink revokes the row, sends peer.unlinked and closes; the receiver revokes its row too.
- **Rotation:** `rotateServerIdentity({announce})`: after the new key is sealed, `LinkService::announceRotation`
  sends peer.identity.rotate (signed by the old key, counter = the new identity version) on every live link; the
  switch transaction revokes every live row that did not store it; the links then reconnect under the new key (the
  peer promotes its next pin). `vh secret device-identity rotate --revoke-peers` announces nothing and drops every
  link. Attestation and wrap keys have no rotation path yet (nothing announced for them).
- **Audit:** peer.pairing.open, peer.link.request (both sides), peer.link (both, compared_by, pinned),
  peer.link.denied, peer.unlink (by this_server | peer), peer.identity.rotate (announced | received), peer.connection
  (up/down, at most one a minute per peer).
- Tests: `PeerCrypto*`, `PeerCards.*`, `PeerEndpoints.*`, `PeerPairingState.*`, `PeerRouting.*`, `PeerSwitch.*`
  (DB-free, `test_peer_crypto.cpp`); `PeerLinkDbTest.*` (the real listener as one end, `test_peer_link_db.cpp`; also
  `peer.status` either way and to whom, and `compared_by` by channel with `pinned` in the audit);
  `DeviceIdentityRotationTest.LinkedServersThatHeardOfTheNewKey*`; Tier B `vhh drill peers`
  (`tools/harness/vhh/drill_peers.py`: two daemons pair TOFU and pinned, reconnect after each restarts, rotate,
  unlink).

### Replication log of a mirrored vault (`mirror/`, `db::query::mirror`, migration 160; `design/peers/mirror.md`)

Core side (phase 2 piece 1; the wire protocol and applier are wave 3, below). Full description: mirror.md "As built: the replication log"; `change-journal.md` for how
it differs from the journal.
- **Tables:** `mirror_vault` (per mirrored vault: peer, role core | mirror | orphaned, term, last_seq, acknowledged and
  pruned positions, running digest, state), `mirror_entry_hash` (each entry's hash as the log last recorded it: the next
  `prev_hash`), `vault_replication_log` (`seq` NULL until numbered, `txid` = the transaction, state JSON, hashes,
  actor as home node + id, origin). Triggers on fs_entry, files, directories, symlinks, files_trashed, vault, sync,
  fsync, rsync, vault_recovery_policy, vault_keys return at once unless the vault's role is core; `vh.mirror_apply`
  (SET LOCAL, `Log::markMirrorApply`) silences them. Type-row triggers take the entry's fs_entry row lock (its writers
  take it first too, migration 164's lock order).
- **Hash and digest:** `core/include/mirror/Hash.hpp` (canonical encoding, test vector; SQL twin
  `vh_mirror_state_hash`); digest = per-word sum mod 2^64, `vh_mirror_digest` aggregate, `vh_mirror_tree` (scrub).
- **Sequencer:** `mirror::Sequencer` ("MirrorSequencer", after DBJanitor, 250 ms; `Log::pending()` on the empty pending
  index otherwise) → `Log::sequence()`: whole groups per vault under the mirror_vault row lock, ordered by each group's
  last row, digest moved with them. Reader `Log::groupsAfter`. Retention in `db::Janitor` (`pruneReplicationLog`: 30
  days / 5,000,000 rows, never past the acknowledged position, orphans of unmirrored vaults).
- Tests: `MirrorEntryHash.*`, `MirrorDigest.*` (DB-free, `test_mirror_hash.cpp`); `MirrorReplicationLogDbTest.*`
  (`test_replication_log.cpp`: every op on a local and an S3 vault, groups, commit order, pages, the apply switch,
  concurrent writers, random ops with digest and replay, retention); `SqlDeployerHistoryDb.ReplicationLogMigration160*`;
  contract `tools/contracts/test_replication_log_contract.py`; cost `tools/dev/bench/replication_log_cost.sh`.

### Sealed contents between linked servers (`peer/ObjectClient`, `protocols/device/PeerObject`, `mirror/Contents`, migration 161)

Phase 2 wave 2 of the server mirror (`design/peers/mirror.md` "As built: sealed contents"): a file generation's sealed
bytes travel between two linked servers exactly as they sit on disk, never re-encrypted. The mirror protocol (what to
fetch when, keys, the tree) is the next wave: nothing marks a file as expected in production yet; tests and the
internal API do.
- **The lane:** `GET|HEAD /peer/object/<vault uid>/<object uid>/<generation>` on the device listener (uids base32,
  generation unpadded base64url; `peer::object::target`/`parseTarget`/`etagOf`). The listener hands it only to a
  linked key (`Authorization::linked`; anyone else 404) as an HTTP session with no user (`DeviceConnection::linked`),
  which serves that lane and nothing else. `peer_object::serve` decides per request: switch off 404; row revoked or
  its key replaced 403 `peer_revoked`; no such mirrored vault, another linked server, an orphaned role or no such file
  404 `not_found`; another current generation 410 `generation_not_current`; gcm0 or plain with bytes 422
  `format_not_portable`; bytes not on disk or not that generation's length 404 `not_held`. Then the bytes from the
  descriptor it opened (the row read again after the open), via `handler::serve` (Content-Length, ETag, one range,
  If-Range, no-store). `peer_object::track` registers each lane connection; `LinkService::disconnect`/`disconnectAll`
  close them.
- **The client:** `peer::object::fetch(Record, Address, FetchOptions, Sink)`: endpoints in order, TLS 1.3 with
  `LinkService::clientTls()` and `peer::pinnedKeyOf` (the same pin check the link's dial now uses; an announced key in
  use is promoted), `Range: bytes=<offset>-` + If-Range, a private io_context run in `kCancelSlice` (200 ms) slices
  (cancellation, an overall deadline, per-step inactivity), body streamed into the sink at its pace. Status
  Complete | Interrupted (resume) | Refused (code) | Unreachable | Cancelled.
- **Slots:** `peer::Transfers` (owned by `LinkService`, `transfers()`): 4 per peer both directions, 1 reserved for
  interactive; interactive waiters go before background ones; `spawn` runs a transfer on a thread joined when the
  service stops (`shutdown` first in `LinkService::shutdown`, `resume` at `runLoop` start).
- **Pending contents:** `mirror_content_pending` (161; `db::query::mirror::PendingContents`): per file of a vault whose
  `mirror_vault.role` is `mirror`: generation, key version, size, content hash, mtime (us), priority, state waiting |
  failed, attempts, last error. `expect`, `get`, `outstanding` (priority order), `recordFailure` (3 →
  failed), `retry`, `dropSuperseded`, `lockForLink` + `clear` (the compare-and-set), `mayHavePending` (per-vault cache:
  one query per vault per process). No foreign key to files (none of its triggers change). `MirrorVaults::startMirror`
  (tests) writes a mirror row.
- **Receive** (`mirror::contents::receive(Expected, Source&)`): O_TMPFILE in the backing directory (named O_EXCL sibling
  on macOS), resumes on Interrupted (≤ 5), then size, `crypto::hash::blake2bFd`, `vault::content::verifyFd` (binding:
  vault uid, generation, key version; not the object: a local copy shares its source's header), then under
  `Filesystem::contentWriteMutex` and in one transaction `lockForLink` (pending row FOR UPDATE, files row FOR SHARE)
  → futimens + durable sync → link at the content sidecar → rename over the backing path → `clear`. Bytes already in
  place that pass the same checks settle the row (a crash between link and commit). Failures counted: refusals and
  verification; not link down, cancellation or a superseded row.
- **Open-time fetch:** `mirror::contents::awaitIfPending(file, kOpenWait = 15 s)` from `Engine::openPlaintextReader`
  (downloads, previews, the ws/share download, CLI, S3 gateway: `ContentUnavailable` with `mirror_link_down|
  mirror_fetch_timeout|mirror_fetch_failed: …`, which `handler::errorFor` answers as 503 with that code) and from the
  working copies' materialize hook (FUSE open: `NotReceived`, a `std::system_error` with ENOLINK | ETIMEDOUT | ENODATA,
  which `fuse::errnoFrom` returns; only `mountWaitCap()` mount opens wait at once, a quarter of the FUSE pool within
  1..4, the rest get ETIMEDOUT at once with their fetch started). Link down is said at once (no transfer); one transfer per file however many wait,
  on an interactive slot, continuing after a waiter gives up. `fetchOutstanding(vault, max)` drains background slots.
- **Test hook:** in test instances only, `LinkService::pollTestFetch` runs `VH_TEST_FAULT_DIR/peer-object-fetch.json`
  (the Tier B drill's request) with the real client.
- Tests: `PeerObjectLaneDbTest.*` (`test_peer_object_lane_db.cpp`: every refusal, the bytes, ranges, the real client
  resuming against the listener); `MirrorContentsDbTest.*`, `PeerTransfersTest.*` (`test_mirror_contents_db.cpp`);
  Tier B `vhh drill peers` step 6 (two daemons, the real link, a resumed transfer, byte for byte).

### Following the core: the first copy and the log applier (`mirror/apply`, `mirror/follow`, `fs/tree_apply`, migration 164)

Phase 2 wave 3 piece B of the server mirror (`design/peers/mirror.md` "As built: following the core"): the data plane.
The control plane (offer, keys, creating the mirror's vault, the grant) is piece A; the only contract between them is
that a `mirror` row exists (`MirrorVaults::startMirror`) and that `MirrorVaults::startCore` takes the baseline.
- **Baseline (core):** `startCore` is per vault: a committed `mirror_vault` row with state `starting` makes the vault's
  writers wait in `vh_mirror_core_term` (FOR SHARE on that row; VOLATILE since 164); writers of the entry tables
  already running are waited for (pg_locks RowExclusive holders, bounded); then under the row's lock the tree's state
  documents go to `mirror_baseline` (ord: a folder before what is under it, trashed files last) with their hashes,
  `mirror_entry_hash` and the digest; state `live`, `baseline_*` columns set. Writers of other vaults never wait.
  Dropped by the first matching acknowledgement and by `remove`. An entry directly under the root names the vault's
  uid as its parent in its state (164's `vh_mirror_entry_state`): each server's root folder has its own uid.
- **Per-group digest:** the sequencer writes `digest_after`/`entries_after` on each group's last log row;
  `MirrorVaults::digestAt` answers the baseline's position or a group's end; `acknowledgeChecked` compares, records or
  stops the vault as `diverged` (`mirror_digest_mismatch`). New states `expired`, `stopped`; `stop_reason`,
  `stop_detail`, `stopped_at`.
- **Wire (`mirror::follow::Protocol`, ws `handler/MirrorFollow`):** `peer.mirror.tree|log|ack` (core answers),
  `peer.mirror.notify` (mirror wakes); peer wire set only (`Router::isPeerWireCommand`), `peers_experimental` when off,
  a vault the caller is not the linked server of answers `not_found` ("Not found"), as the sealed lane. Answers under
  768 KiB (the link's ws frame limit is 1 MiB, `kWebSocketReadBufferMaxBytes`); a group larger than that comes in
  `part`s. `peer::LinkService::request|notify|connected` carry them.
- **Applier (`mirror::apply`):** one transaction per tree page or log group (`ApplyRows::begin`: the apply switch and
  `vh.keep_mtime`); per uid the compare-and-set on `mirror_entry_hash` (kept on the mirror: the Janitor's orphan sweep
  spares mirror rows), entries by uid (`fs::tree_apply::locate`), removals and placements in a work loop with
  `.vh-mirror-<uid>` temporary names for swaps and cycles, every field the core's (accounts {node, id} mapped by
  `ApplyRows::account`: this server's own node id is a local account, any other a remote account created on first use),
  `mirror_content_pending` rows in the same transaction (pending rows locked first: the receive path's order), then each
  entry's hash from this server's tables must equal the core's (else `diverged`, `mirror_apply_mismatch`). A file open
  on the mount defers the whole group. After the commit: backing files and folders moved (via a staging directory),
  removed or made, derived artifacts dropped, `tree_apply::cacheFresh`.
- **Follower (`mirror::follow::Follower`, service "MirrorFollower" after PeerLinks):** visits each `mirror` row (1 s
  while the first copy runs, at once on a notice or link-up, 30 s otherwise; errors back off to 60 s), 3 s per visit,
  acknowledges after it applied; contents are fetched by MirrorContents alone (one drainer of the pending queue). The sequencer's numbered vaults
  become notices (`Follower::numbered`), sent from the follower's thread.
- **Shared tree-apply module (`fs/tree_apply`):** the uid lookup for local vaults and the after-commit cache and folder
  effects; the manifest applier's executors call its effects (its own lookup keeps reading the bucket index).
- **Lock order:** a type row's writer locks the entry's fs_entry row first (`set_file_encryption_iv_and_version`, its
  compare-and-set, `ManifestApply::replaceContent`), as the type trigger does: no crossing with fs_entry-then-files.
- Tests: `MirrorFollowDbTest.*` (`test_mirror_follow_db.cpp`: capture and replay, serving, retention, the per-vault
  baseline, the deadlock); contracts as for 160; `SqlDeployerHistoryDb.*` for 164.

### A change made on the mirror (`mirror/submit`, `db::query::mirror::Pending`, migration 166)

Phase 2 wave 4 piece B (`design/peers/mirror.md` "As built: a change made on the mirror"); piece A's gate
(`mirror/access`, `requireWritable`) decides whether a write may happen at all; this is what happens to one it lets
through on a Live mirror.
- **Local (`mirror::submit::Local`, in `ops::fs` after the gate's line):** mkdir, move, rename, remove applied here as
  pending under the vault's local-change lock (`submit::vaultMutex`, also taken by `mirror::apply::run`): `mirror_pending`
  (state local, then pending) and `mirror_dirty` (each touched entry's last confirmed state) first, then the mutation with
  `vh.mirror_local`/`vh.mirror_request` in every transaction (`db::SessionSettings`, applied by `Transactions::exec`); a
  created entry's uid chosen first (`db::query::fs::AssignedUid`, read by the Directory/File/Symlink inserts). Copy is
  submitted only. Contents are refused on a held vault (`submit::requireSupported`: `mirror_contents_not_built`).
  `mirror_entry_hash` and the digest never move for a pending change.
- **Submit (`mirror::submit::submitPending`, from `Follower::step` before the log):** `peer.mirror.submit` (peer wire
  set), one change at a time per vault in order. Core: `serveSubmit` answers at once from `mirror_submission` (queued,
  running, executed with groups, refused with code: never executed twice) and `drain`s on the sync pool, one vault's in
  order, as the remote account for the person inside `ops::fs::PeerSubmission` (ceiling `PeerVault::may` is the whole
  check for now; audit details `peer_id`, `peer_node`, `origin`), with `vh.mirror_origin` and `vh.actor` set.
- **Confirm/settle (`mirror::apply`):** log rows carry `origin`; a group of a pending request counts
  (`groups_applied` vs the answer's `groups_expected`), confirmation drops the row and settles its entries in the same
  transaction; dirty entries are applied from where they stand (no second apply), set aside to `name (conflict <uid8>)`
  when they hold a name the core's entry needs, reverted when in the way; `apply::settle` reverts on refusal.
  Refusals: `conflict` for mkdir/move/rename resubmits under the conflict name (record kind conflict in `mirror_held`),
  anything else is a held change (`mirror_held` kind held, entries reverted); `ops::mirrors::held|discardHeld|
  retryHeld` (ws `mirror.held.list|discard|retry`, `vh mirror held|discard|retry`), super admins, audited.
- Tests: `MirrorSubmitDbTest.*` (`test_mirror_submit_db.cpp`: both servers in one database, the inactive one parked).

### A linked server's vault role and mirrored vaults (migration 162; `design/peers/identity.md`)

The mirror server's permissions as a role it holds, a ceiling (phase 2 wave 2). Storage, resolver and management
only: nothing transmits the role or enforces it on submitted changes yet. Full text: identity.md "As built: the mirror
server's vault role".
- **Core:** `vault_role_assignments.subject_type = 'peer'` (a `peer` row, trigger-checked; no path overrides) and
  `peer_vault_policy` (a link's default, NULL = none; `db::query::peer::VaultPolicy`). `rbac::resolver::PeerVault`:
  `role(peer, vault)` = per-vault assignment (`implicit_deny`, by name: no access) else the link's default else none,
  nothing for a revoked peer or a deleted vault, never anything from an account's rows; `may(peer, vault, action, path,
  exists, isDirectory)` only on a vault this server is core of, mirrored with that peer. Nothing calls `may` yet.
- **Who may** (`ops::peer_policy`, `ops::roles` for subject peer): `peers.experimental`; a person (Host, Web,
  full-access direct device; Agent, scoped and relayed devices `peer_forbidden`); per vault `vault.roles.assign|revoke`
  as for users and groups; the link's default needs it in every scope of the actor's global vault policy (view to
  read). identity.admin step-up. Audited `peer.policy.set`, `rbac.vault_role.assign|unassign` with `node_id`.
  `vh peer policy show|set`, ws `peer.policy.get|set`, `vh vault role assign|remove --peer`, `role.vault.assign|unassign`
  `subject_type: peer`; listings annotate a peer subject (`subject_name`, `subject_node_id`, `subject_revoked`).
- **Mirror:** `mirror_vault.granted_*` (role name, four permission columns, granting node, time; all or none, never on
  a core row; written only by `db::query::mirror::MirrorVaults::recordGrant|clearGrant`, rows by `startMirror`).
  `rbac::mirrored` (`rbac/Mirrored.hpp`): a vault whose role here is mirror or orphaned resolves from its grant alone,
  for this server's super admins; nobody else, no local source, no grant = nobody. Applied in `resolver::Vault::has`
  (before the super-admin short-circuit), `fs::policy::Evaluator` (stage 0), `resolver::Admin` (`admin.vaults.*`: super
  admins View/ViewStats only), `fs::visibility::seesWholeSubtree`, the S3 policy evaluator and
  `ObjectStore::requireRbacPermission`, `ops::s3_gateway` principal checks, `ops::vaults::listAccessible`; the access
  listing shows the grant (`subject_type: server`, `owned_by`, `editable: false`) and local rows `in_effect: false`;
  assignment and override writes refuse (`conflict`). Not FUSE's own root shortcuts (`fuse/Resolver.cpp`).
- **Hot path and invalidation:** `rbac::mirrored::find` = one atomic load while nothing is held, else an immutable
  snapshot lookup. Loaded in `wireStorage()` before engines serve (failure stops startup); republished by every
  `MirrorVaults` write that changes a held row or grant before it returns; runtime service "MirrorAccessWatcher"
  (after IdentityWatcher, 1 s) reconciles out-of-band changes; each change bumps `rbac::policyEpoch()`. Test schema
  resets call `resetForTesting()` (`db_suite.hpp`).
- Tests: `PeerVaultRoleDb.*` (`test_peer_vault_role_db.cpp`), `SqlDeployerHistoryDb.PeerVaultRoleMigration162*`.

### Starting a mirror (`mirror/start/`, `ops::mirrors`, migration 163; `design/peers/mirror.md`)

Phase 2 wave 3, piece A: the control plane (offer, answer, keys, the mirror's vault, begin, grant, cancel). The tree and
the log are piece B. Full text: mirror.md "As built: starting a mirror". Experimental (peers.experimental).
- **Tables:** `mirror_offer` (163; one row per start per side, shared `offer_uid`; core offered → accepted → keys_acked →
  started, mirror pending → accepted → installed → started; declined | cancelled | expired | failed; `notify` = the
  other server not told yet; 7-day expiry of unanswered offers, 30-day sweep, a started row whose vault is mirrored
  kept), `peer.accept_vaults` (+ set_by/at), `vault_key_origin.anchor` 'peer'. `db::query::mirror::MirrorStart`
  (offers, CAS `transition`, `told`, facts of a core vault, `createMirrorVault`: vault with the core's uid + root uid,
  remote owner, keys sealed here with provenance and origin, `mirror` row, offer installed, one transaction).
- **Protocol** (`mirror::start`): `checkVault` (every precondition its own `Refused` code), `offerVault`; wire
  handlers (`handler/Mirrors.cpp`, Peer sessions only, `Router::isPeerWireCommand`): `peer.mirror.offer|answer|keys|
  begin|grant|cancel`. Keys: KEV1 X25519 to the peer row's wrap key (`peer::keys::unwrapVaultKey` opens them), proven
  with `vault::recover::prove` against the peer row's pinned `attest_public_keys` (node id from the row, the core's
  vault id from the offer, own keys as self keys); one unprovable version fails the start, nothing written. The
  core's `startCore` only after the keys answer; begin resent until answered. `stepMutex()` serializes startCore vs
  cancel and vault creation vs removal; nothing waits on the peer under it.
- **Services:** "MirrorStarter" (`mirror::start::Service`, after PeerLinks; 1 s, woken by operations): tells/asks per
  `notify`, retries after 5 s, expires, sweeps, and keeps each core row's grant current (`PeerVault::role` compared
  every pass, resent on link-up). "MirrorContents" (`BackgroundContents`, after MirrorStarter): per mirror vault with
  the link up, a batch of 16 through `contents::fetchOutstanding` on a `Transfers::spawn` thread; jittered backoff
  5 s..10 min after a batch that received nothing. `LinkService::request(peer, command, payload, timeout)` sends over
  the kept connection and waits (not on the link's io threads). Transport seam: `setTransportForTesting`.
- **Ops / commands:** `ops::mirrors` (add, pending, accept, decline, cancel, list, get, offers, acceptAll/setAcceptAll,
  keepRemoved/setKeepRemoved); ws `mirror.add|pending|accept|decline|cancel|list|get|accept_all.set|keep_removed.set`
  (keys step-up on mirror.add, data.destroy on a removing cancel), `vh mirror
  add|pending|accept|decline|cancel [--remove-copy]|list|info|accept-all|keep-removed`. Who: the switch, a person (`peer_forbidden` otherwise); add
  and the core's cancel: super admin or the vault's admin Edit + vault.roles.assign; the mirror's side and list: super
  admins. Router: `mirror.` forbidden to scoped devices; MCP catalog excludes `mirror`.
- **Ending** (owner's rule, 2026-11-26; mirror.md "Ending a mirror from the core, and deleting"): the core's cancel
  drops its core row and log at once and sends `peer.mirror.cancel {remove_copy}` (queued while the link is down);
  the mirror removes an unfinished copy (`firstCopyFinished`, rewired to piece B's flag at the merge), removes a
  finished one when asked and `peer.keep_vaults` is off, else `MirrorVaults::orphan` (offer state orphaned); its
  answer's `copy` is stored as the core offer's `copy_outcome`. The mirror's own cancel removes an uncompleted start,
  refuses a live one (`mirror_detach_required`), removes an orphaned copy (data.destroy, audited mirror.remove).
  `reconcileUnlinked` (every pass): an unlinked server's queued notices dropped, its copies orphaned, its core rows
  ended. Deletion refused while mirrored (`refuseDeletionIfMirrored` in `ops::vaults::remove` and
  `ObjectStore::deleteBucket`: `vault_mirrored`, `vault_orphaned_copy`).
- **Rotation guard** (`mirror/start/Guard.hpp`): `refuseIfMirrored` in `prepare_key_rotation` and `mintSalvageKey`
  (`vault_mirrored`), `vh vault keys rotate` reports it per vault.
- **At the join with piece B:** the follower asks nothing while the mirror's offer is `installed`
  (`mirror::start::awaitingBegin`; the begin wakes it), since the core's row comes after the keys; `firstCopyFinished`
  reads `copy_finished`; the local sync task (FSTask) skips its content-changing jobs on a vault `rbac::mirrored` holds.
  Test instances only: `VH_TEST_FAULT_DIR/mirror-copy-hold` and `mirror-contents-hold` (the drill's holds).
- Tests: `MirrorStartDbTest.*` (`test_mirror_start_db.cpp`); Tier B `vhh drill peers` steps 7 (a whole mirror) and 8
  (ending it).

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

### Vaulthalla Cloud link (`vh cloud`, migration 134)

Optional link to a vaulthalla.cloud account (valkyrianlabs/vaulthalla-cloud plan step 6; operator page
held in `design/cloud/server-link.md` until vaulthalla.cloud opens: the claims lint allows no published text about it). `cloud/Signing` is VHC1-Ed25519 request signing (libsodium; the cloud's documented vector is
`CloudSigning.MatchesTheCloudsDocumentedVector`). `cloud/Identity` is the Ed25519 seed sealed in KeyProvider slot
`cloud_identity` (`test_cloud_identity`), created by `vh cloud link` and destroyed by unlink; nothing is wrapped under
it. `cloud/Client` makes JSON calls over `storage::s3::curl::http` (bounded, no redirects; `cloud.endpoint` must be
https or loopback http, checked at config load). `db::query::cloud::Link` is the single `cloud_link` row (pending
with the cloud's request id, or linked with installation, account, deployment and account public ids: migration 141).
The link request's proof is v2 and covers this server's node id (`device_node.node_id`). `ops::cloud`
(`startLink`/`claimLink`/`status`/`unlink`) is super admins only, channel Cli or Agent (Agent refused), and
`cloud link|unlink` are in `mcp::exclusions()`; ws `cloud.link.status` (`ops::cloud::linkStatus`) reads the row only.
Unlink sends a signed
`DELETE /v1/installation`, and `--force` forgets the link when the cloud can't confirm. Tests:
`test_cloud_signing.cpp` (DB-free) and `test_cloud_link_db.cpp` (a fake cloud over the http seam verifies every proof
and signature).
`ops::cloud_recovery` (`vh cloud recovery enroll|status|unenroll`, migration 135 `cloud_recovery_vault`) is Tier B
enrollment (spec 05 §3.2; key-backup.md "Recovery recipients"): the bucket's envelopes (checked against
`vault_key_envelope`), key status provenance, signed `PUT|GET|DELETE /v1/recovery/vaults/{uid}`. Tests:
`CloudRecoveryEnrollment` in `test_recovery_recipients.cpp`.
`ops::cloud_restore` (`vh vault recover --from-cloud`) is the receiving side of the cloud's restore relay: a temporary
X25519 secret in process memory (by restore id), a signed request, polling, the bundle opened into an export document
(records' key checks and attestations, anchors' public keys) that `ops::vault_recover` proves like any export, with
the records' checkpoint as the rollback bound (`rec::Material::checkpoint`, used when no kit entry has one; a malformed
one refuses the restore); complete on success, cancel on every other way out. Tests: `VaultRecoverFromCloud` in `test_vault_recover.cpp`.
The account recovery key (`design/cloud/key-manager.md`, "As built"; migration 141): `ops::cloud_keys` fetches
`GET /v1/keys/account`, verifies the chain and the signed recovery policy with vl-keykit 0.2.0 (`verifyChain`,
`follow`, `verifyPolicy`, `compareToFloor`), stores each generation in `cloud_account_key` (pending, pinned,
superseded, refused) with an HMAC under the KeyProvider slot `cloud_account_pin` (`cloud/AccountPin`; the policy floor
lives in the pinned row), pins only after a super admin's `vh cloud key confirm` (CLI, or ws `cloud.key.confirm` from
a paired device with the keys step-up), follows signed rotations itself, and keeps covered vaults' account-managed
grants (`vault_recovery_grant.account_key_generation`, `.account_policy_sequence`) equal to the accepted policy.
`vault::envelopes::put` wraps to such grants only while the MAC-verified pin agrees. `cloud::StorageService`
(`CloudStorageService`, which replaced `CloudKeyService`) runs the check daily while linked. Tests: `AccountKey*`,
`AccountPolicy`, `LocalVaultEnvelopes` in `test_recovery_recipients.cpp`.
Managed storage (`design/cloud/managed-remotes.md`, "As built"; migration 142): `cloud/Storage` makes the signed
`/v1/vaults`, `/v1/storage`, `/v1/billing` and credential calls (the bucket key arrives sealed to a one-time X25519
key, `credential::open`, wiped); `ops::cloud_storage` holds the people's operations (`vh cloud storage …`, ws
`cloud.storage.*`, admin module `cloud`: view/storage/billing, no step-up; agents read only) and the engine `tick()`,
which `CloudStorageService` runs every 30 s: nothing unless linked and the account key pinned; it caches the account
(`cloud_storage_account`), sweeps vaults into `vault_cloud_storage` (new local vaults on by default, existing ones
offered, empty ones not registered), and moves each one step (register + sealed label, switch on, key exchange into an
`api_keys` row with `origin = 'cloud'`, attach via `ops::vault_remote::attachForCloud` with the managed hooks: the
account key's system grant `recovery_recipients::addAccountKeyForManagedVault` and a quota check; retention; automatic
enrollment `cloud_recovery::enrollAutomatic`; the gate from `storage_access`; rotation; switch-off via
`detachForCloud`; moved; ejection in place; `ended` via the in-place detach). Operator attach/detach/abort/access refuse
managed vaults (`managed_storage`); `vh cloud unlink` refuses while any is managed unless `--force`. Tests:
`CloudStorageTest` in `test_cloud_storage_db.cpp` (a fake account service in the cloud's as-built shapes).
The relay (`design/cloud/relay.md`, "As built"; migration 144): `cloud::RelayService` (`CloudRelayService`, after
DeviceServer) does nothing unless linked, the `cloud_relay` row names this installation (`ops::cloud_relay`,
`vh cloud relay status|enable|disable`, ws `cloud.relay.*`, capability `cloud.relay`; super admins switch, enable is a
device.trust step-up, agents never; status for the admin cloud View permission) and `device_server.enabled`. Its
service thread fetches signed `POST /v1/relay/server-tickets` and renews at `renew_after`; its I/O thread holds the
WSS socket (TICKET, CHALLENGE, PROOF by the installation key, WELCOME, OPEN/DATA/CREDIT/CLOSE, RENEW), re-checks every
browser ticket (`verifyBrowserTicket`, `JtiLedger`, `FailureLimiter`) and pumps each stream through a socketpair into
the listener. Backoff 1 s-5 min with jitter; 401/404/other 403 → `stopped` until switched on again, 403
`relay_disabled`/402/503 → `waiting`. Audit `cloud.relay.enable|disable|refused`. `CloudRelayServiceTest` drives it
against a fake relay, and against the cloud's real `vaulthalla-cloud-relay` when `VH_TEST_CLOUD_RELAY_BINARY` names it.

### WebAuthn verifier (vl-webauthn, from #355)

The relying-party half of passkeys (design `docs/dev/mfa-design.md` 4.1, decision D5); the daemon's adapter is
`auth/mfa/Passkeys.hpp` (#357, below). It is `valkyrianlabs/vl-webauthn` (MIT, shared with vaulthalla-cloud;
namespace `vl::webauthn`, headers `<vl/webauthn/*.hpp>`), the release pinned in `subprojects/vl-webauthn.wrap` with its
tarball in `subprojects/packagecache/`; its suites, vectors, fuzz targets and corpora live there
(`tools/contracts/test_webauthn_contract.py` pins the wrap and that no in-tree copy remains). `Verifier` = check 1 (`ChallengeStore`: in-memory,
single use, 120 s, bound to ws session, `Purpose`, user and scope, burnt before any signature check) + the pure
`verifyRegistration`/`verifyAssertion` (checks 2-14). Persistence is the caller's: `CredentialLookup` is an
interface, and an `Outcome` says what to store (new signCount, BS) or do (`suspendCredential` on a device-bound
counter regression, audit `counterRegression`). Parsers: `Cbor` (libcbor streaming decoder as a strict scanner, then
`cbor_load`), `Cose`, `AuthenticatorData`, `ClientData` and `Wire` (nlohmann SAX for duplicates/depth), `Attestation`
(none, packed self, packed x5c without chain, others as none). Crypto only through `OpenSsl` (EVP) and libsodium.
`UserVerification::Preferred` exists for the W3C vectors only. Config `auth.webauthn.{rp_id,rp_name,origins}`
(`config::WebAuthnConfig`, rules in `RelyingParty.hpp`) is checked on load and settings.update; the console edits
it in Settings › Security.

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

**Session assurance and write-once promotion (#354, migration 119; MFA design note §5.3).** `refresh_tokens` carries
`aal` (1|2), `amr TEXT[]` (`pwd`, `hwk`, `swk`, `otp`, `rec`) and `auth_time`; rows from before read as aal 1, `{pwd}`,
`auth_time = issued_at`. `session::Manager::promote(session, assurance::Proof)` inserts the row **once**
(`RefreshToken::insertOnce`, `ON CONFLICT (jti) DO NOTHING`): a jti that already has a row is never promoted or
adopted again. A socket's refresh JWT is minted at its own handshake: `Validator::validateRefreshToken` rehydrates
**only from the stored row** (the old prior-session shortcut, which let a socket adopt another live socket's rowless
cookie, is gone), so a planted cookie is rotated away at the handshake. `auth.login` on a socket that already has a
user is `ops::Refused` `already_signed_in` (before any lookup; not counted by the login rate limit). The MFA policy
hook `auth::session::assurance` (`Assurance.hpp`; the daemon installs `auth::mfa::policy::rowSatisfies` at startup,
#357) is checked against the row on every use: `rehydrateFromStoredRefreshToken` (handshake, validate, auth.refresh), the HTTP lanes' stored-row path, and
`Manager::endIfBelowPolicy` on every `validate`/`renewAccessToken`/`validateRawRefreshToken`; a row below policy is
revoked (`auth.session.revoke`, reason `assurance_policy`). `assurance::setPolicy` / `policyChanged()` bump
`rbac::policyEpoch()`, so the 30 s cache can't hide a change. Sessions list/revoke: `ops::sessions` (own account
only; ids are a keyed BLAKE2b of the jti under a per-process key, never the jti), ws `auth.sessions.list` /
`auth.sessions.revoke {id} | {all_others}`; revoking revokes the rows, then `Manager::endSessionsWithRefreshJti`
invalidates and closes every live socket holding them (the caller's after its reply), so the HTTP lanes refuse the
cookie on the next request. Console: Account › Security › Sessions (`web/src/features/account/SessionsPanel.tsx`).
Tabs on the sign-in page each get their own cookie (the last handshake's wins), so the console's `login()` reconnects
first (`WsClient.reconnect`): the socket that signs in is the one that set the browser's current cookie, and a
connection that comes up already signed in (another tab won) answers `already_signed_in`, which `login()` turns into
`auth.refresh`. Tests: `SessionAssurance*`,
`WsAuthRouting.AuthLoginOnASignedInSocketIsAlreadySignedIn`, `SqlDeployerHistoryDb.RefreshTokenAssurance*`.

**MFA factor storage (#356, migration 120; MFA design note §4.2, §4.3, §9).** `auth::mfa` (`core/{include,src}/auth/mfa/`)
is the storage and model layer, keyed by user id (a pending sign-in has no `session->user`); the sign-in flow below
(#357) is its user. Tables: `user_mfa` (random 32-byte `webauthn_user_handle`, `required`, cooldown),
`webauthn_credentials`, `totp_factors`, `recovery_code_batches`, `recovery_codes`. Two internal secrets in
`crypto::secrets::Manager` via `Manager::sealedKey` (seal-and-read-back; an unreadable row throws and is never
replaced; a missing row while dependents exist is `MasterSecretLost`, `secrets::dependents::mfaSeal/mfaPepper`):
`mfa_seal` (AES-256-GCM over each 20-byte TOTP seed, AAD `"vh/mfa/totp/v1" ‖ BE32(user_id) ‖ factor_uuid`) and
`mfa_pepper` (keyed BLAKE2b-256 per recovery code, domain `"vh/mfa/recovery/v1" ‖ BE32(user_id)`). `auth::mfa::keys`
caches them in locked memory and throws `keys::Unavailable` (only TOTP / recovery codes are refused; passkeys don't
need either). TOTP (`Totp.hpp`): RFC 6238 SHA-1, 6 digits, 30 s, window ±1; a step is claimed by
`UPDATE … WHERE last_step < step`, so replay and concurrent double use fail; enrollment stays unconfirmed (unusable)
until the first correct code within 10 minutes, one in flight per account, the Janitor purges expired ones. Recovery
codes (`RecoveryCodes.hpp`): 10 × `XXXXX-XXXXX` Crockford (50 bits); a batch is inactive until acknowledged,
acknowledging supersedes the active one (partial unique index), a newer generate drops an unacknowledged batch; a code
is spent by one conditional UPDATE joined to an acknowledged, unsuperseded batch. Passkeys: storage only
(`addWebAuthnCredential`, lookup by credential id, compare-and-set `recordWebAuthnUse`, suspend) plus the adapters for
the vl-webauthn verifier (#355): `fromVerified(vl::webauthn::NewCredential, …)`, `CredentialStore` (its
`CredentialLookup`, joined with `user_mfa`'s handle) and `recordAssertion(VerifiedAssertion, expectedSignCount)`. Factors are removed by `disabled_at` (kept for audit). Audit actions
`auth.mfa.factor.enroll|rename|remove|suspend`, `auth.mfa.recovery.generate|acknowledge|use` with ids only;
`ws::LogRedaction` redacts codes, seeds, `otpauth:` URIs (by value) and WebAuthn material. `vh secrets export
mfa-seal|mfa-pepper` (base64); `vh secret set mfa-seal|mfa-pepper <file>` imports that file on a new host (#398,
`ops::mfa_keys`, super admin, confirmed, audited `secrets.mfa_key.import`): the seal must open a stored TOTP seed, the pepper must
reproduce the hash of a recovery code the actor passes (`--code`), a readable stored key is never replaced, a mismatch changes nothing. Tests: `MfaTotp*`, `MfaRecoveryCodes*`, `MfaSeal*`, `MfaLogRedaction*`,
`MfaFactorsDb*`, `MfaKeyImportDb*`, `SqlDeployerHistoryDb.MfaFactors*`.

**Pending-MFA sign-in and guided enrollment (#357; MFA design note §5.2, §7.1, §7.2, §8).** `auth::mfa::policy`
(`Policy.hpp`): level `auth.mfa.policy` (`optional | admins | all`, default `admins` on new and upgraded installs, D2) plus
`user_mfa.required`; "privileged" = super admin, or an admin role that may add/edit/delete users or admins or reset
their passwords, add/edit/delete admin or vault roles, edit any settings section, or export/rotate encryption keys
(auditor/unprivileged are not). It is applied twice: `rowSatisfies` (installed into `assurance` by `main.cpp`) refuses
and revokes an aal 1 row of an account that must have MFA on its next use (no grandfathering; aal 2 rows skip the
lookup; `user_mfa.required` cached per policy epoch, a DB error refuses the request without revoking), and
`auth::Manager::loginUser` (now `bool`) asks `signin::beginIfDue` after a correct password: an account with a usable
factor (whatever the policy) or one that must have MFA is left **pending** (`auth/mfa/Pending.hpp`:
`ws::Session::mfa()` holds `Pending {user_id, kind Mfa|Enrollment, methods, expires_at, failures, enrolled_amr,
recovery_batch}` in memory; `session->user` stays null, no access token, no refresh row, so auth.refresh, a
reconnect, another tab and the HTTP lanes refuse the cookie by construction). `auth.login` then answers ERROR
`mfa_required` / `mfa_enrollment_required` with `data.pending {kind, expires_at, methods, attempts_remaining,
webauthn?: {publicKey}}` (`handler::Mfa::throwPending`; not a login failure for the rate limit). Router: before the
human branch, a pending socket runs exactly `kPendingCommands` (`auth.mfa.verify|cancel`, `auth.logout`) plus
`kPendingEnrollmentCommands` (`auth.mfa.webauthn.register.options|finish`, `auth.mfa.totp.enroll.start|confirm`,
`auth.mfa.recovery.acknowledge`) while enrolling; everything else (auth.login, meta.hello) is UNAUTHORIZED. Mirrored
in the web's `LIFECYCLE` (`tools/contracts/test_mfa_pending_contract.py`). Ends after 5 min (10 enrolling), 5 failed
factors, cancel, logout, or the socket closing (`Session::close` clears it and `passkeys::forgetSession`). A second
cap across sockets: the account backoff (#360, below) → `rate_limited {retry_after}` (`signin::
accountRetryAfter`; in memory). `signin::complete` is the only promotion: clears
pending, `setAuthenticatedUser` + `promote(Proof{2, {pwd, hwk|swk|otp|rec}})` (one row), last login,
`auth.login.success {method, aal, amr}`. `auth.mfa.verify {method webauthn|totp|recovery_code}`: passkeys through
`auth/mfa/Passkeys.hpp` (RP from `config.auth.webauthn`, one process-wide `ChallengeStore`, purpose `mfa` bound to
the socket uuid and user; `{method: webauthn}` without a credential answers `mfa_required` with a fresh challenge,
not an attempt); `mfa_invalid {attempts_remaining, pending}`; a recovery code → RecoveryRestricted: amr `rec`,
the recovery effects of #360 (below), answer `recovery`.
Enrollment: the first factor (UV passkey registration or a confirmed TOTP code) answers ten recovery codes; on a
pending socket `auth.mfa.recovery.acknowledge` of that batch completes the sign-in at aal 2. The same commands
(plus `auth.mfa.status`, `auth.mfa.factor.rename {kind, id, label}`, `auth.mfa.recovery.generate`) serve signed-in web
sessions (Account › Security); device sessions are denied (Desktop never sees an MFA prompt). Adding a second factor,
removing one (`auth.mfa.factor.remove`) and replacing an active recovery batch are account.credentials step-up (#359,
below). Contract auth levels
`pending` / `enrollment`; model `MfaFactor`. Tests: `test_mfa_signin.cpp` (`WsAuthRouting.APending*`,
`MfaSignInDb.*`: no session during pending, one aal 2 row, drift/replay, recovery replay and revocation, expiry,
5 failures, account throttle, D2 aal 1 refusal, passkey enroll/sign-in/UV refused with a software authenticator).

**Discoverable passkey sign-in (#358; MFA design note §4.1, §7.3, §8.6).** A passkey alone, no username or password:
`auth.passkey.options` (no payload) answers `{publicKey: {challenge, rpId, timeout, userVerification: required,
allowCredentials: []}, expires_at}`, the same for every caller but its challenge (no account named or read: no
enumeration); `auth.passkey.login {credential}` verifies an assertion over it (`passkeys::verifyLogin`, purpose `login`,
no expected user: the verifier requires `userHandle` and compares it with the credential owner's
`user_mfa.webauthn_user_handle`; UV required; the backup-aware counter table and suspension as for `mfa`) and signs in
through `signin::complete` at **aal 2, amr `[hwk]` or `[swk]`** (no `pwd`), method `passkey`. Every failure (unknown,
suspended, foreign-rp or other account's credential, no UV, spent/expired/other socket's challenge, an account that
can't sign in) is one plain error, `"That passkey couldn't sign you in..."`; audited `auth.passkey.login` success
`{factor_id, amr, ip}` / failure. Login challenges live in their **own** `ChallengeStore` (capacity
`kMaxLoginChallenges` = 10,000, `rate_limited` when full), so anonymous callers can't fill the store of the mfa,
register and step-up ceremonies, and a challenge of one purpose never answers the other (store and purpose both
differ; `MfaSignInDb.LoginAndMfaChallengesNeverAnswerForEachOther`). Both commands are in `isSessionLifecycleCommand`
(anonymous sockets reach them; the device listener and the pending mode never do); their handlers refuse a signed-in
socket (`already_signed_in`) and a pending one (`denied`). `ShareRateLimit`: 30/min per client address for each.
Tests: `WsAuthRouting.PasskeySignInIsForAnonymousWebSocketsOnly`, `PasskeyRateLimit.*`,
`MfaSignInDb.PasskeySignIn*|APasskeyAlone*|ASyncedPasskey*` (0/0 synced counter, device-bound regression suspended),
`tools/contracts/test_mfa_pending_contract.py` (the lifecycle is read from the router and mirrored in `LIFECYCLE`).

**Step-up (#359; MFA design note §5.4, D3, D6).** `auth::stepup` (`core/{include,src}/auth/stepup/`):
`require(family, target?)` is called in the ops layer (and the MFA factor handlers) after validation and typed
confirmations, right before the mutation. Families: `keys`, `device.trust`, `data.destroy`, `connector.trust` (target-bound, single use;
targets name the action and object: `vault.keys.export:<id>|all`, `vault.keys.import:<id>`,
`device.pairing.approve:<request>:<spki>:<sha256(code)[:16]>`, `device.remote.enable`,
`storage.vault.remove:<id>[:now][:upstream]`, `recovery.point.delete:<id>`, `vault.recovery.suspend:<id>`,
`upstream.bucket.{cleanup,unprotect,lifecycle.set}:<bucket row>`, `connector.enable:<origin>`, `connector.policy:…`,
`connector.client.add:<digest>`), and `account.credentials`, `identity.admin`,
`secrets`, `settings` (family-wide). The command → family table is `contract::stepUpTable()`
(`core/usage/src/contract/ws/stepup.cpp`), exported as `step_up` on annotated commands and as `WS_CONTRACT_STEP_UP`.
Who asks is a thread-local `stepup::Scope`: the ws router sets it per routed command (Web, or Device on the device
listener), the CLI server Host (exempt: peer credentials, design 5.6) or Agent (`vh mcp` agent: true), `/mcp` Agent;
no scope = the daemon's own callers and tests (exempt, like `ops::Actor`'s internal callers). Agent always refuses
(`methods: []`). Device refuses (`methods: [device_approval?, console_approval]`) unless a grant on that device session
covers it: method `device_approval` (its approval key, keys/device.trust only, D6) or `console_approval` (a person's
passkey in the console, any family); any other grant method never counts on a device (#361, below). Exception:
`secrets` on a full-access, directly connected device's session is satisfied by the session itself, before the
recovery cooldown (`stepup::deviceSessionSatisfies`, audited `auth.stepup.grant` method `device_session`): Desktop
creates S3 gateway keys on RBAC alone (Cooper, 2026-11-23). A device's
`vault.keys.export` needs no step-up for a vault its live, unsuspended key-backup grant names (`ops::backup_grants::covering`,
#362, below); anything else is the keys step-up. Web: a grant on
`ws::Session::stepUp()` bound to user + refresh jti + family (+ target), `auth.mfa.step_up_ttl_seconds` (default 300,
60..900); or, family-wide only, an aal 2 sign-in (not `rec`) within the TTL. Refusal `ops::StepUpRequired` → ERROR
`step_up_required {family, target, methods, max_age_seconds}`. `auth.stepup.begin {family, target?}` → `{stepup_id,
methods, webauthn?: {publicKey}}` (purpose `stepup`, challenge scope `stepup␟family␟target`); `auth.stepup.finish`
with a UV assertion, password + TOTP, or D3's password alone (`methods()`: account need not have MFA, no usable
factor, never keys/device.trust/data.destroy; rechecked at finish). 5 failures in 15 min revoke the session
(`ops::sessions::revoke`). Grants die in `session::Manager::invalidate` (logout, idle, revocation, policy) and
`Session::close`. `stepup::Covered`: an op's nested ops ride its step-up (user deletion removing its vaults). Audit:
`auth.stepup.grant|fail|required`. A recovery-code session may still enroll its replacement factor and new codes
without step-up (design 7.4). Capability `auth.step_up`. Console: `WsClient` `onStepUp` → `lib/stepUp.ts` →
`features/auth/stepup/StepUpDialog.tsx` (lazy), then one resend. Tests: `test_mfa_stepup.cpp` (DB-free),
`test_mfa_stepup_db.cpp` (table-driven over the annotations, D3, passkey binding, devices/recovery/refresh never
satisfy, revocation, regression list).

**Device approvals (#361; design 6.1-6.3, 6.5, 8.4, D6; `docs/reference/device-approvals.md`).** `auth::approval`
(`core/{include,src}/auth/approval/`), ws `handler::Approvals`. Migration 128 `device_approval_keys` (PK device_id,
91-byte P-256 SPKI, `spki_sha256` UNIQUE, `registered_via` pairing|console_approval, `revoked_at` set by
`Devices::revoke|revokeAll`; once per device, `db::query::device::ApprovalKeys`). Registered by `device.pair.request
approval_key` (validated `crypto::p256KeyFromSpki`, never the connection's key or a known one; inserted with the device
row in `Devices::insert`'s transaction) or `device.approval.key.register` (`ops::devices::registerApprovalKey`:
device.trust target `device.approval.key.register:<row>:<spki hex>`, so only a console approval satisfies it).
`device.approval.challenge|submit`: in-memory challenges (32 random bytes, 120 s, ≤ 4 per session, bound to session
uuid, family, target; spent by the first answer from that session; another session's attempt doesn't spend it);
`crypto::approvalMessage` = "vh-device-approval-v1" 0 node_id 0 server SPKI hash, device (peer) SPKI hash, challenge,
family 0 target 0 UInt64BE(expires) — recomputed at submit from the current node id and server identity; verified with
the live key (`verifyEcdsaP256Sha256`); grant method `device_approval`. Console approvals (`device.approval.request|
status`, `auth.approval.list|approve|deny`): in memory, 5 min, ≤ 3 open and 10/h per device row; push
`auth.approval.pending` to the user's console sessions (`setPushForTesting`); approve = WebAuthn purpose `approval`,
scope `approval␟id␟family␟target`, UV required, `passkey_required` without a passkey, any TOTP/password payload refused;
failures count on the console session's step-up failures (5 → revoked); the first `status` on the asking session
mints a `console_approval` grant (once). Router: `device.approval.*` are device-only (`isDeviceOnlyCommand`),
`auth.approval.*` denied on device sessions. Shared vector `core/test-assets/device/approval-vectors.json`
(`tools/dev/device_approval_vectors.py --check`). Audit `device.approval.submit`, `device.approval.key.register`,
`auth.approval.request|approve|deny`. Tests: `test_device_approvals.cpp` (vector, SPKI, routing, grant methods,
contract), `test_device_approvals_db.cpp` (8.4 pairing, console/CLI pairing, every signature mismatch, console
approvals, rate limits, key registration, and the table-driven "a device never prompts for a routine command" probe
through the daemon's router; `Session::setSendSinkForTesting` captures the answers).


**Key-backup grants (#362; design 6.4, D1, D4; `docs/reference/device-approvals.md` "Key-backup grants").**
`ops::backup_grants` (`ops/BackupGrants.{hpp,cpp}`), `db::query::device::BackupGrants`, ws `handler::Devices::backupGrant*`.
Migration 130: `key_backup_grants` (one live per device: `uq_key_backup_grant_live`; origin approved|migrated;
`approved_via` webauthn|password_totp|device_approval|console_approval; `suspended_at`; `revoked_at` + `revoked_reason`
manual|device_revoked|user_inactive|export_permission|recovery_code|admin_reset|cli_reset|device_idle),
`key_backup_grant_vaults` (no FK to vault), `key_backup_grant_migration` (D1 snapshot of live devices, taken once when
the table is created, carrying 129's interim revocation; then `devices.key_backup_revoked_*` are dropped).
`migratePending()` runs in `main.cpp initDeps` after the identity preload, before any listener: per snapshot row, a
user that `mayHold` (authorizing and super admin or encryption-key Export) gets an origin `migrated` grant over
`ops::vault_keys::exportableVaults` (live vaults + retained deleted ones it may see), revoked when the snapshot says so;
`keys.backup.grant.migrate` each. Export: `vault_keys::exportVault|exportAll` call `covering(vaultIds)` (Device scope,
the device's live, active grant naming every vault, triggers re-checked, 60 exports per grant per sliding hour in
memory; over it: `suspend` + `keys.backup.grant.suspend` + `notifications::account::send`) and `recordUse`
(`last_used_at`, `keys.backup.export {grant_id, device, versions}`); otherwise `stepup::require(keys,
vault.keys.export:<id>|all)`. Commands `device.backup.grant.list|create|extend|confirm|revoke` (human and device
sessions; a device sees and manages its own grant, a console names `device_id`); create/extend/confirm require
device.trust targets `device.backup.grant.create:<row>:<ids>`, `.extend:<grant>:<ids>`, `.confirm:<grant>`
(ids ascending, `sha256:` digest past 256 chars); confirm lifts a suspension and makes a migrated grant approved.
Triggers: `Devices::revoke|revokeAll` revoke in their transaction (audited by `ops::devices::revoke` / the identity
rotation); `identities::Manager::setPublishedHook` → `reconcile(userIds)` (inactive, deleted, lost Export); `ops::users::remove`
revokes before deleting; `auth::mfa::recovery::revokeKeyBackupGrants` (recovery code, admin and CLI reset);
`device::authorize` calls `revokeIfIdle` (90 days since `last_seen_at`, or pairing) before touching the row; the DB
sweep and startup `reconcile()`. D4: during the cooldown, create runs only on the device itself for vaults ⊆ its last
grant revoked `recovery_code`, approved by its approval key registered before that revocation (`device_approval`
grant only; `recoveryRecreateTarget` lets `auth::approval` challenge/submit that one target through the cooldown).
Console: Devices › My devices "Key backup" column (`KeyBackupCell`: confirm, turn off).
**MFA policy, lockout, reset and auditable recovery (#360, migration 129; MFA design note §7.1, §7.3-§7.5, D2, D4).**
Config `auth.mfa.{policy, admin_webauthn_only, admin_device_bound_only, recovery_cooldown_hours (1..168, 24),
step_up_ttl_seconds}` (`config::validateAuth`: the admin flags need `auth.webauthn.rp_id`). `policy::level()` reads it
(`setLevel` writes the running config, tests); `policy::factorRule(user)` holds privileged accounts to passkeys (no
TOTP) or device-bound passkeys (no BE flag): `allowedPasskeys`, `hasAllowedTotp`, `hasAllowedFactor` feed sign-in
methods, the enrollment decision (an admin whose only factor is disallowed gets pending enrollment, passkey only),
step-up methods and `rowSatisfies` (an aal 2 row of a restricted admin survives only with `hwk`, `swk` if synced is
allowed, or `rec`); TOTP enrollment refuses, registration refuses a BE passkey (`RegistrationDetails::device_bound_only`).
`ops::config::saveSettings` → `policy::policyChanged/weakenings` (lower level, admin flag off, rp_id changed from a set
value): epoch bump, audit `auth.mfa.policy.change {from, to, weakened}`, weakening → `notifications::account::send`
to the security recipients. **Lockout:** `signin::AccountBackoff` (DB-free arithmetic): the 5th factor failure of a
streak delays the account 1 min, doubling to 15 (never a lock); a streak ends 15 quiet minutes after its last
failure or delay; audit `auth.mfa.lockout`; the 10th notifies user + security. **Recovery** (`auth/mfa/Recovery.hpp`):
`afterRecoveryCodeSignIn` (cooldown from config, `ops::sessions::revoke(all_others)`, `revokeKeyBackupGrants` →
`ops::backup_grants::revokeForUser` (`keys.backup.grant.revoke` per grant, #362), the live devices listed in the
answer, never revoked, audit `auth.mfa.recovery.signin`, notice); `reset(target, Resetter{id, name, AdminReset |
CliReset}, reason)`: disables every passkey/TOTP (`auth.mfa.factor.remove` per factor, kept), supersedes every
recovery batch, `user_mfa.required = true`, `reset_at/by`, cooldown, `auth::Manager::revokeSessions`, grants revoked,
`auth.mfa.admin.reset {target_id, reason, channel, counts}`, notice. **Cooldown:** `stepup::cooldownFamily` (keys,
device.trust, identity.admin, secrets, settings); `require` checks `requireNoCooldown` on Web and Device before any
grant (device_approval and console_approval included) or fresh sign-in → `ops::RecoveryCooldown` → ERROR `recovery_cooldown {family, cooldown_until}` (audited
`auth.stepup.required` denied, reason `recovery_cooldown`; Host exempt); `begin`/`finish`, `device.approval.challenge|submit|request` and `auth.approval.approve` refuse it too (approve offers and accepts only passkeys the policy allows, never a recovery-enrolled one for a cooldown family), and factors
`created_during_recovery` (enrolled by a `rec` session or while the cooldown runs) are never offered or accepted for a
cooldown family until it ends; the one exception (#362, D4) is `ops::backup_grants::recoveryRecreateTarget`: the device's
approval key, registered before the recovery, may approve `device.backup.grant.create:<device>:…` for the device whose
latest grant the recovery revoked, and create re-checks the same-vault rule. **Admin/CLI:** `ops::mfa` (`ops/Mfa.hpp`) `status | require | reset`, Channel Web
(never self; users-manage = `ops::users::requireMfaManager`: reset-password over the account, a super admin only by
a super admin; reset `account.credentials`, require `identity.admin`) or Cli (`vh user mfa status|reset|require`: the
bound UID itself (reset/status) or a users-manager; root/UID 0 and unbound actors refused; Host exempt from step-up,
Agent refused). ws `auth.mfa.admin.status|require|reset`; `auth.mfa.status` gains `policy.totp_allowed`,
`synced_passkeys_allowed`, factor `allowed`. Notices: `notifications/AccountSecurity`
(security recipients + the account's email; factor changes to the account only; test sink). Console: Settings ›
Security › Multi-factor sign-in, Users › user › Sign-in factors (`MfaAdminPanel`, lazy), Account › Security
recovery notice with paired devices and revoke. Tests: `test_mfa_policy.cpp` (DB-free: backoff, config, weakening,
contract), `test_mfa_policy_db.cpp` (`MfaPolicyDb.*`: policy raise, D2 upgrade refusal, weakening, webauthn-only,
recovery-code effects and audit sequence, cooldown vs. recovery-enrolled factor, admin reset effects and rules, CLI
reset permissions and ws/CLI parity, password reset, last factor, 10th-failure notice; `vh audit verify` after each
recovery path), `SqlDeployerHistoryDb.MfaRecoveryGrants*`; Tier B ws/CLI parity: `tools/harness/tests/test_mfa_reset_live.py` (opt-in,
`VHH_WS_LIVE_BUILD`; on #395's TOTP/step-up lab clients).

**Identities (`identities::Manager`, `core/{include,src}/identities/`).** One canonical `User`/`Group` object per id,
handed out as the same `shared_ptr` everywhere (sessions, engines, FUSE, HTTP, S3). Each holds an immutable
`UserState`/`GroupState` in an `std::atomic<std::shared_ptr<const ...>>`; the Manager never replaces the object, it
publishes a new state into it, so every holder sees a committed change on its next read. Readers take one state per
logical check (`User::state()`, or `User::authz()` for the user plus its live groups, read under a seqlock so a
multi-object publication is seen whole or not at all). `authorizing()` is false for deactivated accounts and for
tombstones (deleted accounts keep their object, with no roles) and for remote accounts (below); every resolver, the
FUSE identity step and the ws router check it. Group membership lives on the member's state (`groups`, `joinedAt`); a group's own state has no
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

**Remote accounts (server mirror phase 1b, migrations 158/159; `design/peers/identity.md`).** `users` and `groups` have
`home_node`, `home_id` and `remote`: a remote row names a person or group of a linked server, for attribution only,
by its home server's node id and its integer id there (both set on a remote row, both NULL on a local one, unique per
home server); local ids are unchanged and there is no second, shared id on accounts, groups or roles.
`UserState`/`GroupState` carry `homeNode`/`homeId`/`remote`; `ws`/JSON shapes do not (yet). `authorizing()` is false
for a remote account (so every authentication path refuses it: password via `Loader::credentialsByName` (local only)
and `signin::complete`, passkeys, refresh and session tokens, device sessions, the S3 gateway, connectors; `vh` finds
no Linux uid for it), a remote group is left out of `User::authz()`, and names/Linux ids index local accounts only
(`users.name`/`email`, `groups.name` unique `WHERE NOT remote`; `ON CONFLICT (name) WHERE NOT remote`). The database
refuses a remote account with a password hash, Linux uid, protected flag or without both home columns
(`users_remote_check`), a local account becoming remote (`vh_remote_account_guard`), and any credential, admin role or
global policy row naming one (`vh_refuse_remote_account`: refresh_tokens, passkeys, TOTP, recovery codes, devices, S3
gateway keys, connector and key-backup grants, admin_role_assignments, user_global_vault_policy). The account writers
refuse to create or edit remote rows; nothing creates them yet (the link's principal stream will). Tests:
`PermanentIdsDb*`, `RemoteAccounts*`, `SqlDeployerHistoryDb.PermanentIdsMigration158*`.

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
for PDFs; `scale` accepted and ignored), `POST /preview/batch` (≤ 200 items, per-item RBAC, ready URLs are `entry=<id>` (vault or `share=1`), never a path or name (#417), readiness from one index query per engine (`ready` / `queued` /
`failed` (final: the source doesn't render) / `missing` / `unsupported`), never opening or decrypting an artifact,
`ready|queued|missing|unsupported|error`, never fetches remote-only files), `GET|HEAD /download/content` (original
bytes, inline by default), `GET|HEAD /download` (files stream with no size cap; directories stream a STORE ZIP,
see "Folder ZIPs" below), `GET /preview/derived?kind=&variant=` (200 artifact | 202 queued + Retry-After |
415 | 422 `conversion_failed` | 503 `converter_unavailable`/`busy`), `PUT /upload/text`, `PUT /upload/content`
(below), `GET|HEAD /download/conflict?
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

- **Conditional content writes** (`upload/Content.cpp`, #258): `PUT /upload/content?vault_id&path`, humans and devices
  only. `If-Match: <content_version>` replaces (`access::resolve(Need::Overwrite)`; stale or a FUSE working copy open:
  412 + current ETag), `If-None-Match: *` creates (`access::resolveCreate`: Write on the path; missing parents are
  made as for an upload; something there: 412 with its ETag for a file, 409 otherwise). Neither (or both, or `*` in
  If-Match): 428; no Content-Length: 411; > 8 GiB or more than `freeSpace()`: 413. All of that is answered before a
  body byte is read (the connection then closes). `Session::handle_streaming_content` streams the body in 64 KiB reads
  into the staging seam (`.upload-http-content-<uuid>.part`, a `staging::Body`, same private/mount choice as
  uploads); the commit authenticates and authorizes again, then `Filesystem::createFile{source,
  overwrite, expected_source_id}` (the matched sourceId, or "" for create-only), so concurrent writers and an open
  working copy are a ContentConflict → 412. Lane creates of one path are claimed one at a time. 201/200 answers
  `{created, entry}` (the file's entry JSON with both versions) and the new ETag. The `/upload/session` commit seals
  from the staged file the same way (no whole-file buffer; an empty file keeps the empty-buffer branch), and a file
  whose PUT failed may be PUT again from the start (share upload sessions excepted: their record is terminal).

- **Resumable uploads** (`upload/Resumable.cpp`, capability `http.upload.resumable`, normative spec
  `docs/reference/transfer-protocol.md` §3, migration 114 `upload_session`/`_file`/`_part`, query layer
  `db/query/upload/Resumable`): `POST /upload/sessions`, `GET|DELETE /upload/sessions/<id>`, `PUT
  /upload/sessions/<id>/files/<fid>?offset=` (streamed by `Session::handle_resumable_part`, checked from the header,
  refusals close the connection), `POST …/finish`; both listeners, shares via `?share=1`. Typed errors
  `{error:{code,message}}` (never status-by-substring). Ownership: the user id (device principal or cookie) or the
  share session id; anything else is 404 (no oracle). One vault per session; sizes up to the GCM limit 2^36 − 32 (no
  8 GiB cap), quota = `freeSpace()` minus bytes promised to the vault's other open sessions.
  - **Parts are never written under the file's keystream** (the spec's first draft did that; an unrecorded attempt
    followed by different bytes would have reused CTR positions on disk). Each attempt is its own AES-256-GCM message
    (file's key version, fresh IV) in `<spool>/<ord>.<offset>.<rand>.tmp` → fsync → rename to `.part` → dir fsync →
    part row (+ `recordUploadChunk` for shares) → 200. Duplicates of an exact stored range are compared byte for
    byte (decrypting the stored part, or the sealed file once the part is sealed): 200 or 409 `part_conflict`. No
    plaintext digest is stored; the answer's `sha256` is computed in memory.
  - A per-file **sealing cursor** (worker pool `transfer.commit_workers`) decrypts the stored parts in order and
    seals them as VHF1 into `<ord>.sealed` (#367, `vault::content::PrefixSealer`: whole 64 KiB chunks as soon as
    they are complete, the last one final; the partial tail chunk held in memory; + BLAKE2b content hash, passed to
    `createFile` through `SealedContent::content_hash`); `sealed_bytes` checkpoints (whole chunks; ≤ 256 MiB, and
    every pass) let part files the prefix covers completely go. After a restart the cursor authenticates the
    recorded prefix (never re-encrypts); bytes past it, or stored bytes that differ from what was sealed for their
    range, make the sealing continue under a fresh salt (`<ord>.sealed.resalt` → `setSealing` → rename), so no index
    is sealed twice under one salt. Uploads created before #367 (12-byte IV) keep the legacy GCM cursor, which reads
    the sealed prefix back (it must re-encrypt to the same bytes) and truncates the rest. Commit: `Filesystem::createFile{overwrite=true, expected_source_id = "" or
    the if_match generation, sealed = link(spool → dst), copy on EXDEV/EPERM}` under `upload::CreateClaim` (shared
    with `PUT /upload/content`), authorized again as the user is now (share: principal re-resolved, committed as the
    link creator). A target that appeared meanwhile fails the file (`already_exists` / `precondition_failed`), never
    the old silent `overwrite=false` return. The sealed spool file is never reopened for writing once its link count
    is > 1. Key version ≠ current at part or commit → `key_rotated`.
  - State machine `receiving → sealing → committing → committed | failed`, monotonic in the DB (SQL guards a late
    write). `Service::recover()` (main.cpp `wireStorage`, after the engines) reloads sessions, drops part rows whose
    spool file is gone, sweeps attempt files / orphan parts / orphan session dirs and re-queues sealing and commits
    (a share file's commit waits for the share session's next request). `Service::shutdown()` from
    `ProtocolService::shutdownProtocols`; the janitor calls `Service::sweepExpired()` (idle TTL from the last part,
    max age; rows + spool + spool dirs without a row). Finish waits ≤ 5 s for commits (never does them) → 200 / 202
    + `Retry-After` / 409 `incomplete`.

### Byte-serving spine, integrity and derived artifacts

- **Positioned reads.** `storage::Engine::openPlaintextReader(file, ReaderOptions)` is the single funnel for every
  byte consumer (HTTP, media, models, text, thumbnails, converter input). `storage::Generation` identifies one content
  version: `sourceId()` = the generation id (VHF1: the header salt; legacy: the GCM IV; changes on every write;
  rename/move keep it), `plain:0` for an empty file and
  `plain:<size>:<updated_at>` for an unencrypted legacy file. **Entry versions (#257):** fs entry JSON carries
  `content_version` (files: exactly `Generation::etag()`, the `/download/content` ETag) and `metadata_version` (every
  entry: `fs::model::metadataVersion`, a hash of vault, parent, name, mode, owner, group and updated_at; not a counter,
  so it can't disagree with the fields in the same reply), both set by the Entry base serializer. Entry ids survive
  rename and move (`FsEntryVersionsDbTest`). `openLocalReader` dispatches on the format (`vault::content::isVhf1`): a VHF1
  generation gets `storage::Vhf1FileReader` (whole 64 KiB chunks authenticated before any byte of them is returned,
  the catalog's size as the authenticated object size, header bound to vault uid + salt + key version, failures
  sticky for the reader and the generation; no optimistic/strict distinction and no CTR keystream); a legacy one
  `GcmFileReader`, which preads only the requested ciphertext and decrypts with the GCM CTR
  keystream (`crypto::util::gcmCtrDecryptAt`: plaintext offset o ↔ ciphertext offset o, counter IV‖BE32(2+o/16)).
  Keys come from `EncryptionManager::keySnapshot(version)` (immutable `crypto::SecretKey`, mlocked, wiped; rotation
  swaps pointers under a shared_mutex). `readAll()` does one authenticated pass and records the verdict.
- **Master secrets in memory (#350).** `crypto::secrets::KeyProvider` holds its slot in `vl::keykit::SecretBytes`
  (vl-keykit's: mlocked, zeroed on release, random bytes from OpenSSL's `RAND_priv_bytes`; the server's own
  `crypto::SecretBytes` is gone since #443, `crypto/SecretBytes.hpp` keeps `WipedKeyCopy` and `viewBytes`) and
  `getMasterKey()` returns a `std::span` borrowed from it. The AES-GCM helpers take key spans, so callers never copy a
  master into a vector; a plain copy an API insists on (decrypt output, a sealer's return) goes in
  `crypto::WipedKeyCopy`, and `vl::keykit::wipe` zeroes a buffer. The share pepper and attestation seed are cached as
  `shared_ptr<const vl::keykit::SecretBytes>`. `vl::keykit::setWipeObserverForTesting` (it sees `SecretBytes`,
  `SecretKey` and `WipedKeyCopy` buffers) and `KeyProvider::setUnsealHookForTesting` are the test seams
  (`test_master_secret_memory.cpp`).
- **TPM PCR 7 policy (#351).** `platform::sealer::Policy {None, Pcr7}` (Linux TPM only; the Secure Enclave ignores it).
  `secrets.tpm_pcr_policy` binds newly sealed secrets only (PolicyPCR digest as the object's auth policy, no
  USERWITHAUTH); unseal reads the policy off the blob and fails with the typed `PolicyUnsatisfied` once PCR 7 changed,
  which the DB password, `initGuarded` and the attestation key let propagate (nothing is minted or overwritten).
  `vh secret reseal [--pcr7|--none]` (`ops::master_secrets::reseal`, `crypto/secrets/Reseal`) reseals every
  `.sealed_*.blob` staged and verified (`<name>.staged.*`, `<name>.prev.*`; `sealer::recover` from `KeyProvider::init`),
  gated for pcr7 on hardware posture, vault key backups and a `vh secret export all` under 24 h (`secret_exports`,
  migration 132). Health: `deps.secrets_policy|secrets_pcr_bound|secrets_warning`. Design: `design/sealing/master-secrets.md` §5.
- **Verify-once integrity.** `crypto::IntegrityRegistry` keys a verdict on (domain, IV, key version, dev, ino, size,
  mtime_ns) and runs one streaming tag check per key on 2 workers (capacity 8192 settled verdicts). `optimistic`
  (default, `preview.media.integrity`) serves at once and every live reader throws `IntegrityError` on its next read
  after a failed verdict; `strict` waits for the verdict. Failure is sticky for that key (later opens fail fast;
  logged on the crypto channel); a replacement during verification is `Superseded`, not corruption.
- **Remote-only files** (cloud vaults without a local copy) follow `preview.media.remote`: `hydrate` (default: whole
  object once, metered/budgeted, verified, local ciphertext kept), `ranged` (opt-in metered ranged GETs pinned to the
  object version; a VHF1 object's header is fetched and authenticated at open and every window is whole chunks
  authenticated before use; a legacy GCM object has no per-range authentication), `off` (`storage::ContentUnavailable` → HTTP 503
  `content_unavailable`). Grid thumbnails always use `off`. Chunked AEAD at rest would only be needed for
  *authenticated* random access to remote-only objects.
- **VHF1 at rest (#367).** Every new content generation is VHF1: `EncryptionManager` writes (encrypt,
  encryptToFile, reseal, rotation), FUSE seals, `createFile`, the resumable sealing cursor
  (`vault::content::PrefixSealer`), hydrate-and-seal of plaintext objects, provider restores and key salvage.
  `vault/Content.hpp` is the one place that tells the formats apart: by the generation id's length (12-byte IV =
  legacy `gcm0`, 32-byte salt = `vhf1`, empty = `plain`; `files.content_format` / `recovery_blob.content_format`,
  migration 126, are generated from it), with sealed-size math, dispatching readers (`openBuffer`, `openFileTo`,
  `verifyFd`, `StreamOpener`) and the VHF1 sealer. Readers bind a VHF1 object to the vault uid, the recorded salt and
  key version (the object uid when the caller holds it: path_v0 rows can be indexed from a listing before their
  object is read, and the 256-bit salt binds the object to the row on its own). Empty files stay zero bytes with no
  generation locally; uploaded, an empty file is one 136-byte VHF1 object. Legacy GCM files keep reading and are only
  rewritten when their content is (an overwrite, a rotation, a restore under an older key); #372 converts the rest.
  A contract test (`Vhf1AtRestTest.IntegrityContract*`, counter `crypto::util::gcmCtrDecryptAtCallsForTesting`)
  proves no VHF1 read reaches `gcmCtrDecryptAt`.
- **Local format conversion (#372).** `vault::conversion` (`vault/FormatConversion.hpp`) re-seals legacy `gcm0` live
  backing files and `.vh-recovery` blobs as VHF1 under the same key version (never a rotation). Per item: legacy tag
  over the whole input + plaintext BLAKE2b while streaming (`content::openFileTo` → `content::Sealer`), then a full
  chunk walk of the output bound to vault/salt/key version/object with its own BLAKE2b; digests, sizes and the
  catalog's recorded plaintext size must match before anything is replaced. Live files: the rotation sidecar protocol
  under `contentWriteMutex` (seams reused from `sync::rotation::runtimeDeps`): `<backing>.vh-rotate` → (a blob holding
  the same generation is `link(2)`ed from the sidecar under a new store name) → one transaction (files CAS with
  rotation's prepared statement + the blob row's CAS) → rename → unlink the old blob file; so a hard-linked blob
  converts once and stays a link. Other blobs: new store name (O_EXCL) → CAS of the `recovery_blob` row (generation,
  storage name, size) → unlink. Crashes are settled by the existing startup sidecar recovery and the store sweep
  (unreferenced files). `content_hash` columns are kept (sync change detectors; rotation keeps them too). Live files
  of encrypt-upstream cloud vaults are not converted here (local == bucket bytes; the layout migration, spec 01 §6,
  converts both); plaintext-upstream rows without local bytes get their stale legacy id cleared, as rotation does.
  `vault::FormatConversionService` (after VaultRetentionService; first pass 60 s after start) runs
  `conversion::convertVault` every `vaults.format_conversion.pass_interval` for vaults with legacy rows
  (`db::query::vault::FormatConversion`, migration 126's `content_format` + partial indexes), paced between items by
  `max_mib_per_second` / `max_cpu_percent` (`conversion::pauseAfter`), blocked per item while
  `rotation_in_progress()` or a `vault_key_salvage` row is running. Config is YAML-only (not in the settings JSON).
  `vh vault format status` = `ops::vault_format::status` (encryption-key View permission).
- **The vault format library vl-vaultfmt** (#443, `design/core/vault-format-library.md`, "As built: items 7 and 8"):
  VHF1, the object keys and the encrypted manifest below are `valkyrianlabs/vl-vaultfmt` (AGPL-3.0-or-later, shared with
  the Desktop-only engine and the portal's reader; namespaces `vl::vaultfmt::{vhf1,keys,manifest,test_support}`, headers
  `<vl/vaultfmt/...>`, the C API `vl_vaultfmt.h`), linked from the commit pinned in `subprojects/vl-vaultfmt.wrap` (a
  `git archive` tarball under `subprojects/packagecache/` until a release exists; 0.3.0 at its main `54742cb`). Server code names them fully
  (`vl::vaultfmt::manifest::Content`, or a file-scope `namespace mf = vl::vaultfmt::manifest;` alias as before); the
  server's own Fwd headers include `<vl/vaultfmt/Fwd.hpp>`. Its suites, vectors copy and the VHF1 fuzz target live
  there; here stay the protocol suites through the S3 adapter (`test_manifest.cpp`, `test_manifest_interleavings.cpp`
  on the HTTP fake only), `test_vaultfmt_vectors.cpp` (the library's vectors identical to `design/encryption/vectors/`)
  and `tools/contracts/test_format_library_contract.py` (pinned wrap, no in-tree copy, no old include or namespace).
  During co-development `subprojects/vl-vaultfmt-<version>` may be a local symlink to a checkout, never committed.
- **VHF1 codec** (`vl::vaultfmt::vhf1`, vl-vaultfmt `include/vl/vaultfmt/vhf1/{Format,Writer,Reader}.hpp`; #365, spec
  `design/encryption/02-authenticated-file-format.md`). The library under VHF1 at rest (above) and the manifest v2
  objects below: the 120-byte header (HMAC-SHA-256 tag), per-sealing HKDF-SHA-256 keys from vault key + salt,
  64 KiB AES-256-GCM chunks with AAD = header hash ‖ index ‖ final flag, a streaming `Writer` (final-chunk hold-back),
  `open()` / `ChunkWalker` (whole and streamed reads, only authenticated chunks reach the sink) and `RangeReader`
  (authenticated object size required, sticky failure). Errors are `vhf1::Error` with the spec's codes in the §3.6
  check order. Primitives are OpenSSL only (HKDF, HMAC, SHA-256, the CSPRNG for salts, AES-GCM through the codec's
  own one-message wrapper `vhf1/Aead.hpp`); wiping and constant-time comparison are vl-keykit's. Its key type is
  `vhf1::Key` (`vhf1/Key.hpp`, 32 bytes in a `vl::keykit::SecretBytes`); the server's `crypto::SecretKey` derives from
  it and only adds `random()`. `crypto::util::Gcm` (streaming GCM, the legacy v1 positioned decrypt, `gcmVerifyFd`)
  is the server's and VHF1 no longer uses it.
  Proven byte for byte by vl-vaultfmt's `Vhf1Vectors` against its copy of `design/encryption/vectors/vectors.json`;
  fuzz target `fuzz_vhf1` in vl-vaultfmt's CI.
- **Encrypted manifest v2** (`vl::vaultfmt::manifest`, vl-vaultfmt `include/vl/vaultfmt/manifest/`; #368, spec
  `design/encryption/03-metadata-recovery.md` §3-§4; migration 125). The format, its manifest and object keys are
  vl-vaultfmt's (above); the server's side is `storage::s3::ManifestStore`, `sync::vault_manifest` and `db::query::sync::Manifest`. Replaces `.vaulthalla/index-v1.json` for
  `opaque_v1` vaults only (every new encrypting vault since #371). `Document` (root, segment, snapshot schemas; readers ignore unknown
  members; `recovery_policy` v1 of revocable grants, only class `customer` usable, other versions "not understood"),
  `Objects` (VHF1 kind 3 root with object uid = vault uid, kind 2 segments with object uid = sid), `Chain` (rollback,
  fork, gap walked through retained root versions), `Partition` (by first uid byte; split > 8,192 entries or 4 MiB,
  merge < 1,024), `Publisher` (segments `If-None-Match: *`, root `If-Match`, 412 → load, verify, `mergePending`,
  bounded retry; prior names carried; GC keeps the last three roots' segments and anything < 24 h), `Reader`
  (fallbacks: root provider versions; segment provider version → older root → blind range; `blindRebuild` reads
  120-byte headers of `o/` only; `loadForRestore` says "freshness unverified: no checkpoint supplied"), `Store`
  (`storage::s3::ManifestStore` over `s3::Controller`, no `x-amz-meta-*`). `db::query::sync::Manifest` collects the DB into `Content`
  (read-only, `SET TRANSACTION READ ONLY`: every folder, symlink and snapshot has its uid from its insert since migration
  158; trash via `files_trashed.object_uid`, rows without one left out; versions and tombstones from
  `o/<uid>` rows of `upstream_object_version`) and keeps `remote_manifest_state` (manifest_key `.vaulthalla/root`:
  epoch, root hash, ETag, refused root, gc_at) and `remote_manifest_root` (last three roots' sids). The per-vault
  logic is `vl::vaultfmt::manifest::Session` (`Session.hpp`: publish and record, `verifyRemote` in both modes, repair, refusal,
  daily GC) over a `StateStore` interface (`ChainState`, `RootRecord`) and a `SessionHost` of callbacks (content,
  keys, node id, clock, alert, notices); it includes nothing of the server. `sync::vault_manifest::Service`
  (`sync/vault_manifest/`, the server's namespace, since #443) wires it: `StateStore` on PostgreSQL
  (`db::query::sync::Manifest`), `collect`, the vault's `EncryptionManager`, `Devices::nodeId()`, notices to the
  cloud log and `notifyRefusedRoot` to the operator bus. It is the glue `CloudEngine` uses for opaque_v1
  (`publishManifestV2`, `refreshRemoteIndexFromManifestIfChanged`
  verifies only and returns false: one HEAD of the root while its ETag is the recorded one, `ObjectStore::headEtag`);
  a pass publishes only when the collected content moved since the service's last publish (`publishIfChanged`); a
  refused root stalls the pass (`SyncStalled`) and raises one
  `manifest_rollback` / `manifest_fork` operator notification per root. The root carries the vault's recovery grants
  and each key version's envelope kids (#370, below; since #371 grants carry their public key and recovered versions
  their `origin`).
- **version_log publish** (spec `design/encryption/06-publish-without-preconditions.md` §5; migration 137): on a
  bucket whose probe says VersionLog (Backblaze B2) the root is PUT plainly and the provider versions of
  `.vaulthalla/root` are the log. `VersionLog.hpp` (`RootLog`: one ListObjectVersions, roots opened by version id and
  cached in `RootCache`; `walk` = rule C1 from an anchor, `walkBlind` = highest head epoch, `successorOf`, `windowBroken`).
  `publish`: segments, root PUT (a 5xx or transport error = `PutOutcomeUnknown`: found by hash), list (retries 1, 2,
  4, 8 s, then `PublishUnsettled`), won when ours is succ(base) (record version id, base version id and settle
  window), else delete ours by id, reload, merge, retry (max(3, writers + 1)); repair deletes versions newer than the
  head, never an authentic root of a higher epoch nor one such a root builds on (`Walk::ahead`). A chain from the
  anchor with such a root above it is incomplete: the read falls back to `walkBlind` (highest head epoch, then the
  longer chain, then the earliest head) and the chain rules (gap, fork, rollback). `load` follows C1 whenever the store is VersionLog or the root declares `publish: version_log` (a restore
  reads without a probe). Both modes: the root names `publish` and `writers` (the base's set while it names this
  node; a node that never published here takes over with itself alone); a head newer than this node's
  `own_epoch` that excludes it is `superseded`, a head of another node in the other mode `publish_mode_mismatch`, an
  id inside a recorded settle window `order_violation` (each refused, alerted `manifest_<code>`), except this node's own
  superseded attempt (a sibling of the settled root it produced: a lost-reply root PUT that Backblaze, ordering versions
  by upload start, landed below the retry), which the publish and the read delete (vl-vaultfmt 0.4.0
  `windowIntruders`); for 15 minutes after a failed root PUT `verifyRemote` lists instead of one HEAD. One writer per
  version_log bucket: a root naming several is `WritersRefused` (`version_log_writers`), a join `join_version_log`
  (spec 06 §5.5, §11). The root PUT has a 60 s deadline (`storage::s3::kManifestRootPutDeadline`; every buffer PUT a
  30 s connect bound and fails below 1 byte/s for 60 s). GC on VersionLog:
  segments unreferenced 24 h (`remote_manifest_gc`) lose every version by id; the root janitor
  (`collectRootVersions`, daily) keeps head + 2 canonical predecessors, deletes older canonical roots after 7 days and
  non-canonical versions and markers after 24 h. `Service::verifyRemote` on VersionLog: HEAD while the ETag is the
  settled one, else load from the settled anchor, record, repair. Tests: `ManifestPublishVersionLog*`,
  `ManifestChainVersionLog*` (test_manifest.cpp), `ManifestVersionLog*` (test_manifest_interleavings.cpp: scheduler,
  faults, broken order), DB `BucketCapabilityDbTest`, `VaultRecoverDb.OnABackblazeLike*`, live `LiveB2.*`.
- **Manifest applier, items 1-3** (`design/sync/manifest-applier.md`, "As built"; migration 145): snapshot records
  are named by `uid` (`recovery_snapshot.uid`, assigned at insert like `directories.uid` since migration 158, kept by a
  restore);
  `SnapshotRecord::id` is only read from roots written before uids (key `snapshotKey`: uid, or `id:<n>`), so the first
  publish after the upgrade replaces those records with the same snapshots by uid. `<vl/vaultfmt/manifest/Reconcile.hpp>`:
  the pure `reconcile(base, theirs, ours)` (result tree, ordered plan of `Op`s with `ours` for compare-and-set,
  conflicts, key problems that stop it), `applyPlan` (the model executor), `treeProblems`; no DB, no server include.
  The local base copy: `remote_manifest_state.base_root` + `remote_manifest_base` (sealed bytes by sid), written by
  `Manifest::recordRoot` in the recording transaction (a publish and `verifyRemote` both pass `RootRecord::base`), read
  by `StateStore::base()` and checked by `openBaseCopy`; a cold `Session` publishes with the copy's content as
  `PublishOptions::pending_base` (the mergePending base) instead of the head. `applying_epoch` /
  `applying_root_sha256` (`Manifest::markApplying`, cleared by recording that root) make `publish` throw
  `ApplyIncomplete`. Tests `ManifestReconcile*`, `ManifestReconcileProperty*` (test_manifest_reconcile.cpp),
  `ManifestBaseCopy.*`, DB `ManifestDbTest.*`.
- **Manifest applier, items 4-5** (design "As built: items 4 and 5"; migration 146): `verifyRemote` returns a
  `RemoteHead` and never records another writer's root; `known` advances only by an apply or an own publish. The
  server's session publishes with `apply_on_lost` (a moved head throws `HeadMoved`); `vault_manifest::Service`
  applies and republishes (`kPublishRounds` 4). `Service::applyRemote` (finish deferred entries, verify, apply) is the
  pass's remote step (`CloudEngine::refreshRemoteIndexFromManifestIfChanged`, before planning). The executor is
  `sync::vault_manifest::Applier` over `db::query::sync::ManifestApply`: per-op transaction, compare-and-set on
  `op.ours`, `markApplying` first, record with the base copy last (only when nothing was skipped), audit
  `manifest.applied`; moves/trash/deletes through `Filesystem::rename`/`remove` and `Engine::removeLocally` (a
  remote-only file moves in the rows), creates/content/attributes in rows; a local copy not yet uploaded writes only
  the index row; open files are deferred (`manifest_apply_deferred`, overridden in `Manifest::collect`); no usable
  base copy merges as a union. Tests: DB `ManifestApplyDb*` (test_manifest_apply_db.cpp),
  `VaultRecoverDb.ARestoreKeepsEachSnapshotsUid`, `ManifestVersionLogFaults.WithTheApplier*` (`Scenario::model_db`).
  A moved head is classified first (`originOf`): this server's own unrecorded root (producer node and vault id, built
  directly on `known`, hash in `publishing_roots`: every root PUT since the last record, noted before the PUT, reset to
  the recorded root by each record) is adopted by `verifyRemote`;
  one only naming this identity is `ApplyStopped`. `Service::applyRemote` is serialized per vault (`applyMutex_`). A
  head naming several writers is applied (`kCarriesForeignEnvelopes`; refused only on a `mirror` vault). Migration 147:
  other writers' envelope kids kept as references (`manifest_foreign_envelope`, named for recipients this vault's
  grants have), the pending root's base copy (`remote_manifest_pending`, `Session::adoptBuiltOn`), the recorded
  root's `writers` (a trash is purged locally only while another writer exists), and the last apply
  (`manifest_apply_report`, `ManifestApply::status`: `storage.vault.get` `manifest`, `vh vault sync info`; a stopped
  apply alerts once, `manifest_apply_stopped`, through `vault_manifest::stopAt`).
- **The writer floor** (vl-vaultfmt 0.3.0, its `docs/engine.md` "The writer floor"; design
  `vault-format-library.md` decision 7 and "As built: the writer floor"). A root's `writer_floor` (absent = 0) is the
  lowest writer revision allowed to take it in or publish over it. This server is `vault_manifest::kWriterRevision` =
  `kBaselineWriterRevision` (1) and writes no floor (`SessionHost::writerFloor` 0). A head above it stops
  `Service::applyRemote` before reconcile (`RemoteHead::above_floor`, stop reason `manifest_writer_floor`); a publish
  over a recorded root above it gets `WriterFloorRefused` before any PUT, which `Service` records and alerts as the
  same stop (`noteFloorRefused`) and `CloudEngine::publishManifestV2` turns into `SyncStalled`; a successful publish
  or apply clears it (`ManifestApply::clearStopped`, `saveReport`). Raise `kWriterRevision` only with the migration
  that stores every member of the new revision. Vectors: `design/encryption/vectors/writer_floor.json` (+ generator),
  identical to the library's (`test_vaultfmt_vectors.cpp`).
- **Two writers on one bucket** (design "As built: the mirror drill"; migrations 148, 149). Theirs' key checks are
  recomputed over the producer's vault id (`reconcile(..., SameKey)`). `Session::publishIfChanged` publishes nothing
  when the merged result equals the recorded root up to producer-specific values (`differsFromRecorded`). With another
  writer and a bucket that keeps no versions, a content edit/edit is forced to an open conflict (`Cloud::askTwoSided`).
  `Manifest::collect` takes a file's size and hash from its generation's index row. mtimes: the fs_entry trigger
  keeps an explicit `updated_at` (and any, under `set_config('vh.keep_mtime', 'on', true)`), the applier writes the
  target's mtime on moves and attributes, an opaque_v1 download keeps the row's, reconcile carries an mtime one side
  changed. Shared trash: purges remembered (`manifest_shared_purge`), deleted from the bucket by
  `Service::collectSharedOrphans` after 7 days while nothing names them. Test-only seams (test mode only):
  `VH_TEST_FAULT_DIR/crash-after-root-put`.
- **Replicated vaults, experimental** (design "As built: the join"; migration 150; `sync.replicas.experimental`):
  `ops::vault_replicas` (join = `vault_recover` in join mode, leave, replica remove), `sync::replicas` (replicated,
  refuseIfReplicated), `WritersChange` carried by every publish until a recorded root shows it
  (`remote_manifest_state.writers_change`), `manifest_writer_root` for the replica status. Through the cloud:
  `cloud_restore::start(Intent::Join)`, `cloud_storage::joinBucketKey/adoptJoinedVault/reportLeft`, the pass's
  `stepReplicas` (removed → sync off; former replicas, matched by the cloud's `node_id` → writers change),
  `reportWriterRemoved` (replica remove → `POST /v1/vaults/{uid}/replicas/unlisted`; the cloud's set stays the
  owner's), `describeReplicas` (the status's `cloud` per writer and `cloud_only`, from the cached overview),
  `removedAtCloud` (leave after the owner's removal is local only), `refreshSoon` (a cloud restore or join drops the
  cached overview). A join leaves objects no live entry names alone (`vault::recover::Options::join`).
- **`vh vault recover`** (#371, spec 03 §6.4): `vault::recover` (plan: envelopes, export, `loadForRestore` with the
  kit's checkpoint or blind, D1 `prove` against the customer's pinned attestation keys, reconciliation, `MeteredStore`
  download budget), `db::query::vault::Recover` (one transaction: vault, tree with inodes, trash, index, provider
  versions, snapshot records, keys re-sealed and re-attested with `vault_key_origin`, migration 131, grants, envelope
  rows, chain position), `ops::vault_recover` (permission/channel/step-up, `salvage_required` /
  `vault_recover_salvage`, salvage via `ops::vault_keys::salvageRecoveredVault`, reinstate, publish epoch + 1), CLI
  `vh vault recover` (kit and export read by `vh`, sent as one `client_input` bundle), ws `vault.recover` (paired
  devices). Rotation and salvage PUTs update the remote index (`CloudEngine::recordOwnUpload`).
- **Recovery recipients and KEV1 envelopes** (#370, spec 03 §5, §5.8; migration 127). `vl::keykit::kev1` and
  `vl::keykit::{RecoverySeed, Kit}` (the vl-keykit library, `subprojects/vl-keykit.wrap`, MIT, shared with Vaulthalla
  Cloud; the offline `vh-recovery` tool, `core/main/recovery.cpp`, links only it and OpenSSL). `db::query::vault::RecoveryGrants`
  (`vault_recovery_grant`: class CHECKed to `customer`; `vault_key_envelope`). `vault::envelopes`
  (`vault/RecoveryEnvelopes.*`): `put`/`record`/`discard` for one version (no request without a usable grant),
  `ensure` for every held version, `material` (D2: `not_required | recipient | export | recovery_material_missing`),
  `setStoreFactoryForTesting`. Hooks: `EncryptionManager`'s three mint paths (`commitWithEnvelopes`: envelopes PUT
  before the version is committed, a failed PUT fails the rotation), `CloudEngine::ensureRecoveryEnvelopes` at the
  start of each cloud pass (`sync::Cloud::initBins`), `requestManifestPublish`. `ops::recovery_recipients`
  (list/add/revoke; `auth::stepup::require(Keys, "vault.keys.recipients.add|revoke:<vault>")`), ws
  `vault.keys.recipients.*` (`handler::VaultKeys`), CLI `vh vault keys recipient …`, kit import through
  `ops::vault_keys::importKeys` (`ImportRequest::recovery_kit`; `candidatesFromKit`). Health
  `vaults_recovery_material_missing` (`stats::model::SystemHealth`) makes the node degraded.
- **opaque_v1 data plane** (#369, spec `design/encryption/01-provider-blind-storage.md` §4-§5; the layout of every new
  encrypting vault since #371, `vault::model::layoutForNewVault`; path-keyed fake-bucket suites pin path_v0 with
  `setNewEncryptingLayoutForTesting`, test mode only). Keys: `<vl/vaultfmt/ObjectKeys.hpp>` (`vl::vaultfmt::keys`: `o/<file uid>`, `.vaulthalla/{layout.json,root,seg/<sid>,key/<kid>}`,
  classify Content/Metadata/Foreign, `partSizeFor` = max(5 MiB, ceil(size/10,000)) whole MiB, used by every layout).
  `CloudEngine::objectKeyOf(File|Trashed)` / `objectKeyForPath` (opaque: the uid via
  `db::query::sync::ObjectIdentity`: live file, else the newest trashed one) replace `stripLeadingSlash(path)`; path
  APIs (`headRemoteObject`, `downloadToBuffer`, `removeRemotely`, `purge`) resolve through it, key APIs are
  `headObjectKey[Strict]` and `removeRemoteKey`. Request rules: `s3::Controller::setOpaqueLayout` (set from the
  vault's layout by `CloudEngine::applyLayoutPolicy`) makes `enforceRequestPolicy` refuse, before metering, any
  non-allowlisted key or list prefix (only "", `o/`, `.vaulthalla/…`, one allowlisted key), `x-amz-meta-*`, content
  headers other than octet-stream, metadata rewrites, and copies onto another key; only `ScopedForeignObjectRead`
  lets a GET/HEAD name a foreign key (`importForeignObject`). Uploads send no metadata (`uploadOptionsFor`), check the
  header names the file (`requireOpaqueHeader`) and record the PUT's ETag/version on the file (index row, upload
  baseline, manifest object ref). Reads bind the file uid (`openOpaqueObject`; header-named generation when the row
  has none; hydrate is one GET; `Engine::openLocalReader` binds it too). Sync (`sync::Cloud::keyByObjectUid`): maps
  keyed `/o/<uid>`, remote rows bound to the file with that uid (path, id), `sameOpaqueGeneration` in the planner,
  orphans and trashed files' objects excluded, no `EnsureDirectories`; a full listing is `listOpaqueBucket` (no
  prefix; foreign keys to `handleForeignObjects`). Scoped passes resolve `/o/<uid>` through `ObjectIdentity`; the
  applier never HEADs or indexes a foreign key and skips `o/` objects no file has. Backlog keys, `file_versions
  .upstream_key` and provider-version keys are `o/<uid>`; `recovery::provider::versions::{objectKeyOf,
  liveObjectKeyOf, directoryPrefixOf, vaultPathOf, keyUnder}(engine, …)` map them to paths (directories: `o/`
  filtered by the paths the DB gives uids; a uid no row has → `/Recovered/<uid>`), and an opaque transfer restore
  re-seals into the destination's uid. Copies re-seal (new uid, new generation). path_v0/transparent unchanged.
- **Bucket layout migration path_v0 → opaque_v1** (#373; spec 01 §6 as simplified on the issue 2026-11-06: no
  soak/rollback, no encrypt_upstream toggling). `vault::layout` (`vault/LayoutMigration.hpp`: states copying →
  verifying → cut_over → cleanup → cleanup_blocked | complete, failed = still path_v0 and resumable), run by
  `vault::LayoutMigrationService` (polls `vault_layout_migration`, migration 133; never starts a vault itself), catalog
  `db::query::vault::LayoutMigration` (items = the inventory; one cutover transaction), ops `ops::vault_layout` (CLI `vh
  vault migrate-layout`, ws `vault.layout.*`, keys / data.destroy step-up). The run holds the sync pass lease from the
  inventory to the cutover; writes only `o/<uid>` (`CloudEngine::putMigratedObject` / `deleteMigratedObject`: no
  metadata, own-write intents, the recovery hook records the version), never a legacy key; reads legacy versions with
  If-Match; gcm0 local copies convert through `conversion::convertLiveFile` first; proof of storage = MD5 ETag
  (`s3EtagOf`) else read-back; cutover = `CloudEngine::adoptStorageLayout`, then manifest publish +
  `loadManifestFromBucket` check (`manifest_verified_at`, cleanup waits for it). Cleanup deletes inventoried versions
  by id under `s3::ScopedLegacyLayoutCleanup` (HEAD/DELETE of legacy keys only), Object Lock read first, refusals kept
  as `cleanup_blocked`; `complete` only after a complete listing with nothing legacy. path_v0 listings and the event
  applier ignore `o/<uid>` objects; `ObjectIdentity::pathOfUid` falls back to the migrated legacy key. Health
  `legacy_content` (#376 readiness). Tests `LayoutMigration*`, harness `vhh drill migrate`, live
  `LiveR2.LayoutMigrationPrimitives`.
- **Attach a remote to a local vault** (design/storage/attach-remote.md; BYOS only, no cloud code). `vault::remote`
  (`vault/RemoteAttach.hpp`: states preparing → uploading → catching_up → verifying → cutover → done; failed = still
  local and resumable by starting it again with the same key and bucket; aborted), run by
  `vault::RemoteAttachService` (polls `vault_remote_attach`, migration 138; never starts a vault itself; also runs
  requested aborts, retried every 10 min, and starts a queued key rotation once the attach ended), catalog
  `db::query::vault::RemoteAttach` (items = everything the attach wrote to the bucket, the only list an abort or the
  orphan cleanup deletes from; the reservation is a partial unique index on `(api_key_id, bucket)`; one cutover
  transaction), ops `ops::vault_remote` (CLI `vh vault remote attach|status|abort`, ws `vault.remote.*`, keys
  step-up on attach and abort, `--confirm <vault name>` for abort). **The vault has no CloudEngine until the cutover:**
  the run works through its own `s3::Controller` for the reserved bucket (`remote::controllerFor`, opaque_v1 request
  rules from the first request, the vault's usage ledger; `setControllerFactoryForTesting`) and the vault's live local
  `Engine`, so FUSE, the console, shares and the gateway are untouched. Content = a hard link of the backing file
  (already VHF1: a byte copy, never a re-seal), the generation read from the linked bytes' header and authenticated
  against the vault and the file's uid, PUT to `o/<uid>`, proof = MD5 ETag (`layout::s3EtagOf`) else read-back.
  Every item row is written before its PUT, so any unrecorded version at a recorded key is a stray of an interrupted
  PUT (`reconcile`: recorded as stale, then deleted by version id); anything else in the bucket refuses
  (`bucket_not_empty`). `versioned` (ListObjectVersions and deletes by version id) is false only for Cloudflare R2
  (ListObjectsV2, deletes by key after a HEAD shows the recorded ETag). Verification: a second complete listing equal
  to the items, a read-back sample, every envelope inspected, then the manifest v2 published with
  `vl::vaultfmt::manifest::publish` on `db::query::sync::Manifest::collect(vaultId, CollectOptions{staged, sync_strategy})`
  (the staged objects stand in for the remote index, which only the cutover writes) and loaded back from the bucket;
  the published root is kept on the row (`manifest` JSON) and recorded by the cutover (`Manifest::recordRoot(txn,…)`).
  Cutover (`RemoteAttach::cutover`, vault row locked): `vault.type = 's3'`, the `s3` row (encrypting, opaque_v1,
  `manifest_publish` + `bucket_probe` from the attach row), `fsync` → `rsync` with `vaults.s3` defaults and default
  budgets, `remote_object_index` + `sync_file_baseline` at the sent generation (a file changed since is an ordinary
  pending upload), `vault_key_envelope.envelope` cleared, `s3_gateway_bucket.mode` local → remote_cache, a known
  unbound `upstream_bucket` row bound. After commit, under the pass lease: `storage::Manager::reloadEngine` +
  `sync::Controller::refreshEngines`, `recovery::provider::noteOwnWrite` per version, orphan deletes (objects of
  files deleted between upload and cutover), then the first pass (`sync_event` after `cutover_at`) → done. Pricing
  goes through `pricing::PriceSubject` (no engine), operation `remote_attach`. Pre-attach local versions keep
  `upstream_state = 'none'`. Not built: re-attaching the vault's own earlier bucket, an `OperationSpec` (so no Tier B
  oracle entry). Health `remote_attach_failed` (degraded), `remote_attaches_unfinished`; `storage.vault.get` adds
  `remote` (`ops::vault_remote::remoteSummary`: none, attaching:<state>, attached, detaching:<state>). Tests
  `RemoteAttach*` (`test_remote_attach.cpp`), parity `VaultRemoteParityTest.*`.
- **Detach a remote from a vault** (attach-remote.md "The reverse"; `vault::remote::detach`, `vault/RemoteDetach.hpp`,
  migration 139 `vault_remote_detach` + `vault_remote_detach_item`, catalog `db::query::vault::RemoteDetach`). States
  preparing → hydrating → verifying → cutover → done; failed = still an S3 vault, resumed by starting it again;
  aborted. Run by the same `RemoteAttachService` (second loop over the detach rows). The vault's live CloudEngine
  stays until the cutover (it syncs as before). Per live file with content: `CloudEngine::hydrate` when the backing
  file is missing (price gate, metered, authenticated), then `content::verifyFd` of the backing file against the
  catalog's generation, key version and the file's uid; an item records the verified generation. Envelopes: every
  `vault_key_envelope` row without bytes is read from the bucket (`ManifestStore` over the engine's controller),
  checked (`kev1::kid` = name, `kev1::inspect` vault uid, key version, grant's recipient) and stored with
  `RemoteAttach::storeEnvelopeBytes`; an envelope missing from the bucket fails the detach. The final check, the
  cutover transaction and the engine swap run under one hold of the vault's pass lease (a running sync pass or a
  rotation → `busy`, retried; anything that moved → back to hydrating). `RemoteDetach::cutover` refuses while a live
  file has no verified item at its current IV or any envelope row has NULL bytes; then vault.type local, `s3`,
  `rsync`, `remote_object_index`, `sync_file_baseline`, `remote_manifest_{state,root,gc}` rows deleted, `fsync`
  inserted, gateway mode → local, `upstream_bucket.vault_id` → NULL (ownership kept), pending `file_versions`
  backlog → skipped (`upstream_error = 'detached'`), `vault_recovery_policy` provider_versioning → local_snapshots,
  the attach row and items deleted. The bucket is never written to or deleted from. Abort clears only envelope bytes
  the detach copied, and only when the bucket's copy reads back equal. Preconditions (`detach::requireVaultReady`):
  not_s3, attach_running, layout_migration_running, key_rotation_running, key_salvage_running, legacy_content,
  key_version_missing, event_sync_active, sync_conflicts_open. Health `remote_detach_failed` (degraded),
  `remote_detaches_unfinished`. Tests `RemoteDetach*` (`test_remote_detach.cpp`), parity
  `VaultRemoteParityTest.DetachAndItsAbort*`. Console: `features/vaults/settings/RemoteStoragePanel.tsx` (lazy).
- **Remote access gate** (managed-remotes.md "Entitlement states and the access gate", work item 4;
  `storage/RemoteAccess.hpp`, migration 140 `vault_remote_access`, catalog `db::query::vault::RemoteAccess`).
  `full | read_only | none` per S3 vault, no row = full. Held in memory (`remote_access::mode`, a shared-locked map,
  never the database): `CloudEngine`'s constructors `refresh` it, `storage::Manager::initStorageEngines` `clear`s it
  first, `remote_access::set(vaultId, mode, reason, setBy)` writes row + memory + audit `vault.remote.access` and, back
  to full, `sync::Controller::runNow` (a skipped pass, like any stalled one, isn't rescheduled). Enforcement:
  `sync::Cloud::operator()` throws `SyncStalled("skipped: remote read-only|unavailable (reason)")` right after
  `startTask` (no request made); `CloudEngine::upload` (both), `purge` (both, before the local removal),
  `removeRemoteKey`, `removeRemotely(Trashed)`, `publishRemoteIndexManifest`, `ensureRecoveryEnvelopes` call
  `requireWrite`; `hydrate` refuses a remote-only file under none with `ContentUnavailable("remote_unavailable…")`;
  last line `s3::Controller::recordRequest` (beside the protection guard) for any controller with `usageVault() != 0`:
  PUT/COPY/DELETE need full, LIST/HEAD/GET not none (`remote_access::Restricted`, codes `remote_read_only`,
  `remote_unavailable`). `vh vault keys rotate` answers "waits" while restricted. Operator setter `vh vault remote
  access <vault> --set <mode> [--reason]` (`ops::vault_remote::setAccess`, set_by `user:<name>`; the managed-storage
  service is to call `remote_access::set` with `system:<service>`). Status: `vault.remote.status` `access`; health
  `vault_remote_restricted` / `vault_remote_unavailable` (degraded). A detach deletes the row (`forget`). Tests
  `RemoteAccess*` (`test_remote_access.cpp`).
- **Local-vault recovery envelopes** (attach-remote open question 2): `vault::envelopes::storeFor` returns a
  database-backed `ObjectStore` for a local vault (bytes in `vault_key_envelope.envelope`, written in the transaction
  that records the envelope; `KeyEnvelope::envelope`), so `ops::recovery_recipients::add`, rotation, salvage and
  `vh vault keys import --recovery-kit` work for local vaults, and `ops::cloud_recovery::enroll` sends a local
  vault's envelopes from its rows.
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
- **The mount never forks.** `platform::mount::mountWithHelper` starts `fusermount3 -o rw,nosuid,nodev,allow_other,
  auto_unmount,subtype=vaulthalla-fuse -- <mount>` (the command libfuse runs) with `posix_spawn`, its socket as fd 3
  (`_FUSE_COMMFD`) and every other descriptor closed, receives `/dev/fuse` over it and hands libfuse `/dev/fd/<n>`.
  The helper stays (auto_unmount) until its socket closes (`releaseHelper` at the loop's end, or the daemon dying),
  then unmounts. Why: libfuse forks and calls `setenv` in the child, which allocates; in this multithreaded process a
  sanitizer build's allocator (GCC 14's libasan has no fork handling) could be locked by another thread at the fork,
  so the child hung before exec, the mount never came, and the child kept the daemon's listening sockets (the wave 3
  drill's "daemon not ready within 90s" and EADDRINUSE on restart). glibc's malloc is fork-safe, so packaged builds
  never hung, but the child was outside POSIX's async-signal-safe rule there too. libfuse's own unmount fork is gone
  with it (a `/dev/fd` session has no mountpoint; `platform::mount::detach` and the helper unmount). Other children:
  the preview runner uses `_Fork` with everything prepared before it; `gpg` (key export) builds its argv before
  fork; `std::system` and `posix_spawn` users allocate nothing in a child (glibc's `system` is posix_spawn).
- **FUSE ops still hit the DB for content and metadata writes**, but no longer for identity: the caller (by uid), its
  groups and the vault owner come from `identities::Manager` in memory (see Identities below). If the DB pool wedges,
  writes, opens of uncached entries and anything else that queries still hang. See P0 in `production-hardening.md`.
- HTTP uploads (Linux, `mount` staging) stage `.upload-http-<id>-<file>.part` next to the target *through FUSE*, then
  seal it into the target with `Filesystem::createFile{source}` (`http/upload/Coordinator.cpp`, and
  `.upload-http-content-*.part` for `PUT /upload/content`; both through `staging::Body`, `http/upload/Staging.hpp`).
  This is intentional. Don't move staging out of
  FUSE to reduce sync churn; fix duplicate sync triggers or backing-path resolution instead.
- **Resumable uploads deliberately do not stage through FUSE** (`<backing>/.upload-spool/<upload id>/`, 0700,
  ciphertext only, outside the mount and every vault tree; nothing in FUSE, snapshots, versions, archives, copy or
  sync walks it). The rule above is about the `.upload-http-*` lanes. A resumable file receives many parts
  that must each be durable before they are acknowledged; through FUSE every `fsync` re-seals the whole working
  copy (`fuse/Bridge.cpp` fsync → `WorkingCopies::persist`), so per-part durability would cost O(n²) bytes of
  encryption and I/O for an n-part file, and a part acknowledged as durable must survive a restart, which a working
  copy (process-key ciphertext) does not.
- **Vault bytes are always ciphertext at rest; the mount is the decrypting view (#173).** Every backing file (local
  vaults and cloud vaults' local copies) is VHF1 (#367; files written before it: AES-256-GCM body‖16-byte tag), its
  generation id and key version in `files`, and
  `files.size_bytes` is the *plaintext* size. Derived preview artifacts are encrypted too (`VHDERIV1`, see
  "Byte-serving spine"); the legacy plaintext `<cacheRoot>/thumbnails` and `<cacheRoot>/files` trees are deleted by
  `preview::cache::Store::sweep` at startup. The HTTP lanes never write plaintext. FUSE `open` decrypts into a
  per-inode working copy
  (`fuse/WorkingCopies`, a `crypto::ScratchFile` under `<backing>/.fuse-working`, shared by every handle on the
  inode); reads and writes go to it; `flush` (so `close(2)` returns with the change on disk), `fsync` and the last
  `release` seal it back (new IV, fsynced temp + rename). `setattr` size works on the copy. A copy whose last seal
  fails stays registered as *unsaved* (moved to `.fuse-working/unsaved/`): `isOpen` stays true, reopening shows it,
  and the seal is retried every 60 s (`WorkingCopies::startRetrying`, run by the FUSE service), on the next
  flush/fsync/release and at FUSE stop (`shutdown()`, which logs and deletes what is still unsaved); a file deleted
  meanwhile is restored as a new file where it was (`hooks.recover`). Everything under `.fuse-working` is deleted at
  mount (`clearStale`, logging how many unsaved changes a crash lost); the pre-#328 `.fuse-plaintext/unsaved/`
  plaintext is kept for the operator with a warning, the rest of that directory is deleted. A same-vault rename only
  moves the bytes (no re-encryption).
- **Plaintext in use is never on disk (#328).** FUSE working copies, private HTTP upload staging
  (`<backing>/.upload-staging`) and `vh fs put` staging (`.cli-staging`) are `crypto::ScratchFile`s: 64 KiB blocks,
  each `nonce(24, fresh per write) ‖ XChaCha20-Poly1305 ciphertext ‖ tag(16)` at `i * (64 KiB + 40)`, AAD = a random
  per-file id ‖ BE64(i). The key (`ScratchFile::processKey()`, a `SecretKey`, mlocked) is random per process and never
  persisted; the file id, logical size and each block's latest nonce live only in the object, so a flipped byte,
  moved/foreign/replayed block or cut-off file fails closed (`ScratchFile::Tampered` → EIO). Holes are written as
  encrypted zeros. One write block and one read block are cached in locked memory. The file is unlinked with its
  object. A crash leaves only ciphertext no later process can read; each owner sweeps it at startup. Mount staging
  (`.upload-http-*.part` through FUSE) lands in a working copy, then in a sealed vault file: never plaintext either.
  S3 gateway request bodies are scratch files too (`<backing>/.s3-request-body`, #345).
- **S3 multipart parts are sealed under the vault key (#345, migration 118, `protocols/s3/PartCipher.{hpp,cpp}`).**
  Parts must survive restarts (a client resumes an upload days later), so not the process key. Each part is one
  AES-256-GCM message (body ‖ tag) in `<backing>/.8f3a9c1d6e2b4f70/<parts dir id>/<n>.<16 hex>`
  (`VH_S3_GATEWAY_MULTIPART_PARTS_DIRNAME`) under the vault's current key, fresh random IV per write, AAD =
  `"vaulthalla/s3-multipart-part/v1" ‖ 0 ‖ BE32(vault) ‖ BE32(len) ‖ upload id ‖ BE32(part) ‖ BE64(plaintext size)`;
  `s3_gateway_multipart_part.encryption_iv`/`key_version` record it. Every write is a new file and the row switches to
  it in one transaction (`upsertMultipartPart` returns the replaced path, then deleted), so a flipped byte, a part
  moved to another number/upload/vault, an older copy and a cut-off file all fail closed. ETag and `size_bytes` stay
  the plaintext's MD5 and length. Complete (`part_cipher::open`) authenticates every part first (no vault write if one
  fails: `InvalidPart`, upload and parts kept, the client re-uploads that part), then streams them into
  `putObjectFromSource`, re-checking each tag as it is read: no plaintext concatenation file. Parts sealed before a key
  rotation decrypt with the retained version (`historicalKeySnapshot`), so an in-flight upload survives a rotation and
  is resealed under the current key. Startup (`protocols::s3::sweepStagingAtStartup`, `main.cpp` `wireStorage`, gateway
  enabled or not) deletes `.s3-request-body` and the pre-#345 plaintext `<backing>/s3-request-body`, seals pre-#345
  plaintext parts (rows with no IV) after checking size and MD5 and then deletes the plaintext (a part that no longer
  matches is left as is, and Complete refuses it), and removes files no open upload's rows reference (a crashed
  Complete's plaintext `.complete-object`) and directories of finished uploads; Complete seals any plaintext part the
  sweep couldn't reach. Tests: `S3GatewayPartCipher*`, `S3GatewayRequestBodyStaging*`, `S3GatewayDbTest.{MultipartParts
  AreSealedAtRest*,MultipartUploadSurvivesARestart,TamperedOrSwappedPart*,LegacyPlaintextParts*,StagedRequestBodies*}`.
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
  refused (EINVAL).
- **Move and rename into another folder need what a create there needs (#256).** FUSE rename and ws `fs.entry.move` /
  `fs.entry.rename` used to check only Move/Rename on the source (plus Delete on a replaced target). Now, when the
  destination folder differs from the source's, the new path needs Touch (a folder) or Write (a file or symlink), the
  rule of mkdir/create/upload and of `fs.entry.copy`'s per-entry authorizer (`rbac::fs::placement::createAction`), and a
  folder's contents are each checked at their new path (`firstRefusedDescendant`). FUSE answers a refusal like a create
  in that folder (`resolver::deniedErrno`: ENOENT when the caller can't see it, EACCES when it can; EACCES for a
  refused descendant); ws answers `denied` (the check is `ops::fs::move/rename`'s), checked before the endpoint
  lookups, so a refused caller gets no not_found/conflict about the destination. A rename within its own folder is
  unchanged (source check only), and across vaults FUSE still answers EXDEV with nothing authorized.
  `storage::Engine::move/rename` and `Filesystem::rename` stay non-authorizing primitives; their callers are FUSE,
  `ops::fs` and the ws upload commit (`ops::fs::commitStaged`: a same-folder rename of the staged part after Write on
  the target). `FsMoveAuthzDbTest`, Tier A "Move Into
  Unwritable Folder". `Filesystem::repairAtRest` (first sync pass per vault per start) seals plaintext left by older
  builds and corrects ciphertext-length sizes.
- **No key is minted over sealed data (`EncryptionManager::load_key`, `key-backup.md`).** A vault without a
  `vault_keys` row gets a fresh key only when nothing is sealed under any key (no files row with an IV, recovery blob,
  live provider version or encrypted remote index entry). Otherwise, and when a needed row doesn't unseal or a version
  live files (or a pending rotation) need isn't held, `load_key` throws `vault::KeyUnavailable{key_missing |
  key_unsealable | version_missing}` naming `vh vault keys import`; the engine doesn't start, `storage::Manager`
  records it (`unavailableVaults()`), and `stats.system.health` (`vaults_unavailable`) / `vh status` turn degraded.
  Versions a key salvage names (`vault_key_salvage`) don't block it. Every key version carries recorded provenance
  (key check + this node's Ed25519 attestation, migration 113), and import restores only attested versions the
  records reference; anything else is salvaged under a fresh key, never stored (`key-backup.md`, revision 3).
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
- **Listings hide what Lookup hides, on every surface (#255).** FUSE readdir, ws `fs.dir.list` / `fs.list` (outside
  share mode) and `vh fs ls` all list a folder through `rbac::fs::visibility::visibleChildren` (`rbac/fs/Visibility.hpp`):
  each child must pass the evaluator's Lookup. ws used to check only List on the folder and return every child. The
  fast path (no per-entry check) is `seesWholeSubtree`: super admin, vault owner (FUSE's long-standing rule), or no
  override of the caller's can reach the folder's subtree (`Evaluator::overridesMayAffectListing`, now
  `glob::Matcher::mayMatchWithin`: a wildcard reaching in from above, `/**/x` or `/docs/*/x`, counts; it used to be
  missed, so readdir listed names lookup hid) *and* one probe entry per kind (a stand-in file and folder inside it)
  passes Lookup, since without overrides the base permissions judge every entry there by kind alone (a role that lists
  folders but may neither preview nor download sees no files). ws also recounts `size_bytes` / `file_count` /
  `subdirectory_count` of a listed child folder whose subtree holds hidden entries (`visibleTotals`: one cached subtree
  listing, walked through visible folders) and the listed folder's own `size_bytes`; otherwise the stored totals stand.
  `fs.metadata` of a folder recounts its `size_bytes` the same way (#269; its `entry` has the base members only, no
  counts). FUSE getattr and setattr of a folder report the visible
  `size_bytes` (`applyVisibleFolderSize` in `fuse/Bridge.cpp`); lookup's attributes withhold it (0) for such a caller
  instead of walking a subtree on every path walk (attr timeouts are 0, so stat(2) always comes from getattr; only
  `statx(AT_STATX_DONT_SYNC)` sees lookup's). The mount root's size is a super admin's only. Proof:
  `FsListVisibilityDbTest`, Tier A "List Visibility Parity" (readdir == fs.dir.list, and folder stat == fs.metadata ==
  fs.dir.list, for the same account). Share-mode listings (`shareEntryJson`) keep the share's own model.
- **No kernel metadata caching (#183).** The kernel dentry/attr cache is shared across uids and the mount has no
  `default_permissions`, so anything cached is answered for any caller without the daemon. Every reply uses
  `kKernelMetadataTimeout` = 0 (Bridge.cpp; pinned by `tools/contracts/test_fuse_cache_timeout_contract.py`), so each
  lookup/getattr is authorized for the calling uid. Before, a denied uid could `stat` a path another uid had just
  resolved (up to 60 s after a create). Size coherence doesn't need kernel caching: `statFromEntry` reports an open
  working copy's size. The harness passing "override allow: read secret" had relied on that cache: a file Lookup
  maps to Preview, so a download-only grant was hidden; `Evaluator::resolveStage` now lets a denied file Lookup fall
  back to the Read decision (seeing a file is implied by being allowed to download it).

## Database

- PostgreSQL via libpqxx. The schema is `deploy/psql/000…159_*.sql`, applied in order (all in ONE transaction by `core/seed/include/SqlDeployer.hpp`) and installed to `/usr/share/vaulthalla/psql`.
  New migrations take the next number and must be idempotent against upgraded installs. SqlDeployer records sha256(raw bytes)
  per file and refuses to start on a mismatch, so **never edit a shipped migration**: 020/060/082 were edited in place and
  bricked upgrades (1.5.x→1.6.x crash loop on 060). Reviewed exceptions live in `kHistoricalMigrationChecksums` (accepted, recorded
  hash rewritten to current, not re-run; a forward migration owns the delta). `core/seed/shipped_migrations.lock` pins every hash;
  `tools/contracts/test_migration_checksums_contract.py` enforces it (plus every local v* tag).
- `core/include/db/DBPool.hpp` is a pool of `database.pool_size` connections (default 24, kept within 4..256 by
  `Transactions::initFromConfig`; tests use 4) handed out as RAII `DBPool::Lease`s (FIFO) that always return the slot.
  Never acquire a second lease while holding one (a `Transactions` call inside another's lambda): with the pool in
  use, every holder waits on the others until the 30 s timeout. Row mappers that read more take the caller's
  transaction (`files_from_pq_res(res, txn)`, `Entry::collectParentChain(txn, id)`). A dead connection is replaced on
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
key provider, secrets · `db` · `email` providers (Resend, SES v2 signed with `vl::sigv4::sign`; `SesSigning.hpp`'s `detail::signAwsV4` is only the goldens' reference) · `fs` · `fuse` · `identities` users/groups ·
`log` spdlog registries + rotation · `notifications` operator emails · `preview` plans (`Plan.cpp`), in-memory
renders (`render/`: pdfium, turbojpeg, stb), the encrypted derived cache (`cache/Store.cpp`) and the
converter-helper runner/queue (`derive/`, below) · `protocols` · `rbac` roles/permissions/resolver/actor · `runtime` Manager · `share` link
sharing · `stats` dashboard telemetry + snapshots · `storage` local + S3 backends, remote index · `sync`
controller, strategies `cache|sync|mirror`, cost guardrails · `vault` vault model, slugs, FUSE names ·
`recovery` file recovery: local snapshots/versions, provider versioning, usage ledger, cost model (below) ·
`ops` actor-authorized operations shared by the CLI and ws handlers (below) · `device` paired devices: protocol
crypto, server identity, in-memory pairing, handshake authorization (the listener itself is `protocols/device`) ·
`peer` linked servers: card and transcript crypto, link requests, keys, the link service (see "Linked servers").

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
code (the web asks and resends with `accept_encryption_waiver`; the contract names the field per code in
`confirmations`); a non-`ops::Error` fault has no code. The fs/share ws handlers (and share `Manager`,
`TargetResolver`, `PrincipalResolver`) throw ops types for refusals too, and their handlers turn malformed-payload
errors (`std::invalid_argument`, JSON access) into `ops::Invalid` via `handler/RequestErrors.hpp`; HTTP share lanes
still classify by message, unchanged. Handler-level
gates (settings/email/pricing admin checks, share upload scope) throw `ops::Denied` so they carry `denied`; every
`stats.*` command authorizes through `ops::stats` (below). Rules: RBAC for an operation lives in the op, never in the frontend as well; code beneath
`ops::` (managers, `db::query`) never authorizes; internal callers use those primitives directly, not ops; no
registry, base class or transport abstraction. Parity is proven by `test_ops_parity_groups.cpp`, which runs each
group operation through both surfaces for every seeded admin role and compares verdicts and DB state.
Migrated families (each with `test_ops_parity_<family>.cpp`): `groups`, `roles`, `api_keys`, `vaults` (lifecycle,
safe deletion/restore, sync policy, accessible list), `users`, `s3_gateway` (credentials, grants, buckets, credential budgets), `pricing` (price budget
policies), `config` (every settings write: one validation, one apply step that restarts the S3 gateway when
`s3_gateway.enabled` changes), `stats` (authorization only, ws-only: there is no `vh` stats command; `vh status`
is deliberately ungated, see Stats below), `conflicts` (sync conflicts, #187: ws `sync.conflicts.*`, `vh sync resolve` /
`vh resolve`, the HTTP `/download/conflict` lane's authorization), `upstream` (S3/R2 bucket administration and event
sync, #237/#96: ws `upstream.*`, `vh upstream …`; see `upstream-control-plane.md`), `recovery` (file recovery: ws `recovery.*` / `vault.recovery.*`, `vh snapshot|recovery …`, `vh vault recovery …`; see `recovery.md`), `devices` (paired devices: ws `device.*`, `vh device …`; see "Device listener
and pairing"), `peers` (linked servers: ws `peer.*`, `vh peer …`; see "Linked servers"), `mirrors` (starting a mirror: ws `mirror.*`, `vh mirror …`; see "Starting a mirror"), `vault_keys` (key backup and restoration: ws `vault.keys.status|export|export.confirm|import`, `vh vault keys
status|export|import`; key material only through the CLI or a paired device, D4; see `key-backup.md`), `vault_storage`
(the bucket write-capability probe, spec 06 §7: ws `vault.storage.probe`, `vh vault storage probe`; the vault's admin
Edit permission; audited `vault.storage.probe`; agent-available (effect write: it writes and deletes only its own
`.vaulthalla/probe/` versions, no key material); see `upstream-control-plane.md`), `vault_remote` (attach a remote
to a local vault and detach it again: ws `vault.remote.attach|detach|status|abort`, `vh vault remote
attach|detach|status|abort`; attach, detach and abort need the vault's admin Edit + sync config Edit + the
encryption-key Rotate permission (attach also the API key's Consume) and a keys step-up; status the vault's admin
View; audited `vault.remote.attach|detach|abort`; `vault remote attach|detach` are MCP-excluded and refuse under
`AgentCallScope`). Still per-surface: the ws-only
pricing preflight/override/notification endpoints, email test-send/history, `vh vault keys inspect|rotate`, sync
diagnostics, and lifecycle commands (`setup`, `teardown`, `secrets`).

**`ops::fs` (file operations, `ops/Fs.hpp`; mirror phase 2, `design/peers/mirror.md`).** mkdir, move, rename, copy,
remove (files to the trash, folders and symlinks deleted: `Filesystem::remove`), the ws upload's `authorizeUpload` /
`commitStaged`, and `commitSealed` (a file from bytes a `SealedWriter` already sealed: new, or a replacement of a named
base generation through `expected_source_id`). Each op takes the `Actor`, the vault id and vault-relative paths, and
does inside it the filesystem permission check, the name-clash handling, the mutation through `Filesystem`/`Engine`,
the `operations` row (move, rename, copy only, as before), the audit event (`fs.mkdir|move|rename|copy|delete`, by entry
id; `fs.commit` for `commitSealed`) and the early sync pass. Refusals: `Denied`, `NotFound`, `Conflict` (a taken
name), `Invalid` (into itself), and `ops::fs::ContentConflict` (a `Conflict`: the base generation is gone). The vault's RBAC
refuses an action on a missing entry, so a missing source (or a replacement whose file is gone) is `Denied` for any
account the check applies to, and NotFound/ContentConflict only for one it passes (the super admin). Only the ws
`fs.*` handlers (`handler/fs/Storage.cpp`, `Upload.cpp`) call it; they keep parsing, envelopes and upload-session
bookkeeping. The HTTP lanes, text save, `vh fs put`, shares, the S3 gateway and FUSE keep their own paths to
`Filesystem` until each is lifted. The only space check on these ops is the one `Filesystem::copy` makes (-ENOSPC);
`commitSealed` checks none (the HTTP lanes check when an upload begins). Inside `vh::ops`, `fs::` now names this
namespace: write `vh::fs::` for the filesystem layer (and `vh::audit::`, `vh::config::`, `vh::recovery::`, which
`vh::ops` also has). `OpsFsDbTest` (`test_ops_fs.cpp`) runs every op for a constructed `Actor` with no session.

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
- **Accessible vaults** (`ops::vaults::listAccessible`; ws `storage.vault.accessible.list`, `vh vault list
  --accessible`, MCP `vaults_accessible_list`; `VaultAccessParityTest`): `list` (storage.vault.list, `vh vault list`)
  follows the admin role's `admin.vaults.<scope>.view` only, so an owner or vault-role holder without it sees nothing
  there; this list answers "where can I go" and is deliberately separate (global admin policies on others' vaults are
  no local role either). Candidates: `Vault::listLiveVaults()` (one unpaginated read; `listVaults` stops at a
  100-row page, which is why every "all vaults" caller uses `listLiveVaults`). Per vault, with one `authz()` view:
  `browse` = `rbac::resolver::Vault::has<FilesystemAction>(List, path = engine->vaultPathToFusePath("/"))` (exactly
  fs.dir.list `/`), `manage` = `Admin::has<VaultPermissions>(View)` (exactly storage.vault.get); no engine → neither.
  `via` (in order): owner; vault_role / group_role (an assignment in the user's or a live group's `roles.vaults`,
  whatever it grants); admin_policy (not super admin, and manage, or browse with no vault role, i.e. the evaluator's
  globals stage decided); super_admin. Listed iff `via` is non-empty, so an unprivileged owner is listed with neither
  flag (owning grants nothing by itself) and a non-authorizing account gets `[]`. Probing runs under
  `QuietFilesystemDenials` (no auth warning per denied vault). The row is a summary (`toJson`, model
  AccessibleVault): no mount_point, bucket or key; those stay behind manage in storage.vault.get.
- **S3 gateway:** the scope rule that was `CredentialManager::validateScopeMutation` is `requireScopeMutation` in ops;
  `CredentialManager` and `db::query::s3::Gateway` are trusted primitives. Vault names resolve owner-scoped or uniquely,
  never to the first match. Overrides need an explicit effect and pattern. Remote-cache buckets are created through
  `ops::vaults::create` (Consume, waiver) and rolled back if the bind fails. The gateway's own CreateBucket
  (`ObjectStore::createBucket(auth)`) is a surface too: it resolves an upstream profile and calls
  `ops::s3_gateway::createProfileBucket` (upstream-control-plane.md, "S3 gateway upstream profiles"); with no profile
  it makes a local vault as before.
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

- **Audit trail (#323, migration 117).** Everything written to `log::Registry::audit()` also enters the hash-chained
  `audit_event` table through `audit::makeChainSink()` → `audit::Trail` (an `AsyncService`, first to start and last to
  stop). Writers never touch the DB: the sink only queues (bounded; overflow becomes one `audit.gap` event). Use
  `audit::record(Event, message)` (or `audit::OnSuccess` for multi-return ops) for new events: a dotted `action`, the
  actor, `vault_id`/`entry_id` by id, never a file name or path. Inside `vh::ops`, spell it `vh::audit::` (`ops::audit` is
  the reader). The chain layout is pinned in `audit/Chain.hpp` and mirrored by `tools/audit/verify_export.py` (shared
  vector). Heads are signed with the node attestation key under the `vh-audit-head-v1` domain
  (`vault::attestation::signNodeMessage`); the tables are append-only except `vh_audit_purge_before`.

**Filesystem RBAC paths, FS cache and account deletion** (#178–#180, `VaultLifecycleRegressionTest`)
- `rbac::resolver::vault::Context::path` (and `fs::policy::Request::path`) is a **FUSE** path. Callers holding a vault
  path convert it with `engine->vaultPathToFusePath()` first; `share::Manager` once didn't, so only share root `/`
  ever passed and a vault path equal to another vault's FUSE root resolved to that vault. The evaluator refuses an
  entry whose `vault_id` differs from the request's vault (`EntryVaultMismatch`).
- **Per-scope vault permissions use one rule** (`rbac::resolver::vaultScope`, `rbac/resolver/VaultScope.hpp`): the
  actor's own vault is `self`, a vault whose owner is `User::isAdmin()` is `admin`, any other is `user`. It picks the
  scope for the admin role's `admin.vaults.<scope>` (`resolver::Admin`), the global vault policy's sync/role bits
  (`resolver::Vault::grantedByGlobals`), the filesystem evaluator's globals stage (`Evaluator::evaluate` step 3) and
  the listing-override check (`rbac::fs::visibility`). The evaluator used to loop self, admin, user, but a stage always decides, so the
  `self` bits answered for every vault (fixed 2026-10-22; `VaultScopeRbacTest` compares every action on a file and a
  directory with the evaluator applied to exactly the expected scope, plus ws, `vh fs ls`, the access layer and the
  accessible list). Seeded presets are identical in every scope, so they never showed it; an unknown owner grants
  nothing from the globals.
- The FS cache is keyed by FUSE path and can only re-hydrate a vault root through `mkVault` (or the rename path in
  `storage::Manager::updateVault`). `storage::Manager` calls `fs::cache::Registry::evictVault` on remove, on rename
  (old and new root, then re-caches the root) and in `addVault` *before* the engine creates the root. Evicting after
  `mkVault` would drop the fresh root and the whole vault would answer ENOENT.
- `storage::Manager` holds **one engine per vault id** in both indexes (`engines_` by FUSE root, `vaultToEngine_` by
  id): `addVault`, `updateVault` and `reloadEngine` drop the id's previous engine from the path index, and
  `initStorageEngines` clears both. `getEngines()` scans (e.g. `ops::vault_keys::engineFor`) otherwise found a stale
  engine with another vault's key whenever a test process reset its schema and reused ids (`StorageEngineRegistryTest`).
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
  (set by `vh vault keys export` or a device's `vault.keys.export.confirm`; a rotation makes it stale). NeedsConfirmation codes `vault_upstream_key_loss` (S3,
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
- **A same-size pair with matching hashes, or unchanged on both sides since its baseline, plans nothing** (Planner,
  `!hasPotentialConflict` branch), under every strategy and policy. Until this fix it went on to
  `RemotePolicy::decideForBoth`, whose mirror + keep_local answer is always Upload (keep_remote: Download): every
  non-opaque mirrored vault re-sent every file each pass (`SyncPassSchedulingDb.*Mirror*`).
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
- Prices come from the **price bot**, a separate repo (`github.com/valkyrianlabs/vaulthalla-price-bot`, checked out at
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
  `ObjectTooLargeForCopy` before metering; a 200 carrying `<Error>` fails). They sign with `vl::sigv4::sign` (vl-sigv4; sorted,
  RFC 3986 query identical in URL and signature: version ids carry `+/=`) and send through `curl::http` (timeouts,
  test transport). Every PUT path records the thread's `lastPutOutcome()` (ETag + `x-amz-version-id`).
- **The rest of the data path** (object PUT/GET/HEAD/DELETE, copy-in-place metadata, multipart, `listObjectKeysPage`,
  the credential probe, `isBucketEmpty`) builds its own URLs (`constructPaths`: curl-escaped key segments) and header
  maps (`buildHeaderMap`: host + payload hash) and signs with `curl::buildAuthorizationHeader` →
  `curl::signDataPathRequest` (vl-sigv4's primitives: the encoded path as sent, the encoded query sorted without
  re-encoding, every map entry signed with trimmed values). The signer sets `x-amz-date` in the map from the instant it
  signs at and takes the scope date from the same instant, so headers are sent after signing. Payload hashes stay per
  operation: `UNSIGNED-PAYLOAD` for GET/HEAD/copy/initiate/list/probe, the body's SHA-256 for PUT/part/complete, the
  empty body's for DELETE/abort. `curl::buildAuthorizationTrace` (the old signer) is only the goldens' reference.
  Wire guard: `S3DataPathWire.*` (real curl against a capture server; every request verifies and matches the old
  signer).
  Test fake: `tests/helpers/versioned_bucket.hpp` (`VersionedBucket`: S3 versioning modes, delete markers, failure
  injection, body-GET counters).
- **Listings are never partial (#246).** `Controller::listObjects` (the full LIST behind `Cloud::initBins` →
  `RemoteObjectIndex::replaceFromListObjects` and `vault sync reconcile`) and `listObjectKeysPage` throw on any
  transport error, non-2xx (403 SignatureDoesNotMatch, 503 SlowDown), cut/non-XML body, or a truncated page without
  an advancing token; callers fail the pass and leave the index untouched. `listObjects` signs with `vl::sigv4::sign` and
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
- Dev R2 dogfooding hits a real bucket. (The dev-mode `dev.init_r2_test_vault` seeding, which bound a vault to a test
  bucket and cleared it at initdb, was removed 2026-10-22; an older config.yaml key is ignored.)

## Test instances, contracts and the fs actor (2026-10-11)

- `VH_TEST_MODE=1` makes `vaulthalla-server` a private test instance: `runtime/TestInstance.hpp` refuses to start
  (exit 78) unless the DB settings, backing/mount/log/runtime/config paths and `VH_TEST_CLI_SOCKET` all come from the
  environment and are private (paths under `/tmp/`, a `vh_harness_*` or test database). Test mode then serves `vh` on
  that socket (`paths::getCliSocketPath()`); the client honours `VAULTHALLA_CLI_SOCKET`.
- `core/usage` also holds the contract: `FieldGen` generators on CLI usage entries, per-leaf `effect`, `OperationSpec`
  catalog, `WsCommandUsage` book (one file per area in `core/usage/src/contract/ws/`, every registered ws command) and
  the `WsModel` registry (`core/usage/src/contract/models/`, checked against the serializers by `ContractModels.*`),
  exported by `vh_usage --json`; and the MCP catalog built from them (above). Serializers the contract tests call must
  be reachable without a database: handler JSON builders are public statics taking looked-up inputs (`S3GatewayJson`,
  `Vaults::detailsJson`, `Storage::shareEntryJson`, `Links::managementJson`, `Sessions::publicLinkJson`,
  `Email::deliveryRecordJson`, `vault::model::statJson`). Known quirk the contract records: `fs.dir.list` /
  `fs.metadata` `entry` is the base `Entry` JSON (`FsEntryBase`, no `type`/counts/`mime_type`); only `files[]` carries
  the full `FsEntry`.
- `vh_fs_actor` (`core/tests/helpers/fs_actor.cpp`, `-Dintegration_tests=true`): a single-threaded helper that
  switches to a test uid at startup and serves filesystem ops as JSON lines; used by Tier A and `tools/harness`.

