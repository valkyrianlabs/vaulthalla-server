# Remote sign-in for MCP: a node as a Claude or ChatGPT connector (design, not built)

How a node lets a hosted AI client (Claude on the web, phone and desktop, ChatGPT, Claude Code and Codex on another
machine) use its MCP tools through OAuth 2.1 on the public HTTPS port, without weakening anything the local `vh mcp`
and the device listener's `/mcp` enforce today. Held here, never published, until it is built; the operator page
(`docs/admin/remote-connectors.md`) is written with step 10.

Governing texts: MCP authorization, revision 2025-11-25 (the catalog's newest version), and the RFCs it names: OAuth
2.1 (draft-ietf-oauth-v2-1-13), RFC 8414 (server metadata), RFC 9728 (protected resource metadata), RFC 8707
(resource indicators), RFC 7591 (registration), RFC 7009 (revocation), RFC 9207 (`iss` in the response), RFC 8252
§7.3 (loopback redirects) and the Client ID Metadata Document draft (CIMD, draft-ietf-oauth-client-id-metadata-
document-00). Vendor facts (Claude, ChatGPT, Codex) are in the brief that commissioned this note and are not repeated.

## Given (the owner and the coordinator)

1. **Off by default, per node.** Nothing new listens or answers until the operator turns it on; turning it on is
   authorized, audited and step-up confirmed. The device listener's `/mcp` is unchanged.
2. **Read-only by default.** Each grant gets a scope at consent, `read` unless the approver picks a wider one, enforced
   on the server from the catalog's `effect`. `mcp::exclusions()` and the destructive gate stay exactly as they are;
   anything that needs a console step-up is refused remotely with a plain message.
3. **Each grant is its own revocable identity**, bound to the user who approved it, listed and revoked from the console
   and `vh`, audited on creation, every token issue and every tool call, and ended when that user is deactivated or
   loses the right to grant.
4. **Security first** (`docs/contributors/compatibility-policy.md`).
5. **Custody stated honestly** on the consent page and in the operator doc.

## Audit: what exists and what is reused

| Need | What exists | Use |
|---|---|---|
| MCP over HTTP | `protocols/device/Mcp.cpp`: Streamable HTTP, POST only, JSON responses, Origin refused, `MCP-Protocol-Version` checked, batches refused; `mcp::Server` + `mcp::Catalog` (`core/usage`); executor runs `shell::Router::executeLine(line, user, nullptr)` on its own thread under `log::AuditOrigin`, `shell::AgentCallScope` and `stepup::Scope(Channel::Agent)`, abandoned after 10 min | Extracted into a transport shared by both listeners (step 1). The device side keeps its behaviour byte for byte. |
| Effect per leaf | Every leaf declares `CommandEffect::Read|Write|Destructive`; `Invocation::effect` is the stronger of op and leaf; `Catalog::leaves()` | The scope ceiling (below) is a catalog filter on exactly this field. `Unset` is refused. |
| Exclusions | `mcp::exclusions()`; key handlers refuse under `AgentCallScope` (D4) | Unchanged; `connector` (the new command group) is added, so no agent can see or change grants. |
| Step-up | `auth::stepup::require(family, target)`; Channel Agent always refuses (`methods: []`); Web grants bound to user + refresh jti + family + target; families `keys`, `device.trust`, `data.destroy` (target-bound, no password alone) and the family-wide ones; console `StepUpDialog` | Remote calls run as Channel Agent, so every step-up operation is refused; the refusal text is replaced by a plain one. Consent and the switch use a new target-bound family `connector.trust` (rules of `device.trust`: passkey or TOTP, never password alone, a cooldown family). |
| Who may approve | Devices follow D3 (any signed-in user, own account, no new permission bits); MFA "privileged" set; super admin | No new permission bits. Who may grant is one policy function (super admins, "Decided"); each user grants only for their own account. |
| Revocation triggers | `identities::Manager::setPublishedHook` → `reconcile(userIds)` (used by key-backup grants), `auth::Manager::revokeSessions`, `auth::mfa::recovery` effects | The same hooks end grants (below). |
| Token storage | `refresh_tokens.token_hash` = `crypto::hash::tokenDigest()` (`sha256:<hex>`), `verifyToken` constant time | Same digest for connector refresh tokens; access tokens and codes never touch disk. |
| Audit | `audit::record(Event, message)` into the hash-chained `audit_event`; `log::AuditOrigin` suffix on every line a command writes | New `connector.*` actions; origin `connector <grant id16>`. |
| Rate limits | `share::RateLimiter` (keyed sliding window, `check`/`peek`), `ws::ShareRateLimit`, `RefusalLogThrottle` | Reused for every endpoint (table below); unauthenticated failures are logged through the throttle, never audited. |
| Outbound HTTPS | libcurl (`crypto/password/Strength.cpp`: capped writes, timeouts; `storage/s3/curl`) | The CIMD fetcher, with the SSRF guard below. |
| HTTP serving | `http::Server`/`Session` over `TimedStream` (one thread per connection, deadlines, cap → 503); `http::Router` | A third instance on its own loopback port with its own route table. The cookie lanes on 36970 never learn bearer auth. |
| nginx | `vh setup nginx` (`deploy/lifecycle/main.py` `render_managed_nginx_config`): `/ws`, `/preview`, `/download`, `/upload`, `/`; HSTS only with certbot; `X-Frame-Options DENY`, `frame-ancestors 'none'`, `Referrer-Policy no-referrer` on every response; upgrades keep the old site until the command reruns | New exact-path locations, rendered only on certbot sites (below). The "never add prefixes" rule is about the cookie lanes; these go to a different upstream. |
| Switch pattern | `device remote enable` (config + `device.trust` step-up), `cloud relay enable` (DB row, super admin, step-up, MCP-excluded) | The relay's pattern: state in the database, a port in the config. |
| Console page | Next.js `web/src/app/(app)`, route JS budgets (`perf-budgets.json`), `web/middleware.ts` sends a cookieless request to `/login?next=<path+query>` | `/connect/authorize` (consent), Account › Security › Connected apps, Settings › Remote connectors; lazy pieces stay out of budgets. |
| Migration | `deploy/psql/` ends at `150_manifest_replicas_join.sql` on main | `151_connector_grants.sql` (the next free number at landing time). |
| Claims lint | `tools/contracts/encryption_claims.py` scans `docs/`, `README.md`, `web/src` | Consent and doc copy make no encryption claim at all; the custody text is about the vendor, not about vaults. |

## Shape

```
Claude / ChatGPT cloud, or a CLI on a laptop ──HTTPS 443──▶ nginx (public hostname, certbot certificate)
   /.well-known/oauth-protected-resource[/mcp]  /.well-known/oauth-authorization-server  /oauth/*  /mcp
                                                       │ exact locations, proxy to 127.0.0.1:36973
                                                       ▼
   ConnectorServer (runtime service; bound only while the switch is on; loopback only, no `host` key)
     OAuth AS + RS in one process ── grants (DB) ── shared MCP transport ── Router::executeLine(line, user)
Browser ──▶ /oauth/authorize ──303──▶ console /connect/authorize?request=… ──ws──▶ approve (step-up) ──▶ redirect_uri
```

The node is both the authorization server and the resource server; `issuer` = the public origin, resource = origin +
`/mcp`. Nothing is derived from the `Host` header: a request whose `Host` is not the configured hostname is 421.
The client address is nginx's `X-Real-IP`, trusted only because the listener accepts loopback peers only.

## Endpoints

Every response: `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, JSON unless stated. Bodies over the
limit are refused before reading (`/oauth/*` 16 KiB, `/mcp` 1 MiB). While the switch is off the listener is not
bound and nginx answers these paths 404, as any unknown path is today.

| Method, path | Request | Answer | Errors |
|---|---|---|---|
| `GET /.well-known/oauth-protected-resource/mcp` (and the root form, same document) | none | `{resource: "<origin>/mcp", authorization_servers: ["<origin>"], scopes_supported: ["read"], bearer_methods_supported: ["header"], resource_name: "Vaulthalla on <host>"}` | none |
| `GET /.well-known/oauth-authorization-server` | none | `{issuer, authorization_endpoint, token_endpoint, revocation_endpoint, registration_endpoint (only while DCR is on), response_types_supported: ["code"], grant_types_supported: ["authorization_code","refresh_token"], code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["none"], revocation_endpoint_auth_methods_supported: ["none"], scopes_supported: ["read","write","destructive"], client_id_metadata_document_supported: true (while CIMD is on), authorization_response_iss_parameter_supported: true}` | none. No OpenID discovery document (clients try it second and get 404). |
| `GET /oauth/authorize` | `response_type=code`, `client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method=S256`, `state`, `resource`, `scope?` | 303 to `/connect/authorize?request=<id>`; the pending request (256-bit id, 10 min, in memory, ≤ 1000 node-wide, ≤ 20 per address) holds every validated parameter | Client unknown, client fetch failed, `redirect_uri` not an exact match: **never redirected**, 303 to `/connect/error?code=<fixed code>` (the page renders fixed text per code, nothing reflected). Anything else after the redirect is trusted (`code_challenge_method` not S256, missing challenge or `state`, `resource` ≠ the canonical URI (case-insensitive scheme and host), unknown scope, `response_type` ≠ code): redirect with `error=invalid_request|invalid_scope|unsupported_response_type`, `state`, `iss`. |
| ws `connector.authorization.get {request}` (console) | the id | `{client {kind, name, client_id, client_host, redirect_uri, redirect_host, loopback}, requested_scope, max_scope, node_host, user, may_grant, expires_at}` | `not_found` (expired, used, unknown: one answer) |
| ws `connector.authorization.approve {request, scope, label?}` | scope ≤ the node's `max_scope` | `{redirect: "<redirect_uri>?code=…&state=…&iss=…"}`; the page navigates to it | `step_up_required` (family `connector.trust`, target `connector.grant:<request id>:<scope>`), `not_permitted` (policy), `not_found`, `recovery_cooldown` |
| ws `connector.authorization.deny {request}` | the id | `{redirect: "<redirect_uri>?error=access_denied&state=…&iss=…"}` | `not_found` |
| `POST /oauth/token` `grant_type=authorization_code` | form: `code`, `redirect_uri`, `client_id`, `code_verifier` (43-128 unreserved characters), `resource` (required) | `{access_token, token_type: "Bearer", expires_in: 900, refresh_token, scope}` | `invalid_grant` (unknown, expired or used code; verifier mismatch; any field differing from the code's binding), `invalid_target`, `invalid_client`, `unsupported_grant_type`, `invalid_request`. A second use of a code revokes the grant it created. 503 `temporarily_unavailable` when the database is unreachable. |
| `POST /oauth/token` `grant_type=refresh_token` | `refresh_token`, `client_id`, `resource?` (must match), `scope?` (may narrow, never widen) | as above, with a new refresh token | `invalid_grant` for every refresh failure (Claude's expectation), 503 as above |
| `POST /oauth/revoke` | `token`, `token_type_hint?`, `client_id` | 200 always (RFC 7009) | A refresh token ends its grant; an access token ends only itself; another client's token is a silent no-op. |
| `POST /oauth/register` (only while DCR is on, else 404) | RFC 7591 JSON: `redirect_uris` (required), `client_name`, `token_endpoint_auth_method: "none"`, `grant_types` ⊆ {authorization_code, refresh_token}, `response_types` = [code] | 201 `{client_id: "vhc_…", client_id_issued_at, client_name, redirect_uris, token_endpoint_auth_method: "none", grant_types, response_types}`; no secret, no registration access token | `invalid_redirect_uri`, `invalid_client_metadata`; 429 |
| `POST /mcp` | `Authorization: Bearer <access token>`; the device transport's rules (JSON, no batch, version header) | the same JSON-RPC answers as the device `/mcp` | No or bad token: 401 `WWW-Authenticate: Bearer resource_metadata="<origin>/.well-known/oauth-protected-resource/mcp", scope="read"` (+ `error="invalid_token"` when one was sent). Token for another audience: 401. `Origin` present: 403 (as on the device listener; see open item in step 10). `GET`/`DELETE`: 405. 429 over the limits. |

**Scopes are a ceiling on `effect`,** cumulative: `read` = Read leaves; `write` = Read and Write; `destructive` = all
three, and a destructive call still needs `confirm: {"destructive": true}`. `tools/list` shows only tools under the
ceiling (`vh_help` and `vh_read` always, `vh_run` from `write`, typed tools by their effect), and `Catalog::prepare`
refuses anything above it before the executor sees it; the executor checks again. The token's `scope` answers the
cumulative set ("read write"). What the client asked for is shown on the consent page and preselects nothing wider
than `read`. A call above the ceiling is an `isError` tool result ("This connection is read-only. Whoever approved it
can reconnect it with write access."), not the spec's optional 403 `insufficient_scope`: an agent must not be able to
drive the client into repeated consent prompts. Step-up operations answer "This needs a confirmation at the
Vaulthalla console and can't be done through a remote connection."

**Every tool call** re-checks (a 30 s in-process cache under `rbac::policyEpoch()`, dropped at once by every
revocation, which happens in this process): grant live and unexpired, the user `authorizing()`, the user still allowed to grant, switch on. Then
it runs exactly as the device's `/mcp` does, with origin `connector <grant id16>`, at most 8 calls in flight per grant.

## Client identity

| Kind | `client_id` | How it is trusted | Default |
|---|---|---|---|
| CIMD | an HTTPS URL with a path | The document at that URL, fetched by the node; `client_id` in it must equal the URL exactly | **on** |
| Operator-registered | `vhc_<22 base64url>` | `vh connector client add --name … --redirect …` (super admin) | always available |
| DCR | `vhc_<22 base64url>` | nothing: anyone may register; its name is self-asserted | **off** (`vh connector dcr on`) |

The starting position holds. CIMD is what Claude recommends and ChatGPT prefers, so both work with the default; DCR
adds no identity at all (a name anyone can type) and an unauthenticated write path, so it stays off. A CLI that can
only do DCR is served by an operator-registered client id or by turning DCR on (step 10 checks Codex and Claude Code;
"Decided" below). In every case the consent page names the identity it actually has: for CIMD the host of the
`client_id` URL ("published by claude.ai"), for DCR "a self-registered app; its name is not verified", for a
registered client "registered by <operator> on <date>"; and always the exact redirect host.

**CIMD fetch (the SSRF guard, `connector/ClientMetadata`).** `https` only, port 443 only, a DNS name (no IP literal,
no userinfo, no fragment, ≤ 512 characters, IDN refused rather than converted). Resolved once by the node; every
address must be public (refused: loopback, RFC 1918, CGNAT, link-local incl. 169.254.169.254, multicast, reserved,
documentation, `0/8`, IPv6 ULA, link-local, v4-mapped and NAT64 forms of any of these); the connection goes to that
resolved address (`CURLOPT_OPENSOCKETFUNCTION` checks the address actually dialled, so a rebinding answer can't slip
in), system trust store, TLS 1.2+, no redirects, no proxy, no cookies, 5 s in all, ≤ 16 KiB (`CURLOPT_MAXFILESIZE`
and a capped write callback), `application/json`, strict parse. Required: `client_id`, `client_name` (≤ 64
characters, control and bidi characters stripped), `redirect_uris`; `token_endpoint_auth_method` absent or `none`
(`private_key_jwt` is not supported in v1: refused, not ignored). `logo_uri`, `client_uri`, `jwks_uri` are never
fetched or shown. Cached in `connector_clients` for the document's `max-age`, clamped to 5 min-24 h; a failed fetch
is cached negatively for 5 min; at most 4 fetches at once node-wide and 10 a minute per host. Refetched at
authorize time when stale; token requests never fetch.

**Redirect matching** is byte-for-byte string equality against the registered list, with one exception from RFC 8252
§7.3: `http://127.0.0.1`, `http://[::1]` and `http://localhost` redirects match on any port (path and query still
exact). Any other `http` URI, a fragment, or a non-ASCII host is refused at registration and fetch time. A
loopback-only client gets the CIMD draft's warning on the consent page (any program on the user's computer could
present that client id).

## Tokens and lifetimes

| Token | Format | Stored | Lifetime | Why |
|---|---|---|---|---|
| Authorization code | `vh_ac_` + 32 random bytes, base64url | memory, by digest, bound to client, redirect URI, challenge, resource, scope, user, request | 60 s, single use | A restart only makes the user click again. |
| Access token | `vh_at_` + 32 random bytes | memory only, by digest, with grant id, audience, ceiling, expiry | 15 min | Short (MCP: SHOULD be short-lived). Revocation is immediate anyway (grant checked per call); the lifetime bounds a stolen token whose grant is not yet revoked. Lost on restart: clients get 401 and refresh, which Claude does. |
| Refresh token | `vh_rt_` + 32 random bytes | `connector_refresh_tokens.token_digest` = `tokenDigest()` (sha256; 256-bit server-minted, so no password hash) | rotated on every use; 30 days idle | OAuth 2.1 requires rotation for public clients. |
| Grant | row | `connector_grants` | 90 days absolute, then reconnect ("Decided") | A forgotten connection ends by itself. |

Opaque random tokens, not JWTs: only this node validates them, revocation needs a lookup either way, and nothing
signed or decodable is handed to the vendor. The prefixes let secret scanners recognise a leaked token.

**Rotation and reuse.** A refresh is one transaction: `UPDATE … SET used_at = now() WHERE digest = $1 AND used_at IS
NULL AND revoked_at IS NULL RETURNING grant_id`, then the successor row. A token that was already used ends the grant
(`refresh_reuse`), audited and sent to the user through `notifications::account`, with one bounded allowance for a
lost response: within 10 s of its rotation, and only while its successor has never been used, the previous token gets
a fresh successor and the unused one is revoked. A thief who races inside that window still trips detection on the
legitimate client's next refresh (its token is now revoked, which counts as reuse).

**Comparisons.** Tokens, codes and request ids are found by digest (a hash index lookup leaks nothing useful); the
PKCE check compares `BASE64URL(SHA256(verifier))` with `sodium_memcmp`; the `state` is the client's and never
interpreted.

## Data model (migration 151)

- `connector_settings` (singleton): `enabled`, `public_origin`, `max_scope` (default `write`), `client_hosts`
  (empty = any), `dcr_enabled` (false), `changed_by` → users SET NULL, `changed_at`.
- `connector_clients`: `id` uuid, `client_id` TEXT UNIQUE, `kind` (`cimd|registered|dcr`), `name`, `redirect_uris`
  TEXT[], `document_sha256`, `fetched_at`, `cache_until`, `created_by` → users SET NULL, `created_at`,
  `last_used_at`, `disabled_at`. DCR rows that never complete a grant are deleted after 24 h; at most 100 live.
- `connector_grants`: `id` uuid, `user_id` → users CASCADE, `client_row` → connector_clients CASCADE, snapshots of
  `client_id`, `client_name`, `redirect_uri`, `scope` CHECK (`read|write|destructive`), `resource`, `label`,
  `approved_via` (step-up method), `created_at`, `expires_at`, `last_used_at`, `last_ip`, `revoked_at`,
  `revoked_reason` CHECK (`manual|user_inactive|grantor_policy|refresh_reuse|code_reuse|switch_off|expired|
  client_removed|sessions_revoked|mfa_recovery|admin`), `revoked_by` → users SET NULL.
- `connector_refresh_tokens`: `id`, `grant_id` → connector_grants CASCADE, `token_digest` UNIQUE, `issued_at`,
  `expires_at`, `used_at`, `revoked_at`.

Nothing in clear that grants access is at rest. The config file gains only `connector_server.port: 36973` (loopback;
dev +100), which the nginx renderer reads.

## Who approves, and when a grant ends

The signed-in console user approves for their own account only (no admin approves on someone's behalf), when the
grantor policy (`connector::mayGrant`: super admins) includes them, with a `connector.trust` step-up bound to the request id and scope. A grant
ends: revoked by its user or a super admin; its user deactivated or deleted (`setPublishedHook` → reconcile, and the
per-call check); its user no longer a grantor (same); `revokeSessions` for that user (a password change or "sign
out everywhere" also disconnects apps); an MFA recovery-code sign-in or an admin MFA reset; refresh or code reuse;
idle or absolute expiry; its client removed; the switch turned off (every grant is revoked, so turning it on again
never revives a forgotten connection).

## The consent page (`/connect/authorize`, console)

Reached signed in (the middleware's `/login?next=` round trip; step 7 confirms `next` accepts same-origin paths only).
It shows, in this order: "**<client name>** wants to use Vaulthalla on **<node host>** as **<user>**"; the identity
line above; "After you approve, your browser goes to **<redirect host>**" (full URI under "Details"); the loopback
warning when it applies; the access choice (Read only, preselected; Read and change; Read, change and delete, each
with one line of what it allows, and only up to `max_scope`); and the custody box:

> <vendor host> will hold a key that lets it act on this node as you, with the access you choose, until you
> disconnect it or it expires on <date>. What you ask it to do, and what this node answers (names, listings and any
> file contents a tool returns), passes through <vendor host>'s service and is handled under its terms. Vaulthalla
> can't see or limit what happens there. Key and secret export and anything that needs a confirmation at this
> console are never available to it.

Approve (then the step-up dialog) and Deny. Never auto-approved, not even for a client approved before. A user outside
the grantor policy sees why and can only deny. CSRF: there is no cookie-authenticated form; approval is a ws command on the
console's own authenticated socket (Origin checked, `ws/OriginPolicy`), naming a 256-bit single-use request id, and
needing a step-up gesture. Clickjacking: `frame-ancestors 'none'` and `X-Frame-Options: DENY` (already on every
response of the site), plus the step-up gesture. Open redirects: the page only navigates to the `redirect` the daemon
returns, which is always the exactly matched URI with `code|error`, `state` and `iss`.

## Listing and revocation

ws `connector.grants.list {all?}` / `connector.grants.revoke {id} | {all, user_id?}`; `vh connector list [--all]`,
`vh connector revoke <id> | --all [--user <name>]`. A user lists and revokes their own; a super admin lists and
revokes everyone's. Rows show the client name and host, redirect host, scope, created, last used, last address,
expiry and user. Revocation never needs a step-up. Console: Account › Security › Connected apps; Settings › Remote
connectors (switch, hostname, policy, registered clients, everyone's grants for super admins).

## The switch and nginx

`vh connector status|enable --url https://<host>|disable`, `vh connector client list|add|remove`, `vh connector dcr
on|off`, and the same as ws `connector.*` (capability `connector.remote`). All of them: super admins (grant listing
and revocation above excepted); console calls take a `connector.trust` step-up
(`connector.enable:<origin>`, `connector.dcr.on`, `connector.client.add:<sha256 of the document>`); the CLI is Host
(peer credentials, exempt as for every Host call); agents never (`connector` is excluded). Enable refuses a URL that is
not `https`, has a path, query, port other than 443, or an IP literal. Enabling binds the listener at once;
disabling closes it and revokes every grant.

**nginx.** On a site rendered with a certbot certificate, `vh setup nginx` adds `location = /mcp`, `location ^~
/.well-known/oauth-protected-resource`, `location = /.well-known/oauth-authorization-server` and `location ^~ /oauth/`
to `127.0.0.1:<connector_server.port>`, with `error_page 502 504 =404` (switch off = 404, as today), `proxy_buffering
off` and a 660 s read timeout on `/mcp`, and a marker comment the daemon reads. The locations are always present on
such sites so the console switch needs no root step; sites with the local self-signed certificate never get them.
`vh connector status` reports, without claiming more than it saw: the marker present or "run `sudo vh setup nginx`";
an IPv4 A record for the hostname; a self-probe of the metadata URL through the public name with the system trust
store ("couldn't confirm from this host" when hairpin NAT stops it, never a failure). A node without a public
hostname and certificate is told plainly: hosted clients connect from their vendor's cloud, so they need a public
hostname with an IPv4 address, port 443 reachable from the internet and a publicly trusted certificate (`sudo vh
setup nginx --certbot`); without them, use `vh mcp` on the node or Vaulthalla Desktop. The doc also says that the
browser completing consent must reach the console at that hostname, and that the console is then reachable from the
internet like the connector (true of any certbot site already).

## Audit events

`connector.enable|disable {origin}`, `connector.dcr.on|off`, `connector.client.add|remove|register {kind,
client_host}`, `connector.grant.create {grant, client_host, redirect_host, scope, via}`, `connector.grant.deny`,
`connector.token.issue {grant, from: code|refresh}`, `connector.grant.revoke {grant, reason}` (with `refresh_reuse`
and `code_reuse` as reasons), `connector.call {grant, tool, command, effect, exit}`; lines the command itself writes
carry `[via connector <grant id16>]`. Unauthenticated refusals (bad tokens, bad codes, fetch failures, rate limits)
are log lines through `RefusalLogThrottle`, never audit events, so nobody outside can grow the chain.

## Rate limits (`share::RateLimiter`, keyed by client address unless stated)

| What | Limit |
|---|---|
| `/oauth/authorize` | 30/min; 20 pending per address, 1000 node-wide |
| CIMD fetches | 4 at once node-wide, 10/min per host, 5 min negative cache |
| `/oauth/token` | 60/min per address, 20/min per grant; 10 failures/min per client id, then 429 |
| `/oauth/register` | 10/h per address, 100 live DCR clients |
| `/mcp` | 120 requests/min and 8 calls in flight per grant; 60 unauthenticated 401s/min per address, then 429 |
| Consent step-up | the existing step-up failure rule (5 failures in 15 min revoke the console session) |
| Listener | `connector_server.max_connections` (64), the HTTP server's 503 over it |

## Threat model

| Attacker | What stops or bounds it | What remains |
|---|---|---|
| Malicious client registration (DCR spam, a look-alike name) | DCR off by default; when on: rate limits, 100 live, 24 h expiry, the name marked unverified, the redirect host shown | A user who approves an unverified app anyway gets what they chose, at `read` unless they widened it. |
| Phished consent (a link that opens a real consent page for the attacker's client) | Consent names the CIMD host and the redirect host, read is preselected, a step-up gesture is needed, never auto-approved; PKCE means only the initiator can redeem | A user fooled by a convincing host (e.g. `claude-ai.example`) grants read as themselves until revoked; the doc tells users to check the host. |
| Local malware claiming a real CIMD client with a loopback redirect | The loopback warning; it must also get the user to approve a flow they didn't start | Not preventable by CIMD itself (the draft says so). |
| Stolen refresh token | Rotation with reuse detection ends the grant and notifies the user; bound to client id; 30 days idle | Use until the legitimate client next refreshes (≤ 15 min while it is active). |
| Stolen access token | 15 min, audience-bound, ceiling-bound, grant checked per call, memory-only | Up to 15 min of calls within scope, all audited with the grant id. |
| Hostile metadata document or URL (SSRF, slow or huge answers, rebinding) | The fetch rules above; no redirects; the dialled address re-checked; no logos ever fetched | The node makes one bounded HTTPS GET to a public address per stale client. |
| Cross-site request against consent or the switch | No cookie-authenticated form; ws Origin policy; single-use request id; step-up gesture; frame-ancestors none | none known |
| Token or code injection, mix-up | PKCE S256 required, `resource` required and checked, `iss` in the response, exact redirect, code reuse revokes | none known |
| AI vendor compromise | Scope ceiling, exclusions, destructive gate, no step-up operations, per-user RBAC, revocation from the console and `vh`, absolute expiry | Everything the grant's scope and user allow, until someone revokes it; the vendor already sees every argument and result. Stated on the consent page. |
| Prompt-injected agent using a legitimate grant | The same ceiling and gates; read by default; destructive calls need explicit confirmation; every call audited | Within scope it can read (and, if granted, change) what the user can, and whatever it reads goes to the vendor. Read scope bounds the harm to disclosure. |
| Host-header or metadata spoofing | Origin and resource come from the stored public origin; wrong `Host` is 421 | none known |
| Denial of service from outside | Per-address limits, connection cap, bodies capped before reading, no audit writes for failures | nginx and the daemon still spend work on refusals. |

## Not in the first version

- **Sender-constrained tokens (DPoP, mTLS):** neither Claude nor ChatGPT presents them; short access tokens and
  rotation bound the risk instead.
- **SSE (`GET /mcp`), MCP session ids, server-to-client requests:** the device transport has none, and the catalog
  needs none.
- **Per-vault or per-tool scopes:** the user's RBAC already limits what is reachable; finer consent is a later design.
- **Confidential clients (`client_secret_*`, `private_key_jwt`):** secrets at rest for no gain with these vendors.
- **RFC 7592 client management, token introspection, OpenID (`id_token`, userinfo), client logos.**
- **Automatic `insufficient_scope` step-up:** see "Scopes"; reconnecting with wider access is the user's action.
- **Remote console approvals for step-up operations** (`console_approval` for an agent): refused remotely, as given.
- **A vendor allowlist or "trusted vendor" auto-approval:** every consent is explicit ("Decided").
- **Reaching a node without a public hostname** (through the Vaulthalla Cloud relay, or a listener with its own
  certificate): later; v1 is nginx with a certbot certificate only.
- **An address allowlist rendered into nginx** (Claude's egress ranges): the browser and CLI clients come from
  elsewhere; documented as an optional firewall step.

## Scoped devices (shape only; build step 4)

Vaulthalla Desktop is about to give each AI app (Claude Code, Codex) its own device pairing per node, and the owner
wants such a pairing to carry fewer permissions than his account. The ceiling built for grants is the same mechanism:
the execution path takes it from the principal's limit (`protocols::mcp::Principal::ceiling`), not from anything only
the connector knows. What a scoped device adds:

- **Chosen at approval.** `device.pairing.approve` takes `scope` (`read` | `write` | `destructive`); a pairing
  request may carry `requested_scope` (Desktop asks `read` for an AI app), which the approval preselects and may only
  narrow, never widen. Absent means `destructive`: a Desktop pairing is the person's own app and stays exactly as it
  is today.
- **Stored on the device row.** `devices.scope TEXT NOT NULL DEFAULT 'destructive'` (the next migration; existing rows
  unchanged), carried on `device::Peer` as `readOnly()` is for relayed browsers, and shown by `device.list` (and
  `vh device list`). A scope never widens in place: a wider one is a new pairing.
- **`/mcp` through the same ceiling.** One line: `protocols/device/Mcp.cpp` sets `Principal::ceiling` from the peer
  instead of `Destructive`. Nothing else in steps 1 to 3 changes.
- **ws commands by effect.** Every ws contract entry (`WsCommandUsage`) gains an `effect` (`read` | `write` |
  `destructive`; a contract test refuses an entry without one, as `McpCatalog.EveryLeafDeclaresAnEffectAndOnlyLeaves`
  does for CLI leaves). For a scoped device the ws router refuses a command whose effect is above the ceiling or
  unknown: ERROR `device_scope {scope, effect}`, beside the relayed read-only check (which could then become scope
  `read` plus the relay's narrower lane set). HTTP lanes: `read` = GET/HEAD `/preview*`, `/download*`, `/transfer*`;
  `write` adds `/upload*`.
- **Never for a scoped device, whatever its scope:** `device.pairing.*` (opening, approving, denying pairings),
  `device.approval.*` (it neither asks for console approvals nor registers an approval key: a scoped device's commands
  run under step-up `Channel::Agent`, which never steps up), `device.backup.grant.*` and `vault.keys.export|import`
  (key custody stays with the person's own devices), `device.revoke` of any device but itself, and `connector.*`.
- **Tests.** Pairing with each scope and with a narrowed request; a widened request refused; `device.list` shows it;
  `/mcp` lists and runs only within the ceiling; a table-driven router probe over every ws command (allowed exactly
  when within the ceiling and not in the never-list); existing Desktop pairings behave exactly as before.

## Build plan (each step lands separately, with its tests)

1. **Shared MCP transport and the effect ceiling.** Move the HTTP handling out of `protocols/device/Mcp.cpp` into
   `protocols/mcp/HttpTransport` with a `Principal {user, origin, ceiling, ended()}`; `Catalog::tools(ceiling)` and
   a ceiling refusal in `prepare`. Tests: the device `/mcp` tests unchanged; `McpCatalog.CeilingListsAndRefuses*`
   table-driven over every leaf and typed tool (read never reaches a Write or Destructive leaf; `Unset` refused).
2. **Migration 151, query layer, `connector::Grants`.** Tests (DB): code and refresh lifecycle, rotation CAS under
   concurrency, reuse ends the grant, the 10 s allowance and its detection, every end condition in "Who approves",
   `SqlDeployerHistoryDb.Connector*` upgrade safety.
3. **`ops::connector`, `vh connector`, ws `connector.*`, step-up family `connector.trust`, exclusions, audit.** Tests:
   CLI option and example checks, `stepUpTable` entries, `exclusions()` covers `connector`, ws/CLI parity, policy
   and super-admin rules, `WebSocketCommandMap` typing.
4. **Scoped devices** (section above): the migration adding `devices.scope`, `device.pairing.approve` and
   `device.list`, the peer's ceiling into `/mcp`, the ws `effect` annotation and its contract test, the router and
   lane checks. Lands before the connector listener, so both remote principals share one tested ceiling.
5. **`ConnectorServer` and the OAuth endpoints, CIMD fetcher.** Tests (DB-free): redirect matcher (exact, loopback
   ports, fragments, userinfo, case, IDN), resource canonicalisation, metadata documents; SSRF table (each refused
   range v4/v6, mapped and NAT64 forms, decimal and octal IP spellings, rebinding via a test resolver hook,
   redirects, oversize, slow, wrong type); token endpoint (wrong verifier, `plain`, missing `resource`, mismatched
   redirect or client, code reuse revokes, refresh narrowing, `invalid_grant` everywhere); rate limits; Host 421.
6. **Bearer `/mcp`.** Tests: 401 challenge format, audience, ceiling in `tools/list` and `tools/call`, step-up
   refusal text, per-call revocation and deactivation (next call 401), concurrency cap, audit origin.
7. **nginx and status.** `render_managed_nginx_config` locations on certbot sites only, the marker, `error_page`;
   `deploy/lifecycle/tests` render tests and `nginx -t` on the rendered file in CI; status probes behind test hooks.
8. **Console.** `/connect/authorize`, `/connect/error`, Connected apps, Settings › Remote connectors; route budgets;
   the claims lint; `login?next=` stays same-origin; Playwright: consent with TOTP step-up, deny, expired request.
9. **End-to-end with a real client.** `tools/harness/tests/test_connector_e2e.py` (Tier B, opt-in like the other live
   harness tests): a private daemon behind a harness nginx with a test CA, a local HTTPS server publishing a CIMD
   document, and the official MCP Python SDK (`mcp` package: `streamablehttp_client` with `OAuthClientProvider`,
   which does discovery, CIMD or DCR, PKCE and refresh) as the client; consent approved by the harness's ws client
   with its lab TOTP. Test-mode-only hooks admit the test CA and the loopback "public" address; they are compiled out
   of packages (contract check). Asserts: discovery from the 401, CIMD flow, read tools only, a read call runs, a
   write call refused, refresh rotation, replayed refresh ends the grant, `vh connector revoke` → 401, user
   deactivated → 401, switch off → 404 through nginx. A DCR and an operator-registered variant run the same script.
10. **Docs and acceptance.** `docs/admin/remote-connectors.md` (custody text, the public-host requirements, the
   firewall option), release fragments. Proof on a lab node with a public hostname: Claude (web, phone, desktop),
   ChatGPT, Claude Code (`claude mcp login`) and Codex (`codex mcp login`) each connect, list, read, are refused a
   write under `read`, and are cut off by revocation; outside probes: off = 404, wrong Host, open-redirect attempts,
   the SSRF list against the fetcher; whether any vendor sends `Origin` (if one does, an exact-origin allowlist
   replaces the blanket 403). Then the usual proof: unit and DB suites, `make itest`, the harness test, quiet builds
   on Linux and macOS, `vlr check`.

## Decided (2026-11-22)

The five open questions were decided by the coordinator with the recommended defaults, recorded for the owner. Each is
one constant or one setting, so it can change later without a redesign:

| Question | Decision | Where it lives |
|---|---|---|
| Who may grant | Super admins only, each for their own account | `connector::mayGrant` (one function) |
| Widest scope | `write`; `destructive` only when the operator raises it | `connector_settings.max_scope` (default `write`) |
| Grant lifetime | 90 days at most; ends after 30 days without a refresh | `connector::kGrantLifetime`, `kRefreshIdle` |
| DCR | Off | `connector_settings.dcr_enabled` (default false) |
| CIMD hosts | Any HTTPS host, its name, client-id host and exact redirect host on the consent page | `connector_settings.client_hosts` (empty = any; the operator allowlist's place) |

The recommendations as they were argued, for the record: granting sends the user's data through a third party, so a
shared node's operator decides first; a destructive call's per-call confirmation comes from the agent's side, which a
prompt injection can supply; a forgotten connection should end by itself; DCR adds no identity, only an
unauthenticated write path; a default vendor allowlist would break every other client. If step 10 shows that Codex or
Claude Code can use neither CIMD nor a pre-registered id, the operator turns DCR on for that node.
