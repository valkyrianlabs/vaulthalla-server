---
title: S3 Gateway Implementation Notes
description: Development notes for scoped S3 gateway credentials and gateway price-budget controls.
order: 940
status: draft
tags:
  - development
  - s3-gateway
  - cost-control
---

# S3 Gateway Implementation Notes

These notes summarize the scoped credential and per-key budget work on the `s3-endpoint` branch.

:::toc[On this page]{depth="3" theme="compact"}
:::

## What Changed

- Consolidated final S3 Gateway schema into `095_s3_gateway.sql`.
- Extended `s3_gateway_credentials` with creator, effective principal, scope mode, description, and expiry fields.
- Added `enforce_budget_for_local_requests` to gateway credentials.
- Added S3 gateway credential default vault roles, default/key-level role overrides, and selected-vault rows.
- Added gateway credential and gateway credential/vault price-budget scopes.
- Added gateway budget ledger columns for credential id, request UUID, operation, object key, estimated cost, usage source, and synthetic/local marker.
- Added `s3_gateway_sync_origin` rows for future attribution of sync work back to the gateway request/credential that created local-first work.
- Extended C++ S3 gateway query models, credential management, SigV4 auth context, object-store permission checks, router request flow, CLI commands, WebSocket handlers, and web console models/page.
- Added dedicated public S3 host routing for managed Nginx. The S3 host proxies ordinary path-style S3 requests to the direct gateway listener, preserves the signed URI, and marks requests as path-style-only so the public host is not inferred as a virtual-hosted bucket.
- Added Cloudflare DNS-01 Certbot support for managed Nginx so local/dev `vaulthalla.dev` and `s3.vaulthalla.dev` certificates can be issued without an inbound HTTP challenge endpoint.
- Removed configurable `s3_gateway.multipart.part_dir`. Multipart parts now live under a generated Vaulthalla hidden backing path with per-upload opaque `parts_dir_id` directories.
- Added Playwright configuration and a focused S3 Gateway browser suite that can auto-start the local web dev server for localhost E2E runs.

## Implemented

- Credentials can be `user_access`, `vault_allowlist`, or `global`.
- `principal_user_id` is the effective user for gateway authentication; legacy `user_id` remains for compatibility.
- Disabled and expired credentials are rejected during authentication.
- `user_access` checks use the principal user's normal Vaulthalla RBAC without requiring gateway credential vault-role assignments.
- `vault_allowlist` checks require normal Vaulthalla RBAC, an enabled selected-vault row, and an enabled key-level default vault role. Optional per-vault role assignments override the default for one selected vault. Default overrides apply broadly; per-vault overrides apply after them.
- `global` credentials use principal RBAC across gateway bucket bindings, require an admin principal, and require an enabled key-level default vault role. Optional per-vault role assignments/overrides are exceptions, not the primary policy.
- Bucket-admin gateway operations keep RBAC validation separate from object scope. Gateway credentials resolve per-vault access through selected vaults, default roles, and optional per-vault role exceptions.
- Bucket binding mode validation rejects local vaults bound as `remote_cache`/`remote_proxy` and S3/R2 vaults bound as `local`, preventing management UI or CLI actions from creating bindings that route pricing/budget checks to the wrong engine type.
- Remote-backed gateway operations estimate provider cost and evaluate existing global/provider/vault policies plus new per-key and per-key/vault policies only for actual upstream work performed inside the gateway request.
- Remote-backed gateway operations check the vault remote policy's existing S3/R2 request budgets through request-scoped upstream usage capture, so request-budget failures are distinguishable and do not leave committed price ledger rows.
- Request-scoped upstream usage capture avoids using global cumulative S3 controller metrics as the authoritative per-request accounting source. The current gateway provider calls are synchronous on the session worker thread, so the capture is thread-local and snapshots usage behind a mutex.
- Gateway price estimates honor the request storage class when provided, normalizing aliases such as `STANDARD_IA` through the configured provider profile instead of always using the vault default tier.
- Budget denials return S3 XML `AccessDenied` with HTTP 403. The XML message includes the exact blocking policy id, scope, window, limit, used-before amount, remaining-before amount, requested cost, currency, provider key, vault id, gateway credential id, operation, and request UUID.
- `PriceBudgetDecision` now retains all exceeded enforce checks in `blocking_checks` / `blocking_policy_ids` and exposes a deterministic primary blocker through `primary_blocking_check`, `primary_blocking_scope`, and `primary_blocking_window`.
- Ledger reservations include gateway credential and request context.
- Local-only gateway operations are treated as zero/unavailable remote cost and do not consume remote provider budgets.
- Local/cache/metadata hits are treated as zero actual upstream usage by default and do not consume provider/vault/global upstream price budgets or upstream request budgets.
- Gateway credential/key-vault budgets default to the same actual upstream usage as the provider budgets. If `enforce_budget_for_local_requests=true`, pure local buckets, local/cache hits, metadata-only requests, and sync-deferred local-first writes/deletes are recorded as synthetic gateway usage for gateway credential scopes only.
- Synthetic local gateway usage is marked in ledger/status output with `synthetic=true` and `usage_source` values such as `metadata`, `local_file`, `local_cache`, and `sync_deferred`.
- Pure local synthetic accounting uses `s3_gateway.synthetic_local_request_cost_usd`, with tiny nonzero per-request defaults so gateway credential budgets can deterministically throttle local API usage. Synthetic local accounting never matches provider/vault/global upstream policy scopes.
- Gateway LIST is metadata-only. It uses `s3_gateway_object`, filesystem metadata, and `remote_object_index`; it does not decrypt object bodies, compute plaintext MD5 ETags, refresh manifests, or call upstream S3/R2 LIST/HEAD/GET APIs.
- `vh s3-gateway bucket backfill <bucket>` performs explicit metadata-only gateway object-state backfill. `--calculate-etags` is the intentional local body-reading/decrypting path for plaintext MD5 ETag import and is never invoked by LIST.
- Gateway PUT/COPY/multipart completion writes Vaulthalla local state and gateway metadata first for remote-backed buckets. Sync owns eventual upstream upload/index/manifest side effects and the provider/vault/global upstream price-budget ledger rows for that work.
- Gateway DELETE now removes or tombstones Vaulthalla local state and clears gateway metadata without direct upstream delete calls from the S3 Router/ObjectStore layer. Sync owns upstream purge.
- Bucket delete emptiness checks use Vaulthalla metadata, filesystem rows, gateway metadata, and remote index state instead of only `s3_gateway_object`.
- CLI management exists under `vh s3-gateway creds scope ...` for scope/default role/selected vault policy, `vh s3-gateway creds role ...` for per-vault exceptions, and `vh s3-gateway budget ...`.
- WebSocket management endpoints exist for service status, credentials, credential scope updates, credential default role get/set/clear, selected vault list/add/remove/replace, default role overrides, per-vault role assignments, per-vault path overrides, buckets, budget policy upsert/list/disable, ledger, and status.
- WebSocket credential endpoints name every id explicitly: `credential_id` (or `access_key` / `name`) for the credential, `override_id` for a role override, and `permission_id` (or `permission_qualified` / `permission_name`) for an override's permission. A payload that carries a bare `id` is refused with a typed `invalid` error (`data.code: "invalid"`) whose message names the expected field; `id` is never guessed to mean a credential, override or permission. The CLI twin is `vh s3-gateway creds role override remove <credential> --vault <vault> --override-id <id>` (`--id` and a second positional still work).
- WebSocket credential create/update normalizes `user-access`, `vault-allowlist`, and their underscore forms to the canonical DB scope values, matching CLI behavior.
- Web console route `/s3-gateway` exists with service, credential, role-native credential access, bucket, budget, ledger, and client setup sections. The page has been split into `web/src/components/s3-gateway/*` components so browser tests can target stable sections.
- DB-backed coverage includes disabled/expired credential rejection, shorthand-to-RBAC table writes, scoped action denial, and a signed S3 route returning XML `AccessDenied` when credential policy denies access after RBAC passes.
- DB-backed route coverage now distinguishes actual upstream use from local-first gateway work: remote-only GET commits actual upstream gateway ledger rows with `synthetic=false` and `usage_source=remote_download`, remote-only GET can be denied by upstream request budget with `SlowDown` or price budget with `AccessDenied`, LIST/local GET/local-first PUT/DELETE/multipart do not commit gateway ledger rows by default, synthetic local accounting can be enabled per credential, pure local buckets can consume synthetic key usage, and request-budget `SlowDown` remains distinct from price-budget `AccessDenied`.
- DB-backed object-store coverage includes metadata-only local/remote LIST behavior, local-first remote delete with tombstones, no direct upstream delete from gateway DELETE, bucket-delete rejection from filesystem rows without gateway rows, bucket-delete rejection from remote index rows, and truly empty API-exclusive bucket deletion.
- DB-backed WebSocket coverage includes gateway budget policy upsert/list/disable/status for `gateway_credential` and `gateway_credential_vault` scopes.
- DB-backed WebSocket permission coverage includes non-admin denial for cross-user credential create/update/revoke, non-admin denial for global credential creation, non-admin denial for key-only budget cap management, outsider denial for key/vault policy management, and owner-managed key/vault policy disable.
- Gateway budget status trends are credential-aware for `s3.gateway.budget.status`, including current monthly used, remaining, and percent-used data for per-key and per-key/vault policies.
- WebSocket budget policy/status filtering preserves the key-wide cap when a caller scopes a view to both one credential and one vault, so UI/status views show both applicable monthly limits.
- S3 gateway budget WebSocket endpoints only manage `gateway_credential` and `gateway_credential_vault` policies; generic global/provider/vault price-budget policy mutation remains on the generic pricing handler, and gateway ledger/status output filters out non-gateway rows.
- Generic pricing WebSocket status/list endpoints accept `gateway_credential_id` and now consistently filter gateway policies, ledger rows, and trends to that credential; when a vault is also supplied, gateway credential/vault rows must match both dimensions. Generic pricing vault budget checks also honor direct vault ownership before falling back to admin vault permissions.
- S3 gateway CLI budget ledger/status output also filters out non-gateway price-budget rows, and vault-only status can show monthly trend rows for every `gateway_credential_vault` cap on that vault.
- Same-vault remote `CopyObject` uses one conservative `CopyObject` budget reservation instead of also reserving a separate source `GetObject`; cross-vault copies still budget source read and destination write separately.
- The S3 gateway web store refreshes budget status after policy save/disable and the page-level refresh path includes budget status, keeping current-month usage widgets aligned with management actions.
- The smoke script can exercise AWS CLI and MinIO `mc` clients when those binaries are present; set `S3_GATEWAY_SMOKE_REQUIRE_AWS=1` or `S3_GATEWAY_SMOKE_REQUIRE_MC=1` to require either client in a CI/live-smoke environment. It can either use an existing `S3_GATEWAY_SMOKE_API_KEY` or create a temporary upstream API key from `S3_GATEWAY_SMOKE_UPSTREAM_*` environment variables before creating a remote-cache bucket (a Vaulthalla gateway bucket over an existing `vh-test-*` upstream bucket; the smoke never creates provider buckets). AWS CLI is preferred when both clients exist because the gateway currently interoperates cleanly with AWS SigV4 payload handling.
- The smoke script now supports `--local-only`, `--require-remote`, `--keep-resources`, and `--prefix <prefix>`. It defaults to unique `s3-gateway-test/<timestamp>-<pid>` object prefixes and reports endpoint, bucket, credential, mode, prefix, and remote cleanup status in a PASS/FAIL summary.
- `tools/e2e/load_env.sh` sources the known local/dev env files with exported variables and exposes a redacted diagnostics report plus helpers for DB and R2 availability checks.
- `tools/e2e/provision_e2e_user.sh` can provision or verify an S3 Gateway E2E admin identity. Forced browser E2E provisioning creates a fresh `e2e_s3gw_*` admin user for local/dev runs so a running server cannot reuse a stale cached password hash. Generated credentials are written only to `test-results/s3-gateway-e2e/e2e.env` with mode `0600`.
- `tools/smoke/s3_gateway_scoped_budget_smoke.sh` supports `--budget-denial synthetic`, `--budget-denial actual-upstream`, and `--budget-denial both`. Synthetic mode validates local/cache synthetic ledger rows without upstream R2 activity. Actual-upstream mode seeds remote-only objects, imports the remote index, validates remote-only GET behavior, and checks `AccessDenied` price-budget plus `SlowDown` request-budget failures. If the local/dev provider pricing catalog is unavailable, the smoke reports the `synthetic=false` `remote_download` price-ledger assertion as catalog-gated; DB-backed coverage validates that ledger path with a seeded catalog. It no longer expects local-first PUT to create provider/vault/global spend.
- `tools/smoke/s3_gateway_e2e.sh` wraps the Playwright S3 Gateway UI suite and the existing scoped-budget smoke script. The wrapper sources the E2E env loader, starts the local web dev server when needed, attempts to enable/start the S3 gateway before declaring it unreachable, relies on Playwright global setup for browser credential seeding, runs synthetic local-only smoke by default, and runs both synthetic and actual-upstream R2/S3 smoke when remote config is present or `--require-remote` is passed.
- `tools/smoke/s3_gateway_merge_ready.sh` runs the final merge-readiness sequence and writes `test-results/s3-gateway-e2e/merge-ready-report.txt` with stage statuses, exact commands, env-source status, credential provisioning status, local/remote prefixes, and R2 cleanup result.
- Admin CLI and WebSocket scope updates can retarget the effective principal; converting a credential to `global` stamps `created_by` with the admin actor so audit metadata matches runtime global-scope validation.
- Non-admin `vault_allowlist` creation/update now requires the principal to have real access to every named vault. Boolean shorthand writes final selected-vault/default-role/per-vault role tables, and request authorization still requires the principal's matching RBAC action.
- CLI gateway budget status supports JSON output with `policies`, `ledger`, and credential-aware `trends`; combined `--key --vault` status includes both the key-wide cap and the key/vault cap.
- CLI key-only budget cap creation/disable now requires admin permission; non-admin budget management is limited to key/vault caps where the caller owns or can manage the vault. This matches the WebSocket path and lets vault managers cap another principal's gateway key on their vault without seeing that key's key-wide budget cap.
- The generic pricing WebSocket policy handler also rejects non-admin key-wide `gateway_credential` mutations so callers cannot bypass the S3 gateway management endpoint's admin-only key cap rule.
- CLI usage metadata matches the scoped credential command contract: `allow-vault` and `revoke-vault` take positional vault arguments, and JSON flags are exposed only for gateway budget commands that return JSON.
- `runtime::Deps::init()` fills missing dependency slots instead of returning early when any dependency already exists, so CLI-only test helpers that initialize `shellUsageManager` do not prevent later S3 gateway DB fixtures from initializing storage dependencies in the same test process.
- `PriceBudgetPreflightRequest` keeps the existing sync preflight initializer prefix stable and appends gateway request metadata fields afterward, avoiding feature-introduced missing-initializer warnings in non-gateway pricing paths.

## Not Implemented Or Still Shallow

- The gateway price estimate path reuses the existing provider pricing catalog and sync estimate machinery where possible; it does not reconcile against provider invoices or live billing APIs.
- Gateway preflight commits usually use the estimated cost. Actual provider billable cost can differ if the provider applies request batching, free tier rules, lifecycle behavior, or provider-side copy billing that is not represented in the catalog.
- Web UI coverage now includes a focused Playwright suite for login/auth, admin navigation, page load, credential creation, local-budget enforcement create/update, secret reveal/hide, scope edit visibility, local bucket creation, key budget save/disable, key/vault budget save, selected-credential budget filtering, ledger source display, and invalid budget feedback. It intentionally avoids full-browser coverage of every gateway control.
- Route-level gateway budget tests cover core actual-vs-synthetic accounting paths, including pure local synthetic enforcement and thread-local actual usage capture isolation. Provider-specific copy pricing can still be expanded.
- The R2-backed path is available through the opt-in smoke script when `S3_GATEWAY_SMOKE_UPSTREAM_*` configuration is present. It is skipped by default unless remote configuration exists or `--require-remote` is supplied. Live R2 price-budget ledger assertions require a local pricing catalog for `cloudflare-r2/global/standard`; without that catalog, live smoke still validates remote-only GET setup and denial status codes while DB-backed tests provide deterministic ledger evidence.
- WebSocket gateway budget management has DB-backed coverage for core policy/status flows and representative non-admin permission denials, but additional role-matrix coverage could still be expanded.
- The management page exposes the core workflows but does not yet include advanced filtering, pagination, or notification drill-down.

## Validation Run

Validation performed on 2026-06-02 for the dedicated S3 host endpoint, Cloudflare DNS-01 lifecycle support, and multipart part-directory hardening pass:

Commands and results:

```bash
meson compile -C build
meson test -C build vh_unit_tests --print-errorlogs --test-args='--gtest_filter=S3Gateway*:S3GatewayDbTest.*Multipart*:S3GatewayRouterTest.*:S3GatewaySigV4Test.*'
python3 -m unittest deploy.lifecycle.tests.test_main
pnpm --dir web run test
tools/smoke/s3_gateway_merge_ready.sh
git diff --check
```

- `meson compile -C build` passed.
- The focused S3 gateway Meson filter passed.
- `python3 -m unittest deploy.lifecycle.tests.test_main` ran 13 tests and passed.
- `python3 -m unittest tools.release.tests.packaging.test_debian_install_flow_contract tools.release.tests.packaging.test_debian_rules_contract` ran 20 tests and passed.
- `pnpm --dir web run test` passed typecheck and lint.
- `tools/smoke/s3_gateway_merge_ready.sh` passed shell syntax, Meson compile, DB-backed gateway/cost/pricing tests, web tests, Playwright S3 Gateway, local smoke, and remote smoke. The remote smoke log reported gateway cleanup and remote cleanup as `ok`.
- The merge-ready wrapper did not reach its final report/diff-check stage because the build runtime hung during FUSE shutdown after the remote smoke completed; the stuck validation runtime was terminated.
- `git diff --check` passed as a standalone command.

Exact Nginx endpoint coverage added:

- Static Nginx template no longer exposes an S3 path endpoint.
- Managed lifecycle rendering emits HTTPS `vaulthalla.dev` and `s3.vaulthalla.dev` server blocks when Cloudflare DNS-01 certificate setup is used.
- The dedicated S3 server uses `proxy_pass http://127.0.0.1:39000;` without a URI suffix and sets `X-Vaulthalla-S3-Path-Style-Only: true`.
- `ConfigProjectionTests.test_render_managed_nginx_config_includes_dedicated_https_s3_host`
- `ConfigProjectionTests.test_render_managed_nginx_config_uses_configured_s3_loopback_safe_host`
- `ConfigProjectionTests.test_render_managed_nginx_config_without_cert_does_not_emit_s3_route`
- `ConfigProjectionTests.test_cloudflare_credentials_file_requires_private_mode`
- `ConfigProjectionTests.test_request_dns_cloudflare_certificate_builds_multi_domain_command`
- `ConfigProjectionTests.test_parse_projection_uses_s3_defaults_when_section_missing`

Exact SigV4/dedicated-host coverage added:

- `S3GatewayRouterTest.DedicatedS3HostUsesPathStyleWhenProxyMarkerIsPresent`
- `S3GatewayRouterTest.ApiS3IsOrdinaryPathStyleWithoutPrefixRouting`
- `S3GatewayRouterTest.PublicHostStillTriggersVirtualHostedBucketWithoutProxyMarker`
- `S3GatewayRouterTest.FalsePathStyleOnlyMarkerLeavesVirtualHostedBucketEnabled`
- `S3GatewayDbTest.SignedDedicatedHostRootListsBuckets`
- `S3GatewayDbTest.SignedDedicatedHostPutAndGetAuthenticateAndRoutePathStyle`

Exact multipart path coverage added and run:

- `S3GatewayMultipartTest.PartRootUsesGeneratedHiddenBackingPath`
- `S3GatewayConfigTest.MultipartPartDirIsNotEmittedAndLegacyPartDirIsIgnored`
- `S3GatewayDbTest.MultipartUploadUsesOpaquePartDirAndCompleteKeepsRoot`
- `S3GatewayDbTest.AbortMultipartUploadRemovesOpaquePartDirAndKeepsRoot`
- `S3GatewayDbTest.AbortExpiredMultipartUploadsUsesConfiguredRetention`

Live dedicated-host AWS CLI smoke requires local DNS for `vaulthalla.dev` and `s3.vaulthalla.dev` plus a Cloudflare DNS-01 credentials file at `/etc/vaulthalla/certbot/cloudflare.ini`. Record whether the live smoke passed when those host prerequisites are present.

Validation performed on 2026-06-01 for the self-provisioning E2E pass:

Known env files sourced by `tools/e2e/load_env.sh`:

```text
/home/coop/.bashrc: sourced
/srv/vaulthalla/.bashrc: sourced
/srv/vaulthalla/deploy/bashrc: sourced
/srv/vaulthalla/deploy/vaulthalla.env: sourced
```

Redacted env report from `test-results/s3-gateway-e2e/env-report.txt`:

```text
VH_TEST_DB_USER: set
VH_TEST_DB_PASS: set
VH_TEST_DB_HOST: set
VH_TEST_DB_PORT: set
VH_TEST_DB_NAME: set
VAULTHALLA_TEST_R2_ACCESS_KEY: set
VAULTHALLA_TEST_R2_SECRET_ACCESS_KEY: set
VAULTHALLA_TEST_R2_ENDPOINT: set
VAULTHALLA_TEST_R2_REGION: set
VAULTHALLA_TEST_R2_BUCKET: set
VAULTHALLA_E2E_USER: missing
VAULTHALLA_E2E_PASSWORD: missing
```

Because all `VH_TEST_DB_*` variables loaded from those files, no DB setup fallback command was required. The browser suite now runs Playwright global setup, which force-seeds a fresh `e2e_s3gw_*` admin user against the local dev DB for each run and stores the generated password only in the private E2E env file. No generated credential value was printed or committed.

Commands and results:

```bash
bash -n tools/e2e/load_env.sh tools/e2e/provision_e2e_user.sh tools/smoke/s3_gateway_e2e.sh tools/smoke/s3_gateway_scoped_budget_smoke.sh
pnpm --dir web exec playwright install chromium
pnpm --dir web run typecheck
meson compile -C build
source tools/e2e/load_env.sh
meson test -C build vh_unit_tests --print-errorlogs --test-args='--gtest_filter=S3GatewayDbTest.*:S3CostSafetyTest.*Gateway*:S3PricingTest.*Gateway*'
pnpm --dir web run test:e2e:s3-gateway
tools/smoke/s3_gateway_e2e.sh --local-only
tools/smoke/s3_gateway_e2e.sh --require-remote --prefix "s3-gateway-e2e/20260601T185624Z-remote-final"
```

- Shell syntax, Playwright Chromium install, web typecheck, and `meson compile -C build` passed.
- DB-backed Meson filter ran 56 tests from `S3GatewayDbTest`, `S3CostSafetyTest`, and `S3PricingTest` with 0 failures and 0 skips.
- The direct Playwright S3 Gateway suite ran live, not `--list`; Playwright auto-started the Next dev server for `http://127.0.0.1:3000`, force-seeded a per-run local dev admin user, and reported 10 passed tests.
- The earlier local wrapper run started the web server, provisioned E2E credentials, ran Playwright with 7 passed tests before the final browser coverage additions, ran local S3 smoke, and cleaned up prefix `s3-gateway-e2e/20260601T185535Z-683559/local` for bucket `vh-smoke-local-684480`.
- The earlier remote wrapper run started the web server, ran Playwright with 7 passed tests before the final browser coverage additions, ran local smoke, ran R2 remote-cache smoke using prefix `s3-gateway-e2e/20260601T185624Z-remote-final/remote` and bucket `vh-smoke-remote-685504`, and reported remote cleanup `ok`.
- A post-run R2 prefix check for `s3-gateway-e2e/20260601T185624Z-remote-final/remote/` returned `remote_prefix_object_count=0`.
- The old remote PUT budget-denial loop has been replaced. Current smoke validation uses deterministic synthetic local/cache denial by default and actual-upstream remote GET denial when R2 env is available.

## Next Hardening Steps

1. Expand WebSocket role-matrix tests for delegated vault admin roles beyond owner/super-admin cases.
2. Add provider-specific copy-object pricing refinements if catalogs expose provider-side copy pricing separately from GET plus PUT estimates.
3. Add deeper browser coverage for permission-denied role states if those workflows start changing frequently.

## Deferred Cleanup Notes

- Consider a future v1.6 fresh-install schema baseline cleanup after S3 Gateway ships and the migration boundary is stable.
- Keep vault slug/display-name cleanup deferred to a separate pass; this release cleanup does not add slug columns or change vault display-name behavior.
