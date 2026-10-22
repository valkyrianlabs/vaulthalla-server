---
title: Validation Guide
description: Contributor validation guidance for Vaulthalla changes.
order: 960
status: published
tags:
  - contributors
  - validation
---

# Validation Guide

This is the "what should I run before opening a PR?" guide.

Run the narrowest checks that actually prove your change. Then be honest about what you did and did not validate.

## Quick Reality Check

Useful repo helpers:

```bash
bash tools/dev/verify.sh doctor      # toolchain and version-pin sanity
bash tools/dev/verify.sh             # infer checks from your uncommitted changes
bash tools/dev/verify.sh web         # typecheck + lint
bash tools/dev/verify.sh release     # version drift + release-tooling tests
bash tools/dev/verify.sh packaging   # packaging contracts, lab and board tooling tests (needs python3-yaml)
bash tools/dev/verify.sh all         # everything except the destructive integration harness
```

These profiles are helpful shortcuts, not a substitute for subsystem-specific judgment.

## Docs-Only Changes

Docs are validated in the release pipeline with `pmdocs validate --source docs`. Locally, run:

```bash
bash tools/dev/verify.sh docs   # Payload Markdown checks on changed pages, then pmdocs validate when installed
```

For docs-only PRs, do this at minimum:

- verify every command against the repo
- verify every referenced path exists
- avoid claims about infrastructure or workflows that are only planned
- read the rendered markdown in your editor and check relative links

If the change is truly docs-only, code tests are usually not required.

The docs checks validate structure and directives. They do not prove that commands, paths, or described behavior are correct, so that review is still on you.

## Web And Frontend Changes

Run:

```bash
cd web
pnpm test
```

That runs the repo's web check path:

- `pnpm run typecheck`
- `pnpm run lint`

Useful extra validation:

```bash
cd web
pnpm dev
```

Use that for manual checks when you changed UI behavior.

You can also run the repo helper from the root:

```bash
bash tools/dev/verify.sh web
```

## S3 Gateway Browser And Smoke Validation

The S3 Gateway E2E harness sources the standard local/dev env files before it reports missing DB, R2, or browser-login settings:

```bash
source tools/e2e/load_env.sh
vh_e2e_redacted_env_report
```

The loader reads, when present:

- `$HOME/.bashrc`
- `./.bashrc`
- `./deploy/bashrc`
- `./deploy/vaulthalla.env`

The redacted report shows whether `VH_TEST_DB_*`, `VAULTHALLA_TEST_R2_*`, and `VAULTHALLA_E2E_*` are set without printing secret values.

The focused browser suite can auto-start the local Next dev server when the base URL is localhost and `VAULTHALLA_E2E_NO_WEB_SERVER` is not set:

```bash
pnpm --dir web run test:e2e:s3-gateway
```

The Playwright suite seeds its own admin login during global setup. For local/dev runs it assumes the Vaulthalla backend is already running in dev mode, creates a fresh `e2e_s3gw_*` admin user in the configured local dev DB, exports the generated username/password to the test workers, and stores the password only under `test-results/s3-gateway-e2e/e2e.env` with private permissions. Set `VAULTHALLA_E2E_SKIP=1` only when you are intentionally skipping the browser suite.

For data-plane validation, use the smoke wrapper:

```bash
tools/smoke/s3_gateway_e2e.sh
```

The wrapper sources the env loader, starts the web dev server when needed, attempts to enable/start the S3 gateway before declaring it unreachable, runs the self-seeding Playwright S3 Gateway suite, and then runs `tools/smoke/s3_gateway_scoped_budget_smoke.sh --local-only`. Set `S3_GATEWAY_ENDPOINT` when the gateway is not on `http://127.0.0.1:39000`.

Useful wrapper options:

```bash
tools/smoke/s3_gateway_e2e.sh --local-only
tools/smoke/s3_gateway_e2e.sh --no-start-web
tools/smoke/s3_gateway_e2e.sh --keep-processes
tools/smoke/s3_gateway_e2e.sh --web-timeout 180
```

Remote R2/S3 validation is opt-in:

```bash
tools/smoke/s3_gateway_e2e.sh --require-remote --prefix vh-test-runs/manual-$$-$(date -u +%s)/s3-gateway-e2e
```

Remote smoke uses the shared live test bucket (`VAULTHALLA_TEST_R2_*`) and a prefix under `vh-test-runs/`. It deletes only the unique prefix it was given. If cleanup fails, the script prints the exact prefix to remove manually.

The scoped smoke has explicit budget-denial modes:

```bash
tools/smoke/s3_gateway_scoped_budget_smoke.sh --budget-denial synthetic
tools/smoke/s3_gateway_scoped_budget_smoke.sh --require-remote --budget-denial actual-upstream
tools/smoke/s3_gateway_scoped_budget_smoke.sh --require-remote --budget-denial both
```

Use `synthetic` for deterministic local validation. It enables `enforce_budget_for_local_requests`, uses nominal gateway-local synthetic rates, and asserts local/cache ledger rows have `synthetic=true`. Use `actual-upstream` only with remote env available; it seeds remote-only objects, imports the remote index, validates remote-only GET behavior, and checks `AccessDenied` price-budget plus `SlowDown` request-budget denial. If the local/dev pricing catalog for the live provider is unavailable, the smoke reports that `synthetic=false` `remote_download` price-ledger capture is catalog-gated; the DB-backed accounting tests cover that ledger assertion with a seeded catalog. Do not use a local-first PUT loop as proof of upstream provider spend.

For final S3 Gateway merge readiness, run:

```bash
tools/smoke/s3_gateway_merge_ready.sh
```

The wrapper runs shell syntax checks, `meson compile -C build`, the DB-backed S3 gateway/cost/pricing filter, web unit tests, Playwright S3 Gateway E2E, local smoke, remote smoke when R2 env exists, and `git diff --check`. It writes `test-results/s3-gateway-e2e/merge-ready-report.txt` with pass/fail per stage, exact commands, env-source status, E2E credential status, smoke prefixes, and R2 cleanup result.

Do not report "DB env missing", "E2E credentials missing", "web stack unreachable", or "S3 gateway unreachable" until the loader, provisioner, and startup attempts above have run and their redacted diagnostics/log paths are captured.

## C++ Core Changes

Use the CI-style Meson build path:

```bash
meson setup build --buildtype=debug -Dbuild_unit_tests=true -Dinstall_data=false
meson compile -C build
meson test -C build
```

If your change is in core code and you did not build it on Linux, say so.

### Zero-Warning Builds On Both Platforms

Every pushed C++ change must configure and build on Linux and macOS with nothing but progress output:

```bash
meson setup build -Dwerror=true -Dbuild_unit_tests=true 2>&1 | tee setup.log     # macOS: source tools/macos/env.sh first
bash tools/dev/quiet-build.sh build setup.log
```

CI runs the same check on both platforms and fails on any warning, note or Meson deprecation. If you only have one platform, say which one you built on; CI covers the other. See [Builds Must Be Silent](/contributors/development-setup#builds-must-be-silent).

## macOS Service And Package Changes

For `deploy/launchd/*` or `tools/macos/pkg/*`:

```bash
python3 -m unittest tools/contracts/test_macos_launchd_contract.py tools/contracts/test_macos_caddy_contract.py
tools/macos/candidate.sh stage && tools/macos/candidate.sh pkg
sudo tools/macos/candidate.sh accept
```

The contract tests run the real scripts against stubs and also run on Linux CI. Only the last command installs the package as the real system service and proves it end to end (account and permissions, the LaunchDaemons, an encrypted vault, crash and database-outage recovery, CLI access, `vh setup caddy`, an upgrade). Do it on a Mac you may change.

## FUSE And Filesystem Changes

FUSE work needs more than a compile.

Use the Linux integration path when possible:

```bash
make itest
```

Also capture the manual behavior you checked, for example:

- mount comes up cleanly
- file operations behave as expected
- unmount and shutdown behavior are sane
- no obvious regressions in permissions or cache behavior

FUSE changes without Linux runtime validation are incomplete.

## CLI Changes

If you changed CLI parsing, usage text, shell protocol behavior, or lifecycle commands:

```bash
meson setup build --buildtype=debug -Dbuild_unit_tests=true -Dinstall_data=false
meson compile -C build
make itest
```

For help or manpage-related work, also inspect the affected usage definitions under `core/usage/*` and confirm the output is coherent.

## Packaging Changes

Run:

```bash
bash tools/dev/verify.sh release packaging
make deb   # local release rehearsal: builds and validates the package from a worktree of HEAD (commit first)
```

Then describe the lifecycle validation you performed:

- install
- upgrade if relevant
- remove
- purge
- service start and stop behavior
- config and local-state preservation

If you did not test package lifecycle on a Linux host or VM, say so.

## Database Or Schema Changes

Schema and DB-layer changes need more than "the SQL looked fine."

At minimum:

```bash
make itest
make test
```

If packaging or release behavior is involved, also run:

```bash
bash tools/dev/verify.sh packaging
make deb
```

Use a disposable PostgreSQL-backed environment when you can. Document migration or upgrade assumptions clearly.

## Security-Sensitive Changes

Before you even get to validation, read [Security-Sensitive Work](/contributors/security-sensitive-work).

If the change was approved for public work, do not rely on partial validation. Sensitive changes should include:

- focused tests or reproducible manual checks
- clear impact description
- explicit note about anything you could not validate

## Release Changes

Releases use [vl-release](https://github.com/valkyrianlabs/vl-release) (`vlr`), configured by `release.toml`. Run:

```bash
bash tools/dev/verify.sh release    # vlr check + vlr version check
vlr prepare --dry-run               # preview the release notes and Debian changelog entry
```

If the change affects packaging outputs, add `make deb`.

Changes users or operators would notice also update `.release/RELEASE_NOTES_NEXT.md`, and packaging-facing ones
`.release/CHANGELOG_NEXT.md`, in the same pull request. Never edit `debian/changelog`, `RELEASE_NOTES.md` or version
numbers by hand.

## What To Put In The PR

A good validation note says:

- what you changed
- what commands you ran
- what manual checks you performed
- what you could not test

Examples:

- "Docs-only. Verified all commands and paths against the repo. No code paths changed."
- "Ran `cd web && pnpm test` and manually checked the updated admin page under `pnpm dev`."
- "Ran `make test` and `make itest` on Linux. Did not validate upgrade behavior."

That level of honesty is enough. Hand-wavy claims are not.
