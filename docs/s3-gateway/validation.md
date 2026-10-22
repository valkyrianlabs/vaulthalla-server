---
title: S3 Gateway Validation
description: Run focused web, local smoke, remote R2/S3 smoke, and merge-ready validation for Vaulthalla S3 Gateway.
order: 70
status: published
tags:
  - s3-gateway
  - validation
  - smoke
  - playwright
---

# S3 Gateway Validation

Use focused validation for S3 Gateway changes. Do not run live remote smoke unless the environment is configured for it or the validation pass explicitly requires it.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Web And Local Smoke

For local/dev validation from the repo root:

```bash
tools/smoke/s3_gateway_e2e.sh --local-only
```

The wrapper sources known local environment files, starts the web dev server when needed, attempts to enable and start the S3 Gateway service before failing reachability, runs the self-seeding Playwright S3 Gateway suite, and then runs local S3 smoke.

The browser suite creates a fresh `e2e_s3gw_*` admin user during global setup for local/dev validation and stores the generated password under `test-results/s3-gateway-e2e/e2e.env` with private permissions.

## Remote R2/S3 Smoke

Remote-backed smoke runs when remote env is present or required explicitly:

```bash
tools/smoke/s3_gateway_e2e.sh --require-remote --prefix s3-gateway-e2e/manual-$(date -u +%Y%m%dT%H%M%SZ)
```

The remote smoke uses a unique prefix and reports cleanup status. It deletes only the supplied prefix. If cleanup fails, it reports the prefix and exits non-zero.

## Budget-Denial Smoke

The scoped smoke supports explicit budget-denial modes:

```bash
tools/smoke/s3_gateway_scoped_budget_smoke.sh --budget-denial synthetic
tools/smoke/s3_gateway_scoped_budget_smoke.sh --require-remote --budget-denial actual-upstream
tools/smoke/s3_gateway_scoped_budget_smoke.sh --require-remote --budget-denial both
```

Synthetic mode uses local/cache gateway requests with `enforce_budget_for_local_requests` and does not require upstream R2 activity.

Actual-upstream mode seeds remote-only objects, imports their metadata into the remote index, validates remote-only GET behavior, and checks both `AccessDenied` price-budget and `SlowDown` request-budget denial paths. When the local pricing catalog for the live provider is unavailable, the smoke reports the actual remote-download price-ledger assertion as catalog-gated; DB-backed tests cover that ledger path with a seeded catalog.

No smoke test expects local-first PUT or DELETE to create provider, vault, or global upstream spend at gateway request time.

## Merge-Ready Command

For final branch validation:

```bash
tools/smoke/s3_gateway_merge_ready.sh
```

The wrapper writes `test-results/s3-gateway-e2e/merge-ready-report.txt` with pass/fail status, exact commands, environment-source status, credential provisioning status, local/remote smoke prefixes, and R2 cleanup result.

## Docs-Only Validation

For docs-only changes to this category, run:

```bash
pmdocs validate --source main-docs
pnpm --dir web run typecheck
git diff --check
```

Run additional gateway smoke only when the docs change is coupled to runtime behavior, client examples need live verification, or release validation requires it.
