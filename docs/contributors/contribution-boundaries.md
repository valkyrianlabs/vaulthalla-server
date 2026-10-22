---
title: Contribution Boundaries
description: Contribution policy map for safe Vaulthalla changes.
order: 910
status: published
tags:
  - contributors
---

# Contribution Boundaries

This guide is the policy map for where contributors can move quickly, where discussion should happen first, and where the maintainer needs to stay in the loop.

The point is not to keep people out. The point is to keep sharp systems boring, safe, and reviewable.

## The Four Categories

### 1. Open contribution areas

Good areas for new contributors, assuming the work is scoped, behavior-preserving, and validated.

Examples:

- contributor docs
- typo fixes
- usage examples
- CLI help text
- small copy improvements
- logging or error message clarity
- narrowly scoped, behavior-preserving test cleanup

### 2. Coordinate before implementing

These areas are open to contribution, but significant implementation work should start with alignment.

Typical reasons:

- the work changes user-facing behavior
- the work affects install/operator workflows
- the change may be bigger than it first appears
- the subsystem has hidden edge cases

### 3. Maintainer-guided areas

These areas touch core correctness, data safety, runtime lifecycle, or long-term architecture.

Work here is still welcome, but the right sequence is:

1. discuss the change
2. agree on scope
3. implement narrowly

Do not show up with a giant uncoordinated rewrite in these areas and expect it to merge.

### 4. Security-sensitive or restricted work

If the work touches auth bypasses, privilege escalation, RBAC, crypto, secrets, local trust boundaries, TPM/swtpm, or privileged package behavior, read [Security-Sensitive Work](/contributors/security-sensitive-work) first.

Some of that work should begin as a private report, not a public PR.

## Area Map

| Area | Paths | Contribution model | Good contributor work | Requires maintainer alignment |
| --- | --- | --- | --- | --- |
| Contributor and repo docs | `docs/contributors/`, `CONTRIBUTING.md`, `README.md`, `DISTRIBUTION.md` | Open contribution area | Clarity fixes, onboarding docs, better cross-links, command spelling checks | Claims about unreleased infrastructure, unsupported platforms, or undocumented behavior |
| CLI usage and manpage text | `core/usage/*`, `core/main/usage.cpp` | Open contribution area | Help text, usage examples, wording cleanup, docs for existing commands | New commands, changed semantics, lifecycle command behavior |
| Small web/admin polish | `web/src/components/*`, `web/src/app/(app)/*` | Coordinate before implementing | Copy polish, empty-state clarity, small visual cleanup, non-behavioral UX fixes | New admin flows, websocket/API changes, auth/session behavior, new operator workflows |
| Focused test and validation work | `core/tests/*`, `deploy/lifecycle/tests/*`, `tools/contracts/*`, `tools/dev/verify.sh` | Open contribution area | Behavior-preserving cleanup, narrow fixture updates, targeted missing coverage | Broad test rewrites, new infrastructure assumptions, churn-heavy fixture resets |
| Preview and thumbnail behavior | `core/src/preview/*`, `core/include/preview/*`, `core/tools/*`, `web/src/features/files/preview/*` | Coordinate before implementing | Focused bug reports, narrow fixes with proof, UI copy around previews | Format support changes, caching behavior, thumbnail pipeline semantics |
| Storage provider work | `core/src/storage/*`, `core/include/storage/*`, `core/src/vault/model/*`, `core/tests/helpers/live_bucket.hpp` | Coordinate before implementing | Focused provider fixes, validation docs, narrow error handling improvements | Provider auth flow changes, remote data semantics, compatibility changes |
| Packaging and lifecycle | `debian/*`, `deploy/systemd/*`, `deploy/lifecycle/*`, `bin/install.sh`, `bin/uninstall.sh`, `bin/setup/*`, `bin/teardown/*` | Coordinate before implementing | Docs, validation improvements, conservative bug fixes with install/remove notes | Install, upgrade, remove, purge behavior; service startup/shutdown; nginx/Certbot; TPM bootstrap; operator-visible lifecycle changes |
| Core runtime orchestration | `core/main/main.cpp`, `core/src/runtime/*`, `core/src/protocols/*` | Maintainer-guided area | Focused diagnostics and carefully scoped fixes after discussion | Watchdog behavior, service lifecycle, protocol contracts, shutdown/restart behavior |
| FUSE and filesystem semantics | `core/src/fuse/*`, `core/include/fuse/*`, `core/src/fs/*`, `core/include/fs/*` | Maintainer-guided area | Narrow fixes after design alignment, additional validation notes | Mutation behavior, path/inode mapping, cache invalidation, mount behavior, trust boundaries |
| Database schema and query layer | `deploy/psql/*`, `core/src/db/*`, `core/include/db/*` | Maintainer-guided area | Audits, docs, tightly scoped fixes after discussion | Schema changes, migration ordering, retention semantics, query contract changes |
| Sync engine | `core/src/sync/*`, `core/include/sync/*` | Maintainer-guided area | Diagnostics, targeted fixes with strong repro and validation | Conflict resolution, remote/local policy changes, key rotation, deletion/download/upload semantics |
| Auth, RBAC, crypto, secrets, TPM | `core/src/auth/*`, `core/src/rbac/*`, `core/src/crypto/*`, `core/include/auth/*`, `core/include/rbac/*`, `core/include/crypto/*`, `web/middleware.ts`, `web/src/lib/session.ts`, `deploy/systemd/vaulthalla-swtpm.service.in` | Security-sensitive or restricted work | Documentation, approved hardening, tests, threat-model clarifications | Public exploit details, bypass fixes without prior coordination, secret-handling changes, token/session changes, TPM backend behavior |
| Release process and publication | `release.toml`, `.release/*`, `.github/workflows/release.yml` | Maintainer-guided area | Package contract and contract-test improvements, release notes for your change | Publication policy, Nexus/GitHub release behavior, versioning contract changes |

## Good First PR Shapes

Good PRs usually look like this:

- one doc area improved, with links checked and claims verified against the repo
- one CLI help or usage cleanup, with the affected help text reviewed
- one focused web/admin polish change, with `pnpm test` run
- one targeted packaging or lifecycle fix, discussed first, with install/remove validation notes
- one narrow test improvement that preserves existing behavior

## Bad PR Shapes

Bad PRs usually look like this:

- a 2,500-line cross-cutting refactor with a vague title and no migration story
- a generated rewrite of runtime, permissions, and packaging code in one shot
- a schema change, auth tweak, and UI flow update bundled into the same PR
- a FUSE behavior change with no Linux runtime validation
- a public security PR that includes exploit details before any private coordination

## How To Choose Work

For early contributors:

1. start with the roadmap
2. pick something scoped
3. read the area map above
4. validate it properly

If your idea is not on the roadmap, open an issue first.

## Ownership And Independence

Contributors who consistently ship good work may get more room to scope and drive work independently.

That does not remove the need for alignment in sharp areas. Even trusted contributors should coordinate before changing filesystem semantics, auth boundaries, crypto behavior, package lifecycle contracts, or release publication flows.

Vaulthalla welcomes contributors. It does not reward chaos.
