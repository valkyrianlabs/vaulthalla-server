# Vaulthalla

A Linux-native, self-hosted cloud: a C++23 daemon with a native FUSE filesystem, encrypted vaults (AES-256-GCM,
TPM2/swtpm-sealed secrets), RBAC, local and S3/R2 storage with cost guardrails, an S3-compatible gateway,
a `vh` CLI over a unix socket, and a packaged Next.js web console. It ships as a single Debian package
`vaulthalla` from `apt.vaulthalla.sh`. It was built mostly by hand by one maintainer (Cooper). Version: `VERSION` (kept in sync by `vlr version`).

**Current phase: production hardening.** The build → package → publish → install/upgrade → run pipeline
has to become trustworthy on real hosts. Start with `.claude/context/production-hardening.md`: it has a
live P0 (the DB pool wedges after a PostgreSQL restart, which hangs FUSE and `apt upgrade`) plus the backlog.

## Map

| Path | What | Deep context |
|---|---|---|
| `core/` | C++ daemon `vaulthalla-server`, CLI `vaulthalla-cli`, `usage/` (help + manpages), `tests/{unit,integrations}`, `tools/` (sandboxed preview helpers shipped as optional packages `vaulthalla-preview-{cad,media}`) | `.claude/context/architecture.md` |
| `web/` | Next.js 16 / React 19 console: typed ws client + TanStack Query, `components/ui` design system, hard per-route JS budgets | `.claude/context/web-client.md` |
| `deploy/` | runtime config, `psql/000…107` migrations, systemd units, nginx template, `lifecycle/` (Python behind `vh setup/teardown`) | `.claude/context/packaging-lifecycle.md` |
| `debian/` | package metadata + maintainer scripts (the lifecycle source of truth) | `.claude/context/packaging-lifecycle.md` |
| `release.toml`, `.release/` | vl-release (`vlr`) contract: versions, Debian package contract, APT publication; staged release notes + changelog for the next release | `.claude/context/release-pipeline.md` |
| `.github/` | `build_and_test.yml`, `release.yml` (a thin `vlr` transaction), composite actions, self-hosted runners | `.claude/context/release-pipeline.md` |
| `bin/` | source install/uninstall/test-env scripts (dev helpers, **not** apt semantics) | `.claude/context/testing.md` |
| `docs/` | operator docs (Payload Markdown, published by `pmdocs`) | `.claude/context/docs-authoring.md` |
| `tools/{smoke,e2e,dev}` | S3 gateway smoke, Playwright env, share preview smoke, `dev/verify.sh` (shared verification entrypoint) | `.claude/context/testing.md` |
| `tools/contracts/` | product contracts (Debian packaging, maintainer scripts, shipped migrations, release workflow) | `.claude/context/packaging-lifecycle.md` |
| `.github/project/`, `tools/project/` | Roadmap board schema (fields, `area:*` labels, views, Ready gate) + `board.py` reconcile/migrate/lint | `.claude/context/project-board.md` |
| `tools/harness/` | Tier B integration engine: private daemon instances, multi-surface seeded sessions, oracle/parity/canary judges, trace replay/shrink, regressions, fault fixtures, agent gateway | `.claude/context/testing.md` |
| `tools/lab/` | real-host tooling: ws client, CLI↔web parity smoke, ws churn, `lab_smoke` (real-apt upgrade check), TEST-ONLY S3/R2 credential scaffold, `pentest/` (seed/verify/publish/reset a synthetic authorized-pentest fixture; seeding mutates the lab) | `.claude/context/phase1-results.md` |

Phase 1 (packaging/upgrade/release hardening) results and how candidates are proven on the lab: `.claude/context/phase1-results.md`.
Phase 2 (one CLI/web operation layer, security fixes, v1.8.0 candidate) lab matrix and open items: `.claude/context/phase2-results.md`.
Web console overhaul + dogfood (design system, data layer, budgets, e2e suites, bugs filed): `.claude/context/web-dogfood-results.md`.
Other context: `.claude/context/environment.md` (VM topology: this box, the lab, dev-db, price bot), `link-sharing.md`
(share model, invariants, open gaps), `history/stats-dashboard.md` (dashboard design log).
`.claude/scratch/` is gitignored working notes, including the pre-migration Codex archive. Use it for
in-flight plans; promote durable facts into `.claude/context/`.

## Commands

```bash
meson setup build -Dbuild_unit_tests=true && meson compile -C build   # core: unity, -O0 (= PR CI; packages are -O3); `make build` is broken (conan)
meson test -C build --print-errorlogs                                 # unit tests (DB-backed: see testing.md)
make test && make itest                                               # DB-backed unit tests + Tier A proofs, isolated (sudo; never touch the dev install)
sudo tools/harness/vhh.sh run --target launch --build build           # Tier B multi-surface engine (see testing.md)
pnpm --dir web typecheck && pnpm --dir web lint                       # web ("pnpm test" = the same two)
vlr check && vlr version check                                        # release contract + version drift (VERSION/meson/package.json)
bash tools/dev/verify.sh [profiles]               # surface-aware verification (see /verify)
bash .claude/skills/lab/scripts/inspect.sh                            # read-only lab health snapshot (see /lab)
```

Skills: `/verify` (proof per surface), `/lab` (vh-storage procedures and FUSE hazards), `/vl-release` (staged release docs,
versions, cutting releases), `payload-markdown` + `payload-markdown-docs` (doc authoring; vendored by `pmdocs install skill --claude`).

## Hard rules

- **Never kill by substring** (`pkill -f`, `pgrep -f vaulthalla`, `killall`, `fuser -k`). IDE/agent processes
  carry `/srv/vaulthalla` in argv. Stop exact systemd units. `vaulthalla*` unit globs also match
  `vaulthalla-price-bot.service` on this VM (the separate price-bot repo that drives S3 cost estimates).
- **Anything touching `/mnt/vaulthalla` can block forever** if the daemon is wedged. Use `timeout`, prefer
  `/proc/self/mountinfo` and fusectl counters, and use `df -x fuse.vaulthalla-fuse`.
- **vh-storage is production.** Read-only inspection is fine. Every mutation (install, restart, dpkg,
  DB, unmount, kill) needs explicit approval in the current conversation. See `/lab`.
- **Destructive local commands need a heads-up:** `make dev|uninstall|clean-full` tear down or replace
  the live dev install on this VM. This VM is disposable, but say what you're about to wipe. Tests (`make test`,
  `make itest`, `tools/harness`) are isolated and need no heads-up; root-only harness settings live in
  `/var/lib/vaulthalla-harness/db.env`, never printed.
- **Secrets on disk, never print or commit them:** repo-root `.bashrc`, `deploy/vaulthalla.env`, `deploy/bashrc`,
  `/etc/vaulthalla/vaulthalla.env`, `cloudflare.ini`, `config.yaml` at the repo root (gitignored override). Source them; don't cat them.
- **No tags, pushes, releases, or workflow dispatches** without explicit instruction. A `v*` tag publishes to the real APT repo.
- **Release history and versions are vl-release's:** never hand-edit `debian/changelog`, `RELEASE_NOTES.md` or version
  numbers (`vlr version`). Material changes update `.release/RELEASE_NOTES_NEXT.md` and `.release/CHANGELOG_NEXT.md` in
  the same change (see `/vl-release`); run `vlr check` before calling substantial work done.
- **Unity build:** no new file-scope `using namespace` in `core/src/**/*.cpp`, keep `LC_ALL=C sort` source
  discovery, and never weaken unity/warning flags to get green.
- **Maintainer scripts:** idempotent, never overwrite `/etc/vaulthalla/config.yaml`, never destructively reset
  DB/nginx/TPM/web cache on upgrade, tolerate every Recommends being absent, and never block indefinitely.
- **Migrations:** new `deploy/psql/NNN_*.sql` takes the next number and must be safe on upgraded installs.
- **HTTP upload staging through FUSE (`.upload-http-*.part`) is intentional.** Don't move it out of FUSE.
- **Share overwrite goes through filesystem RBAC** (`FilesystemAction::Overwrite`), never a share-only shortcut.
- **Stats never fake health.** Unknown values are `null`/`"not_available"`, and the backend owns severity.

## Working conventions

- Root-cause first: find where state diverges, fix it at the source, and add a regression guard (test or contract check).
- Forward-declare through the subsystem's `Fwd.hpp` (e.g. `identities/Fwd.hpp`, `<pqxx/types>`), not ad hoc
  `namespace vh::x { struct Y; }` blocks (see architecture.md, Build graph).
- Run the proof for the surface you touched (`/verify`), and report exactly what ran, what passed, and what was skipped.
  Runtime/packaging changes aren't proven by unit tests alone. Say whether a lab install was done.
- Keep `.claude/context/*` true. When code changes a fact recorded there, update the doc in the same change.
- Handoff format: **Outcome**, **Scope** (files/subsystems and why), **Validation** (commands + results), **Risks**,
  **Next action**.
- The review hotspots, in order, are: behavior regressions; auth/RBAC/share scoping; FUSE and DB-pool blocking paths;
  maintainer-script idempotency and upgrade safety; secret handling; unity-build namespace leaks; ws command
  typing (`WebSocketCommandMap`) kept in sync with core handlers.
