---
title: Development Setup
description: Local development setup for Vaulthalla contributors.
order: 930
status: published
tags:
  - contributors
  - development
---

# Development Setup

This guide is for contributors getting from clone to useful local work.

If you are doing docs-only work, you do not need a runtime environment. If you are touching the core daemon, you need Linux or a Mac; if you are touching FUSE, Debian packaging, systemd, TPM/swtpm or the Linux install lifecycle, you need Linux.

## Platform Assumptions

The core builds and its unit tests run natively on Linux (GCC, libstdc++) and on Apple Silicon Macs (Apple clang, libc++). OS-specific code lives behind small seams in `core/include/platform` with `linux` and `darwin` implementations chosen by Meson, so one code base serves both.

| Area | Where it can be validated |
| --- | --- |
| Core daemon logic, storage, sync, auth, RBAC, protocols | Linux or macOS (`meson test`) |
| FUSE behavior | Linux (the macOS package has no FUSE bridge) |
| Debian packaging and maintainer scripts | Linux |
| systemd units, TPM/`swtpm`, `make test` / `make itest` harness | Linux |
| launchd units, `vaulthalla-provision`, `vaulthalla-caddy`, the macOS package | macOS (contract tests also run on Linux CI) |
| Web console | Either |

Debian and Ubuntu-style environments remain the reference: the integration harness, the Debian package and the release pipeline assume `apt`, `sudo` and systemd. A green macOS build does not validate Linux-only behavior, and the reverse is also true.

## Quick Health Check

From the repo root:

```bash
bash tools/dev/verify.sh doctor
```

The `doctor` profile checks for `git`, `python3`, `node`, `pnpm`, `meson`, and `ninja`, flags Node and pnpm versions that drift from `web/.nvmrc` and the `packageManager` pin, and reports a missing `web/node_modules`, missing private web icons, an unconfigured `build/` directory, and release-version drift.

## Toolchains

### Streamlined local install via `Makefile`

If you want the repo's higher-level entrypoints instead of driving the scripts manually, the top-level `Makefile` is the streamlined route.

Common targets:

```bash
make install
make dev
make test
make itest
make clean-test
make clean
```

What they do at a high level:

- `make install` runs the normal install guard, then `./bin/install.sh` (the production install; Linux only, as before)
- `make dev` runs `./bin/uninstall.sh`, then the install guard, then `./bin/install.sh`, all for the isolated dev
  instance (see below); `make dev-plan` prints what it would do, `make dev-uninstall` removes the dev instance
- `make test` runs the DB-backed unit tests against a database created for that run, then drops it
- `make itest` runs the integration proofs as a private daemon instance (own database, paths and FUSE mount)
- `make clean-test` removes leftovers of interrupted test runs, nothing else

`make install` and `make dev` are host-mutating install workflows. The test targets are not: they never install
anything, never change the development install, and never touch a database they didn't create. They need a one-time
`sudo tools/harness/bootstrap.sh` and passwordless sudo.

### Web/admin work

The web client uses:

- Node pinned by `web/.nvmrc` (`24.13`)
- `pnpm`
- Next.js, React, TypeScript, ESLint

Setup:

```bash
cd web
pnpm install --frozen-lockfile
pnpm test
pnpm dev
```

### Release work

Releases use [vl-release](https://github.com/valkyrianlabs/vl-release) (`vlr`), installed from the ValkyrianLabs APT
repository (`sudo apt install vl-release`). `release.toml` configures it; the repository needs no Python packages.

```bash
vlr doctor
vlr check
vlr status
```

### Core/runtime work

For Linux contributors on a machine or VM you are comfortable modifying, the repo provides an install-deps helper:

```bash
./bin/setup/install_deps.sh
```

That script configures the Valkyrian Labs APT repository (`apt.valkyrianlabs.com`) and installs native dependencies such as Meson, Ninja, PostgreSQL, FUSE, `libsodium`, `libtss2`, `swtpm`, and related packages. The two Vaulthalla-built SDKs come only from that repository: `libpdfium-dev` (PDFium) and `libpqxx-vh-dev` (a static libpqxx 8 build; the package build links it in, so servers need only `libpq5`). Ubuntu's `libpqxx-dev` is not used.

Run it deliberately. It changes the host.

## Preferred Dev Workflow

The fastest rebuild-and-reinstall loop in this repo is the dev workflow behind `make dev`.

It installs an **isolated dev instance** (meson `-Dinstance=dev`, `bin/lib/platform.sh`) that can sit beside a
production install on the same host and never touches it:

| | Production | Dev instance |
|---|---|---|
| Linux prefix | `/usr` | `/opt/vaulthalla-dev` |
| Linux paths | `/etc`, `/var/lib`, `/var/log`, `/run` `…/vaulthalla`, `/mnt/vaulthalla` | `…/vaulthalla-dev`, `/mnt/vh_dev` |
| Linux units | `vaulthalla.service`, `-web`, `-swtpm` | `vaulthalla-dev.service`, `-web`, `-swtpm` (swtpm on 2421) |
| macOS prefix | the package (`/usr/local`) | `/usr/local/vaulthalla-dev` |
| macOS paths | `/Library/Application Support/Vaulthalla`, `/Library/Logs/Vaulthalla` | `…/Vaulthalla-dev` |
| macOS daemons | `sh.vaulthalla.{server,web}` | `sh.vaulthalla.dev.{server,web,postgres}` |
| Account | `vaulthalla` (macOS `_vaulthalla`) | `vaulthalla-dev` (macOS `_vaulthalla_dev`) |
| Database | `vaulthalla` | `vaulthalla_dev` (macOS: its own cluster on 127.0.0.1:5532) |
| Ports | web 36968, ws 36969, http 36970, s3 39000 | +100 |
| CLI | `vh` | `vh-dev` |

It is fast because it starts from a fresh dev instance every time: `make dev` begins by running `./bin/uninstall.sh`,
which wipes the dev instance's directories, database and account (and only those) with no interactive warning once
dev mode is active. The vaulthalla.dev nginx endpoint (`bin/setup/install_dev_nginx.sh`) belongs to production and is
skipped for the instance. `VH_INSTANCE= make dev` restores the old behavior (a dev build installed over production's
paths) on a box where that is what you want.

On macOS, `make dev` is the only source install: production comes from the installer package or the Homebrew cask.
It needs Homebrew (`tools/macos/bootstrap.sh` runs as you), `node` and `pnpm`, and sudo for the privileged steps;
`make dev-plan` (`VH_DRY_RUN=1`) prints every privileged command without running any of them.

### Dev mode guardrails

The repo requires two guardrails before the destructive dev workflow is considered valid:

1. set `VH_BUILD_MODE=dev`
2. create a repo-root sentinel file named `enable_dev_mode` whose contents are exactly `true`

Example:

```bash
export VH_BUILD_MODE=dev
printf 'true\n' > enable_dev_mode
make dev
```

This behavior is enforced by `bin/lib/dev_mode.sh`. If `VH_BUILD_MODE=dev` is set without the sentinel, the scripts fail. If the sentinel exists but `VH_BUILD_MODE` is not `dev`, the scripts warn about the mismatch.

If you use this workflow, do it on a machine or VM where destroying the local Vaulthalla install is acceptable.

### Custom install path

If you want the same install plumbing without using the `Makefile`, the equivalent lower-level path is:

```bash
./bin/install.sh
```

For destructive dev-mode reinstall behavior, the `Makefile` target is just wrapping:

```bash
./bin/uninstall.sh
./bin/install.sh
```

## Core Build Path

The current CI-style core build path is Meson-based:

:::tabs{default="linux"}

:::tab[Linux]{value="linux"}
```bash
meson setup build --buildtype=debug -Dwerror=true -Dbuild_unit_tests=true -Dinstall_data=false 2>&1 | tee setup.log
bash tools/dev/quiet-build.sh build setup.log
meson test -C build
```

That matches the shape used in `.github/actions/build/action.yml` and `.github/actions/test/action.yml`.
:::

:::tab[macOS]{value="macos"}
```bash
tools/macos/bootstrap.sh                      # once: Brewfile, pinned PDFium, pkg-config aliases (runs as you)
source tools/macos/env.sh                     # every shell: pkg-config paths, openssl@3 first, system include paths
meson setup build-macos -Dwerror=true -Dbuild_unit_tests=true 2>&1 | tee setup.log
bash tools/dev/quiet-build.sh build-macos setup.log
eval "$(tools/macos/test-db.sh up)"           # a disposable PostgreSQL 16 cluster on :54329
meson test -C build-macos
tools/macos/test-db.sh down
```

`env.sh` pins OpenSSL 3 ahead of Homebrew's unversioned `openssl` (which may be 4.x), treats a `CPATH` that points at Homebrew's headers as system include paths so their warnings stay out of the build, and drops `-L`/`-I` entries for directories that no longer exist. CI runs the same steps in `.github/workflows/macos.yml`, minus the test database: the DB-backed suites are manual validation and skip in CI, as on Linux.
:::

:::

### Builds Must Be Silent

Code pushed to GitHub, to a branch or a pull request, must build on Linux and macOS with no output but ninja's `[n/N]` progress lines: no compiler or linker warnings, no notes, no Meson `WARNING` or `DEPRECATION` lines. `tools/dev/quiet-build.sh` runs ninja and fails on anything else; CI runs it on both platforms with `-Werror`. Fix the cause of a warning; never silence it with a pragma, a weaker warning set, or by dropping `-Werror`. Third-party headers are the only exception and are already treated as system headers. The rule is stated in `AGENTS.md` at the repository root.

The repo root is the Meson project root. `core/` remains the C++ subsystem, and `compile_commands.json` is emitted at `build/compile_commands.json`.

If your work needs an installed runtime rather than just a compiled binary, the repository also provides higher-level install and test helpers under `bin/`.

## Integration And Runtime Test Path

For Linux-only runtime validation, once per machine:

```bash
sudo tools/harness/bootstrap.sh
```

Then, as often as you like:

```bash
make itest     # integration proofs as a private instance
make test      # DB-backed unit tests against a per-run database
```

What the setup does once: a Python 3.14 venv for `tools/harness`, a dedicated PostgreSQL role (`vh_harness`) whose
connection settings live in the root-only `/var/lib/vaulthalla-harness/db.env`, and a few nologin accounts used as
test actors. What every run does: build what it needs in `build-itest/`, create its own database (the integration
proofs clone a pre-migrated template), run with private `/tmp/vhh_*` paths, and drop everything afterwards.

This path depends on `sudo`, Linux, FUSE and PostgreSQL. Use it when your change affects runtime behavior rather than
simple docs or web copy. `bash bin/tests/prove_isolation.sh` checks that a run leaves the development install, its
binaries, environment files and database untouched.

### Test database requirements

There is nothing to configure. Each run creates its own database owned by `vh_harness` and passes the connection
settings only to the test process. Test code refuses to run without them, and refuses to wipe any database that
isn't a test database.

## Local Config And Environment Notes

- Default runtime config ships from `deploy/config/config.yaml`.
- Install scripts copy config into `/etc/vaulthalla/config.yaml` on Linux; on macOS, `vaulthalla-provision` writes `/Library/Application Support/Vaulthalla/config.yaml`.
- The web service unit uses `deploy/systemd/vaulthalla-web.service.in`.
- Local environment values (test credentials, `VH_TEST_DB_*`) live in one gitignored file, the repo-root `.bashrc`. Scripts that need them source it; keep secrets out of commits. The older env files under `deploy/` are retired: `bin/tests/retire_legacy_test_env.sh` offers to delete stray copies.

### Live R2 tests

The live Cloudflare R2 tests (`core/tests/unit/test_live_r2.cpp`) are opt-in. They run only with `VH_LIVE_TESTS=1`
and an R2 admin key in `VH_R2_ADMIN_ACCESS_KEY`, `VH_R2_ADMIN_SECRET_KEY` and `VH_R2_ADMIN_ENDPOINT` (keep it in the
gitignored repo-root `.bashrc`; never commit it). A run creates one bucket named `vh-test-<host>-<pid>-<start>`, works in
it under a prefix per test, and deletes it afterwards, also when tests fail. Nothing else in the account is touched.

## Known Practical Snags

### Missing `web/node_modules`

`bash tools/dev/verify.sh doctor` will flag this. Run:

```bash
cd web
pnpm install --frozen-lockfile
```

### Web build failures caused by missing private icons

The CI web build syncs private icons from `~/vaulthalla-web-icons` before `pnpm build`. If local web build work depends on those assets, coordinate with the maintainer instead of committing fake replacements.

### DB-backed unit tests outside `make test`

`meson test -C build` doesn't source any env file, so the DB-backed suites skip there. Run them with `make test` (`bin/tests/run_unit.sh`), which creates a per-run database and its own environment.

### `make dev` is not a safe default

It is a rebuild convenience for contributors who intentionally want a fresh dev instance every time. It is not a
normal "development server" command, and the dev instance's data does not survive it. A production install beside it
is never touched.

### Cross-platform false confidence

If you changed FUSE, Debian packaging, systemd, the Linux PostgreSQL lifecycle, or TPM behavior from a Mac, your local check is not enough; if you changed launchd, provisioning, Caddy or the macOS package from Linux, the contract tests are not a real install. Say that plainly in the PR and ask for the right validation. The macOS install is proven with `tools/macos/candidate.sh stage && tools/macos/candidate.sh pkg`, then `sudo tools/macos/candidate.sh accept`, which installs the package on the Mac and runs the full acceptance.

## Where To Go Next

- Read [Contribution Boundaries](/contributors/contribution-boundaries) before picking sharp work.
- Use the [Architecture Map](/contributors/architecture-map) to find the right subsystem.
- Follow the [Validation Guide](/contributors/validation-guide) before opening a PR.
