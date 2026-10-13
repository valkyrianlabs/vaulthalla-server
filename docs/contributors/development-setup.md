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

If you are doing docs-only work, you do not need the full Linux runtime environment. If you are touching core runtime, FUSE, packaging, systemd, PostgreSQL, TPM/swtpm, or install lifecycle behavior, you do.

## Platform Assumptions

Vaulthalla is Linux-native software.

Meaningful validation for these areas requires a Linux environment:

- core daemon work
- FUSE behavior
- package lifecycle scripts
- systemd services
- PostgreSQL bootstrap and state handling
- TPM or `swtpm` integration

Debian and Ubuntu-style environments are the safest contributor path because the repo scripts and package metadata assume `apt`, `sudo`, systemd, and Debian packaging.

If you are on macOS or Windows, docs work is fine, and some web or release-tooling work may still be possible. Do not pretend that means you fully validated Linux runtime behavior.

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

That script configures the Vaulthalla APT repository and installs native dependencies such as Meson, Ninja, PostgreSQL, FUSE, `libsodium`, `libtss2`, `swtpm`, and related packages. The two Vaulthalla-built SDKs come only from apt.vaulthalla.sh: `libpdfium-dev` (PDFium) and `libpqxx-vh-dev` (a static libpqxx 8 build; the package build links it in, so servers need only `libpq5`). Ubuntu's `libpqxx-dev` is not used.

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

```bash
meson setup build --buildtype=debug -Dbuild_unit_tests=true -Dinstall_data=false
meson compile -C build
meson test -C build
```

That matches the shape used in `.github/actions/build/action.yml` and `.github/actions/test/action.yml`.

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
- Install scripts copy config into `/etc/vaulthalla/config.yaml`.
- The web service unit uses `deploy/systemd/vaulthalla-web.service.in`.
- Some local scripts look for `deploy/vaulthalla.env`.

The repo only ships `deploy/vaulthalla.env.example` as a public template. If you need real storage-backed test credentials or environment values, create your own local `deploy/vaulthalla.env` from that template and keep secrets out of commits.

### R2/S3 test environment

If you want the dev workflow to carry R2 test credentials into the installed environment:

1. copy `deploy/vaulthalla.env.example` to `deploy/vaulthalla.env`
2. uncomment and fill in the `VAULTHALLA_TEST_R2_*` variables

The example variables are:

```text
# VAULTHALLA_TEST_R2_ACCESS_KEY=<your_access_key>
# VAULTHALLA_TEST_R2_SECRET_ACCESS_KEY=<your_secret_key>
# VAULTHALLA_TEST_R2_ENDPOINT=https://<your_unique_id>.r2.cloudflarestorage.com
# VAULTHALLA_TEST_R2_REGION=auto
# VAULTHALLA_TEST_R2_BUCKET=<your_bucket_name>
```

When `deploy/vaulthalla.env` exists, `bin/setup/install_dirs.sh` installs it as `/etc/vaulthalla/vaulthalla.env`.

### Optional dev R2 test vault seeding

`deploy/config/config.yaml` includes:

```yaml
dev:
  enabled: false
  init_r2_test_vault: false
```

If dev mode is enabled in config and `init_r2_test_vault` is set to `true`, the storage manager can seed an `R2 Test Vault` automatically during startup when the required `VAULTHALLA_TEST_R2_*` environment variables are present.

Keep this workflow-specific and local. Do not commit real credentials.

## Known Practical Snags

### Missing `web/node_modules`

`bash tools/dev/verify.sh doctor` will flag this. Run:

```bash
cd web
pnpm install --frozen-lockfile
```

### Web build failures caused by missing private icons

The CI web build syncs private icons from `~/vaulthalla-web-icons` before `pnpm build`. If local web build work depends on those assets, coordinate with the maintainer instead of committing fake replacements.

### Integration test scripts expecting `deploy/vaulthalla.env`

Some scripts reference `deploy/vaulthalla.env`, while the repo only includes `deploy/vaulthalla.env.example`. If your test path needs environment values, create the local file explicitly.

### `make dev` is not a safe default

It is a rebuild convenience for contributors who intentionally want a fresh dev instance every time. It is not a
normal "development server" command, and the dev instance's data does not survive it. A production install beside it
is never touched.

### Cross-platform false confidence

If you changed FUSE, packaging, auth/session, systemd, PostgreSQL lifecycle, or TPM behavior from a non-Linux machine, your local check is not enough. Say that plainly in the PR and ask for the right Linux validation.

## Where To Go Next

- Read [Contribution Boundaries](/contributors/contribution-boundaries) before picking sharp work.
- Use the [Architecture Map](/contributors/architecture-map) to find the right subsystem.
- Follow the [Validation Guide](/contributors/validation-guide) before opening a PR.
