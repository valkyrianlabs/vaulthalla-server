---
name: verify
description: Run the right verification for what changed in the vaulthalla monorepo (C++ core, Next.js web, release tooling, Debian packaging, lifecycle, docs, shell scripts). Use before claiming a change works, before committing, or when asked to test/validate/check a change.
---

# Verify

Pick proof that matches the surface you changed, run it, and report what actually ran. The script
`tools/dev/verify.sh` is shared with human contributors (`docs/contributors/validation-guide.md`), so
keep it dependency-light bash.

## Run

```bash
bash tools/dev/verify.sh            # infer profiles from git changes vs HEAD
bash tools/dev/verify.sh core web   # explicit profiles
```

| Profile | What it runs | Cost |
|---|---|---|
| `doctor` | toolchain/version pin check (node vs `.nvmrc`, pnpm vs `packageManager`, icons, build dir, release sync) | seconds |
| `core` | `meson compile -C build` then `meson test -C build` (no env file sourced: DB-backed suites need `make test`; live tests are opt-in) | minutes |
| `web` | `pnpm --dir web typecheck` + `lint` (strict; `VERIFY_STRICT_LINT=0` to soften) | ~1 min |
| `release` | `vlr check` + `vlr version check` (release.toml, staged `.release/` docs, version targets) | seconds |
| `packaging` | `tools/contracts` (packaging, maintainer scripts, migrations, release workflow) + `tools/lab/tests`, with minimum test counts | seconds |
| `lifecycle` | `deploy/lifecycle` unit tests (minimum test count) | seconds |
| `docs` | payload-markdown checker on changed docs (or all), then `pmdocs validate --source docs` | seconds |
| `shell` | `bash -n` (+ shellcheck if installed) on changed `bin/`, `web/bin/`, and maintainer scripts | seconds |
| `integration` | `make itest`: Tier A proofs as an isolated private instance (sudo; never touches the dev install) | ~10 s once built |
| `all` | every profile except `integration` | |

## Rules

- `integration` tears down the live dev install on this VM. It refuses to run without
  `VERIFY_ALLOW_DESTRUCTIVE=1`. Only set that after the user agrees in this conversation.
- DB-backed unit tests: `make test` (per-run DB; ARGS="--gtest_filter=..."). Isolated, no heads-up needed.
  See `.claude/context/testing.md`.
- The `packaging` and `lifecycle` suites have minimum test counts (`run_suite` in `tools/dev/verify.sh`). When you add
  tests, raise the floor; never lower it to get green, and never weaken a contract test to pass.
- `release` needs `vlr` (vl-release). A change to user-visible behavior should also update `.release/` (`/vl-release`).
- Web: if `node -v` doesn't match `web/.nvmrc`, say so in the report. A toolchain mismatch weakens the result.
- Report honestly. List each profile run and its pass/fail, anything skipped and why, and the exact failing test names.
  Never summarize a partial run as "tests pass".

## Upgrading from the stronger proofs

Unit and contract tests don't prove packaging or runtime behavior. For changes to `debian/`,
`deploy/systemd`, `deploy/psql`, startup/shutdown, FUSE, or the DB layer, recommend a lab install/upgrade
via the `/lab` skill, and state that it wasn't done if it wasn't.
