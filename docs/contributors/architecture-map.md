---
title: Architecture Map
description: Contributor-facing map of Vaulthalla subsystems and validation expectations.
order: 920
status: published
tags:
  - contributors
  - architecture
---

# Architecture Map

This is the contributor-facing map of the repo. It is not a full internal design document. Its job is to help you answer five questions quickly:

1. what subsystem am I touching
2. where does that code live
3. how sharp is it
4. what kind of contribution is appropriate
5. what should I validate before opening a PR

## Top-Level Repo Map

| Area | What it contains |
| --- | --- |
| `core/` | C++ daemon, CLI transport, FUSE service, runtime manager, auth, RBAC, crypto, sync, storage, previews, tests, usage/manpage generation |
| `web/` | Next.js admin and filesystem client, websocket session and data layer, login-gate middleware |
| `deploy/` | Runtime config, PostgreSQL schema SQL, systemd units, launchd LaunchDaemons and the macOS provisioning and Caddy tools (`deploy/launchd/`), nginx template, lifecycle utility |
| `debian/` | Debian package metadata and maintainer scripts |
| `bin/` | Dev and operator install/uninstall/test helpers (Linux and macOS, through `bin/lib/platform.sh`) |
| `tools/macos/` | macOS build environment (`env.sh`, `bootstrap.sh`), the installer package (`pkg/`), install candidates and the install acceptance |
| `release.toml`, `.release/` | vl-release configuration and the staged release notes and changelog for the next release |
| `tools/contracts/` | Contract tests for Debian packaging, maintainer scripts, shipped migrations, and the release workflow |
| `.github/` | CI workflows and composite actions |

## Subsystem Map

| Subsystem | What it does | Main paths | Contribution fit | Likely validation |
| --- | --- | --- | --- | --- |
| Core runtime manager | Starts and supervises runtime services such as sync, FUSE, protocol services, log rotation, DB janitor, and shell server | `core/main/main.cpp`, `core/src/runtime/*`, `core/src/protocols/ProtocolService.cpp` | Maintainer-guided | Linux build, targeted runtime checks, integration coverage when behavior changes |
| FUSE and filesystem behavior | Mounts the filesystem, dispatches FUSE requests, and enforces filesystem semantics | `core/src/fuse/*`, `core/include/fuse/*`, `core/src/fs/*`, `core/include/fs/*` | Maintainer-guided | Linux-only runtime validation, integration tests, manual mount/unmount behavior checks |
| CLI and local shell protocol | Implements `vh` and `vaulthalla`, talks to `/run/vaulthalla/cli.sock`, and shares help/manpage generation | `core/main/cli.cpp`, `core/src/protocols/shell/*`, `core/usage/*` | Open for help text, coordinate for behavior, maintainer-guided for lifecycle/protocol changes | Core build, CLI usage review, integration tests for command behavior |
| Web/admin client | Next.js app for admin and filesystem flows, backed by websocket requests and a refresh-cookie login gate | `web/src/app/*`, `web/src/components/*`, `web/src/lib/*`, `web/middleware.ts` | Open for small polish, coordinate for flow changes | `cd web && pnpm test`, manual local UI checks when possible |
| Database and query layer | Owns schema files, prepared statements, and DB access for auth, FS metadata, RBAC, sync, and vault state | `deploy/psql/*`, `core/src/db/*`, `core/include/db/*` | Maintainer-guided | PostgreSQL-backed validation, integration tests, schema review |
| Storage providers | Manages storage engine abstractions and S3-compatible provider behavior | `core/src/storage/*`, `core/include/storage/*`, `core/src/vault/model/*`, `core/include/vault/*` | Coordinate before implementing | Linux/runtime validation, storage-provider-specific checks, honest test notes if remote credentials were not available |
| HTTP byte lanes (previews, downloads, media, text saves) | Authenticates and authorizes every `/preview`, `/download` and `/upload/text` request, then streams plaintext from encrypted files with Range support | `core/src/protocols/http/*` (`Access.cpp`, `handler/*`, `Session.cpp`, `Server.cpp`), `core/src/storage/{PlaintextReader,GcmFileReader}.cpp`, `core/src/crypto/IntegrityRegistry.cpp` | Security-sensitive | Focused unit tests (`test_http_access`, `test_http_session`, `test_gcm_range_reader`), core build, threat-aware review |
| Preview, thumbnail and derived-artifact pipeline | Classifies files into preview plans, renders thumbnails and PDF pages in memory, caches every derived artifact encrypted, and runs converters out of process | `core/src/preview/*` (`Plan.cpp`, `render/*`, `cache/Store.cpp`, `derive/*`), `core/tools/*`, `web/src/features/files/PreviewSheet.tsx`, `web/src/features/files/preview/*` | Coordinate before implementing | Targeted file-format testing, `test_preview_store`, `test_derive_runner`, helper tests, `web/tests/e2e/preview.spec.ts` |
| Sync engine | Plans and executes upload, download, delete, conflict, and key-rotation work | `core/src/sync/*`, `core/include/sync/*` | Maintainer-guided | Integration-style validation, repro steps, manual data-safety checks |
| RBAC and permission model | Defines admin and vault permissions, glob/path policy logic, role templates, and permission resolution | `core/src/rbac/*`, `core/include/rbac/*`, `deploy/psql/060_acl.sql` | Security-sensitive | Maintainer approval first, focused tests, threat-aware review |
| Auth, session, and secret handling | Manages token issuance, refresh/session validation, secret storage, and auth-related protocol behavior | `core/src/auth/*`, `core/include/auth/*`, `core/src/crypto/*`, `core/include/crypto/*`, `web/src/stores/useWebSocket.ts` | Security-sensitive | Maintainer approval first, focused tests, no hand-wavy validation |
| Platform seams | Isolate OS-specific system calls behind small interfaces with `linux` and `darwin` implementations chosen by Meson: peer credentials, local accounts, child processes, mounts, sealers, state directory checks, staged files, wakers | `core/include/platform/*`, `core/src/platform/{linux,darwin}/*` | Maintainer-guided | Build and unit tests on both platforms |
| Packaging, systemd, and lifecycle | Defines package payload, install/remove/purge scripts, systemd units, and privileged host setup flows | `debian/*`, `deploy/systemd/*`, `deploy/lifecycle/main.py`, `bin/setup/*`, `bin/teardown/*` | Coordinate before implementing | Package dry runs, lifecycle tests, clean-host install/upgrade/remove/purge checks |
| macOS service and package | launchd LaunchDaemons, idempotent provisioning (account, directories, bundled PostgreSQL, enrollment), `vh setup caddy`, the self-contained installer package and Homebrew cask | `deploy/launchd/*`, `tools/macos/pkg/*`, `tools/macos/install-acceptance.sh` | Coordinate before implementing | `tools/contracts/test_macos_*_contract.py`, a real install with `sudo tools/macos/candidate.sh accept` |
| Release process | vl-release (`vlr`) keeps versions in sync, builds and validates the package, publishes to APT and records the release history | `release.toml`, `.release/*`, `.github/workflows/release.yml`, `web/bin/build_release_payload.sh` | Maintainer-guided | `bash tools/dev/verify.sh release packaging`, `make deb` |
| Tests and harnesses | Unit, integration, lifecycle, and packaging contract coverage | `core/tests/*`, `deploy/lifecycle/tests/*`, `tools/contracts/*`, `tools/lab/tests/*` | Open for scoped work | Run the relevant test surface and avoid unrelated churn |

## Subsystem Notes

### Core runtime

`core/src/runtime/Manager.cpp` is where service orchestration comes together. If your change affects startup order, restart behavior, shutdown behavior, or service wiring, treat it as maintainer-guided work.

### FUSE and filesystem semantics

`core/src/fuse/Service.cpp` mounts the filesystem with `allow_other` and `auto_unmount`. That is not casual plumbing. Filesystem behavior changes can affect user data, trust boundaries, and operator expectations.

### CLI and shell protocol

`core/main/cli.cpp` talks to the local control socket at `/run/vaulthalla/cli.sock`. Help text and usage improvements are easy contributions. Protocol or privileged lifecycle command changes are not.

### Web/admin surface

The web client is a real contributor surface, but it is still wired into auth and websocket behavior. Small UX work is fair game. New flows, new command surfaces, and auth/session changes should start with discussion.

One practical caveat: the CI web build syncs private icon assets from `~/vaulthalla-web-icons` in `.github/actions/build_web/action.yml`. If you are touching web UI and hit build failures related to missing private icons, coordinate with the maintainer rather than stubbing fake assets into the repo.

### Previews, downloads and the byte-serving spine

Every byte the HTTP lanes hand out (downloads, media playback, 3D models, text, thumbnails, converter input) goes through one funnel, `storage::Engine::openPlaintextReader`, which returns a `storage::PlaintextReader` over one exact file version:

- `GcmFileReader` serves positioned reads from the AES-256-GCM ciphertext by `pread`ing only the requested region and decrypting it with the GCM counter keystream. No plaintext is written anywhere.
- `crypto::IntegrityRegistry` authenticates each file version's GCM tag once and shares the verdict with every reader of that version. `preview.media.integrity: optimistic` serves immediately and aborts every live reader if verification fails; `strict` verifies before the first byte. A failed version stays refused until the file changes.
- `protocols/http/Access.cpp` is the only place a route's need (Preview, Download, Overwrite) is mapped onto RBAC: vault filesystem permissions for signed-in users, `share::TargetResolver` for share links. Handlers in `protocols/http/handler/` only see resolved targets and serve them with conditional GET, single Range, HEAD and chunked streaming. Each connection runs on its own thread, capped by `http_preview_server.max_connections`, with real read/write deadlines.
- `preview::cache::Store` holds every derived artifact (thumbnails, page renders, posters, GLB from STEP, transcodes) as a `VHDERIV1` file sealed with the vault key, with the artifact's identity bound into the GCM associated data and keyed to the source file's version, indexed in `cache_index` (migration 103). It is disposable: evicted by size and age and regenerated on demand.
- `preview::derive::Runner` spawns the optional converter helpers (`core/tools/preview-cad`, `core/tools/preview-media`) as separate sandboxed processes that pull plaintext over a socketpair. Their libraries (Open CASCADE, FFmpeg, libseccomp) are never linked into the daemon.

Read [Security-Sensitive Work](/contributors/security-sensitive-work#preview-and-download-invariants) before changing any of this.

### Database and schema

`deploy/psql/000_schema.sql` through the highest-numbered `deploy/psql/NNN_*.sql` define the installed schema surface; new migrations take the next number. Schema work is sharp because it crosses packaging, bootstrap, runtime queries, retention, and upgrade safety.

### Packaging and lifecycle

The Debian maintainer scripts in `debian/postinst`, `debian/prerm`, and `debian/postrm` are the lifecycle source of truth for install, upgrade, remove, and purge on Linux. On macOS that role belongs to `deploy/launchd/vaulthalla-provision.in`, which the package's postinstall runs, and `tools/macos/pkg/uninstall.sh`. The `bin/` scripts are helpful local wrappers, but they are not either platform's package contract.

### Releases

Releases are cut with [vl-release](https://github.com/valkyrianlabs/vl-release) (`vlr`). `release.toml` is the contract: the version files kept in sync, what the Debian package must and must never contain, and where it is published. Release notes and the Debian changelog are written ahead of time in `.release/`, in the same change as the code they describe; the published `debian/changelog` and `RELEASE_NOTES.md` are written only by `vlr prepare` during a release. Treat this as a product surface, not a scratchpad.

## Read By Interest

If you are working on:

- docs and onboarding: start with [Contribution Boundaries](/contributors/contribution-boundaries) and [Validation Guide](/contributors/validation-guide)
- web/admin polish: read `web/src/app/*`, `web/src/components/*`, and `web/src/stores/*`
- CLI help and examples: read `core/usage/*` and `core/main/cli.cpp`
- packaging: read [Packaging and Release](/contributors/packaging-and-release), then `debian/*` and `deploy/systemd/*`
- security-sensitive work: read [Security-Sensitive Work](/contributors/security-sensitive-work) first
