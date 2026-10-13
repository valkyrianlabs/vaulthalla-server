# macOS port (roadmap #199)

Started 2026-10-12. Goal: a native Apple Silicon daemon with the same `vh`/web/`vh setup` experience. FUSE is
optional on macOS (#200); Milestones A (native core) and B (working storage) don't wait on Finder or app design.
Decisions awaiting the maintainer are `needs:review` issues #200–#206 on the Roadmap's macOS view.

## Layout

- `core/include/platform/*.hpp`: one narrow interface per OS-specific need; `core/src/platform/{linux,darwin}/`
  implements it, and meson compiles only the host's directory. Linux implementations are the code that used to be
  inline (moved, not changed). Business logic has no `#ifdef __APPLE__`; the one exception is the header-only
  `FileTime.hpp` (field names differ).
  - `Waker`, `process::disableCoreDumps`, `fd::*` (CLOEXEC, SIGPIPE), `PeerCredentials`, `accounts::*`
    (group membership, first human uid 1000|501, add-to-group command), `child::*` (converter runner),
    `staged::*` (O_TMPFILE), `sealer::*` (secrets).
- `-Dfuse` (auto): Linux requires libfuse3; macOS builds without the kernel bridge. `fuse::makeService()` is
  nullptr there and the runtime registers no FUSE service. Inode numbers outside the bridge are `vh::fs::Inode`.
- Secrets: `crypto::secrets::KeyProvider` (shared) over `platform::sealer`. Linux: TPM2 (`platform/linux/TpmSealer.cpp`,
  same blobs as before). macOS: a **development-only** `file` backend, reported as `file`. Production backend: #201
  (Secure Enclave spike from a user session passed; the pre-login LaunchDaemon test needs maintainer approval).
- Paths: macOS defaults from meson (`/Library/Application Support/Vaulthalla/{config.yaml,state}`,
  `/Library/Logs/Vaulthalla`, `/var/run/vaulthalla`, mount `/Library/Application Support/Vaulthalla/mount`), per #199/#216.

## FUSE on macOS (macOS 27 audit: #213)

- `-Dfuse=enabled` builds the real bridge against macFUSE ≥ 5.4.0 (libfuse 3.18.2, `fuse3.pc`); default stays off.
  macOS compiles with `FUSE_DARWIN_ENABLE_EXTENSIONS=0` (vanilla libfuse API, same code as Linux). macFUSE maps
  `RENAME_NOREPLACE/EXCHANGE` to Darwin's `RENAME_EXCL/SWAP`. Mount lifecycle is `platform/Mount.hpp`.
- FSKit backend: forwards euid/egid on 27 but keeps its own name/attr cache with no invalidation (macfuse#1207) and
  can't mount as root/headless (per-user extension). Not used on the server path. Kernel backend: needs Reduced
  Security on Apple Silicon; supports `novncache`/`noattrcache`; mounts without a session once approved.
- Modes (`mount.mode` in config.yaml, read-only; default per build): `disabled` (macOS default) | `service_private`
  (kext, no allow_other, `nobrowse`) | `multiuser` (Linux, always; macOS only after gate K2). `fuse::makeService()`
  creates no service unless the configured mode is supported here and libfuse is present (weak-linked on macOS);
  `fuse::mountStatus()` reports configured mode, actual state, backend and isolation to health and `vh status`.
  Proof tooling: `tools/macos/fuse-probe/`.
- macFUSE's license forbids bundling or automated installation with commercial software without permission.

## System service (launchd, #216/#202)

- `deploy/launchd/sh.vaulthalla.{server,web}.plist.in` mirror the systemd units (KeepAlive SuccessfulExit=false ≈
  Restart=on-failure, ThrottleInterval, ExitTimeOut 30, NOFILE 65535, Core 0, Umask 077), running as `_vaulthalla`
  in the system domain: up before login, across logout. No StartLimit and no ordering after PostgreSQL in launchd.
- `vaulthalla-provision` (installed to `<prefix>/lib/vaulthalla/`): idempotent; plan by default, `--apply`,
  `--remove [--purge]`. Hidden role account `_vaulthalla` (uid/gid 450-499 from the top, clear of Apple's role accounts that grow upward from 200, alias `vaulthalla` so the daemon's
  `vaulthalla` user/group lookups work unchanged), `state` 0700, `run` 0750 (CLI socket), `mount` 0700, logs 0750,
  config.yaml only if missing. Never enrolls a user in the group (#202). Contract:
  `tools/contracts/test_macos_launchd_contract.py` (stubs, `--root`; runs on Linux CI too).
- Runtime dir on macOS is `/Library/Application Support/Vaulthalla/run` (launchd has no RuntimeDirectory).
- Dev instance (`make dev`, meson `-Dinstance=dev`): the same provisioner configured with `_vaulthalla_dev` / alias
  `vaulthalla-dev` / labels `sh.vaulthalla.dev.*` / ports +100 (it renders production's plist templates), prefix
  `/usr/local/vaulthalla-dev`, `/Library/Application Support/Vaulthalla-dev`, its own PostgreSQL 16 cluster
  (Homebrew binaries, `sh.vaulthalla.dev.postgres`, 127.0.0.1:5532, scram) and `vh-dev`. `bin/lib/darwin_private_dylibs.sh`
  copies dylibs a build links from `~/.cache` (PDFium) into the prefix: the role account can't read a 0750 home.
  `make dev-plan` prints every privileged step. A production install is never touched by any of it.

## Build and test on a Mac

`tools/macos/bootstrap.sh` (Brewfile, pinned PDFium `chromium/8066`, `libpqxx-vh.pc` alias over Homebrew's shared
libpqxx), then `source tools/macos/env.sh && meson setup build-macos -Dbuild_unit_tests=true && meson compile -C
build-macos`. DB-backed tests: `eval "$(tools/macos/test-db.sh up)"; meson test -C build-macos; tools/macos/test-db.sh
down` (disposable cluster on :54329, never the brew service). CI: `.github/workflows/macos.yml` (hosted `xcode-27`: macOS 27 public preview; `macos-26` is the fallback).

## Gotchas found by the port (keep these in mind on Linux too)

- **libpqxx `row[name]` is `[[gnu::pure]]`.** clang treats pure functions as non-throwing, so `try { row["x"] }
  catch (...)` never catches a missing column. Check `db::encoding::hasColumn` first. GCC hides this.
- libc++ has no `std::atomic<std::shared_ptr>`: use `concurrency::AtomicSharedPtr` (the std type on libstdc++).
- libc++'s `filesystem::path::iterator` isn't bidirectional (no `std::prev(end())`).
- macOS `uuid_unparse` is upper case; PostgreSQL returns uuid lower case. Use `uuid_unparse_lower`.
- `sockaddr_un` on BSD starts with `sun_len`; use `offsetof(sockaddr_un, sun_path)`; `sun_path` is 104 bytes.
- macOS refuses to lower `RLIMIT_AS` (EINVAL), has no PDEATHSIG/NO_NEW_PRIVS, and no `sigisemptyset`;
  `sigemptyset` is a macro (no `::`).
- `/tmp` → `/private/tmp`, `$TMPDIR` is a private 0700 dir under `/var/folders` (→ `/private/var/...`).
- The generated `paths.h` shadows the system `<paths.h>` on macOS (both are found as `<paths.h>`). It works because
  the build dir comes first; renaming it is a cleanup worth doing.
- Never put the repo root on `-I`: APFS is case-insensitive and `VERSION` answers `#include <version>`.
- Meson debug builds on libc++ enable libc++ hardening, which traps on UB that GCC builds tolerate (it found the
  unset-optional read in `CommandBook::renderHelp`).
- HTTP uploads stage through the kernel mount (`/mnt/vaulthalla/...`); with FUSE disabled they need another staging
  location (#213, needs review). Linux keeps staging through FUSE.
