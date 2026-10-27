# macOS port (roadmap #199)

Started 2026-10-12. Goal: a native Apple Silicon daemon with the same `vh`/web/`vh setup` experience. The server has
no FUSE on macOS; Finder is Vaulthalla Desktop's File Provider (valkyrianlabs/vaulthalla-desktop#1, see below).
Decisions awaiting the maintainer are `needs:review` issues #200–#206 on the Roadmap's macOS view.

## Layout

- `core/include/platform/*.hpp`: one narrow interface per OS-specific need; `core/src/platform/{linux,darwin}/`
  implements it, and meson compiles only the host's directory. Linux implementations are the code that used to be
  inline (moved, not changed). Business logic has no `#ifdef __APPLE__`; the one exception is the header-only
  `FileTime.hpp` (field names differ).
  - `Waker`, `process::disableCoreDumps`, `fd::*` (CLOEXEC, SIGPIPE), `PeerCredentials`, `accounts::*`
    (group membership, first human uid 1000|501, add-to-group command), `child::*` (converter runner),
    `staged::*` (O_TMPFILE), `sealer::*` (secrets), `durable::sync` (every durability flush: `fsync` on Linux,
    `F_FULLFSYNC` on macOS, whose plain `fsync` stops at the drive cache; #205, guarded by
    `tools/contracts/test_durable_sync_contract.py`). Measured on Apple SSD: about 4.7 ms per 4 KiB flush and about
    21 ms per 64 MiB, against 0.04 and 1.7 ms for plain `fsync`.
- `-Dfuse` (auto): Linux requires libfuse3; macOS never builds the kernel bridge (see below). `fuse::makeService()`
  is nullptr there and the runtime registers no FUSE service. Inode numbers outside the bridge are `vh::fs::Inode`.
- Secrets: `crypto::secrets::KeyProvider` (shared) over `platform::sealer`. Linux: TPM2 (`platform/linux/TpmSealer.cpp`,
  same blobs as before). macOS: a **development-only** `file` backend, reported as `file`. Production backend: #201
  (Secure Enclave spike from a user session passed; the pre-login LaunchDaemon test needs maintainer approval).
- Paths: macOS defaults from meson (`/Library/Application Support/Vaulthalla/{config.yaml,state}`,
  `/Library/Logs/Vaulthalla`, `/var/run/vaulthalla`, mount `/Library/Application Support/Vaulthalla/mount`), per #199/#216.

## No server mount on macOS (#262)

**The server never mounts anything on macOS.** macFUSE is ruled out in every form (kext, its FSKit backend, its SDK,
a cask dependency); its build path, mount modes and proof tooling from #228/#213 were removed in #262 (history stays
in git: `tools/macos/fuse-probe/` lived there). Finder integration belongs to **Vaulthalla Desktop**, through a File
Provider extension that talks to the daemon over the mTLS device listener under server-side RBAC
(valkyrianlabs/vaulthalla-desktop#1). The server gets no macOS filesystem presentation logic, and Desktop hosts no server features.

- Build: on darwin `core/meson.build` never looks for `fuse3`; the bridge sources are left out and
  `fuse/unbuilt/Service.cpp` is the service. `-Dfuse=auto|disabled` is silent; `-Dfuse=enabled` fails at setup with
  a pointer to Desktop. Linux is unchanged (libfuse3 required, same dependency expression).
- `platform/darwin/Mount.cpp` is policy only: `defaultMode()`/`supportsMode()` = `disabled`,
  `fuseRuntimeAvailable()` = false. The lifecycle half of `platform/Mount.hpp` (options, detach, mount table,
  connection abort) is called only by the bridge, so only Linux implements it.
- `mount.mode` (config.yaml, read-only): the spelling check is shared (a typo refuses to start everywhere). Where the
  platform has no FUSE runtime, `service_private`/`multiuser` are **read as `disabled` with a `[config]` warning**
  rather than refusing to start: the default there is already `disabled`, and storage must keep serving
  (`ConfigSettingsTest.MountModeThisPlatformNeverMountsRunsDisabled`). Linux keeps every known mode as written.
- Health / `vh status` / console: `mount: disabled -> disabled — the server never mounts on this platform; Finder
  access is provided by Vaulthalla Desktop` (backend `none`, isolation `not_applicable`); health is not degraded by
  it. The console's Runtime page shows the same note.
- `vh fs ls|get|put` stays the CLI file path on macOS (still "don't grow it"; see architecture.md).

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
down` (disposable cluster on :54329, never the brew service). CI: `.github/workflows/macos.yml` (hosted `xcode-27`: macOS 27 public preview; `macos-26` is the fallback) runs
`vh_unit_tests` without a database, like Linux CI: the DB-backed suites are manual validation only.

`make test` also works here (#217): no sudo or harness bootstrap; it sources `env.sh`, builds `build-itest` with the
Linux options (ASan/UBSan, `-Dintegration_tests=true`, only `vh_unit_tests` and the fake derive helper compiled) and
runs the binary against its own `test-db.sh` cluster (per-run `$TMPDIR/vh-unit-pg-<pid>`, free port), torn down on
exit. It sets `ASAN_OPTIONS=detect_container_overflow=0` (see Gotchas). `make itest` refuses (Tier A is FUSE and /proc proofs,
Linux only) and points at `make test`. Open follow-up: `tools/harness/vhh/platform.py` (Tier B: mount table, /proc
introspection, unmount, account helpers) is still Linux-only, and so are `_validate_private`'s /proc checks.

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
- ASan + libc++ reports `container-overflow` on valid `pqxx::params` appends: libc++ annotates `std::vector`, and the
  uninstrumented Homebrew libpqxx grows the same vectors. Run sanitized tests with `detect_container_overflow=0`
  (Linux's libstdc++ doesn't annotate vectors without `_GLIBCXX_SANITIZE_VECTOR`, so nothing is lost relative to it).
- Meson 1.8 with stale `-L` dirs in `LDFLAGS` fails `-Db_sanitize=…` at setup ("Linker … does not support sanitizer
  arguments": its link probe uses `-Wl,-fatal_warnings`); `env.sh` drops those dirs. It also warns about `b_lundef`
  with clang sanitizers; that warning is harmless on Apple ld.
- Meson debug builds on libc++ enable libc++ hardening, which traps on UB that GCC builds tolerate (it found the
  unset-optional read in `CommandBook::renderHelp`).
- HTTP uploads stage through the kernel mount (`/mnt/vaulthalla/...`) on Linux; macOS has no mount and stages in a
  private directory under the state root (`-Dhttp_upload_staging=private`, the darwin default). Linux keeps staging
  through FUSE.
