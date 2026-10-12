# macOS build bootstrap (Apple Silicon + Homebrew)

Development builds and unit tests of `core/` on macOS. Packages and releases stay Linux-only (Debian, `vlr`);
FUSE is off by default on darwin and TPM2/uuid are Linux-only deps, so none of them are installed here.

| File | What it does |
|---|---|
| `Brewfile` | Build + test formulae (no casks): meson, ninja, pkgconf, pandoc, the core libraries, googletest, postgresql@16, python@3.12. |
| `bootstrap.sh` | `brew bundle install --no-upgrade`, then the two scripts below into `$VH_MACOS_DEPS`, then prints the build commands. |
| `fetch-pdfium.sh <prefix>` | Pinned `bblanchon/pdfium-binaries` `chromium/8066` (mac-arm64, SHA-256 checked): `lib/libpdfium.dylib` with an absolute install name, headers in `include/pdfium/`, `lib/pkgconfig/pdfium.pc` with version `156.8066.0`. Skips a matching install. |
| `make-pc-aliases.sh <prefix>` | Writes `libpqxx-vh.pc`, which points at Homebrew's shared libpqxx + libpq (Linux uses the static `libpqxx-vh-dev` SDK). |
| `env.sh` | Source it. Sets `PKG_CONFIG_PATH` (openssl@3 first, then the deps prefix, libpq and curl), puts postgresql@16 and python@3.12 on `PATH`, and sets `BOOST_ROOT`. |
| `test-db.sh up\|env\|down` | Runs a throwaway PostgreSQL 16 cluster in `$VH_TEST_PG_DIR` (default `$TMPDIR/vh-macos-test-pg`, port 54329, 127.0.0.1 only) and prints the `VH_TEST_DB_*` exports. It never uses `brew services` or the default data dir. |

`VH_MACOS_DEPS` defaults to `~/.cache/vaulthalla-macos-deps`.

## Build locally

```bash
tools/macos/bootstrap.sh
source tools/macos/env.sh
meson setup build-macos -Dbuild_unit_tests=true -Dmanpage=true
meson compile -C build-macos
```

## Unit tests

```bash
eval "$(tools/macos/test-db.sh up)"     # role vh_harness owns the empty vh_harness_unit_macos; the suites build the schema
meson test -C build-macos --print-errorlogs
tools/macos/test-db.sh down             # stops the cluster and deletes its directory
```

CI uses the same scripts: `.github/workflows/macos.yml` (GitHub-hosted `macos-26`, arm64).

To bump PDFium, edit the four pin values at the top of `fetch-pdfium.sh`. The tag and digest come from
`gh release view chromium/<branch> -R bblanchon/pdfium-binaries --json assets`. The version must stay
`>=155.8059,<1000` (`core/meson.build`).
