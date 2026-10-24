<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
## Durability
- Durability flushes go through `platform::durable::sync`: `fsync` on Linux (unchanged), `F_FULLFSYNC` on macOS
  (falling back to `fsync` only where the file system refuses it). A contract test rejects raw `fsync` outside
  `core/src/platform/` (#205).

## Security
- ws `fs.dir.list` / `fs.list` (outside share mode) and `vh fs ls` leave out children the caller cannot Lookup, through
  the filter FUSE readdir uses (`rbac::fs::visibility`), and recount a listed child folder's size and counts and the
  folder's own size without them (#255).
- The listing fast path no longer skips the per-entry Lookup when a wildcard override reaches the folder from above
  (`glob::Matcher::mayMatchWithin`) or when the base permissions hide one kind of entry.
- FUSE rename and ws `fs.entry.move` / `fs.entry.rename` into another folder authorize the new path with the action a
  create there needs (Touch for a folder, Write for a file or symlink; `rbac::fs::placement`), and every entry a folder
  carries at its new path. FUSE answers a refusal as a create in that folder would (`resolver::deniedErrno`), ws with
  `denied` before any destination lookup. Same-folder renames and cross-vault EXDEV are unchanged (#256).

## Test tooling
- `make test` runs the derive suites: `vh_fake_derive_helper` is built without sanitizers (an ASan helper aborted
  under the Runner's RLIMIT_AS cap), so DeriveRunnerTest and DeriveQueueDbTest pass in the sanitized build-itest.
- `make test` works on macOS: it builds with tools/macos/env.sh and runs vh_unit_tests against a disposable per-run
  PostgreSQL cluster (tools/macos/test-db.sh), torn down afterwards; `make itest` exits early there with what to run.
  Test scripts drop GNU-only `realpath -m`, `base64 -w0`, `mapfile` and `declare -A` (bash 3.2 compatible), and the
  harness provisioner accepts /tmp as /private/tmp.

## macOS mount
- Retire the macOS macFUSE integration (#262): darwin never builds the kernel FUSE bridge (`-Dfuse=enabled` is a
  setup error there; `fuse/unbuilt` is the service), `platform/darwin/Mount.cpp` drops the macFUSE mount options,
  the `fuse_session_mount` probe and the `macfuse-kernel` backend, and `tools/macos/fuse-probe/` is removed. Finder
  access belongs to Vaulthalla Desktop's File Provider (vaulthalla/desktop#1). Linux FUSE is unchanged.
  - macOS `mount.mode` is `disabled` only: `service_private`/`multiuser` left in config.yaml run as `disabled` with a
    `[config]` warning instead of degrading health; a misspelled mode still refuses to start everywhere.
  - Health, `vh status` and the console's Runtime page report the macOS mount as disabled, noting that Finder access
    is provided by Vaulthalla Desktop. `vh fs` help no longer calls itself interim.

## Packaging
- The repository moved to `github.com/vaulthalla/server`. The package `Homepage`/`Source` fields (`debian/control`, `debian/copyright`), the release contract (`release.toml`), the Homebrew cask URL and the docs links point there; the old `vaulthalla-core` and `vaulthalla/vaulthalla` URLs are gone.
