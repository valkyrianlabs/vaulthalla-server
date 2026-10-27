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

## File API
- fs entries (ws `fs.dir.list` / `fs.list` / `fs.metadata`, sync conflict artifacts) carry `metadata_version` (all
  entries) and `content_version` (files), set by the Entry base serializer (#257).
  - `content_version` = `storage::Generation::etag()`, the strong ETag `/download/content` serves; it changes on every
    content write, never on rename or move.
  - `metadata_version` = `"m<id>-<hex16(sha256(vault|parent|name|mode|owner|group|updated_at))>"`, a stable hash of
    the fields the reply carries (no counter, no migration).
  - An empty file's generation is `plain:0` whatever its `updated_at`, so its ETag survives rename and touch.
  - `FsEntryVersionsDbTest`: the entry id is unchanged across ws rename, ws move, FUSE rename over an existing file
    and a folder move (its children too).
- `PUT /upload/content?vault_id&path` (#258, `protocols/http/upload/Content.cpp`): conditional replace (`If-Match`,
  `Need::Overwrite`) or create (`If-None-Match: *`, `access::resolveCreate`: Write) of one file, body streamed by
  `Session::handle_streaming_content` into the upload staging seam and sealed through
  `Filesystem::createFile{source_path, overwrite, expected_source_id}`.
  - 412 + current ETag on a stale version, an open FUSE working copy or an existing file on create; 409 for a
    non-file in the way; 428 / 411 / 413 answered before the body; access checked again at commit.
  - 201/200 answer `{created, entry}` with `content_version` / `metadata_version` and the new ETag.
- `/upload/session` commits seal from the staged file (`source_path`) instead of reading it whole into memory; an
  empty file keeps the empty-buffer branch (same MIME type). A file whose PUT failed may be PUT again (human and
  device sessions; a share upload's record stays failed).
- `tools/contracts/test_upload_content_contract.py` pins the bounded-memory commit and the streaming route.

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
- Valkyrian Labs LLC is the copyright holder and trademark owner: `NOTICE`, `TRADEMARKS.md`, `debian/copyright`
  (`Upstream-Contact` and both `Files` stanzas), `debian/copyright_human`, the README and CONTRIBUTING say so.
  `debian/copyright` now also lists the vendored jwt-cpp, nlohmann/json, picojson and stb headers under their own
  licenses.
- The repository moved to `github.com/vaulthalla/server`. The package `Homepage`/`Source` fields (`debian/control`, `debian/copyright`), the release contract (`release.toml`), the Homebrew cask URL and the docs links point there; the old `vaulthalla-core` and `vaulthalla/vaulthalla` URLs are gone.
