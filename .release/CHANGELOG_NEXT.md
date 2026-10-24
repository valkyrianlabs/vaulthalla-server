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

## Test tooling
- `make test` runs the derive suites: `vh_fake_derive_helper` is built without sanitizers (an ASan helper aborted
  under the Runner's RLIMIT_AS cap), so DeriveRunnerTest and DeriveQueueDbTest pass in the sanitized build-itest.
- `make test` works on macOS: it builds with tools/macos/env.sh and runs vh_unit_tests against a disposable per-run
  PostgreSQL cluster (tools/macos/test-db.sh), torn down afterwards; `make itest` exits early there with what to run.
  Test scripts drop GNU-only `realpath -m`, `base64 -w0`, `mapfile` and `declare -A` (bash 3.2 compatible), and the
  harness provisioner accepts /tmp as /private/tmp.
