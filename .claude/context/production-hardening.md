# Production hardening phase: kickoff state

> **Status (Phase 1, 2026-09-30):** P0-1..P0-4 are fixed on `phase1/hardening` (PR #124) and tracked as GitHub
> issues #97–#126 on the "Vaulthalla Roadmap" project. The live incident was recovered (daemon cgroup killed,
> postinst completed). Real-host results, the release loop, and remaining defects are in
> `.claude/context/phase1-results.md` — read that first; the sections below are the original kickoff capture.
>
> **Status (Phase 2, 2026-10-02):** on `phase2/trustworthy` (v1.8.0 candidate): every audit finding S1–S11 is fixed with
> regression tests, #123/#125/#132 are fixed, and the lab matrix is in `phase2-results.md`. #133 stays a product decision.

Phase goal: make the build → package → publish → install/upgrade → run pipeline robust enough for
real-world use, proven on the `vh-storage` lab VM. The backlog below was captured on 2026-09-30 during repo
ingestion. Items were verified against code and the live lab unless marked otherwise.

## P0: live incident on vh-storage (observed 2026-09-30)

**State at capture:** `sudo apt upgrade -y` (started ~40 min earlier) was stuck. `vaulthalla` 1.6.6-1 was
`iF` (half-configured), dpkg was holding its lock, and `vaulthalla.postinst configure 1.6.5-1` was blocked in
`mountpoint -q /mnt/vaulthalla`. The running 1.6.5 daemon (PID 1031, up since 2026-09-18) was not answering
FUSE requests. Several other Ubuntu packages were also left unconfigured behind the lock. Two stuck `df` processes from the
ingestion session are in uninterruptible FUSE wait; they'll clear when the mount is serviced or aborted.
Nothing was changed on the lab. Recovery needs the maintainer's approval. The likely path: restart
`vaulthalla.service` (or `fusermount3 -uz` / abort via `/sys/fs/fuse/connections/*/abort`), let the
postinst finish, then `sudo dpkg --configure -a`.

### P0-1: DB pool leaks connections and wedges the whole daemon after a PostgreSQL restart

Evidence: `postgresql@16-main` restarted at 2026-09-22 06:30:03 (unattended upgrade). At 06:30:26 vaulthalla logged
three `StatsSnapshotService … Lost connection to the database server` warnings and has logged **nothing
since**. 28 of 38 threads are in `futex_wait`, and one is in `fuse_dev_do_read`. The previous boot showed the identical
pattern on 2026-08-22 06:39.

Root cause (in code):
- `core/include/db/Transactions.hpp` `exec()`: `auto conn = dbPool_->acquire(); pqxx::work txn(conn->get());`
  runs **outside** the `try`. When the connection is broken, the `pqxx::work` constructor throws, and `conn` (a `unique_ptr`) is
  destroyed without `release()`, so a pool slot is permanently lost.
- `core/include/db/DBPool.hpp`: a fixed 4 connections with **no health check or reconnect**. Broken connections
  that are returned stay broken and keep leaking slots on reuse. `acquire()` waits on a condvar **with no timeout**.
- Net effect: after 4 failures the pool is empty, and every DB caller blocks forever, including FUSE ops, ws
  handlers, and snapshots. The watchdog can't see it, because services are "running", not crashed.

Fix direction: RAII lease that always returns or replaces the connection, reconnect-on-broken
(`pqxx::broken_connection`) with backoff, a bounded `acquire()` timeout that surfaces an error instead of hanging,
a health signal into `SystemHealth`/watchdog, and a regression test that restarts or kills PostgreSQL
backends (`pg_terminate_backend`) mid-run.

**Status (branch `worktree-agent-af71be6ff010ea87d`, not yet merged or lab-proven):** code fix landed as described
in `architecture.md` → Database, and `core/tests/unit/test_db_pool_reconnect.cpp` covers termination of all pool
backends (repeated, concurrent), mid-transaction loss, exhaustion timeout, and an unreachable DB (via
`CONNECTION LIMIT 0`). Still open: lab proof (restart `postgresql@16-main` under a running daemon on vh-storage),
wiring `database.pool_size`, a database line in the watchdog email body, and a statement timeout for a server that
hangs mid-query. TCP keepalives + `tcp_user_timeout` landed with the libpqxx 8 migration (2026-10-10), which also
replaces connections libpqxx reports as poisoned (`DBPoolReconnectTest.PoisonedConnectionsAreReplacedOnTheNextAcquire`).

### Fixed on feat/rich-preview-platform: a crash wedged the daemon instead of restarting it

Found on the dev VM (2026-10-06). `fs::metadata::Magic` shared one libmagic cookie per static instance across
threads with no lock. Concurrent FUSE seals and uploads corrupted the heap, and a SIGSEGV hit `malloc` in
`WorkingCopies::seal`. The kernel core dump then waited forever: two daemon threads were in `close()` on files of
its own mount, waiting for a FUSE reply. Ports accepted but never answered, `gdb` attach hung, and
`Restart=on-failure` never fired. Fixes: `Magic` serializes each cookie (`test_magic_concurrency`, which is red
under ASan without it), and `main()` sets `PR_SET_DUMPABLE 0` plus a backtrace-to-journal fatal handler
(contract `test_daemon_crash_exits_instead_of_wedging_its_mount`). To recover a host wedged in `coredump_wait`,
write `1` to `/sys/fs/fuse/connections/<minor>/abort` (the minor comes from `/proc/self/mountinfo`).

### P0-2: maintainer scripts can block indefinitely on the FUSE mount

`debian/postinst` `is_mountpoint()` (~L67) runs `mountpoint -q "$path"` with no timeout, and there may be other
callers too. Any wedged daemon therefore hangs `apt upgrade` for the whole host, blocking unrelated security updates.
Fix direction: `timeout` every FUSE-touching probe, prefer `/proc/self/mountinfo` parsing (no FUSE
round-trip) to detect the mount, and consider stopping `vaulthalla.service` in `prerm upgrade` so the new binary
comes up on a fresh mount. Add a packaging contract test that greps maintainer scripts for unguarded mount
probes.

### P0-3: nothing verifies an upgrade on a real host

`publish-debian` ships straight to `apt.valkyrianlabs.com stable` (apt.vaulthalla.sh until 1.16.0), and the lab pulled 1.6.6 from there. There is no
gate that installs and upgrades the candidate `.deb` on a real host with a running daemon, TPM, PostgreSQL, and nginx before
publication. Candidate: a lab smoke stage (N-1 → N upgrade, service health, FUSE `stat` with timeout,
`vh status`, DB restart survival) using vh-storage or a disposable clone of it.

### P0-4 (resolved): packaging guardrail tests that never ran

They lived in a directory `unittest discover` skipped. They are now `tools/contracts` (a package), run by
`tools/dev/verify.sh packaging` in CI and release with a minimum test count, so a suite dropped from discovery fails.

## P1: pipeline and packaging robustness

- `make build` is broken (conan, no conanfile). `run-test` is PHONY without a recipe.
- The dev VM Node (22.16) and pnpm (10.12) don't match the pins (24.13, 11.0.8); CI and dev drift is possible.
- `Config.hpp` default ports (33369/33370) disagree with the shipped config (36969/36970).
- `bin/install_deb.sh --push` is a second, older publication path alongside CI. Decide whether to retire it.
- `debian/changelog` top entry: only the version string is bumped locally, and CI refreshes the body. A manual build
  ships stale bullets (the current 1.6.6 entry body dates from 2026-04-23).
- No `shellcheck` in the toolchain or CI for `bin/` and the maintainer scripts.
- `deploy/lifecycle` unit tests (18, backing `vh setup/teardown`) are **not run by any CI workflow**.

## P2: known functional gaps (carried from earlier workstreams)

- Share email-challenge codes are never delivered (see `link-sharing.md` #1). Other share gaps are listed there too.
- Stats: `integrityCheckStatus` is hard-coded to `"not_available"`, storage `providerOps*` are never populated, and there's no
  global share stats card.
- Operator email: no `vh secret email-provider` alias, and no dedupe, digest scheduler, or security-enqueue tests.
- Web has no unit test runner.
