# Controlled fault fixtures

Each patch reintroduces one defect class into a scratch build (`build.sh <fault>`), never into a checkout. The engine
must detect every one of them, and the unpatched tree must pass the same seeded scenario. They are the proof that a
green engine run means something.

| Fault | What it breaks | Must be caught by |
|---|---|---|
| `libmagic-race` | Reverts d69f11ce: one libmagic cookie shared across threads with no lock (the 2026-10-06 heap corruption). | Concurrent FUSE writes + HTTP uploads in `pressure`/`free` on an ASan build: daemon crash (liveness / supervisor) or a sanitizer report in the run artifacts. |
| `stale-revocation` | `ops::roles::unassignVaultRole` deletes the assignment row without telling the identity manager, so the canonical subject keeps the grant until the watcher reconciles. | A revoker session plus the oracle judge: an allow on the revoked vault after the grace window. |
| `ws-list-skips-rbac` | The console's `fs.dir.list` skips its List permission check. | Oracle judge (allow where the model denies) and parity judge (ws allows, FUSE denies). |

Daemon hang/crash during an active FUSE operation needs no patch: the `hang` scenario stops the daemon (SIGSTOP)
while a FUSE actor has a request in flight, and the supervisor must report a wedge with evidence and abort only the
run's own FUSE connection.

Broken assertions and a broken oracle are covered by negative controls: Tier A `VH_TEST_NEGATIVE_CONTROL` and the
engine's planted-defect self tests (`tools/harness/tests/test_selftests.py`).
