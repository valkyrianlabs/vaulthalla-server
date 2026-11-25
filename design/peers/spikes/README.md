# Spikes behind `design/peers/`

Evidence for claims in [`../mirror.md`](../mirror.md), "What the spikes found". Nothing here is built or run by CI.

## The tree merge on a local vault (finding 11)

- **Question:** does the three-way merge that the manifest applier uses work when the three trees come from
  databases, on a local vault with no bucket?
- **Test:** [`test_mirror_spike_db.cpp`](test_mirror_spike_db.cpp), a DB-backed unit test written for the spike.
- **Run:** on the dev box, commit 5aa0b231 (v1.26.1), in a private clone: the test copied to `core/tests/unit/`, the
  `build-itest` configuration (debug, ASan and UBSan), then
  `bash bin/tests/run_unit.sh -j 1 -- "--gtest_filter=MirrorSpikeDb.*"`.
- **Output:** [`merge-on-local-vault.log`](merge-on-local-vault.log).

| Test | Result | Meaning |
|---|---|---|
| `MirrorSpikeDb.ReconcileOverLocalVaultCollects` | Passed | `Manifest::collect` and `reconcile` give the expected plan and the four expected conflicts on a local vault, and reconciling again gives an empty plan |
| `MirrorSpikeDb.ApplierOnALocalVault` | **Failed, as recorded in the design** | The existing applier reports the peer's delete and edit as "kept" and does not apply them, and creates files as rows without contents |

When the shared tree-apply module is built (mirror.md, work item 3), this test moves into `core/tests/unit/` and
its second case has to pass.

## The other three spikes

Code reading only, with no experiment: whether `fs_change_log` can be the replication stream (findings 1 and 2),
sealed-byte transfer and key delivery (findings 3 to 5 and 10), and write gating on the mirror (findings 6 to 9).
Their file references are in mirror.md.
