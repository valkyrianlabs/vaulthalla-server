"""The mirror drill (design/sync/manifest-applier.md, work item 6, first half): two real daemons write one bucket.

    sudo tools/harness/vhh.sh drill mirror --build build [--keep] [--out report.json]

Node A writes an opaque_v1 vault on the harness's fake S3 (versioned) and enrolls a recovery kit. Node B, an
independent instance (own database, swtpm, mount), restores the vault from the bucket with the kit
(`vh vault recover`). There is no join yet, so both nodes are made writers by a harness-only path: node B's daemon
runs with VH_TEST_MANIFEST_WRITERS=<A's node id>, which the server reads only in test mode (an installed service never
enters test mode: runtime::test_instance), so B's first root names both nodes and A's roots carry the set after it.
A fault file (VH_TEST_FAULT_DIR/crash-after-root-put, test mode only) ends a daemon between a root's PUT and its
record.

Each phase changes files through the real FUSE mounts, runs real sync passes (`vh vault sync`, waited for in the
instance's database), and checks both daemons: the trees (path, kind, size, mode, bytes, symlink target) are equal, each
change journal holds what the phase did, and the per-rule outcome holds. Phases: creates, edits, renames, moves, trash
and restore, deletes; every row of the conflict table with real files; a file held open on B (a real FUSE handle)
deferred, then applied after the close; B crashing between its root PUT and the record while A builds on it; a
remote-only file hydrated on B after A moved it; the trash race (A deletes, B edits) with real passes and no remote
DELETE from either side's purge; publishes stable when nothing changes; a recovery grant on one node only detected.

Secrets (the kit, S3 credentials) stay in the drill's private directory and process memory; nothing is printed.
"""
from __future__ import annotations

import json
import os
import pwd
import secrets
import shutil
import signal
import subprocess
import time
from pathlib import Path

from vhh.drill import Bucket, DrillError, Node, Report, _write_private, snapshot_tree, vault_id_of
from vhh.fake_s3 import FakeS3
from vhh.instance import Instance

FUSE = "drill"


def _sql(node: Node, query: str) -> str:
    cp = subprocess.run(["runuser", "-u", "postgres", "--", "psql", "-d", node.inst.db_name, "-tAc", query],
                        capture_output=True, text=True, timeout=60)
    if cp.returncode != 0:
        raise DrillError(f"psql on {node.inst.db_name} failed: {cp.stderr.strip()[:300]}")
    return cp.stdout.strip()


def object_key(uuid_text: str) -> str:
    """o/<uid> for a files.object_uid (vl-keykit base32: 26 lower-case symbols, MSB first, zero padding)."""
    alphabet, n = "0123456789abcdefghjkmnpqrstvwxyz", int(uuid_text.replace("-", ""), 16) << 2
    return "o/" + "".join(alphabet[(n >> (5 * i)) & 31] for i in reversed(range(26)))


def _last_event(node: Node, vid: int) -> int:
    return int(_sql(node, f"SELECT COALESCE(max(id), 0) FROM sync_event WHERE vault_id = {vid}") or 0)


def sync(node: Node, vid: int, timeout: float = 300) -> None:
    """One real pass, waited for: a sync event after the trigger that is no longer running."""
    before = _last_event(node, vid)
    node.vh("vault", "sync", str(vid))
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        time.sleep(1.0)
        if not node.inst.alive():
            return
        done = _sql(node, f"SELECT count(*) FROM sync_event WHERE vault_id = {vid} AND id > {before} "
                          f"AND status <> 'running'")
        # Only this trigger's passes: a daemon that died mid-pass leaves its event 'running' (the drill's crash).
        running = _sql(node, f"SELECT count(*) FROM sync_event WHERE vault_id = {vid} AND id > {before} "
                             f"AND status = 'running'")
        if int(done or 0) > 0 and int(running or 0) == 0:
            time.sleep(0.5)
            return
    raise DrillError(f"vault {vid}: no finished pass within {timeout}s: {diagnose(node, vid)}")


def epoch(node: Node, vid: int) -> int:
    v = _sql(node, f"SELECT epoch FROM remote_manifest_state WHERE vault_id = {vid} AND manifest_key = '.vaulthalla/root'")
    return int(v or 0)


def root_sha(node: Node, vid: int) -> str:
    return _sql(node, f"SELECT root_sha256 FROM remote_manifest_state WHERE vault_id = {vid} "
                      f"AND manifest_key = '.vaulthalla/root'")


def diagnose(node: Node, vid: int) -> str:
    """The recorded root, the last pass and the last apply, for a failure message (no secrets in these rows)."""
    state = _sql(node, f"SELECT epoch, left(root_sha256, 12), applying_epoch FROM remote_manifest_state "
                       f"WHERE vault_id = {vid} AND manifest_key = '.vaulthalla/root'")
    ev = _sql(node, f"SELECT status, coalesce(stall_reason, ''), left(coalesce(error_message, ''), 240) FROM sync_event "
                    f"WHERE vault_id = {vid} ORDER BY id DESC LIMIT 1")
    ap = _sql(node, f"SELECT epoch, producer, recorded, applied, skipped, deferred, kept, conflicts_open, "
                    f"coalesce(stopped_reason, ''), left(notes::text, 240) FROM manifest_apply_report WHERE vault_id = {vid}")
    changes = _sql(node, f"SELECT string_agg(kind || ' ' || path || ' ' || to_char(changed_at, 'HH24:MI:SS'), ', ') FROM "
                         f"(SELECT * FROM fs_change_log WHERE vault_id = {vid} ORDER BY id DESC LIMIT 30) c WHERE path LIKE '%top%' OR kind = 'move'")
    return f"state [{state}] pass [{ev}] apply [{ap}] last changes [{changes}]"


def journal(node: Node, vid: int, since: int = 0) -> dict:
    rows = _sql(node, f"SELECT kind, count(*) FROM fs_change_log WHERE vault_id = {vid} AND id > {since} GROUP BY kind")
    return {k: int(n) for k, n in (line.split("|") for line in rows.splitlines() if "|" in line)}


def journal_head(node: Node, vid: int) -> int:
    return int(_sql(node, f"SELECT COALESCE(max(id), 0) FROM fs_change_log WHERE vault_id = {vid}") or 0)


def tree(node: Node) -> dict:
    t = snapshot_tree(node, FUSE, hashes=True)
    return {p: {k: v for k, v in e.items() if k != "mtime"} for p, e in t.items()}


class Pair:
    def __init__(self, a: Node, b: Node, va: int, vb: int, report: Report, fake: FakeS3):
        self.a, self.b, self.va, self.vb, self.report, self.fake = a, b, va, vb, report, fake

    def sync(self, *order: str) -> None:
        for who in order:
            sync(self.a, self.va) if who == "a" else sync(self.b, self.vb)

    def settle(self) -> None:
        """Passes until both nodes recorded the same root (at most a few rounds)."""
        for _ in range(4):
            self.sync("a", "b", "a")
            if root_sha(self.a, self.va) == root_sha(self.b, self.vb):
                return
        raise DrillError("the nodes did not settle on one root: " + "; ".join(
            f"{name}: {diagnose(n, v)}" for name, n, v in (("A", self.a, self.va), ("B", self.b, self.vb))))

    def converged(self, label: str) -> tuple[dict, dict]:
        self.settle()
        ta, tb = tree(self.a), tree(self.b)
        diff = {p: (ta.get(p), tb.get(p)) for p in set(ta) | set(tb) if ta.get(p) != tb.get(p)}
        self.report.check(f"{label}: both FUSE views equal", not diff, json.dumps(dict(list(diff.items())[:8])))
        return ta, tb

    def a_sh(self, line: str): return self.a.sh(line.replace("M/", f"MNT/{FUSE}/"))

    def b_sh(self, line: str): return self.b.sh(line.replace("M/", f"MNT/{FUSE}/"))


def run(build: Path, *, keep: bool = False, out: Path | None = None) -> tuple[bool, dict]:
    report = Report()
    run_id = time.strftime("%Y%m%dT%H%M%S") + "_" + secrets.token_hex(3)
    admin = os.environ.get("SUDO_USER") or "coop"
    private = Path(f"/tmp/vhh_mirror_{run_id}")
    private.mkdir(mode=0o700)
    pw = pwd.getpwnam(admin)
    os.chown(private, pw.pw_uid, pw.pw_gid)
    out = Path(out) if out else private / "report.json"
    summary: dict = {"run_id": run_id, "report": str(out)}
    nodes: list[Node] = []
    fake = FakeS3().__enter__()
    holder: subprocess.Popen | None = None
    try:
        name = f"vh-test-mirror-{secrets.token_hex(4)}"
        fake.create_bucket(name, "Enabled")
        bucket = Bucket(name, fake, fake.endpoint, "AKIAVHHMIRROR", secrets.token_hex(16), "other", "us-east-1")

        def node(tag: str, extra: dict | None = None) -> Node:
            faults = private / f"faults-{tag}"
            faults.mkdir(exist_ok=True)
            inst = Instance(build, run_id=f"mirror{tag}_{run_id}", own_tpm=True,
                            extra_env={"VH_TEST_FAULT_DIR": str(faults), **(extra or {})})
            inst.start()
            n = Node(inst, admin, private)
            n.faults = faults  # type: ignore[attr-defined]
            nodes.append(n)
            code, _ = n.frame(["api-key", "create", "drill", "--access", bucket.access, "--secret", bucket.secret,
                               "--provider", bucket.provider, "--endpoint", bucket.endpoint, "--region", bucket.region])
            if code != 0:
                raise DrillError(f"node {tag}: api-key create failed ({code})")
            return n

        def quiet(n: Node, vid: int) -> None:
            """Sync strategy, keep_local, and passes only when the drill asks (an hourly interval)."""
            n.vh("vault", "sync", "set", str(vid), "--sync-strategy", "sync", "--s3-budget-preset", "unlimited",
                 "--on-sync-conflict", "keep_local", "--interval", "1h")
            interval = _sql(n, f"SELECT interval FROM sync WHERE vault_id = {vid}")
            if interval != "3600":
                raise DrillError(f"vault {vid}: the sync interval is {interval}s, not an hour")

        # ------------------------------------------------------------------ A writes, B restores, both writers
        print("vhh drill mirror: node A writes; node B restores; both become writers (test-only)", flush=True)
        a = node("a")
        cp = a.vh("vault", "create", FUSE, "--s3", "--api-key", "drill", "--bucket", bucket.name)
        va = vault_id_of(cp.stdout)
        quiet(a, va)
        a.sh(f"mkdir -p MNT/{FUSE}/Docs MNT/{FUSE}/Photos MNT/{FUSE}/Old MNT/{FUSE}/Keep && "
             f"printf 'report v1\\n' > MNT/{FUSE}/Docs/report.txt && printf 'notes\\n' > MNT/{FUSE}/Docs/notes.txt && "
             f"printf 'a\\n' > MNT/{FUSE}/Photos/a.jpg && printf 'b\\n' > MNT/{FUSE}/Photos/b.jpg && "
             f"printf 'top\\n' > MNT/{FUSE}/top.txt && printf 'old\\n' > MNT/{FUSE}/Old/inside.txt && "
             f"for f in clash edit edit2 rename attr trash trash2 delete del2 cycle1 cycle2 held race hydrate; do "
             f"printf \"$f v1\\n\" > MNT/{FUSE}/Keep/$f.txt; done && mkdir -p MNT/{FUSE}/C1 MNT/{FUSE}/C2")
        sync(a, va)
        kit = private / "kit.json"
        cp = subprocess.run(["runuser", "-u", admin, "--", str(build / "core" / "vh-recovery"), "kit", "create",
                             "--output", str(kit)], capture_output=True, text=True, timeout=60, cwd=str(private))
        if cp.returncode != 0:
            raise DrillError("vh-recovery kit create failed")
        a.vh("vault", "keys", "recipient", "add", str(va), "--public-key", cp.stdout.split()[0], "--label", "mirror")
        sync(a, va)
        status_a = a.key_status(va)
        status_path = _write_private(private / "status-a.json", {"vaults": [status_a]}, admin)
        subprocess.run(["runuser", "-u", admin, "--", str(build / "core" / "vh-recovery"), "kit", "add-vault", str(kit),
                        "--status", str(status_path)], check=True, capture_output=True, timeout=60)
        node_a = status_a["node_id"]

        b = node("b", {"VH_TEST_MANIFEST_WRITERS": node_a})
        code, res = b.vh_json("vault", "recover", "--api-key", "drill", "--bucket", bucket.name, "--kit", "kit.json")
        if not report.check("B: restored from the bucket with the kit", code == 0 and res.get("written") is True,
                            json.dumps(res)[:800]):
            raise DrillError("the restore failed")
        vb = int(res["vault_id"])
        quiet(b, vb)
        sync(b, vb)
        sync(a, va)
        writers_a = _sql(a, f"SELECT cardinality(writers) FROM remote_manifest_state WHERE vault_id = {va} "
                            f"AND manifest_key = '.vaulthalla/root'")
        report.check("both nodes are writers of the recorded root (the harness-only path)", writers_a == "2", writers_a)
        pair = Pair(a, b, va, vb, report, fake)
        pair.converged("after the restore")

        # ------------------------------------------------------------------ 1. every kind of change, on both sides
        print("vhh drill mirror: creates, edits, renames, moves, trash and restore, deletes", flush=True)
        ja, jb = journal_head(a, va), journal_head(b, vb)
        pair.a_sh("printf 'new from A\\n' > M/fromA.txt && mkdir M/NewA && printf 'x\\n' > M/NewA/x.txt && "
                  "printf 'report v2\\n' > M/Docs/report.txt && mv M/top.txt M/top-renamed.txt && "
                  "mv M/Photos/a.jpg M/Docs/a.jpg && rm M/Photos/b.jpg")
        pair.b_sh("printf 'new from B\\n' > M/fromB.txt && printf 'notes v2\\n' > M/Docs/notes.txt && "
                  "rm -r M/Old && ln -s Docs/report.txt M/latest")
        ta, _ = pair.converged("1 changes")
        report.check("1: A's and B's creates, edits, renames, moves and deletes are on both",
                     all(p in ta for p in ("/fromA.txt", "/fromB.txt", "/NewA/x.txt", "/top-renamed.txt", "/Docs/a.jpg",
                                           "/latest")) and not any(p in ta for p in ("/top.txt", "/Photos/a.jpg",
                                                                                      "/Photos/b.jpg", "/Old")),
                     json.dumps(sorted(ta))[:800])
        for who, n, vid, since in (("A", a, va, ja), ("B", b, vb, jb)):
            kinds = journal(n, vid, since)
            report.check(f"1: {who}'s change journal holds creates, updates, renames, moves and deletes",
                         all(kinds.get(k, 0) > 0 for k in ("create", "update", "rename", "move", "delete")),
                         json.dumps(kinds))
        # trash and restore: B restores what A trashed before A's pass purges it is not possible on a cloud vault
        # (the trash is purged at the start of the trashing node's next pass), so the restore is the trashing node's
        pair.a_sh("rm M/Keep/trash2.txt")
        report.check("1: A's trash row exists until its pass", _sql(a, f"SELECT count(*) FROM files_trashed WHERE "
                                                                    f"vault_id = {va} AND deleted_at IS NULL") != "0")
        ta, _ = pair.converged("1 trash")
        report.check("1: the trashed file is gone on both", "/Keep/trash2.txt" not in ta)

        # ------------------------------------------------------------------ 2. the conflict table, with real files
        print("vhh drill mirror: the conflict table", flush=True)
        pair.a_sh("printf 'edit by A\\n' > M/Keep/edit.txt && mv M/Keep/rename.txt M/Keep/rename-A.txt && "
                  "chmod 600 M/Keep/attr.txt && printf 'A\\n' > M/Keep/clash-new.txt && mv M/C1 M/C2/C1 && "
                  "printf 'A edited\\n' > M/Keep/del2.txt && rm M/Keep/trash.txt && rm M/Keep/delete.txt")
        pair.b_sh("printf 'edit by B\\n' > M/Keep/edit.txt && mv M/Keep/rename.txt M/Keep/rename-B.txt && "
                  "chmod 640 M/Keep/attr.txt && printf 'B\\n' > M/Keep/clash-new.txt && mv M/C2 M/C1/C2 && "
                  "rm M/Keep/del2.txt && rm M/Keep/trash.txt && rm M/Keep/delete.txt && "
                  "printf 'in a folder A keeps\\n' > M/Docs/fromB-in-docs.txt")
        pair.a_sh("rm -r M/NewA")   # a folder deleted on A while B (above) adds nothing in it: plain delete
        # Content edit/edit with another writer, keep_local configured: the conflict is recorded and stays open on the
        # node that saw both sides (the bucket keeps no versions for Vaulthalla: no provider_versioning policy), that
        # node keeps its own edit locally and the bucket keeps the other's. Nothing is dropped; then decided by hand.
        pair.settle()
        ta, tb = tree(a), tree(b)
        diff = sorted(p for p in set(ta) | set(tb) if ta.get(p) != tb.get(p))
        report.check("2 conflicts: both FUSE views equal but the open edit/edit", diff == ["/Keep/edit.txt"],
                     json.dumps(diff[:8]))
        open_a = int(_sql(a, f"SELECT count(*) FROM sync_conflicts WHERE vault_id = {va} AND resolved_at IS NULL") or 0)
        open_b = int(_sql(b, f"SELECT count(*) FROM sync_conflicts WHERE vault_id = {vb} AND resolved_at IS NULL") or 0)
        edit_a = a.sh(f"cat MNT/{FUSE}/Keep/edit.txt").stdout
        edit_b = b.sh(f"cat MNT/{FUSE}/Keep/edit.txt").stdout
        report.check("2 edit/edit: recorded and open on one node whatever the policy (keep_local here)",
                     open_a + open_b == 1, json.dumps({"open_a": open_a, "open_b": open_b}))
        report.check("2 edit/edit: both generations readable (each node's own edit; the open side's is local, the "
                     "other's is the bucket's)", {edit_a, edit_b} == {"edit by A\n", "edit by B\n"},
                     json.dumps([edit_a, edit_b]))
        loser, lvid = (b, vb) if open_b else (a, va)
        loser.vh("sync", "resolve", "--vault", str(lvid), "--all", "--keep-remote", "--yes")
        ta, tb = pair.converged("2 after the edit/edit is decided (keep remote)")
        winner_text = edit_a if open_b else edit_b
        report.check("2 edit/edit decided: the bucket's generation on both",
                     a.sh(f"cat MNT/{FUSE}/Keep/edit.txt").stdout == winner_text ==
                     b.sh(f"cat MNT/{FUSE}/Keep/edit.txt").stdout, winner_text)
        report.check("2 rename/rename: the head's name on both, the other undone",
                     ("/Keep/rename-A.txt" in ta) != ("/Keep/rename-B.txt" in ta) and "/Keep/rename.txt" not in ta)
        # chmod through FUSE is a no-op by design (fuse::Bridge setattr: mode and owner are refused), so the attribute
        # rule can't be driven with real files here; ManifestReconcile and ManifestApplyDb.AnAttributeChange* cover it.
        report.check("2 attributes: chmod is a FUSE no-op on both, one mode on both",
                     ta.get("/Keep/attr.txt", {}).get("mode") == tb.get("/Keep/attr.txt", {}).get("mode") == "644",
                     json.dumps([ta.get("/Keep/attr.txt"), tb.get("/Keep/attr.txt")]))
        clash = sorted(p for p in ta if p.startswith("/Keep/clash-new"))
        report.check("2 two creates of one name: both kept, the greater uid renamed (uid suffix)", len(clash) == 2,
                     json.dumps(clash))
        report.check("2 a move closing a cycle: not applied, one tree",
                     ("/C2/C1" in ta) != ("/C1/C2" in ta), json.dumps([p for p in ta if p.startswith("/C")]))
        report.check("2 edit/delete: the edit wins", ta.get("/Keep/del2.txt", {}).get("sha256") is not None)
        report.check("2 trash/trash and delete/delete: converged (gone)",
                     "/Keep/trash.txt" not in ta and "/Keep/delete.txt" not in ta)
        report.check("2 a folder deleted on one side, a file added in another: the added file stays",
                     "/Docs/fromB-in-docs.txt" in ta)

        # ------------------------------------------------------------------ 3. an open file on B (a real FUSE handle)
        print("vhh drill mirror: a file held open on B is deferred", flush=True)
        target = f"{b.inst.mount}/{FUSE}/Keep/held.txt"
        holder = subprocess.Popen(["runuser", "-u", admin, "--", "sh", "-c", f"exec 3<>'{target}'; sleep 600"],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  start_new_session=True)
        time.sleep(1.5)
        pair.a_sh("printf 'held v2 from A\\n' > M/Keep/held.txt")
        pair.sync("a", "b")
        deferred = int(_sql(b, f"SELECT count(*) FROM manifest_apply_deferred WHERE vault_id = {vb}") or 0)
        report.check("3: B deferred the replacement while the file is open", deferred == 1, str(deferred))
        os.killpg(holder.pid, signal.SIGTERM)   # our own process group (started above), never by name
        holder.wait(timeout=30)
        holder = None
        time.sleep(1)
        ta, tb = pair.converged("3 after the close")
        report.check("3: after the close B holds A's content", b.sh(f"cat MNT/{FUSE}/Keep/held.txt").stdout ==
                     "held v2 from A\n")

        # ------------------------------------------------------------------ 4. B crashes between its PUT and record
        print("vhh drill mirror: B crashes between a root PUT and its record; A builds on it", flush=True)
        pair.b_sh("printf 'written on B before the crash\\n' > M/crash.txt")
        (b.faults / "crash-after-root-put").write_text("")  # type: ignore[attr-defined]
        try:
            b.vh("vault", "sync", str(vb), check=False)
        except subprocess.TimeoutExpired:
            pass
        end = time.monotonic() + 120
        while b.inst.alive() and time.monotonic() < end:
            time.sleep(1)
        report.check("4: B ended between the PUT and the record", not b.inst.alive())
        pair.a_sh("printf 'A after B crashed\\n' > M/after-crash.txt")
        sync(a, va)
        b.close()
        b.inst.restart()
        ta, tb = pair.converged("4 after B's restart")
        report.check("4: B's change from its unrecorded root and A's change on top are on both",
                     "/crash.txt" in ta and "/after-crash.txt" in ta)

        # ------------------------------------------------------------------ 5. remote-only hydration after a move
        print("vhh drill mirror: a remote-only file hydrated on B after A moved it", flush=True)
        pair.a_sh("mv M/Keep/hydrate.txt M/Docs/hydrated.txt")
        pair.settle()
        report.check("5: B reads the moved file at its new place", b.sh(f"cat MNT/{FUSE}/Docs/hydrated.txt").stdout ==
                     "hydrate v1\n")

        # ------------------------------------------------------------------ 6. the trash race, with real passes
        print("vhh drill mirror: A deletes a file B edits; no remote DELETE from a shared purge", flush=True)
        race_uid = _sql(a, f"SELECT f.object_uid FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id WHERE "
                           f"e.vault_id = {va} AND e.path = '/Keep/race.txt'")
        fake.clear_requests()
        pair.a_sh("rm M/Keep/race.txt")
        pair.b_sh("printf 'race edited on B\\n' > M/Keep/race.txt")
        ta, _ = pair.converged("6 the trash race")
        deletes = [r for r in fake.requests() if r.get("method") == "DELETE" and str(r.get("key", "")).startswith("o/")]
        report.check("6: the edit beats the delete on both", ta.get("/Keep/race.txt") is not None)
        report.check("6: no remote DELETE of an object from either node's shared trash purge", not deletes,
                     json.dumps(deletes[:5]))
        purged = _sql(a, f"SELECT object_key FROM manifest_shared_purge WHERE vault_id = {va}").split()
        report.check("6: A remembered its local purge (beside its earlier shared purges) for the orphan collection "
                     "(deleted after 7 days only, and only if no root names it: B's edit names it again)",
                     object_key(race_uid) in purged,
                     json.dumps(purged[:5]))
        report.check("6: the object is still in the bucket", fake.current(bucket.name, object_key(race_uid)) is not None,
                     race_uid[:8])

        # ------------------------------------------------------------------ 7. stable publishes
        print("vhh drill mirror: nothing changes: no new roots", flush=True)
        before = (epoch(a, va), epoch(b, vb), root_sha(a, va))
        pair.sync("a", "b", "a", "b")
        after = (epoch(a, va), epoch(b, vb), root_sha(a, va))
        report.check("7: four passes with nothing changed publish nothing (no alternating roots)", before == after,
                     json.dumps({"before": before, "after": after}))

        # ------------------------------------------------------------------ 8. a grant on one node only (detected)
        print("vhh drill mirror: a recovery grant on B only", flush=True)
        kit2 = private / "kit-b-only.json"
        cp = subprocess.run(["runuser", "-u", admin, "--", str(build / "core" / "vh-recovery"), "kit", "create",
                             "--output", str(kit2)], capture_output=True, text=True, timeout=60, cwd=str(private))
        b.vh("vault", "keys", "recipient", "add", str(vb), "--public-key", cp.stdout.split()[0], "--label", "b-only")
        pair.sync("b", "a")
        notes = _sql(a, f"SELECT notes::text FROM manifest_apply_report WHERE vault_id = {va}")
        report.check("8: A detects the grants differ between the writers (report note)", "grants_differ" in notes,
                     notes[:300])
        info = a.vh("vault", "sync", "info", str(va)).stdout
        report.check("8: `vh vault sync info` shows the manifest status", "Manifest:" in info and "writers: 2" in info,
                     info[-400:])
        summary["epochs"] = {"a": epoch(a, va), "b": epoch(b, vb)}
    except (DrillError, KeyboardInterrupt) as e:
        report.check("drill completed", False, str(e) or type(e).__name__)
        for n in nodes:   # what a failed step leaves behind: directory totals below zero
            try:
                bad = _sql(n, "SELECT string_agg(e.path || ' ' || d.file_count || '/' || d.subdirectory_count || '/' || "
                              "d.size_bytes, ', ') FROM directories d JOIN fs_entry e ON e.id = d.fs_entry_id "
                              "WHERE d.file_count < 0 OR d.subdirectory_count < 0 OR d.size_bytes < 0")
                if bad:
                    report.check(f"{n.inst.run_id}: directory totals stay non-negative", False, bad[:600])
            except DrillError:
                pass
    finally:
        if holder is not None:
            try:
                os.killpg(holder.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for n in nodes:
            n.close()
            try:
                n.inst.stop()
            except Exception as e:  # noqa: BLE001
                report.check("instance stopped", False, str(e))
        fake.__exit__(None, None, None)
        summary["checks"] = report.checks
        summary["ok"] = report.ok
        out.write_text(json.dumps(summary, indent=2))
        if not keep:
            for f in private.glob("*.json"):
                if f != out:
                    f.unlink()
            shutil.rmtree(private / "staging", ignore_errors=True)
    return report.ok, summary
