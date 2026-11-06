"""The bucket layout migration drill (#373; design/encryption/01-provider-blind-storage.md §6, §8 "Harness Tier B").

    sudo tools/harness/vhh.sh drill migrate --build build [--files 300]

A private daemon (its own database and swtpm) on the harness's fake S3 with versioning writes an encrypting vault on
the legacy path_v0 layout (the test-only VH_TEST_NEW_ENCRYPTING_LAYOUT=path_v0), syncs it, overwrites and deletes
files so the bucket holds provider history and delete markers. Then the migration is started with a sync pass running
and a writer busy on the FUSE mount the whole time. Pass criteria (each a check in the report): the vault cuts over to
opaque_v1 with its manifest verified from the bucket; the tree read through the mount equals what was written before
plus everything the writer wrote meanwhile; nothing path-named was deleted before the cleanup; the cleanup is refused
before the waiting period; after it (the waiting period shortened in the instance's database) the confirmed cleanup
leaves no path-named key, version or delete marker in the bucket and status says complete; the tree still reads.

Secrets: the S3 credentials reach the daemon over its socket; the key export stays in the drill's private directory.
Nothing is printed.
"""
from __future__ import annotations

import json
import os
import pwd
import random
import secrets
import shutil
import subprocess
import threading
import time
from pathlib import Path

from vhh.drill import Bucket, DrillError, Node, Report, build_tree, snapshot_tree, vault_id_of
from vhh.fake_s3 import FakeS3
from vhh.instance import Instance

OPAQUE_PREFIXES = ("o/", ".vaulthalla/root", ".vaulthalla/seg/", ".vaulthalla/key/", ".vaulthalla/layout.json")


def legacy_keys(bucket: Bucket) -> dict:
    return {k: v for k, v in bucket.keys().items() if not k.startswith(OPAQUE_PREFIXES)}


def wait_for(what: str, predicate, timeout: float, step: float = 1.5):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(step)
    raise DrillError(f"timed out waiting for {what}")


def status(node: Node, vid: int) -> dict:
    code, j = node.vh_json("vault", "migrate-layout", str(vid), "--status", check=False)
    return j if code == 0 else {}


def psql(inst: Instance, sql: str) -> None:
    subprocess.run(["runuser", "-u", "postgres", "--", "psql", "-q", "-v", "ON_ERROR_STOP=1", "-d", inst.db_name,
                    "-c", sql], check=True, capture_output=True, timeout=60)


class Writer(threading.Thread):
    """Writes small files through the FUSE mount until stopped (the vault stays in use during the migration)."""

    def __init__(self, node: Node, folder: str):
        super().__init__(name="vhh-migrate-writer", daemon=True)
        self.node, self.folder = node, folder
        self.stop = threading.Event()
        self.written: dict[str, bytes] = {}
        self.error: str | None = None

    def run(self) -> None:
        n = 0
        try:
            self.node.sh(f"mkdir -p MNT/{self.folder}")
            while not self.stop.is_set():
                body = f"written during the migration #{n}\n".encode()
                self.node.sh(f"printf '%s' '{body.decode()}' > MNT/{self.folder}/w-{n:04d}.txt")
                self.written[f"w-{n:04d}.txt"] = body
                n += 1
                time.sleep(0.2)
        except Exception as e:  # noqa: BLE001
            self.error = str(e)


def run(build: Path, *, files: int = 300, keep: bool = False, out: Path | None = None) -> tuple[bool, dict]:
    report = Report()
    run_id = time.strftime("%Y%m%dT%H%M%S") + "_" + secrets.token_hex(3)
    admin = os.environ.get("SUDO_USER") or "coop"
    private = Path(f"/tmp/vhh_layoutdrill_{run_id}")
    private.mkdir(mode=0o700)
    pw = pwd.getpwnam(admin)
    os.chown(private, pw.pw_uid, pw.pw_gid)
    out = Path(out) if out else private / "report.json"
    rng = random.Random(0x373)
    summary: dict = {"run_id": run_id, "files": files}
    fake = FakeS3().__enter__()
    node: Node | None = None
    writer: Writer | None = None
    try:
        name = f"vh-test-migrate-{secrets.token_hex(4)}"
        fake.create_bucket(name, "Enabled")
        bucket = Bucket(name, fake, fake.endpoint, "AKIAVHHMIGRATE", secrets.token_hex(16), "other", "us-east-1")
        inst = Instance(build, run_id=f"migrate_{run_id}", own_tpm=True,
                        extra_env={"VH_TEST_NEW_ENCRYPTING_LAYOUT": "path_v0"})
        inst.start()
        node = Node(inst, admin, private)
        code, _ = node.frame(["api-key", "create", "migrate", "--access", bucket.access, "--secret", bucket.secret,
                              "--provider", bucket.provider, "--endpoint", bucket.endpoint, "--region", bucket.region])
        if code != 0:
            raise DrillError("api-key create failed")
        cp = node.vh("vault", "create", "migrate", "--s3", "--api-key", "migrate", "--bucket", bucket.name)
        vid = vault_id_of(cp.stdout)
        report.check("a legacy (path_v0) vault", status(node, vid).get("layout") == "path_v0")
        node.vh("vault", "sync", "set", str(vid), "--sync-strategy", "sync", "--s3-budget-preset", "unlimited")
        node.vh("vault", "keys", "export", str(vid), "--output", str(private / "export.json"))  # recovery material

        # ------------------------------------------------------------ a path-keyed bucket with history and markers
        staging = private / "staging"
        staging.mkdir()
        build_tree(staging, files, rng)
        subprocess.run(["chown", "-R", f"{admin}:{admin}", str(staging)], check=True)
        node.sh(f"cp -r {staging}/. MNT/migrate/", timeout=1800)
        node.vh("vault", "sync", str(vid))
        wait_for("the first upload", lambda: len(legacy_keys(bucket)) >= files, 900)
        node.sh("printf 'board notes, second draft\\n' > MNT/migrate/notes.txt && rm MNT/migrate/empty.txt")
        node.vh("vault", "sync", str(vid))
        wait_for("the overwrite and the delete marker",
                 lambda: len(legacy_keys(bucket).get("notes.txt", [])) >= 2 and
                 legacy_keys(bucket).get("empty.txt", [{}])[0].get("delete_marker"), 600)
        before = snapshot_tree(node, "migrate")
        legacy_before = legacy_keys(bucket)
        summary["legacy_keys"] = len(legacy_before)
        summary["legacy_versions"] = sum(len(v) for v in legacy_before.values())

        # ------------------------------------------------------------ migrate while FUSE and a sync pass are busy
        writer = Writer(node, "migrate/live")
        writer.start()
        time.sleep(1)
        node.vh("vault", "sync", str(vid))                         # a pass holds the lease when the migration starts
        node.vh("vault", "migrate-layout", str(vid), "--accept-unpriced")
        t0 = time.time()
        final = wait_for("the cutover", lambda: (s := status(node, vid)) and s.get("migration") and
                         s["migration"]["state"] in ("cut_over", "failed") and s, 1800, step=2)
        summary["migration_seconds"] = round(time.time() - t0, 1)
        time.sleep(3)
        writer.stop.set()
        writer.join(timeout=60)
        report.check("the writer kept writing through FUSE during the migration", writer.error is None and
                     len(writer.written) > 0, writer.error or f"{len(writer.written)} files")
        m = final["migration"]
        summary["estimate"] = m.get("estimate")
        summary["usage"] = m.get("usage")
        if not report.check("cut over to opaque_v1", m["state"] == "cut_over" and final["layout"] == "opaque_v1",
                            json.dumps({"state": m["state"], "error": m.get("last_error")})):
            raise DrillError("the migration did not cut over")
        wait_for("the manifest check", lambda: status(node, vid)["migration"].get("manifest_verified_at"), 300)
        report.check("the manifest was verified from the bucket alone", True)
        missing = [k for k, versions in legacy_before.items()
                   if len(legacy_keys(bucket).get(k, [])) < len(versions)]
        report.check("nothing path-named was deleted before the cleanup", not missing, json.dumps(missing[:10]))

        # the writes made meanwhile upload with the next opaque_v1 passes
        node.vh("vault", "sync", str(vid))
        time.sleep(5)
        node.vh("vault", "sync", str(vid))
        time.sleep(5)
        after = snapshot_tree(node, "migrate")
        def in_live(p: str) -> bool:
            return p.lstrip("/") == "live" or p.lstrip("/").startswith("live/")

        live = {p.lstrip("/"): e for p, e in after.items() if in_live(p)}
        rest = {p: e for p, e in after.items() if not in_live(p)}
        report.check("the tree written before the migration reads the same after it",
                     {p: e.get("sha256") for p, e in rest.items()} == {p: e.get("sha256") for p, e in before.items()},
                     json.dumps(sorted(set(rest) ^ set(before))[:10]))
        report.check("every file written during the migration is there",
                     all(f"live/{n}" in live for n in writer.written), f"{len(live)} of {len(writer.written)}")

        # ------------------------------------------------------------ cleanup: refused, then after the wait, complete
        cp = node.vh("vault", "migrate-layout", str(vid), "--cleanup", "--confirm", "migrate", check=False)
        report.check("the cleanup is refused before the waiting period", cp.returncode != 0, cp.stdout[-300:])
        psql(inst, f"UPDATE vault_layout_migration SET cleanup_after = now() - interval '1 minute' "
                   f"WHERE vault_id = {vid}")
        code, dry = node.vh_json("vault", "migrate-layout", str(vid), "--cleanup")
        report.check("the dry run lists the legacy versions", code == 0 and dry.get("dry_run") and
                     dry["plan"]["deletable"] >= summary["legacy_versions"] - 1, json.dumps(dry.get("plan", {}))[:300])
        node.vh("vault", "migrate-layout", str(vid), "--cleanup", "--confirm", "migrate")
        done = wait_for("the cleanup", lambda: (s := status(node, vid)) and s["migration"]["state"] in
                        ("complete", "cleanup_blocked") and s, 300, step=2)
        report.check("complete: no path-named key, version or delete marker is left",
                     done["migration"]["state"] == "complete" and not legacy_keys(bucket),
                     json.dumps({"state": done["migration"]["state"], "left": list(legacy_keys(bucket))[:10]}))
        again = snapshot_tree(node, "migrate")
        report.check("the tree still reads after the cleanup",
                     {p: e.get("sha256") for p, e in again.items()} == {p: e.get("sha256") for p, e in after.items()})
    except (DrillError, KeyboardInterrupt, subprocess.SubprocessError, RuntimeError, OSError) as e:
        report.check("drill completed", False, str(e) or type(e).__name__)
    finally:
        if writer:
            writer.stop.set()
        if node:
            node.close()
            try:
                node.inst.stop()
            except Exception as e:  # noqa: BLE001
                report.check("instance stopped", False, str(e))
        fake.__exit__(None, None, None)
        summary["checks"] = report.checks
        summary["ok"] = report.ok
        out.write_text(json.dumps(summary, indent=2))
        if not keep:
            for f in private.glob("*.json"):
                if f != out:
                    f.unlink()   # the key export
            shutil.rmtree(private / "staging", ignore_errors=True)
    return report.ok, summary
