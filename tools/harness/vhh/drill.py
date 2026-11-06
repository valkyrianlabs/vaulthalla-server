"""The catastrophic restore drill (design/encryption/03-metadata-recovery.md §7; #371).

    sudo tools/harness/vhh.sh drill recover --build build [--files 2000]          # fake S3 with versioning (harness)
    sudo tools/harness/drill_recover_r2.sh --build build                          # live Cloudflare R2 (vh-test-* bucket)

Node A (a private daemon with its own database, state directory and swtpm) writes an opaque_v1 vault: nested folders,
0-byte, small and multipart-sized files, symlinks, renames of files and folders, a purged file, overwrites, a
snapshot, two key rotations, a recovery recipient enrolled after the first rotation, a key export taken before the
second, a checkpoint pinned in the kit, and an abandoned multipart upload. Then node A is destroyed: the daemon
stopped, its database dropped, its TPM state and backing store deleted. Node B, an independent instance with its own
database and swtpm and nothing shared but the bucket and the customer's material, runs `vh vault recover --kit`.

Pass criteria (each one a check in the report): the plaintext tree (path, kind, bytes, mode, mtime, symlink target)
equals node A's; key status shows every version present and attested by origin; no byte of content is fetched
beyond 120-byte headers until a file is read; the restored vault rotates its key and syncs; a second restore of the
same bucket on node C is consistent (the original kit proves node A's versions, a kit refreshed from node B proves all
of them). Negative drills (harness only, each on a snapshot of the bucket): root deleted (versioned: an older root;
unversioned: blind rebuild under /Recovered), a corrupt segment, a rollback with and without a checkpoint, a wrong
seed, a kit for another vault, an export alone after a rotation, a kit without attestation keys, and anchors that
belong to another node or to the restoring node itself.

Secrets: the kit (it holds the recovery seed), the key exports and the S3 credentials stay in the drill's private
directory and process memory; API keys reach the daemon over its socket, never on a command line. Nothing is printed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pwd
import random
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from vhh.drivers.cli_sock import Connector, _recv_frame, _send_frame
from vhh.fake_s3 import FakeS3, content_downloads
from vhh.instance import Instance

HEADER = 120


class DrillError(RuntimeError):
    pass


class Report:
    def __init__(self):
        self.checks: list[dict] = []

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append({"check": name, "ok": bool(ok), "detail": detail[:2000]})
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(': ' + detail[:300]) if detail and not ok else ''}", flush=True)
        return ok

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c["ok"] for c in self.checks)


# ------------------------------------------------------------------------------------------------ talking to a node

class Node:
    """One private instance and the admin account the drill drives it as (the sudo user is its super admin)."""

    def __init__(self, inst: Instance, admin: str, private: Path):
        self.inst = inst
        self.admin = admin
        self.private = private
        self.connector: Connector | None = None

    @property
    def cli(self) -> str:
        return str(self.inst.cli)

    def vh(self, *args: str, timeout: float = 300, check: bool = True) -> subprocess.CompletedProcess:
        """The real vh binary as the admin account (reads --kit / --export files on its own side)."""
        env = [f"VAULTHALLA_CLI_SOCKET={self.inst.socket_path}", "VAULTHALLA_NONINTERACTIVE=1", "PATH=/usr/bin:/bin"]
        cp = subprocess.run(["runuser", "-u", self.admin, "--", "env", "-i", *env, self.cli, *args],
                            capture_output=True, text=True, timeout=timeout, cwd=str(self.private))
        if check and cp.returncode != 0:
            raise DrillError(f"vh {args[0]} {args[1] if len(args) > 1 else ''} failed ({cp.returncode}): "
                             f"{(cp.stdout + cp.stderr)[-600:]}")
        return cp

    def vh_json(self, *args: str, timeout: float = 600, check: bool = True):
        cp = self.vh(*args, "--json", timeout=timeout, check=check)
        text = cp.stdout.strip() or cp.stderr.strip()
        try:
            return cp.returncode, json.loads(text[text.index("{"):]) if "{" in text else {"raw": text}
        except (ValueError, json.JSONDecodeError):
            return cp.returncode, {"raw": text[-800:]}

    def frame(self, args: list[str], timeout: float = 60) -> tuple[int, str]:
        """A command sent over the socket by the drill itself (for arguments that are secrets)."""
        if self.connector is None:
            self.connector = Connector(str(self.inst.socket_path), self.admin)
        sock = self.connector.connect(10)
        with sock:
            _send_frame(sock, {"cmd": args[0], "args": args[1:], "argv": args, "line": shlex.join(args),
                               "interactive": False})
            out = []
            end = time.monotonic() + timeout
            while True:
                sock.settimeout(max(1.0, end - time.monotonic()))
                f = _recv_frame(sock)
                if f.get("type") == "hello":
                    continue
                if f.get("type") == "output":
                    out.append(f.get("text", ""))
                    continue
                code = f.get("exit_code")
                if not isinstance(code, int):
                    code = 0 if f.get("ok") else 1
                return code, "".join(out) + (f.get("stdout") or "") + (f.get("stderr") or "")

    def sh(self, line: str, timeout: float = 600) -> subprocess.CompletedProcess:
        """A shell line as the admin account against this node's mount (bounded: a wedged mount can't hang it)."""
        line = line.replace("MNT", str(self.inst.mount))
        cp = subprocess.run(["runuser", "-u", self.admin, "--", "timeout", str(int(timeout)), "sh", "-c", line],
                            capture_output=True, text=True, timeout=timeout + 30)
        if cp.returncode != 0:
            raise DrillError(f"shell step failed ({cp.returncode}): {(cp.stdout + cp.stderr)[-600:]}")
        return cp

    def close(self):
        if self.connector:
            self.connector.close()
            self.connector = None

    # ---- vault helpers
    def key_status(self, vault: int) -> dict:
        code, j = self.vh_json("vault", "keys", "status", str(vault))
        if code != 0 or "vaults" not in j:
            raise DrillError(f"key status failed: {j}")
        return j["vaults"][0]

    def epoch(self, vault: int) -> int:
        cp = self.key_status(vault).get("checkpoint")
        return int(cp["epoch"]) if cp else 0

    def sync(self, vault: int, timeout: float = 900) -> None:
        """Runs a sync pass and waits until it published (the manifest epoch moved) and the vault is quiet."""
        before = self.epoch(vault)
        self.vh("vault", "sync", str(vault))
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            time.sleep(1.5)
            if self.epoch(vault) > before:
                time.sleep(2)  # the pass's tail (index, GC) after the publish
                return
        raise DrillError(f"vault {vault}: no manifest publish within {timeout}s of a sync")


def snapshot_tree(node: Node, fuse_name: str, hashes: bool = True) -> dict:
    """path → {kind, size, mode, mtime, target, sha256} through the node's mount (reads files when hashes)."""
    root = f"MNT/{fuse_name}"
    listing = node.sh(f"cd {root} && find . -mindepth 1 -printf '%y\\t%s\\t%m\\t%T@\\t%p\\t%l\\n'").stdout
    tree = {}
    for line in listing.splitlines():
        kind, size, mode, mtime, path, target = line.split("\t")
        path = path[1:]
        if path.startswith("/.vh") or "/.upload-http-" in path:
            continue
        tree[path] = {"kind": kind, "size": int(size) if kind == "f" else None, "mode": mode,
                      "mtime": int(float(mtime)), "target": target or None}
    if hashes:
        files = [p for p, e in tree.items() if e["kind"] == "f"]
        for i in range(0, len(files), 200):
            batch = files[i:i + 200]
            quoted = " ".join("'." + p.replace("'", "'\\''") + "'" for p in batch)
            out = node.sh(f"cd {root} && sha256sum -- {quoted}").stdout
            for line in out.splitlines():
                digest, _, name = line.partition("  ")
                tree[name[1:]]["sha256"] = digest
    return tree


def vault_id_of(text: str) -> int:
    for line in text.splitlines():
        if line.strip().startswith("ID:"):
            return int(line.split(":", 1)[1])
    raise DrillError("no vault id in the create output")


# ------------------------------------------------------------------------------------------------ the bucket

class Bucket:
    """Where the drill's vault lives: the fake S3 (with a side channel to damage it) or a live R2 bucket."""

    def __init__(self, name: str, fake: FakeS3 | None, endpoint: str, access: str, secret: str, provider: str,
                 region: str):
        self.name, self.fake, self.endpoint = name, fake, endpoint
        self.access, self.secret, self.provider, self.region = access, secret, provider, region

    def admin(self, op: str, body: bytes = b"", **q) -> bytes:
        if not self.fake:
            raise DrillError("bucket damage is a harness-only drill")
        import urllib.request
        from urllib.parse import urlencode
        q.setdefault("bucket", self.name)
        req = urllib.request.Request(f"{self.endpoint}/__vhh/{op}?{urlencode(q)}", data=body or None,
                                     method="POST" if body or op not in ("log", "keys", "get") else "GET")
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read()

    def keys(self) -> dict:
        return json.loads(self.admin("keys"))


# ------------------------------------------------------------------------------------------------ the drill

def _write_private(path: Path, data, owner: str) -> Path:
    path.write_text(json.dumps(data, indent=2) if not isinstance(data, str) else data)
    pw = pwd.getpwnam(owner)
    os.chown(path, pw.pw_uid, pw.pw_gid)
    os.chmod(path, 0o600)
    return path


def build_tree(staging: Path, files: int, rng: random.Random) -> None:
    """Nested folders; 0-byte, small and multipart-sized (6 MiB, above the 5 MiB part size) files."""
    folders = [staging / f"d{i:02d}" / f"s{j}" for i in range(max(1, files // 100)) for j in range(5)]
    for f in folders:
        f.mkdir(parents=True, exist_ok=True)
    (staging / "Reports" / "2026").mkdir(parents=True)
    (staging / "Reports" / "2026" / "q3 board pack.pdf").write_bytes(rng.randbytes(6 * 1024 * 1024 + 4321))
    (staging / "empty.txt").write_bytes(b"")
    (staging / "notes.txt").write_bytes(b"board notes, first draft\n")
    for n in range(max(0, files - 3)):
        size = 0 if n % 50 == 0 else rng.randint(1, 4096)
        (folders[n % len(folders)] / f"file-{n:05d}.bin").write_bytes(rng.randbytes(size))


def run(build: Path, *, files: int = 2000, s3: str = "fake", negative: bool = True, keep: bool = False,
        out: Path | None = None) -> tuple[bool, dict]:
    report = Report()
    run_id = time.strftime("%Y%m%dT%H%M%S") + "_" + secrets.token_hex(3)
    admin = os.environ.get("SUDO_USER") or "coop"
    private = Path(f"/tmp/vhh_drill_{run_id}")
    private.mkdir(mode=0o700)
    pw = pwd.getpwnam(admin)
    os.chown(private, pw.pw_uid, pw.pw_gid)
    out = Path(out) if out else private / "report.json"
    rng = random.Random(0x371)
    fake: FakeS3 | None = None
    nodes: list[Node] = []
    bucket: Bucket | None = None
    live_tool = build / "core" / "vh_live_bucket"
    summary: dict = {"run_id": run_id, "s3": s3, "files": files}
    try:
        if s3 == "fake":
            fake = FakeS3().__enter__()
            name = f"vh-test-drill-{secrets.token_hex(4)}"
            fake.create_bucket(name, "Enabled")
            bucket = Bucket(name, fake, fake.endpoint, "AKIAVHHDRILL", secrets.token_hex(16), "other", "us-east-1")
        else:
            name = "vh-test-recover-drill"
            env = {k: os.environ[k] for k in os.environ if k.startswith("VH_R2_ADMIN_")}
            missing = [k for k in ("VH_R2_ADMIN_ACCESS_KEY", "VH_R2_ADMIN_SECRET_KEY", "VH_R2_ADMIN_ENDPOINT") if k not in env]
            if missing:
                raise DrillError(f"live drill needs {', '.join(missing)} in the environment")
            cp = subprocess.run([str(live_tool), "create", name], env={**env, "PATH": "/usr/bin:/bin",
                                "VH_LIVE_TESTS": "1"}, capture_output=True, text=True, timeout=300)
            if cp.returncode != 0:
                raise DrillError(f"vh_live_bucket create failed: {cp.stdout[-300:]}{cp.stderr[-300:]}")
            bucket = Bucket(name, None, env["VH_R2_ADMIN_ENDPOINT"], env["VH_R2_ADMIN_ACCESS_KEY"],
                            env["VH_R2_ADMIN_SECRET_KEY"], "cloudflare-r2", env.get("VH_R2_ADMIN_REGION", "auto"))
        summary["bucket"] = bucket.name

        def node(tag: str) -> Node:
            inst = Instance(build, run_id=f"drill{tag}_{run_id}", own_tpm=True)
            inst.start()
            n = Node(inst, admin, private)
            nodes.append(n)
            code, text = n.frame(["api-key", "create", "drill", "--access", bucket.access, "--secret", bucket.secret,
                                  "--provider", bucket.provider, "--endpoint", bucket.endpoint, "--region",
                                  bucket.region])
            if code != 0:
                raise DrillError(f"node {tag}: api-key create failed ({code})")
            return n

        # ---------------------------------------------------------------- node A writes
        print(f"vhh drill: node A writes {files} files to {bucket.name}", flush=True)
        a = node("a")
        cp = a.vh("vault", "create", "drill", "--s3", "--api-key", "drill", "--bucket", bucket.name)
        vid = vault_id_of(cp.stdout)
        report.check("A: a new encrypting vault is opaque_v1", "opaque (v1)" in cp.stdout)
        # A drill writes thousands of objects in one pass: no per-run request budget.
        a.vh("vault", "sync", "set", str(vid), "--sync-strategy", "sync", "--s3-budget-preset", "unlimited")
        a.vh("vault", "recovery", "set", str(vid), "--mode", "local-snapshots", check=False)
        staging = private / "staging"
        staging.mkdir()
        build_tree(staging, files, rng)
        subprocess.run(["chown", "-R", f"{admin}:{admin}", str(staging)], check=True)
        a.sh(f"cp -r {staging}/. MNT/drill/", timeout=1800)
        a.sync(vid)
        # renames (a file, a folder), a symlink, a purged file, an overwrite (a provider version)
        a.sh("mv MNT/drill/notes.txt MNT/drill/Reports/notes.txt && mv MNT/drill/Reports/2026 MNT/drill/Reports/FY26 "
             "&& ln -s FY26/'q3 board pack.pdf' MNT/drill/Reports/latest && rm MNT/drill/d00/s0/file-00000.bin")
        a.sync(vid)
        a.sh("printf 'board notes, second draft\\n' > MNT/drill/Reports/notes.txt")
        a.sync(vid)
        a.vh("snapshot", "create", str(vid), "/d00", "--name", "before rotation", check=False)
        # rotation 1, then the recovery recipient (a kit made "on the customer's device": vh-recovery)
        a.vh("vault", "keys", "rotate", str(vid), "--sync-now")
        a.sync(vid)
        kit_path = private / "kit.json"
        cp = subprocess.run(["runuser", "-u", admin, "--", str(build / "core" / "vh-recovery"), "kit", "create",
                             "--output", str(kit_path)], capture_output=True, text=True, timeout=60, cwd=str(private))
        if cp.returncode != 0:
            raise DrillError("vh-recovery kit create failed")
        public_key = cp.stdout.split()[0]
        a.vh("vault", "keys", "recipient", "add", str(vid), "--public-key", public_key, "--label", "drill kit")
        a.sync(vid)
        export1 = private / "export-before-rotation.json"
        a.vh("vault", "keys", "export", str(vid), "--output", str(export1))
        os.chown(export1, pw.pw_uid, pw.pw_gid)
        # rotation 2
        a.vh("vault", "keys", "rotate", str(vid), "--sync-now")
        a.sync(vid)
        a.sh("printf 'written after the second rotation\\n' > MNT/drill/after-rotation.txt")
        a.sync(vid)
        export2 = private / "export-current.json"
        a.vh("vault", "keys", "export", str(vid), "--output", str(export2))
        os.chown(export2, pw.pw_uid, pw.pw_gid)
        if fake:
            bucket.admin("abandon-upload", b"\0" * 64, key="o/" + base64.b32encode(os.urandom(16)).decode()[:26].lower())
        # the checkpoint and node A's attestation keys, pinned in the kit (vh-recovery kit add-vault)
        status_a = a.key_status(vid)
        status_path = _write_private(private / "status-a.json", {"vaults": [status_a]}, admin)
        subprocess.run(["runuser", "-u", admin, "--", str(build / "core" / "vh-recovery"), "kit", "add-vault",
                        str(kit_path), "--status", str(status_path)], check=True, capture_output=True, timeout=60)
        expected = snapshot_tree(a, "drill")
        versions_a = sorted(v["version"] for v in status_a["needed_versions"])
        summary["key_version_a"] = status_a["version"]
        summary["entries"] = len(expected)
        report.check("A: key versions (two rotations)", status_a["version"] == 3, json.dumps(versions_a))
        if fake:
            bucket.admin("snapshot", name="written")

        # ---------------------------------------------------------------- destroy node A
        print("vhh drill: destroying node A (daemon, database, TPM state, backing store)", flush=True)
        a.close()
        stop = a.inst.stop()
        report.check("A destroyed: database dropped, mount gone", stop.get("db_dropped") is True and
                     "STILL" not in str(stop.get("mount_cleanup", "")), json.dumps(stop))
        nodes.remove(a)

        # ---------------------------------------------------------------- node B restores
        print("vhh drill: node B (independent database and swtpm) restores from the bucket and the kit", flush=True)
        b = node("b")
        code, dry = b.vh_json("vault", "recover", "--api-key", "drill", "--bucket", bucket.name, "--kit", "kit.json",
                              "--dry-run")
        report.check("B: dry run plans a canonical restore", code == 0 and dry.get("mode") == "canonical" and
                     not dry.get("written"), json.dumps(dry)[:1500])
        if fake:
            fake.clear_requests()
        t0 = time.time()
        code, res = b.vh_json("vault", "recover", "--api-key", "drill", "--bucket", bucket.name, "--kit", "kit.json")
        summary["restore_seconds"] = round(time.time() - t0, 1)
        summary["restore_report"] = {k: res.get(k) for k in ("mode", "counts", "canonical_versions", "freshness",
                                                              "downloads", "published_epoch", "orphans", "issues")}
        if not report.check("B: restored", code == 0 and res.get("written") is True and res.get("key_available"),
                            json.dumps(res)[:1500]):
            raise DrillError("the restore failed; nothing else to check")
        rvid = int(res["vault_id"])
        report.check("B: every key version canonical (verified against the kit's pinned key)",
                     res.get("canonical_versions") == versions_a and
                     all(v.get("verdict") == "verified" for v in res.get("key_versions", [])),
                     json.dumps(res.get("key_versions"))[:1500])
        report.check("B: freshness verified against the kit's checkpoint", res.get("freshness") == "verified",
                     res.get("freshness_report", ""))
        report.check("B: nothing beyond headers, the manifest and envelopes downloaded (report)",
                     res.get("downloads", {}).get("content_bytes") == 0, json.dumps(res.get("downloads")))
        time.sleep(5)  # a scheduled pass of the cache-strategy vault must not fetch content either
        if fake:
            log = fake.requests()
            report.check("B: no GET of content beyond a 120-byte header until a file is read (provider log)",
                         not content_downloads(log, HEADER), json.dumps(content_downloads(log, HEADER)[:5]))
            summary["restore_requests"] = len(log)
        report.check("B: a new manifest root chained on the loaded one",
                     res.get("published_epoch") == (res.get("epoch") or 0) + 1,
                     f"{res.get('epoch')} -> {res.get('published_epoch')}")

        status_b = b.key_status(rvid)
        report.check("B: key status: every version present and attested by origin",
                     status_b.get("key_available") and not status_b.get("missing_versions") and
                     all(n.get("origin") and n["origin"].get("node_id") == status_a["node_id"] and n.get("attestation")
                         for n in status_b.get("needed_versions", [])),
                     json.dumps(status_b.get("needed_versions"))[:1500])
        fuse_b = "drill"
        actual = snapshot_tree(b, fuse_b, hashes=False)
        def same(e: dict | None, x: dict | None) -> bool:
            # The manifest keeps times in whole seconds (spec 03 §3.3): a sub-second mtime may round either way.
            if not e or not x:
                return False
            e = {k: v for k, v in e.items() if k != "sha256"}
            return abs(e.pop("mtime") - x.get("mtime", 0)) <= 1 and e == {k: v for k, v in x.items() if k != "mtime"}

        mismatch = {p: (expected.get(p), actual.get(p)) for p in set(expected) | set(actual)
                    if not same(expected.get(p), actual.get(p))}
        report.check("B: the tree (path, kind, size, mode, mtime, symlink target) equals node A's", not mismatch,
                     json.dumps(dict(list(mismatch.items())[:10])))
        actual = snapshot_tree(b, fuse_b, hashes=True)
        wrong = [p for p, e in expected.items() if e.get("sha256") != actual.get(p, {}).get("sha256")]
        report.check("B: every file's bytes equal node A's (read through the mount)", not wrong, json.dumps(wrong[:10]))

        # the vault rotates and syncs afterwards
        b.vh("vault", "sync", "set", str(rvid), "--sync-strategy", "sync", "--s3-budget-preset", "unlimited")
        b.vh("vault", "keys", "rotate", str(rvid), "--sync-now")
        b.sync(rvid)
        b.sh("printf 'written on node B\\n' > MNT/drill/after-restore.txt")
        b.sync(rvid)
        status_b2 = b.key_status(rvid)
        report.check("B: the restored vault rotates (version 4) and syncs", status_b2.get("version") == 4 and
                     b.sh("cat MNT/drill/after-restore.txt").stdout == "written on node B\n",
                     json.dumps({"version": status_b2.get("version")}))
        status_b_path = _write_private(private / "status-b.json", {"vaults": [status_b2]}, admin)
        kit_b = private / "kit-b.json"
        shutil.copy(kit_path, kit_b)
        os.chown(kit_b, pw.pw_uid, pw.pw_gid)
        subprocess.run(["runuser", "-u", admin, "--", str(build / "core" / "vh-recovery"), "kit", "add-vault",
                        str(kit_b), "--status", str(status_b_path)], check=True, capture_output=True, timeout=60)
        b.close()
        b.inst.stop()
        nodes.remove(b)

        # ---------------------------------------------------------------- node C: a second restore of the same bucket
        print("vhh drill: node C restores the same bucket again", flush=True)
        c = node("c")
        code, again = c.vh_json("vault", "recover", "--api-key", "drill", "--bucket", bucket.name, "--kit",
                                "kit.json", "--dry-run")
        report.check("C: the original kit proves node A's versions through their recorded origin; node B's new one "
                     "needs node B's key", code == 0 and again.get("canonical_versions") == versions_a and
                     again.get("salvageable_versions") == [4], json.dumps(again.get("key_versions"))[:1500])
        code, again = c.vh_json("vault", "recover", "--api-key", "drill", "--bucket", bucket.name, "--kit",
                                "kit-b.json", "--dry-run")
        report.check("C: a kit refreshed from node B proves every version", code == 0 and
                     again.get("canonical_versions") == versions_a + [4], json.dumps(again.get("key_versions"))[:1500])

        if negative and fake:
            negatives(c, bucket, private, admin, kit_path, export1, export2, report)
        c.close()
        c.inst.stop()
        nodes.remove(c)
    except (DrillError, KeyboardInterrupt) as e:
        report.check("drill completed", False, str(e) or type(e).__name__)
    finally:
        for n in nodes:
            n.close()
            try:
                n.inst.stop()
            except Exception as e:  # noqa: BLE001
                report.check("instance stopped", False, str(e))
        if fake:
            fake.__exit__(None, None, None)
        elif bucket is not None:
            env = {k: os.environ[k] for k in os.environ if k.startswith("VH_R2_ADMIN_")}
            cp = subprocess.run([str(live_tool), "delete", bucket.name],
                                env={**env, "PATH": "/usr/bin:/bin", "VH_LIVE_TESTS": "1"}, capture_output=True,
                                text=True, timeout=600)
            report.check("live bucket deleted (HeadBucket: gone)", cp.returncode == 0, cp.stdout[-300:])
        summary["checks"] = report.checks
        summary["ok"] = report.ok
        out.write_text(json.dumps(summary, indent=2))
        if not keep:
            for f in private.glob("*.json"):
                if f != out:
                    f.unlink()  # kits and exports hold secrets
            shutil.rmtree(private / "staging", ignore_errors=True)
    return report.ok, summary


def negatives(c: Node, bucket: Bucket, private: Path, admin: str, kit_path: Path, export1: Path, export2: Path,
              report: Report) -> None:
    print("vhh drill: negative drills on node C", flush=True)
    kit = json.loads(kit_path.read_text())

    def recover(*extra: str, kit_file: str | None = "kit.json", export: str | None = None, dry: bool = True):
        args = ["vault", "recover", "--api-key", "drill", "--bucket", bucket.name]
        if kit_file:
            args += ["--kit", kit_file]
        if export:
            args += ["--export", export]
        if dry:
            args.append("--dry-run")
        return c.vh_json(*args, *extra, check=False)

    def kit_variant(name: str, change) -> str:
        k = json.loads(json.dumps(kit))
        change(k)
        _write_private(private / name, k, admin)
        return name

    def restore_bucket():
        bucket.admin("restore", name="written")

    def code_of(j) -> str:
        return j.get("error") or ("ok" if "vault_uid" in j else json.dumps(j)[:200])

    def refused(j, code: str) -> bool:
        return j.get("error") == code or code in j.get("raw", "")

    # root deleted: versioned → its newest retained provider version
    restore_bucket()
    bucket.admin("delete", key=".vaulthalla/root")
    code, j = recover()
    report.check("negative: root deleted (versioned) → the newest retained root, canonical", code == 0 and
                 not j.get("blind") and j.get("mode") == "canonical" and "provider version" in json.dumps(j.get("issues")),
                 json.dumps(j.get("issues"))[:600])
    # root deleted: unversioned → blind rebuild; the kit alone can't prove anything, the current export can
    restore_bucket()
    bucket.admin("versioning", status="")
    bucket.admin("purge", key=".vaulthalla/root")
    code, j = recover()
    report.check("negative: root deleted (unversioned), kit only → salvage only (nothing attests the keys)",
                 j.get("blind") is True and j.get("mode") == "salvage", json.dumps(j.get("key_versions"))[:600])
    code, j = recover(export=export2.name)
    report.check("negative: root deleted (unversioned), kit + export → blind, content under /Recovered",
                 code == 0 and j.get("blind") is True and j.get("mode") == "canonical" and len(j.get("orphans", [])) > 0,
                 json.dumps({k: j.get(k) for k in ("mode", "blind", "counts")})[:600])
    # one segment corrupted (unversioned: no provider version to fall back on)
    restore_bucket()
    bucket.admin("versioning", status="")
    segs = [k for k in bucket.keys() if k.startswith(".vaulthalla/seg/")]
    seg = segs[0]
    body = bytearray(bucket.admin("get", key=seg))
    body[len(body) // 2] ^= 0x5A
    for s in segs:  # every segment damaged, its history gone: none of the ranges survives
        bucket.admin("purge", key=s)
        bucket.admin("put", bytes(body), key=s)
    code, j = recover()
    report.check("negative: corrupt segment → reported, its objects found by their headers under /Recovered",
                 code == 0 and "segment" in json.dumps(j.get("issues")) and len(j.get("orphans", [])) > 0,
                 json.dumps(j.get("issues"))[:600])
    # rollback: the bucket presents an older root
    restore_bucket()
    versions = json.loads(bucket.admin("keys")).get(".vaulthalla/root", [])
    older = [v for v in versions if not v["delete_marker"]][3]["version_id"]
    bucket.admin("put", bucket.admin("get", key=".vaulthalla/root", version=older), key=".vaulthalla/root")
    code, j = recover()
    report.check("negative: rollback with a checkpoint → refused", refused(j, "rollback"), code_of(j))
    code, j = recover("--accept-rollback")
    report.check("negative: rollback accepted explicitly → restorable, reported", code == 0 and
                 j.get("freshness") == "rollback_accepted", j.get("freshness_report", "")[:300])
    no_checkpoint = kit_variant("kit-no-checkpoint.json", lambda k: k["vaults"][0].pop("checkpoint", None))
    code, j = recover(kit_file=no_checkpoint)
    report.check("negative: rollback without a checkpoint → accepted, \"freshness unverified\"", code == 0 and
                 j.get("freshness") == "unverified" and "freshness unverified" in j.get("freshness_report", ""),
                 j.get("freshness_report", ""))
    restore_bucket()
    # wrong seed, a kit for another vault
    other_seed = subprocess.run(["runuser", "-u", admin, "--", str(Path(c.cli).parent / "vh-recovery"), "kit",
                                 "create", "--output", str(private / "other-kit.json")], capture_output=True,
                                text=True, timeout=60, cwd=str(private))
    other = json.loads((private / "other-kit.json").read_text()) if other_seed.returncode == 0 else {}
    wrong_seed = kit_variant("kit-wrong-seed.json", lambda k: k.update(recovery_seed=other.get("recovery_seed", "")))
    code, j = recover(kit_file=wrong_seed)
    report.check("negative: wrong seed → refused", refused(j, "recovery_material_mismatch"), code_of(j))
    other_uid = next(line.split(":", 1)[1].strip() for line in
                     c.vh("vault", "create", "othervault", "--local").stdout.splitlines() if line.startswith("Vault UID"))
    another = kit_variant("kit-other-vault.json", lambda k: k["vaults"][0].update(vault_uid=other_uid))
    code, j = recover(kit_file=another)
    report.check("negative: a kit for another vault → refused", refused(j, "kit_vault_mismatch"), code_of(j))
    # an export alone, taken before the second rotation
    code, j = recover(kit_file=None, export=export1.name)
    missing = [v["version"] for v in j.get("key_versions", []) if v.get("state") == "missing"]
    report.check("negative: an export alone after a rotation → the later version reported missing, never invented",
                 3 in missing and j.get("mode") == "salvage", json.dumps(j.get("key_versions"))[:600])
    code, j = recover(kit_file=None, export=export1.name, dry=False)
    report.check("negative: … and the restore refuses (salvage_required)", refused(j, "salvage_required"), code_of(j))
    # anchors: none, another node's, the restoring node's own
    empty = kit_variant("kit-no-keys.json", lambda k: k["vaults"][0].update(attestation_public_keys=[]))
    code, j = recover(kit_file=empty)
    report.check("negative: a kit without attestation keys → salvage offered, nothing canonical",
                 j.get("mode") == "salvage" and not j.get("canonical_versions") and
                 all(v.get("verdict") == "empty_anchor" for v in j.get("key_versions", []) if v.get("held")),
                 json.dumps(j.get("key_versions"))[:600])
    foreign = base64.b64encode(os.urandom(32)).decode()
    wrong = kit_variant("kit-wrong-keys.json", lambda k: k["vaults"][0].update(
        attestation_public_keys=[{"key_id": 1, "public_key": foreign}]))
    code, j = recover(kit_file=wrong)
    report.check("negative: a kit whose attestation key belongs to another node → salvage only, mismatch named",
                 j.get("mode") == "salvage" and not j.get("canonical_versions") and
                 all(v.get("verdict") == "unverified" for v in j.get("key_versions", []) if v.get("held")),
                 json.dumps(j.get("key_versions"))[:600])
    own = c.key_status_any()
    selfish = kit_variant("kit-self.json", lambda k: k["vaults"][0].update(attestation_public_keys=own))
    code, j = recover(kit_file=selfish)
    report.check("negative: the restoring node's own attestation keys as the anchor → never proof of origin",
                 j.get("mode") == "salvage" and not j.get("canonical_versions"),
                 json.dumps(j.get("key_versions"))[:600])


def _key_status_any(self: Node) -> list[dict]:
    """This node's own attestation keys (from any vault's status: a vault is created for it when there is none)."""
    code, j = self.vh_json("vault", "keys", "status", "all", check=False)
    for v in j.get("vaults", []):
        if v.get("attestation_public_keys"):
            return [{"key_id": k["key_id"], "public_key": k["public_key"]} for k in v["attestation_public_keys"]]
    self.vh("vault", "create", "selfkeys", "--local")
    code, j = self.vh_json("vault", "keys", "status", "all")
    for v in j.get("vaults", []):
        if v.get("attestation_public_keys"):
            return [{"key_id": k["key_id"], "public_key": k["public_key"]} for k in v["attestation_public_keys"]]
    raise DrillError("node C has no attestation key to present")


Node.key_status_any = _key_status_any


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vhh drill", description=__doc__.split("\n\n")[0])
    ap.add_argument("kind", choices=("recover",))
    ap.add_argument("--build", required=True)
    ap.add_argument("--files", type=int, default=2000)
    ap.add_argument("--s3", choices=("fake", "r2"), default="fake")
    ap.add_argument("--no-negative", action="store_true")
    ap.add_argument("--keep", action="store_true", help="keep the drill's private directory (kits, exports)")
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    if os.geteuid() != 0:
        print("vhh drill: needs root (private daemon instances): use sudo", file=sys.stderr)
        return 2
    ok, summary = run(Path(a.build).resolve(), files=a.files, s3=a.s3, negative=not a.no_negative, keep=a.keep,
                      out=Path(a.out) if a.out else None)
    print(f"vhh drill: {'PASS' if ok else 'FAIL'}: {sum(c['ok'] for c in summary.get('checks', []))}/"
          f"{len(summary.get('checks', []))} checks; report {a.out or '/tmp/vhh_drill_' + summary['run_id'] + '/report.json'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
