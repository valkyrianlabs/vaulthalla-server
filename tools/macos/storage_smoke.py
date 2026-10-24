#!/usr/bin/env python3
"""Milestone B storage smoke (roadmap #215): a private daemon instance on this machine, end to end.

Starts build-macos/core/vaulthalla-server as a VH_TEST_MODE instance (every path under /tmp, the disposable cluster
from tools/macos/test-db.sh), then over the real surfaces: logs in as the generated admin (ws), creates a vault,
uploads a random file over the HTTP lane, downloads it and checks the bytes, checks the vault's backing file is
ciphertext, restarts the daemon and checks again that the login, the vault and the bytes survived.

Usage (after `source tools/macos/env.sh && eval "$(tools/macos/test-db.sh up)"`):
  python3 tools/macos/storage_smoke.py [--build build-macos] [--ws-port 46969] [--http-port 46970] [--keep]
Needs the `websockets` package. Prints one line per step; exit 0 only if every step passed. Never prints secrets.
"""
from __future__ import annotations

import argparse
import json
import asyncio
import hashlib
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from tools.lab.pentest.client import Target, Ws, http_request, ok, upload_files  # noqa: E402

ROOT = Path("/tmp/vh-macos-storage-smoke")


def step(name: str, passed: bool, detail: str = "") -> bool:
    print(f"{'PASS' if passed else 'FAIL'} {name}{': ' + detail if detail else ''}", flush=True)
    return passed


def instance_env() -> dict:
    env = dict(os.environ)
    for key in ("VH_TEST_DB_HOST", "VH_TEST_DB_PORT", "VH_TEST_DB_USER", "VH_TEST_DB_PASS", "VH_TEST_DB_NAME"):
        if not env.get(key):
            sys.exit(f"{key} is not set: eval \"$(tools/macos/test-db.sh up)\" first")
    env.update({
        "VH_TEST_MODE": "1",
        "VH_TEST_BACKING_PATH": str(ROOT / "backing"),
        "VH_TEST_MOUNT_PATH": str(ROOT / "mount"),
        "VH_TEST_LOG_PATH": str(ROOT / "log"),
        "VH_PATH_TO_SUPERADMIN_UID": str(ROOT / "run"),
        "VH_PATH_TO_CONFIG": str(ROOT / "config.yaml"),
        "VH_TEST_CLI_SOCKET": str(ROOT / "run" / "cli.sock"),
    })
    return env


class Daemon:
    def __init__(self, server: Path, env: dict):
        self.server, self.env, self.proc, self.runs = server, env, None, 0

    def start(self, ws_port: int, timeout: float = 60) -> bool:
        self.runs += 1
        out = open(ROOT / f"server-{self.runs}.out", "w")
        self.proc = subprocess.Popen([str(self.server)], env=self.env, stdout=out, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                return False
            try:
                import socket
                with socket.create_connection(("127.0.0.1", ws_port), timeout=1):
                    return True
            except OSError:
                time.sleep(0.5)
        return False

    def stop(self, timeout: float = 15) -> float | None:
        if not self.proc or self.proc.poll() is not None:
            return None
        began = time.monotonic()
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=timeout)
            return time.monotonic() - began
        except subprocess.TimeoutExpired:
            self.proc.kill()  # our own child, by pid
            return None


def prepare(ws_port: int, http_port: int, mount_mode: str | None) -> None:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    for d in ("backing", "mount", "log", "run"):
        (ROOT / d).mkdir(parents=True)
    config = (REPO / "deploy/config/config.yaml").read_text()
    config = config.replace("port: 36969", f"port: {ws_port}").replace("port: 36970", f"port: {http_port}")
    if mount_mode:
        config += f"\nmount:\n  mode: {mount_mode}\n"
    (ROOT / "config.yaml").write_text(config)


async def login(target: Target, password: str, name: str = "admin") -> tuple[Ws, str]:
    ws = await Ws(target).__aenter__()
    res = await ws.login(name, password)
    if not ok(res):
        await ws.__aexit__(None, None, None)
        raise RuntimeError(f"{name} login failed: {res.get('status')}")
    return ws, ws.cookie_header()


def download(target: Target, cookie: str, vault_id: int, path: str) -> bytes | None:
    r = http_request(target, "GET", "/download/content", query={"vault_id": vault_id, "path": path}, cookie=cookie)
    return r.body if r.status == 200 else None


def backing_files(name: str) -> list[Path]:
    return [p for p in (ROOT / "backing").rglob(name) if p.is_file()]


def refuses_symlinked_state_root(args) -> bool:
    # Fail closed: a state root the daemon can't make private (here: a symlink) must stop startup.
    prepare(args.ws_port, args.http_port, args.mount_mode)
    real = ROOT / "elsewhere"
    real.mkdir()
    shutil.rmtree(ROOT / "backing")
    (ROOT / "backing").symlink_to(real)
    proc = subprocess.run([str(REPO / args.build / "core/vaulthalla-server")], env=instance_env(),
                          capture_output=True, text=True, timeout=60)
    out = proc.stdout + proc.stderr
    return step("daemon refuses to start on a symlinked state root", proc.returncode != 0 and "state directory" in out,
                f"exit {proc.returncode}")


async def run(args) -> bool:
    if not refuses_symlinked_state_root(args):
        return False
    prepare(args.ws_port, args.http_port, args.mount_mode)
    daemon = Daemon(REPO / args.build / "core/vaulthalla-server", instance_env())
    target = Target(hostname="127.0.0.1", connect_ip="127.0.0.1", ws_port=args.ws_port, http_port=args.http_port)
    payload = os.urandom(1 << 20)
    digest = hashlib.sha256(payload).hexdigest()
    name = "smoke.bin"
    good = True
    try:
        good &= step("daemon starts", daemon.start(args.ws_port))
        if not good:
            return False
        password = (ROOT / "backing/super_admin_initial_password").read_text().strip()

        ws, cookie = await login(target, password)
        good &= step("ws login as admin", True)
        health = (await ws.must("stats.system.health")).get("stats", {})
        deps = health.get("deps", {})
        state = deps.get("mount_state")
        good &= step("health reports mount + secrets backend honestly",
                     deps.get("fuse_mount") in ("disabled", "service_private", "multiuser") and bool(deps.get("secrets_backend"))
                     and (args.expect_mount_state is None or state == args.expect_mount_state),
                     f"mode={deps.get('fuse_mount')} state={state} detail={deps.get('mount_detail')} "
                     f"secrets_backend={deps.get('secrets_backend')}")
        if args.expect_mount_state not in (None, "disabled", "mounted"):
            # A configured mount that isn't there is degraded health, never "healthy", and never blocks storage.
            overall = health.get("overall_status") or health.get("status")
            good &= step("unmounted configured mount reads as degraded", overall in ("degraded", "warning"), f"overall={overall}")
        vault = (await ws.must("storage.vault.add", {"name": "storage_smoke", "type": "local"}))["vault"]
        vault_id = int(vault["id"])
        good &= step("create encrypted local vault", vault_id > 0, f"id={vault_id}")

        errors = upload_files(target, cookie, vault_id, [(f"/{name}", payload)])
        good &= step("HTTP upload (1 MiB)", not any(errors.values()), str(errors.get(f"/{name}") or ""))
        got = download(target, cookie, vault_id, f"/{name}")
        good &= step("HTTP download matches", got is not None and hashlib.sha256(got).hexdigest() == digest)
        # Backing files are stored under aliases: find the sealed copy by size (body + 16-byte GCM tag) and make
        # sure the plaintext exists nowhere under the backing tree.
        sealed = [p for p in backing_files("*") if p.stat().st_size == len(payload) + 16]
        plain = [p for p in backing_files("*") if p.stat().st_size == len(payload) and p.read_bytes() == payload]
        good &= step("backing bytes are ciphertext", len(sealed) == 1 and not plain,
                     f"{len(sealed)} sealed, {len(plain)} plaintext copies")
        # Nested upload: the target's parent folders are created in the vault (the staging file lives elsewhere).
        nested = os.urandom(64 * 1024)
        errors = upload_files(target, cookie, vault_id, [("/a/b/c/nested.bin", nested)])
        good &= step("nested HTTP upload creates its folders", not any(errors.values()), str(errors.get("/a/b/c/nested.bin") or ""))
        got = download(target, cookie, vault_id, "/a/b/c/nested.bin")
        good &= step("nested download matches", got == nested)

        # Share upload: an upload-only public link into /inbox, used from a share session.
        await ws.must("fs.dir.create", {"vault_id": vault_id, "path": "/inbox"})
        inbox = (await ws.must("fs.metadata", {"vault_id": vault_id, "path": "/inbox"}))["entry"]
        link = await ws.must("share.link.create", {
            "vault_id": vault_id, "root_entry_id": inbox["id"], "root_path": "/inbox", "target_type": "directory",
            "link_type": "upload", "access_mode": "public", "allowed_ops": ["metadata", "upload"],
            "public_role_assignment": {"vault_role_name": "share_upload_dropbox"}, "name": "smoke-upload"})
        dropped = os.urandom(32 * 1024)
        async with Ws(target, path="/ws/share") as share:
            opened = await share.send("share.session.open", {"public_token": link["public_token"]})
            good &= step("share session opens", ok(opened), str(opened.get("status")))
            share_cookie = share.cookie_header()
            r = http_request(target, "POST", "/upload/session", query={"share": "1"}, cookie=share_cookie,
                             body=json.dumps({"files": [{"file_id": "f0", "path": "/dropped.bin",
                                                        "size_bytes": len(dropped)}]}).encode(),
                             headers={"Content-Type": "application/json"})
            upload_id = r.json().get("upload_id") if r.status == 200 else None
            if upload_id:
                put = http_request(target, "PUT", f"/upload/{upload_id}/files/f0", query={"share": "1"},
                                   cookie=share_cookie, body=dropped, headers={"Content-Type": "application/octet-stream"})
                fin = http_request(target, "POST", f"/upload/{upload_id}/finish", query={"share": "1"}, cookie=share_cookie)
                good &= step("share upload completes", put.status == 200 and fin.status == 200,
                             f"session {r.status} put {put.status} finish {fin.status}")
            else:
                good &= step("share upload completes", False, f"session HTTP {r.status}: {r.body[:120]!r}")
        got = download(target, cookie, vault_id, "/inbox/dropped.bin")
        good &= step("owner downloads the share-uploaded file intact", got == dropped)

        mode = (ROOT / "backing").stat().st_mode & 0o777
        good &= step("backing root is private to the daemon uid (0700)", mode == 0o700, f"mode={mode:o}")
        staged = list((ROOT / "backing/.upload-staging").rglob("*.part")) if (ROOT / "backing/.upload-staging").exists() else []
        good &= step("no staged plaintext left behind", not staged, f"{len(staged)} left")
        # RBAC over the web surface: a second, unprivileged account can't read or write the admin's vault.
        other_pw = os.urandom(12).hex()
        await ws.must("auth.register", {"name": "smoke_other", "password": other_pw, "role": "unprivileged"})
        await ws.__aexit__(None, None, None)
        other, other_cookie = await login(target, other_pw, name="smoke_other")
        good &= step("second user logs in", True)
        denied = http_request(target, "GET", "/download/content", query={"vault_id": vault_id, "path": f"/{name}"},
                              cookie=other_cookie)
        good &= step("second user can't download the admin's file", denied.status in (403, 404), f"HTTP {denied.status}")
        errs = upload_files(target, other_cookie, vault_id, [("/intruder.bin", b"x")])
        good &= step("second user can't upload into the admin's vault", any(errs.values()),
                     str(errs.get("/intruder.bin"))[:60])
        await other.__aexit__(None, None, None)

        took = daemon.stop()
        good &= step("SIGTERM shutdown", took is not None, f"{took:.1f}s" if took is not None else "had to SIGKILL")
        good &= step("daemon restarts", daemon.start(args.ws_port))
        ws, cookie = await login(target, password)
        good &= step("ws login after restart", True)
        vaults = (await ws.must("storage.vault.list")).get("vaults", [])
        good &= step("vault survived restart", any(int(v["id"]) == vault_id for v in vaults))
        got = download(target, cookie, vault_id, f"/{name}")
        good &= step("download after restart matches (keys unsealed)",
                     got is not None and hashlib.sha256(got).hexdigest() == digest)
        await ws.__aexit__(None, None, None)
    except Exception as e:  # report and fail; secrets never reach the message
        good = step("unexpected error", False, f"{type(e).__name__}: {e}")
    finally:
        daemon.stop()
        if not args.keep and good:
            shutil.rmtree(ROOT, ignore_errors=True)
    return good


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--build", default="build-macos")
    p.add_argument("--ws-port", type=int, default=46969)
    p.add_argument("--http-port", type=int, default=46970)
    p.add_argument("--keep", action="store_true", help=f"keep {ROOT} (kept anyway on failure)")
    p.add_argument("--mount-mode", choices=["disabled", "service_private", "multiuser"],
                   help="write mount.mode into the instance's config.yaml")
    p.add_argument("--expect-mount-state", help="health must report this mount_state (macOS: always disabled)")
    ok_all = asyncio.run(run(p.parse_args()))
    print("storage smoke:", "PASSED" if ok_all else "FAILED")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
