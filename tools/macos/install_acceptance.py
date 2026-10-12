#!/usr/bin/env python3
"""Client half of the installed-service acceptance (tools/macos/install-acceptance.sh, roadmap #230).

Talks to an installed daemon over its real surfaces (ws + HTTP on 127.0.0.1) as an ordinary local user; it never needs
root and never reads the service's state directory. The admin password arrives on stdin (the root script opens the
daemon's super_admin_initial_password and hands it over), and is never printed or written anywhere.

  seed    create (or reuse) the 'install_acceptance' vault; HTTP upload of a 1 MiB file, a nested upload and a
          share-link upload; download and compare each; a second, unprivileged account is refused (403/404) on the
          admin's vault. Writes what it stored (paths, sizes, sha256; no secrets) to --state.
  verify  log in again and download every file recorded in --state, comparing sha256 (after a restart, a crash, a
          stop/start: the encrypted vault and its keys must survive).

Prints one PASS/FAIL line per step; exit 0 only if every step passed.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from tools.lab.pentest.client import Target, Ws, http_request, ok, upload_files  # noqa: E402

VAULT = "install_acceptance"
OTHER = "acceptance_other"


def step(name: str, passed: bool, detail: str = "") -> bool:
    print(f"{'PASS' if passed else 'FAIL'} {name}{': ' + detail if detail else ''}", flush=True)
    return passed


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def login(target: Target, password: str, name: str = "admin") -> Ws:
    ws = await Ws(target).__aenter__()
    res = await ws.login(name, password)
    if not ok(res):
        await ws.__aexit__(None, None, None)
        raise RuntimeError(f"{name} login failed: {res.get('status')}")
    return ws


def download(target: Target, cookie: str, vault_id: int, path: str) -> bytes | None:
    r = http_request(target, "GET", "/download/content", query={"vault_id": vault_id, "path": path}, cookie=cookie)
    return r.body if r.status == 200 else None


async def seed(target: Target, password: str, state: Path, expect_mount_state: str | None) -> bool:
    good = True
    ws = await login(target, password)
    cookie = ws.cookie_header()
    good &= step("ws login as admin", True)
    deps = (await ws.must("stats.system.health")).get("stats", {}).get("deps", {})
    good &= step("health reports the mount honestly",
                 expect_mount_state is None or deps.get("mount_state") == expect_mount_state,
                 f"mode={deps.get('fuse_mount')} state={deps.get('mount_state')} "
                 f"secrets_backend={deps.get('secrets_backend')}")

    vaults = (await ws.must("storage.vault.list")).get("vaults", [])
    existing = [v for v in vaults if v.get("name") == VAULT]
    if existing:
        vault_id = int(existing[0]["id"])
        step("reuse encrypted local vault", True, f"id={vault_id}")
    else:
        vault_id = int((await ws.must("storage.vault.add", {"name": VAULT, "type": "local"}))["vault"]["id"])
        good &= step("create encrypted local vault", vault_id > 0, f"id={vault_id}")

    run = os.urandom(4).hex()  # reruns add new files instead of overwriting
    files: dict[str, bytes] = {f"/acceptance-{run}.bin": os.urandom(1 << 20),
                               f"/a/b/c/nested-{run}.bin": os.urandom(64 * 1024)}
    for path, data in files.items():
        errors = upload_files(target, cookie, vault_id, [(path, data)])
        good &= step(f"HTTP upload {path} ({len(data)} B)", not any(errors.values()), str(errors.get(path) or ""))
        good &= step(f"HTTP download {path} matches", download(target, cookie, vault_id, path) == data)

    # Share upload: an upload-only public link into /inbox, used from a share session.
    if not ok(await ws.send("fs.metadata", {"vault_id": vault_id, "path": "/inbox"})):
        await ws.must("fs.dir.create", {"vault_id": vault_id, "path": "/inbox"})
    inbox = (await ws.must("fs.metadata", {"vault_id": vault_id, "path": "/inbox"}))["entry"]
    link = await ws.must("share.link.create", {
        "vault_id": vault_id, "root_entry_id": inbox["id"], "root_path": "/inbox", "target_type": "directory",
        "link_type": "upload", "access_mode": "public", "allowed_ops": ["metadata", "upload"],
        "public_role_assignment": {"vault_role_name": "share_upload_dropbox"}, "name": f"acceptance-{run}"})
    dropped, drop_path = os.urandom(32 * 1024), f"/dropped-{run}.bin"
    async with Ws(target, path="/ws/share") as share:
        good &= step("share session opens", ok(await share.send("share.session.open",
                                                                {"public_token": link["public_token"]})))
        share_cookie = share.cookie_header()
        r = http_request(target, "POST", "/upload/session", query={"share": "1"}, cookie=share_cookie,
                         body=json.dumps({"files": [{"file_id": "f0", "path": drop_path,
                                                    "size_bytes": len(dropped)}]}).encode(),
                         headers={"Content-Type": "application/json"})
        upload_id = r.json().get("upload_id") if r.status == 200 else None
        if upload_id:
            put = http_request(target, "PUT", f"/upload/{upload_id}/files/f0", query={"share": "1"},
                               cookie=share_cookie, body=dropped, headers={"Content-Type": "application/octet-stream"})
            fin = http_request(target, "POST", f"/upload/{upload_id}/finish", query={"share": "1"}, cookie=share_cookie)
            good &= step("share upload completes", put.status == 200 and fin.status == 200,
                         f"put {put.status} finish {fin.status}")
        else:
            good &= step("share upload completes", False, f"session HTTP {r.status}")
    good &= step("owner downloads the share-uploaded file", download(target, cookie, vault_id, f"/inbox{drop_path}") == dropped)
    files[f"/inbox{drop_path}"] = dropped

    # RBAC over the web surface: a second, unprivileged account can't read or write the admin's vault.
    other_pw, other_name = os.urandom(12).hex(), f"{OTHER}_{run}"
    await ws.must("auth.register", {"name": other_name, "password": other_pw, "role": "unprivileged"})
    await ws.__aexit__(None, None, None)
    other = await login(target, other_pw, name=other_name)
    other_cookie = other.cookie_header()
    first = next(iter(files))
    denied = http_request(target, "GET", "/download/content", query={"vault_id": vault_id, "path": first},
                          cookie=other_cookie)
    good &= step("second Vaulthalla user can't download the admin's file", denied.status in (403, 404),
                 f"HTTP {denied.status}")
    errs = upload_files(target, other_cookie, vault_id, [(f"/intruder-{run}.bin", b"x")])
    good &= step("second Vaulthalla user can't upload into the admin's vault", any(errs.values()))
    await other.__aexit__(None, None, None)

    record = json.loads(state.read_text()) if state.exists() else {"files": {}}
    record["vault_id"] = vault_id
    record["files"].update({p: {"size": len(d), "sha256": sha(d)} for p, d in files.items()})
    state.write_text(json.dumps(record, indent=2))
    return good


async def verify(target: Target, password: str, state: Path) -> bool:
    record = json.loads(state.read_text())
    vault_id = int(record["vault_id"])
    ws = await login(target, password)
    cookie = ws.cookie_header()
    good = step("ws login as admin", True)
    vaults = (await ws.must("storage.vault.list")).get("vaults", [])
    good &= step("vault is still there", any(int(v["id"]) == vault_id for v in vaults), f"id={vault_id}")
    for path, meta in record["files"].items():
        got = download(target, cookie, vault_id, path)
        good &= step(f"download {path} matches (keys unsealed)", got is not None and sha(got) == meta["sha256"])
    await ws.__aexit__(None, None, None)
    return good


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("phase", choices=["seed", "verify"])
    p.add_argument("--state", type=Path, required=True, help="JSON record of what was stored (no secrets)")
    p.add_argument("--ws-port", type=int, default=36969)
    p.add_argument("--http-port", type=int, default=36970)
    p.add_argument("--expect-mount-state", help="health must report this mount_state (e.g. disabled)")
    args = p.parse_args()
    password = sys.stdin.readline().strip()
    if not password:
        sys.exit("the admin password is expected on stdin")
    target = Target(hostname="127.0.0.1", connect_ip="127.0.0.1", ws_port=args.ws_port, http_port=args.http_port)
    try:
        if args.phase == "seed":
            good = asyncio.run(seed(target, password, args.state, args.expect_mount_state))
        else:
            good = asyncio.run(verify(target, password, args.state))
    except Exception as e:  # report and fail; secrets never reach the message
        good = step("unexpected error", False, f"{type(e).__name__}: {e}")
    print(f"install acceptance {args.phase}:", "PASSED" if good else "FAILED")
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
