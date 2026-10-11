"""Filesystem operations on the instance's mount, through a long-lived vh_fs_actor process per test uid.

vh_fs_actor (core/tests/helpers/fs_actor.cpp) is a single-threaded helper that switches to the given uid/gid at
startup and then serves one JSON request per line (protocol in .claude/scratch/harness-plan.md, "vh_fs_actor
protocol"). The engine never forks itself to touch the mount. Every request has a deadline: on expiry the actor is
killed, and if it does not exit (a request stuck in the kernel waiting on the daemon), the run's own FUSE connection
is aborted through the supervisor so nothing blocks forever.
"""
from __future__ import annotations

import asyncio
import base64
import errno as errno_mod
import json
import time
from pathlib import Path

from vhh.model import Op, Result

_ERRNO_OUTCOME = {
    0: "ok",
    errno_mod.EACCES: "denied",
    errno_mod.EPERM: "denied",
    errno_mod.ENOENT: "not_found",
    errno_mod.EEXIST: "conflict",
    errno_mod.ENOTEMPTY: "conflict",
    errno_mod.EBUSY: "conflict",
    errno_mod.EINVAL: "invalid",
    errno_mod.ENOTDIR: "invalid",
    errno_mod.EISDIR: "invalid",
    errno_mod.ENOTCONN: "disconnected",
    errno_mod.ECONNABORTED: "disconnected",
    errno_mod.ETIMEDOUT: "timeout",
}


def classify_errno(e: int) -> str:
    return _ERRNO_OUTCOME.get(e, "error")


class FuseDriver:
    surface = "fuse"

    def __init__(self, actor_bin: str | Path, mount: str | Path, uid: int, gid: int, supervisor=None,
                 kill_grace_s: float = 3.0):
        self.actor_bin = str(actor_bin)
        self.mount = Path(mount)
        self.uid, self.gid = uid, gid
        self.supervisor = supervisor          # vhh.instance.Instance: abort_fuse(), capture_evidence()
        self.kill_grace_s = kill_grace_s
        self.proc: asyncio.subprocess.Process | None = None
        self._next_id = 0
        self.wedged = False

    async def open(self) -> None:
        if not Path(self.actor_bin).exists():
            raise FileNotFoundError(f"{self.actor_bin} not built (meson compile -C <build> core/vh_fs_actor)")
        self.proc = await asyncio.create_subprocess_exec(
            self.actor_bin, "--uid", str(self.uid), "--gid", str(self.gid),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            cwd="/", env={"PATH": "/usr/bin:/bin"},
            limit=8 * 1024 * 1024)   # one reply line carries up to 1 MiB of base64 file bytes
        line = await asyncio.wait_for(self.proc.stdout.readline(), timeout=10)
        ready = json.loads(line or b"{}")
        if not ready.get("ready") or ready.get("uid") != self.uid:
            raise RuntimeError(f"vh_fs_actor did not start as uid {self.uid}: {line[:200]!r}")

    def path(self, rel: str) -> str:
        """Absolute path on the mount for a vault-relative path ("<vault fuse name>/a/b")."""
        p = (self.mount / rel.lstrip("/")).resolve()
        if p != self.mount and self.mount not in p.parents:
            raise ValueError(f"{rel!r} escapes the mount")
        return str(p)

    async def request(self, req: dict, deadline_s: float) -> dict:
        if self.proc is None or self.proc.returncode is not None:
            return {"errno": errno_mod.ECONNABORTED, "error": "actor not running"}
        self._next_id += 1
        req = {"id": self._next_id, **req}
        self.proc.stdin.write((json.dumps(req) + "\n").encode())
        try:
            await asyncio.wait_for(self.proc.stdin.drain(), timeout=deadline_s)
            line = await asyncio.wait_for(self.proc.stdout.readline(), timeout=deadline_s)
        except asyncio.TimeoutError:
            await self._on_deadline()
            return {"errno": errno_mod.ETIMEDOUT, "error": f"no reply within {deadline_s}s", "wedge": self.wedged}
        if not line:
            return {"errno": errno_mod.ECONNABORTED, "error": "actor exited"}
        reply = json.loads(line)
        if reply.get("id") != req["id"]:
            return {"errno": errno_mod.EPROTO, "error": f"reply id {reply.get('id')} != {req['id']}"}
        return reply

    async def _on_deadline(self) -> None:
        """Kill the actor; if it can't exit it is stuck in a FUSE request: abort this run's connection."""
        if self.proc is None:
            return
        self.proc.kill()
        try:
            await asyncio.wait_for(self.proc.wait(), timeout=self.kill_grace_s)
            return
        except asyncio.TimeoutError:
            pass
        self.wedged = True
        if self.supervisor is not None:
            await asyncio.to_thread(self.supervisor.capture_evidence, "fuse-actor-stuck")
            await asyncio.to_thread(self.supervisor.abort_fuse)
        try:
            await asyncio.wait_for(self.proc.wait(), timeout=self.kill_grace_s)
        except asyncio.TimeoutError:
            pass  # reported as a wedge; never wait forever

    async def execute(self, op: Op, deadline_s: float) -> Result:
        """Canonical fs ops: fs.write, fs.append, fs.read, fs.list, fs.stat, fs.mkdir, fs.rmdir, fs.delete,
        fs.rename, fs.truncate, fs.copy, fs.rm_rf. args.path / args.to are mount-relative; args.data is bytes or str."""
        t0 = time.time_ns()
        a = op.args
        verb = op.op.split(".", 1)[-1]
        wire = {"write": "write", "append": "append", "read": "read", "list": "ls", "stat": "stat", "mkdir": "mkdir",
                "rmdir": "rmdir", "delete": "unlink", "rename": "rename", "truncate": "truncate", "copy": "cp_tree",
                "rm_rf": "rm_rf", "fsync": "fsync", "hold": "hold", "release": "release"}.get(verb)
        if wire is None:
            return Result("invalid", detail=f"fuse driver has no binding for {op.op}", t0_ns=t0, t1_ns=time.time_ns())
        req: dict = {"op": wire, "path": self.path(a["path"])}
        if "to" in a:
            req["to"] = self.path(a["to"])
        if "data" in a:
            data = a["data"].encode() if isinstance(a["data"], str) else a["data"]
            req["data_b64"] = base64.b64encode(data).decode()
        for k in ("offset", "size", "mode"):
            if k in a:
                req[k] = a[k]
        reply = await self.request(req, deadline_s)
        e = int(reply.get("errno", errno_mod.EPROTO))
        data = {k: reply[k] for k in ("entries", "size", "mode", "type") if k in reply}
        if reply.get("wedge"):
            data["wedge"] = True
        rendered = f"{wire} {req['path']}" + (f" -> {req['to']}" if "to" in req else "")
        body = base64.b64decode(reply["data_b64"]) if wire == "read" and reply.get("data_b64") else None
        res = Result(classify_errno(e), detail=reply.get("error", "")[:200], code=e, data=data, rendered=rendered,
                     bytes_sha256=reply.get("sha256"), t0_ns=t0, t1_ns=time.time_ns())
        res.body = body   # memory only (never serialized): the canary and integrity judges read it
        return res

    async def close(self) -> None:
        if self.proc is None or self.proc.returncode is not None:
            return
        try:
            self.proc.stdin.write(b'{"id":0,"op":"exit"}\n')
            await asyncio.wait_for(self.proc.stdin.drain(), timeout=2)
            await asyncio.wait_for(self.proc.wait(), timeout=3)
        except (asyncio.TimeoutError, ConnectionError):
            await self._on_deadline()
