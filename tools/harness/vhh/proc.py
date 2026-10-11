"""A JSON-lines helper process with per-request deadlines (the vh_fs_actor protocol transport).

The child prints one ready line, then answers one JSON request per line with one JSON reply per line. Every wait is
bounded: a child that dies, closes its pipe, prints garbage or misses a deadline yields a typed failure instead of a
hang. Stopping only ever signals the PID this object started.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal


class ProcError(RuntimeError):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind              # "died" | "timeout" | "protocol"


class JsonLineProcess:
    def __init__(self, argv: list[str], ready_timeout_s: float = 10.0, env: dict | None = None):
        self.argv, self.ready_timeout_s, self.env = argv, ready_timeout_s, env
        self.proc: asyncio.subprocess.Process | None = None
        self.ready: dict | None = None
        self._next_id = 0

    async def start(self) -> dict:
        self.proc = await asyncio.create_subprocess_exec(
            *self.argv, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, env=self.env)
        self.ready = await self._read(self.ready_timeout_s)
        if not self.ready.get("ready"):
            raise ProcError("protocol", f"expected a ready line, got {self.ready!r}")
        return self.ready

    async def _read(self, timeout: float) -> dict:
        try:
            line = await asyncio.wait_for(self.proc.stdout.readline(), timeout)
        except asyncio.TimeoutError:
            raise ProcError("timeout", f"no reply within {timeout}s") from None
        if not line:
            rc = await self._reap(0.5)
            raise ProcError("died", f"helper exited (rc={rc})")
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            raise ProcError("protocol", "helper printed a non-JSON line") from None
        if not isinstance(msg, dict):
            raise ProcError("protocol", "helper reply is not an object")
        return msg

    async def request(self, req: dict, timeout_s: float) -> dict:
        if self.proc is None or self.proc.returncode is not None:
            raise ProcError("died", f"helper not running (rc={self.proc.returncode if self.proc else None})")
        self._next_id += 1
        req = {"id": self._next_id, **req}
        try:
            self.proc.stdin.write((json.dumps(req) + "\n").encode())
            await asyncio.wait_for(self.proc.stdin.drain(), timeout_s)
        except (BrokenPipeError, ConnectionResetError):
            rc = await self._reap(0.5)
            raise ProcError("died", f"helper exited (rc={rc})") from None
        except asyncio.TimeoutError:
            raise ProcError("timeout", "helper stopped reading") from None
        reply = await self._read(timeout_s)
        if reply.get("id") != req["id"]:
            raise ProcError("protocol", f"reply id {reply.get('id')} != request id {req['id']}")
        return reply

    async def _reap(self, timeout: float) -> int | None:
        try:
            return await asyncio.wait_for(self.proc.wait(), timeout)
        except asyncio.TimeoutError:
            return None

    async def stop(self, grace_s: float = 1.0) -> int | None:
        """Ask nicely, then SIGKILL our own PID; never wait unboundedly (a child stuck in the kernel may not die)."""
        if self.proc is None or self.proc.returncode is not None:
            return self.proc.returncode if self.proc else None
        try:
            self.proc.stdin.write(b'{"op":"exit"}\n')
            await asyncio.wait_for(self.proc.stdin.drain(), grace_s)
        except (BrokenPipeError, ConnectionResetError, asyncio.TimeoutError):
            pass
        rc = await self._reap(grace_s)
        if rc is None:
            try:
                os.kill(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            rc = await self._reap(grace_s)
        return rc
