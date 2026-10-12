"""CLI over the daemon's unix socket, speaking the frame protocol directly (core/main/cli.cpp, shell/SocketIO.cpp).

Frames are a 4-byte big-endian length followed by JSON. The request is {cmd, args, argv, line, interactive}; the daemon
answers with a "hello" frame, optional "output" frames, and a final "result" frame {ok, exit_code, stdout, stderr}
(or a legacy type-less reply). Requests are always non-interactive, so commands that would prompt must pass --yes.

Identity comes from the peer credentials: root sessions connect directly (uid 0 is the seeded `root` principal);
actor sessions connect through a connector process running as the actor's Linux account (helpers/connect_as.py).
"""
from __future__ import annotations

import asyncio
import grp
import json
import os
import pwd
import shlex
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

from vhh.model import Op, Result

MAX_FRAME = 64 * 1024 * 1024


def _send_frame(sock: socket.socket, obj: dict) -> None:
    body = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(body)) + body)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return bytes(buf)


def _recv_frame(sock: socket.socket) -> dict:
    (n,) = struct.unpack(">I", _recv_exact(sock, 4))
    if n > MAX_FRAME:
        raise ValueError(f"frame too large ({n})")
    return json.loads(_recv_exact(sock, n))


def classify_exit(code: int, stderr: str) -> str:
    """Map a CLI result onto the engine's normalized outcomes."""
    if code == 0:
        return "ok"
    low = stderr.lower()
    if "permission" in low or "not authorized" in low or "denied" in low or "forbidden" in low:
        return "denied"
    if "not found" in low or "no such" in low or "does not exist" in low or "unknown user" in low:
        return "not_found"
    if "already exists" in low or "conflict" in low or "in use" in low:
        return "conflict"
    if "are you sure" in low or "confirm" in low:
        return "needs_confirmation"
    if "invalid" in low or "unrecognized" in low or "usage" in low or "requires" in low or "missing" in low:
        return "invalid"
    return "error"


class Connector:
    """A long-lived connect_as process for one Linux account."""

    def __init__(self, socket_path: str, account: str):
        pw = pwd.getpwnam(account)
        self.uid, self.gid = pw.pw_uid, pw.pw_gid
        vh_gid = grp.getgrnam("vaulthalla").gr_gid
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        helper = Path(__file__).resolve().parent.parent / "helpers" / "connect_as.py"
        os.set_inheritable(child.fileno(), True)
        self.proc = subprocess.Popen([sys.executable, "-I", str(helper), socket_path, str(child.fileno())],
                                     user=self.uid, group=self.gid, extra_groups=[vh_gid],
                                     pass_fds=(child.fileno(),), stdin=subprocess.DEVNULL,
                                     close_fds=True, cwd="/", env={"PATH": "/usr/bin:/bin"})
        child.close()
        self.ctl = parent

    def connect(self, timeout: float) -> socket.socket:
        self.ctl.settimeout(timeout)
        self.ctl.sendall(b"\x00")
        msg, fds, _flags, _addr = socket.recv_fds(self.ctl, 16, 1)
        if not fds:
            raise ConnectionError(f"connector could not connect: errno {msg[1:].decode(errors='replace')}")
        return socket.socket(fileno=fds[0])

    def close(self) -> None:
        try:
            self.ctl.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


class CliSockDriver:
    surface = "cli_sock"

    def __init__(self, socket_path: str, account: str | None, redactor=None, on_secret=None):
        self.socket_path = socket_path
        self.on_secret = on_secret        # called with (label, value) for secrets printed once (generated passwords)
        self.account = account            # None = root
        self.redactor = redactor
        self.connector: Connector | None = None

    async def open(self) -> None:
        if self.account:
            self.connector = await asyncio.to_thread(Connector, self.socket_path, self.account)

    async def close(self) -> None:
        if self.connector:
            await asyncio.to_thread(self.connector.close)

    async def run_line(self, argv: list[str], deadline_s: float) -> Result:
        return await asyncio.to_thread(self._run_line_sync, argv, deadline_s)

    def _run_line_sync(self, argv: list[str], deadline_s: float) -> Result:
        t0 = time.time_ns()
        line = shlex.join(argv)
        rendered = self.redactor.redact_text("vh " + line) if self.redactor else "vh " + line
        end = time.monotonic() + deadline_s
        try:
            if self.connector:
                sock = self.connector.connect(min(10.0, deadline_s))
            else:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(min(10.0, deadline_s))
                sock.connect(self.socket_path)
        except (OSError, ConnectionError) as e:
            return Result("error", detail=f"connect: {e}", rendered=rendered, data={"stdout": ""}, t0_ns=t0,
                          t1_ns=time.time_ns())
        out, err = [], []
        try:
            with sock:
                _send_frame(sock, {"cmd": argv[0] if argv else "help", "args": argv[1:], "argv": argv,
                                   "line": line, "interactive": False})
                while True:
                    left = end - time.monotonic()
                    if left <= 0:
                        return Result("timeout", detail=f"no result within {deadline_s}s", rendered=rendered,
                                      t0_ns=t0, t1_ns=time.time_ns())
                    sock.settimeout(left)
                    frame = _recv_frame(sock)
                    ftype = frame.get("type")
                    if ftype == "hello":
                        continue
                    if ftype == "output":
                        (err if frame.get("stream") == "stderr" else out).append(frame.get("text", ""))
                        continue
                    if ftype == "prompt":
                        return Result("needs_confirmation", detail=str(frame.get("text", ""))[:200], rendered=rendered,
                                      t0_ns=t0, t1_ns=time.time_ns())
                    # "result" or legacy reply
                    code = frame.get("exit_code")
                    if not isinstance(code, int):
                        code = 0 if frame.get("ok") else 1
                    stdout = "".join(out) + (frame.get("stdout") or "")
                    stderr = "".join(err) + (frame.get("stderr") or "")
                    return self._result(code, stdout, stderr, rendered, t0)
        except socket.timeout:
            return Result("timeout", detail=f"no result within {deadline_s}s", rendered=rendered, t0_ns=t0,
                          t1_ns=time.time_ns())
        except (EOFError, ConnectionError, OSError) as e:
            return Result("disconnected", detail=str(e), rendered=rendered, t0_ns=t0, t1_ns=time.time_ns())

    def _result(self, code: int, stdout: str, stderr: str, rendered: str, t0: int) -> Result:
        # A generated password is printed exactly once ("Password: …"): hand it to the broker, keep it out of results.
        secrets_found = []
        for ln in stdout.splitlines():
            key, sep, value = ln.strip().partition(":")
            if sep and key.strip().lower() in ("password", "generated password", "initial password") and value.strip():
                secrets_found.append(value.strip())
        for value in secrets_found:
            if self.redactor:
                self.redactor.register_secret(value)
            if self.on_secret:
                self.on_secret("password", value)
            stdout = stdout.replace(value, "<redacted>")
        red = self.redactor.redact_text if self.redactor else (lambda s: s)
        return Result(classify_exit(code, stderr), detail=red(stderr.strip())[:400], code=code,
                      data={"stdout": red(stdout)[:20000]}, rendered=rendered, t0_ns=t0, t1_ns=time.time_ns())
