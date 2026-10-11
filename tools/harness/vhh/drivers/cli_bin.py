"""The real `vh` client (vaulthalla-cli) run as the session's Linux account against the instance's socket.

Covers what the socket driver skips: argv canonicalization, the client's own exit codes (69/75/76/77), and
non-interactive handling. Same outcome classification and secret handling as cli_sock.
"""
from __future__ import annotations

import asyncio
import grp
import pwd
import shlex
import time

from vhh.drivers.cli_sock import CliSockDriver, classify_exit
from vhh.model import Result

CLIENT_EXIT = {69: "error", 75: "timeout", 76: "error", 77: "denied"}


class CliBinDriver:
    surface = "cli_bin"

    def __init__(self, cli_path: str, socket_path: str, account: str | None, redactor=None, on_secret=None):
        self.cli_path = cli_path
        self.socket_path = socket_path
        self.account = account
        self.redactor = redactor
        self.on_secret = on_secret
        self._secrets = CliSockDriver(socket_path, None, redactor=redactor, on_secret=on_secret)

    async def open(self) -> None:
        pass

    async def close(self) -> None:
        pass

    async def run_line(self, argv: list[str], deadline_s: float) -> Result:
        t0 = time.time_ns()
        rendered = "vh " + shlex.join(argv)
        if self.redactor:
            rendered = self.redactor.redact_text(rendered)
        kw = {}
        if self.account:
            pw = pwd.getpwnam(self.account)
            kw = {"user": pw.pw_uid, "group": pw.pw_gid, "extra_groups": [grp.getgrnam("vaulthalla").gr_gid]}
        proc = await asyncio.create_subprocess_exec(
            self.cli_path, *argv, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, cwd="/",
            env={"PATH": "/usr/bin:/bin", "VAULTHALLA_CLI_SOCKET": self.socket_path, "VAULTHALLA_NONINTERACTIVE": "1",
                 "VAULTHALLA_CLI_TIMEOUT": str(max(1, int(deadline_s)))},
            **kw)
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=deadline_s + 2)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return Result("timeout", detail=f"vh did not exit within {deadline_s}s", rendered=rendered,
                          data={"stdout": ""}, t0_ns=t0, t1_ns=time.time_ns())
        code = proc.returncode
        r = self._secrets._result(code, out.decode(errors="replace"), err.decode(errors="replace"), rendered, t0)
        if code in CLIENT_EXIT:
            r.outcome = CLIENT_EXIT[code]
        elif code != 0:
            r.outcome = classify_exit(code, err.decode(errors="replace"))
        return r
