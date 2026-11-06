#!/usr/bin/env python3
"""WebSocket connection-churn smoke for a packaged Vaulthalla host.

Runs concurrent clients through the connection lifecycles that exercise server-side closes
(logout, bad-login rate limiting, sweeper idle timeout, abrupt client disconnects, garbage frames)
and asserts the daemon survives: same MainPID, NRestarts unchanged, `vh status` healthy.
Regression guard for #127 / #129 (handler exceptions and close/read races aborting the daemon).

  ws_churn.py --host vh-storage --ws-url ws://10.0.0.33/ws --admin-password-file F [--admin-totp-file T]
              [--rounds 5] [--idle]

The admin signs in with a second factor (#357). Each round, one client completes the whole sign-in with the TOTP
authenticator in --admin-totp-file (tools/lab/mfa.py TotpStore, 0600) and the other login clients stop at the pending
step and sign out from it: one authenticator yields about one code per 30 s (the daemon's replay guard), and a socket
closed while its sign-in is pending is a lifecycle worth churning too. Without --admin-totp-file every login client
takes the pending path.

Requires `pip install websockets`. Passwords, seeds and codes are read from files and never printed.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import uuid
from pathlib import Path

import websockets

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.lab import mfa  # noqa: E402


ADMIN_USER = "admin"


def daemon_state(host: str) -> tuple[str, str]:
    out = subprocess.run(["ssh", "-o", "BatchMode=yes", host,
                          "systemctl show vaulthalla -p MainPID --value; systemctl show vaulthalla -p NRestarts --value"],
                         capture_output=True, text=True, timeout=30).stdout.split()
    return (out + ["?", "?"])[0], (out + ["?", "?"])[1]


async def call(ws, command, payload=None, token=""):
    rid = str(uuid.uuid4())
    await ws.send(json.dumps({"command": command, "payload": payload or {}, "requestId": rid, "token": token}))
    while True:
        msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=20))
        if msg.get("requestId") == rid:
            return msg


class ChurnError(RuntimeError):
    pass


async def login_logout(url, password, totp):
    """The whole sign-in (password, then the TOTP step), an authenticated command, sign-out."""
    async with websockets.connect(url, open_timeout=10) as ws:
        token = ""

        async def send(command, payload):
            nonlocal token
            msg = await call(ws, command, payload, token)
            token = msg.get("token") or token
            return msg

        msg, _ = await mfa.sign_in(send, ADMIN_USER, password, totp)
        if not mfa.ok(msg):
            raise ChurnError(f"admin sign-in failed: {mfa.code_of(msg) or msg.get('status')}")
        listed = await send("storage.vault.list", None)
        if not mfa.ok(listed):
            raise ChurnError("storage.vault.list failed after sign-in")
        await send("auth.logout", None)


async def pending_logout(url, password, _totp):
    """Password only: the socket is left pending its second factor (#357), then signs out from there."""
    async with websockets.connect(url, open_timeout=10) as ws:
        msg = await call(ws, "auth.login", {"name": ADMIN_USER, "password": password})
        if mfa.code_of(msg) not in ("mfa_required", "mfa_enrollment_required") and not mfa.ok(msg):
            raise ChurnError(f"admin password step failed: {mfa.code_of(msg) or msg.get('status')}")
        await call(ws, "auth.logout", None, msg.get("token", ""))


async def abrupt_disconnect(url, password, _totp=None):
    ws = await websockets.connect(url, open_timeout=10)
    rid = str(uuid.uuid4())
    await ws.send(json.dumps({"command": "auth.login", "payload": {"name": ADMIN_USER, "password": password},
                              "requestId": rid, "token": ""}))
    ws.transport.abort()  # drop the TCP connection while the server is answering


async def garbage(url, _password, _totp=None):
    async with websockets.connect(url, open_timeout=10) as ws:
        await ws.send("{not json")
        await ws.send(b"\x00\x01binary-without-upload")
        await asyncio.wait_for(ws.recv(), timeout=20)


async def bad_logins(url, _password, _totp=None):
    async with websockets.connect(url, open_timeout=10) as ws:
        for _ in range(3):
            await call(ws, "auth.login", {"name": "churn-nobody", "password": "wrong"})


async def idle_until_swept(url, _password, _totp=None):
    async with websockets.connect(url, open_timeout=10) as ws:
        try:
            while True:
                await asyncio.wait_for(ws.recv(), timeout=150)
        except (websockets.ConnectionClosed, asyncio.TimeoutError):
            return


async def run(args) -> int:
    global ADMIN_USER
    ADMIN_USER = args.admin_user
    with open(args.admin_password_file) as fh:
        password = fh.read().strip()
    pid0, restarts0 = daemon_state(args.host)
    print(f"daemon before: pid={pid0} restarts={restarts0}")
    totp = mfa.TotpStore(args.admin_totp_file).load() if args.admin_totp_file else None
    flows = [pending_logout, abrupt_disconnect, garbage, bad_logins]
    errors = 0
    for rnd in range(args.rounds):
        tasks = [(login_logout if flow is pending_logout and i == 0 and totp is not None else flow)(
                     args.ws_url, password, totp) for flow in flows for i in range(args.concurrency)]
        if args.idle and rnd == 0:
            tasks += [idle_until_swept(args.ws_url, password) for _ in range(args.concurrency)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        errs = [r for r in results if isinstance(r, Exception) and not isinstance(r, websockets.ConnectionClosed)]
        errors += len(errs)
        pid, restarts = daemon_state(args.host)
        print(f"round {rnd + 1}: {len(tasks)} clients, {len(errs)} client-side errors, daemon pid={pid} restarts={restarts}")
        for e in errs[:3]:
            print(f"   client error: {type(e).__name__}: {str(e)[:160]}")
        if pid != pid0 or restarts != restarts0:
            print("FAIL: daemon restarted during churn")
            return 1
    status = subprocess.run(["ssh", "-o", "BatchMode=yes", args.host, "sudo timeout 20 vh status >/dev/null"],
                            timeout=60).returncode
    print(f"vh status rc={status}")
    return 0 if status == 0 and errors == 0 else 1


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--host", required=True)
    ap.add_argument("--ws-url", required=True)
    ap.add_argument("--admin-user", default="admin")
    ap.add_argument("--admin-password-file", required=True)
    ap.add_argument("--admin-totp-file", help="private (0600) file with the admin's TOTP authenticator")
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--idle", action="store_true", help="also hold unauthenticated connections until the sweeper closes them")
    sys.exit(asyncio.run(run(ap.parse_args())))


if __name__ == "__main__":
    main()
