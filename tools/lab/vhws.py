#!/usr/bin/env python3
"""Minimal Vaulthalla websocket client for web-console ("web-CLI") contract testing.

Requires: pip install websockets (e.g. in a venv).
Usage:
  vhws.py --url ws://10.0.0.33/ws --user admin --password-file F [--totp-file T [--enroll-totp]]  CMD [JSON] ...
Signs in first, then sends each command in order on the same session and prints one JSON line per response:
{"command", "status", "data"/"error"}. Exit 1 if any response is an error.

An admin signs in with a second factor (#357): --totp-file names a private (0600) file holding the account's TOTP
authenticator (tools/lab/mfa.py TotpStore: JSON, or a bare base32 secret). With --enroll-totp, an account that has no
factor yet enrolls one on this sign-in and the new seed and recovery codes are written to that file (it must not exist
yet). Enrolling changes the account: on the lab (vh-storage) it needs approval first. A command refused with
step_up_required (#359) is confirmed with the password and a code, then resent once.
Passwords, seeds and codes are read from files (or VHWS_PASSWORD) and never printed.
"""
import argparse
import asyncio
import json
import os
import sys
import uuid
from pathlib import Path

import websockets

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.lab import mfa  # noqa: E402


async def run(args):
    password = os.environ.get("VHWS_PASSWORD")
    if args.password_file:
        with open(args.password_file) as fh:
            password = fh.read().strip()
    token = ""
    failed = False
    async with websockets.connect(args.url, open_timeout=10, close_timeout=5, max_size=2**24) as ws:
        async def send(command, payload):
            nonlocal token
            rid = str(uuid.uuid4())
            await ws.send(json.dumps({"command": command, "payload": payload, "requestId": rid, "token": token}))
            while True:
                raw = await asyncio.wait_for(ws.recv(), timeout=args.timeout)
                msg = json.loads(raw)
                if msg.get("requestId") != rid:
                    continue
                if msg.get("token"):
                    token = msg["token"]
                return msg

        totp = None
        store = mfa.TotpStore(args.totp_file) if args.totp_file else None
        if store is not None and store.exists():
            totp = store.load()
        steps = []
        if args.user:
            try:
                msg, totp = await mfa.sign_in(send, args.user, password, totp, enroll=args.enroll_totp,
                                              label="vhws", on_enrolled=store.enrolled if store else None)
            except (asyncio.TimeoutError, mfa.MfaError) as e:
                print(json.dumps({"command": "auth.login", "status": "ERROR", "error": str(e)[:200]}))
                return 1
            out = {"command": "auth.login", "status": msg.get("status")}
            if "error" in msg:
                out["error"] = msg["error"]
                out["code"] = mfa.code_of(msg)
            if args.full:
                out["data"] = msg.get("data")
            print(json.dumps(out, default=str))
            if not mfa.ok(msg):
                return 1
        rest = list(args.commands)
        while rest:
            cmd = rest.pop(0)
            payload = {}
            if rest and rest[0].lstrip().startswith("{"):
                payload = json.loads(rest.pop(0))
            steps.append((cmd, payload))
        for cmd, payload in steps:
            try:
                msg = await mfa.send_stepped(send, cmd, payload, password if args.user else None, totp)
            except asyncio.TimeoutError:
                print(json.dumps({"command": cmd, "status": "TIMEOUT"}))
                failed = True
                continue
            status = msg.get("status")
            out = {"command": cmd, "status": status}
            if "error" in msg:
                out["error"] = msg["error"]
            out["data"] = msg.get("data")
            print(json.dumps(out, default=str))
            if status not in ("ok", "OK", "success"):
                failed = True
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--user")
    ap.add_argument("--password-file")
    ap.add_argument("--totp-file", help="private (0600) file with the account's TOTP authenticator")
    ap.add_argument("--enroll-totp", action="store_true",
                    help="enroll a TOTP authenticator if the account must have one and has none (writes --totp-file)")
    ap.add_argument("--timeout", type=float, default=20)
    ap.add_argument("--full", action="store_true", help="also print the sign-in answer's data")
    ap.add_argument("commands", nargs="*")
    args = ap.parse_args()
    if args.enroll_totp and not args.totp_file:
        ap.error("--enroll-totp needs --totp-file: the new authenticator's seed has to be kept somewhere")
    sys.exit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
