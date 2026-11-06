#!/usr/bin/env python3
"""Give the web e2e account its second factor at provisioning (#405; MFA is mandatory for admins since #357).

provision_e2e_user.sh runs this once per account, before any Playwright worker signs in: it signs the account in over
the daemon's ws with the real two-step flow (tools/lab/mfa.py, no bypass) and, when the daemon asks for the account's
first factor, enrolls an authenticator app (RFC 6238) and keeps it in --totp-file (mfa.TotpStore: 0600 JSON with the
seed, the last step spent and the recovery codes). The specs read that file and compute their codes from it
(web/tests/e2e/helpers/totp.ts); every sign-in spends a step, so the file's last_step moves forward.

When the file exists, the account signs in with it (a check that the factor still works). An account the daemon
lets in with the password alone needs no factor, and no file is written. The password arrives on stdin; the seed, the
codes and the password are never printed.

  enroll_totp.py --user NAME --totp-file PATH [--ws-url ws://127.0.0.1:36969/ws] < password
The ws URL defaults from the same settings the console uses (see default_ws_url). Needs the `websockets` package
(VAULTHALLA_E2E_PYTHON in provision_e2e_user.sh picks the interpreter).
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import urllib.parse
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from tools.lab import mfa  # noqa: E402
from tools.lab.pentest.client import Target, Ws, ok  # noqa: E402

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def default_ws_url(env: dict) -> str:
    """Where the console's ws goes (web/src/util/getUrl.ts, web/playwright.config.ts, `pnpm dev:e2e`):
    VAULTHALLA_E2E_WS_URL, else NEXT_PUBLIC_VAULTHALLA_WS_ORIGIN + /ws, else the base URL's own origin when the console
    is served by an install (behind its reverse proxy), else the dev server's default daemon."""
    if env.get("VAULTHALLA_E2E_WS_URL"):
        return env["VAULTHALLA_E2E_WS_URL"]
    if env.get("NEXT_PUBLIC_VAULTHALLA_WS_ORIGIN"):
        return env["NEXT_PUBLIC_VAULTHALLA_WS_ORIGIN"].rstrip("/") + "/ws"
    base = urllib.parse.urlsplit(env.get("VAULTHALLA_E2E_BASE_URL") or "http://127.0.0.1:3000")
    if base.hostname not in LOCAL_HOSTS or env.get("VAULTHALLA_E2E_NO_WEB_SERVER"):
        scheme = "wss" if base.scheme == "https" else "ws"
        return f"{scheme}://{base.netloc}/ws"
    return "ws://127.0.0.1:36969/ws"


def target_for(url: str) -> tuple[Target, str]:
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    path = parts.path or "/ws"
    if parts.scheme == "ws":
        return Target(hostname=host, connect_ip=host, ws_port=parts.port or 80), path
    if parts.scheme == "wss" and (parts.port or 443) == 443:
        # A local install's reverse proxy has a self-signed certificate (as playwright.config.ts's ignoreHTTPSErrors).
        return Target(hostname=host, insecure=host in LOCAL_HOSTS), path
    raise SystemExit(f"enroll_totp: unsupported ws URL {url!r}: set VAULTHALLA_E2E_WS_URL to ws://host:port/ws "
                     "or wss://host/ws")


async def ensure(url: str, user: str, password: str, path: Path) -> str:
    target, ws_path = target_for(url)
    store = mfa.TotpStore(path)
    totp = store.load() if store.exists() else None
    async with Ws(target, path=ws_path, user_agent="vh-e2e-provision/1") as ws:
        res = await ws.sign_in(user, password, totp, enroll=totp is None, on_enrolled=store.enrolled,
                               label="Playwright e2e")
        await ws.send("auth.logout", {})
    if ok(res):
        if totp is not None:
            return "signed in with the account's TOTP factor"
        return "enrolled a TOTP factor" if store.exists() else "signed in without a second factor (none required)"
    code = mfa.code_of(res)
    if code == "mfa_required":
        raise SystemExit(f"enroll_totp: '{user}' already has a second factor that {path} doesn't hold: provision a "
                         "fresh e2e user (--fresh-user)")
    if code == "mfa_enrollment_required":
        raise SystemExit(f"enroll_totp: '{user}' has no second factor, but {path} holds one: remove that file")
    raise SystemExit(f"enroll_totp: '{user}' could not sign in: {res.get('status')}{' (' + code + ')' if code else ''}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--user", required=True)
    p.add_argument("--totp-file", type=Path, required=True)
    p.add_argument("--ws-url", help="the daemon's ws endpoint (default: from the console's e2e settings)")
    args = p.parse_args()
    password = sys.stdin.readline().rstrip("\n")
    if not password:
        raise SystemExit("enroll_totp: the password is expected on stdin")
    url = args.ws_url or default_ws_url(dict(os.environ))
    try:
        outcome = asyncio.run(ensure(url, args.user, password, args.totp_file))
    except (OSError, RuntimeError, mfa.MfaError) as e:  # never carries a secret
        raise SystemExit(f"enroll_totp: {type(e).__name__}: {e} (ws {url})")
    print(f"E2E user '{args.user}': {outcome}.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
