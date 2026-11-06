"""Signed-in ws sessions for the macOS smokes (install_acceptance.py, storage_smoke.py; #405).

Admins must sign in with a second factor (#357) and confirm sensitive commands with a step-up (#359). These clients do
the real flow through tools/lab/mfa.py, with no daemon bypass: the password, then a TOTP code (enrolling an
authenticator when the daemon asks for the account's first factor), and a step_up_required refusal is answered with
the password and a fresh code, then the command is resent once.

The authenticator lives in the caller's run state only: in memory for one process (storage_smoke.py), or in a private
0600 file (mfa.TotpStore) when separate runs sign in as the same account (install_acceptance.py's seed, then every
verify). Secrets are never printed, logged or put in an exception.
"""
from __future__ import annotations

import time
from typing import Callable

from tools.lab import mfa
from tools.lab.pentest.client import Target, Ws, WsError, ok


class AdminFactor:
    """The admin's authenticator between sign-ins: a TotpStore file (several runs) or memory (store=None)."""

    def __init__(self, store: mfa.TotpStore | None = None, clock: Callable[[], float] = time.time):
        self.store, self.clock = store, clock
        self.totp: mfa.Totp | None = None

    def load(self) -> mfa.Totp | None:
        if self.totp is None and self.store is not None and self.store.exists():
            self.totp = self.store.load(clock=self.clock)
        return self.totp

    def enrolled(self, totp: mfa.Totp, recovery_codes: list) -> None:
        """on_enrolled: keep the new factor before the recovery codes are acknowledged (that completes the sign-in)."""
        if self.store is not None:
            self.store.enrolled(totp, recovery_codes)
        self.totp = totp


class SignInError(RuntimeError):
    """A sign-in that didn't complete. The text names the account and the daemon's code, never a secret."""


async def open_ws(target: Target, path: str = "/ws") -> Ws:
    """Open a ws session (the offline tests replace this with a scripted daemon)."""
    return await Ws(target, path=path).__aenter__()


def _refusal(name: str, msg: dict, factor: AdminFactor | None) -> str:
    code = mfa.code_of(msg)
    held = factor.totp if factor is not None else None
    store = factor.store if factor is not None else None
    if code == "mfa_required" and held is None:
        where = f"pass --totp-file with its authenticator ({store.path} has none)" if store else "this client holds none"
        return f"{name} has a second factor: {where}"
    if code == "mfa_enrollment_required" and held is not None and store is not None:
        return f"{name} has no second factor, but {store.path} holds one from an earlier install: remove that file"
    return f"{name} sign-in failed: {msg.get('status')}{' (' + code + ')' if code else ''}"


async def sign_in(target: Target, name: str, password: str, factor: AdminFactor | None = None, *,
                  label: str = "vh macOS smoke") -> Ws:
    """A ws session signed in as `name`. With `factor`, the TOTP step is answered from it, or a first authenticator is
    enrolled into it when the daemon asks for one; without, the password alone (an account that doesn't need MFA)."""
    ws = await open_ws(target)
    try:
        totp = factor.load() if factor is not None else None
        res = await ws.sign_in(name, password, totp, enroll=factor is not None and totp is None,
                               on_enrolled=factor.enrolled if factor is not None else None, label=label,
                               clock=factor.clock if factor is not None else time.time)
        if not ok(res):
            raise SignInError(_refusal(name, res, factor))
    except BaseException:
        await ws.__aexit__(None, None, None)
        raise
    return ws


async def must(ws: Ws, command: str, payload=None, timeout: float = 60) -> dict:
    """ws.must, answering a step_up_required refusal with the session's password and TOTP (then one resend)."""
    msg = await ws.stepped(command, payload, timeout)
    if not ok(msg):
        code = mfa.code_of(msg)
        raise WsError(f"{command}: {msg.get('status')} {msg.get('error')}{' (' + code + ')' if code else ''}")
    return msg.get("data") or {}
