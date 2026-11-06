"""Second-factor sign-in and step-up for the lab and harness ws clients (#395).

Since #357 an account that must have MFA (every admin, policy `admins`) signs in in two steps: `auth.login` answers
ERROR with data.code `mfa_required` (a factor is enrolled: finish with `auth.mfa.verify`) or `mfa_enrollment_required`
(none yet: `auth.mfa.totp.enroll.start` / `.confirm`, then `auth.mfa.recovery.acknowledge` completes the sign-in).
Since #359 a signed-in web session may also be refused with `step_up_required` {family, target, methods}: the client
runs `auth.stepup.begin` / `.finish` (password and a TOTP code together) and resends the request once, as the
console's lib/stepUp.ts does. These clients do the real flow: nothing here weakens or skips a daemon check.

The factor these clients use is an RFC 6238 authenticator (HMAC-SHA1, 6 digits, 30 s), the one core/auth/mfa/Totp
implements. The daemon accepts the step before and after the current one and refuses a step at or below the last one
it accepted (the replay guard), so a Totp hands out each step once and waits for the next when the window is spent.

Secrets: the seed, every code, the recovery codes and the passwords are never printed, logged or put in an exception.
Callers keep them in their own run state (the harness broker, the pentest seed-state, or a 0600 file: TotpStore).

`send` everywhere is an async callable (command, payload) -> the response envelope as a dict.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import stat
import struct
import threading
import time
from pathlib import Path
from typing import Awaitable, Callable

PERIOD_SECONDS = 30
DIGITS = 6
WINDOW_STEPS = 1
# The previous step is used only while this much of the current one is left, so it can't age out of the daemon's
# window between computing the code and the daemon checking it.
_PREVIOUS_STEP_MARGIN_S = 3.0
_WAKE_MARGIN_S = 0.25

Send = Callable[[str, object], Awaitable[dict]]


def ok(msg: dict) -> bool:
    return isinstance(msg, dict) and str(msg.get("status", "")).upper() in ("OK", "SUCCESS", "READY")


def code_of(msg: dict) -> str | None:
    data = msg.get("data") if isinstance(msg, dict) else None
    value = data.get("code") if isinstance(data, dict) else None
    return value if isinstance(value, str) else None


def decode_secret(secret_base32: str) -> bytes:
    cleaned = "".join(secret_base32.split()).upper().rstrip("=")
    if not cleaned:
        raise ValueError("empty TOTP secret")
    try:
        return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))
    except (ValueError, TypeError):
        raise ValueError("TOTP secret is not base32") from None


def hotp(secret: bytes, counter: int, digits: int = DIGITS) -> str:
    """RFC 4226: HMAC-SHA1 over the big-endian counter, dynamic truncation, `digits` decimal digits."""
    mac = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


class Totp:
    """One enrolled authenticator: the seed and the last step spent. Safe to share between coroutines and threads."""

    def __init__(self, secret_base32: str, last_step: int = -1, clock: Callable[[], float] = time.time,
                 on_spend: Callable[["Totp"], None] | None = None):
        self._secret = decode_secret(secret_base32)
        self._secret_base32 = "".join(secret_base32.split()).upper().rstrip("=")
        self.last_step = int(last_step)
        self.clock = clock
        self.on_spend = on_spend
        self._lock = threading.Lock()

    def __repr__(self) -> str:  # never show the seed, even in tracebacks
        return f"Totp(last_step={self.last_step})"

    @property
    def secret_base32(self) -> str:
        return self._secret_base32

    def code(self, step: int) -> str:
        return hotp(self._secret, step)

    def allocate(self) -> tuple[int, float]:
        """Claim the next step the daemon will accept and say how long to wait before it is inside the window."""
        with self._lock:
            now = self.clock()
            current = int(now // PERIOD_SECONDS)
            left_in_step = (current + 1) * PERIOD_SECONDS - now
            earliest = current - WINDOW_STEPS if left_in_step >= _PREVIOUS_STEP_MARGIN_S else current
            step = max(earliest, self.last_step + 1)
            # A step is accepted once the daemon's current step is at least step - 1.
            wait = 0.0 if step <= current + WINDOW_STEPS else (step - WINDOW_STEPS) * PERIOD_SECONDS - now + _WAKE_MARGIN_S
            self.last_step = step
        if self.on_spend is not None:
            self.on_spend(self)
        return step, max(0.0, wait)

    async def next_code(self) -> str:
        step, wait = self.allocate()
        if wait > 0:
            await asyncio.sleep(wait)
        return self.code(step)

    def to_json(self) -> dict:
        return {"secret_base32": self._secret_base32, "last_step": self.last_step}

    @classmethod
    def from_json(cls, doc: dict, **kw) -> "Totp":
        return cls(doc["secret_base32"], int(doc.get("last_step", -1)), **kw)


class MfaError(RuntimeError):
    """A sign-in or step-up that could not finish. The text is fixed or the daemon's; it never holds a secret."""

    def __init__(self, text: str, code: str | None = None):
        super().__init__(text)
        self.code = code


# ---------------------------------------------------------------------------------------------------- sign-in

Enrolled = Callable[[Totp, list], None]


async def enroll_totp(send: Send, *, label: str = "lab client", clock: Callable[[], float] = time.time,
                      on_enrolled: Enrolled | None = None) -> tuple[dict, Totp]:
    """Finish a pending enrollment with a new authenticator. `on_enrolled(totp, recovery_codes)` runs after the factor
    is confirmed and before the recovery codes are acknowledged (which is what completes the sign-in): it is where the
    caller keeps the secret. Returns (the acknowledge answer, the factor)."""
    start = await send("auth.mfa.totp.enroll.start", {"label": label})
    if not ok(start):
        raise MfaError(f"TOTP enrollment could not start: {start.get('error', '')}", code_of(start))
    data = start.get("data") or {}
    secret, enrollment_id = data.get("secret_base32"), data.get("enrollment_id")
    if not isinstance(secret, str) or not secret or enrollment_id is None:
        raise MfaError("TOTP enrollment answer has no secret or enrollment id")
    totp = Totp(secret, clock=clock)
    confirm = await send("auth.mfa.totp.enroll.confirm", {"enrollment_id": enrollment_id,
                                                          "code": await totp.next_code()})
    if not ok(confirm):
        raise MfaError(f"TOTP enrollment was not confirmed: {confirm.get('error', '')}", code_of(confirm))
    recovery = (confirm.get("data") or {}).get("recovery_codes") or {}
    codes = list(recovery.get("codes") or [])
    if on_enrolled is not None:
        on_enrolled(totp, codes)
    batch = recovery.get("batch_id")
    if not batch:
        return confirm, totp  # not a pending enrollment: nothing to acknowledge
    ack = await send("auth.mfa.recovery.acknowledge", {"batch_id": batch})
    return ack, totp


async def sign_in(send: Send, name: str, password: str, totp: Totp | None = None, *, enroll: bool = False,
                  label: str = "lab client", on_enrolled: Enrolled | None = None,
                  clock: Callable[[], float] = time.time) -> tuple[dict, Totp | None]:
    """auth.login, then the second step when the daemon asks for one. Returns (the final answer, the factor in use).

    - mfa_required: answered with `totp` (auth.mfa.verify, method totp). Without one, the pending refusal is returned.
    - mfa_enrollment_required: when `enroll`, a new authenticator is enrolled (see enroll_totp); otherwise the pending
      refusal is returned. A client that holds a factor for an account that asks for enrollment was given a stale one.
    Anything else (a wrong password, a deactivated account, rate limiting) is returned as the daemon answered."""
    msg = await send("auth.login", {"name": name, "password": password})
    code = code_of(msg)
    if ok(msg) or code not in ("mfa_required", "mfa_enrollment_required"):
        return msg, totp
    if code == "mfa_enrollment_required":
        if not enroll:
            return msg, totp
        return await enroll_totp(send, label=label, on_enrolled=on_enrolled, clock=clock)
    methods = ((msg.get("data") or {}).get("pending") or {}).get("methods") or []
    if totp is None or "totp" not in methods:
        return msg, totp
    verify = await send("auth.mfa.verify", {"method": "totp", "code": await totp.next_code()})
    return verify, totp


# ---------------------------------------------------------------------------------------------------- step-up

def step_up_required(msg: dict) -> bool:
    return not ok(msg) and code_of(msg) == "step_up_required"


async def step_up(send: Send, refusal: dict, password: str, totp: Totp | None) -> dict:
    """Run auth.stepup.begin / .finish for the family and target a step_up_required refusal named. Prefers
    password_totp; the password alone only where the daemon offers it (an account with no factor, D3)."""
    data = refusal.get("data") or {}
    begin = await send("auth.stepup.begin", {"family": data.get("family"), "target": data.get("target")})
    if not ok(begin):
        return begin
    ceremony = begin.get("data") or {}
    methods = ceremony.get("methods") or []
    payload = {"stepup_id": ceremony.get("stepup_id")}
    if totp is not None and "password_totp" in methods:
        payload.update(method="password_totp", password=password, code=await totp.next_code())
    elif "password" in methods:
        payload.update(method="password", password=password)
    else:
        return {"status": "ERROR", "error": "no step-up method this client can answer", "data":
                {"code": "step_up_unavailable", "methods": methods}}
    return await send("auth.stepup.finish", payload)


async def send_stepped(send: Send, command: str, payload, password: str | None, totp: Totp | None) -> dict:
    """Send; on step_up_required, step up and resend once. A failed step-up is returned in place of the refusal."""
    msg = await send(command, payload)
    if not step_up_required(msg) or not password:
        return msg
    done = await step_up(send, msg, password, totp)
    if not ok(done):
        return done
    return await send(command, payload)


# ---------------------------------------------------------------------------------------------------- storage

class TotpStore:
    """A private file holding one factor: {"secret_base32", "last_step", "recovery_codes"?} as JSON, 0600, or a bare
    base32 secret on one line (an authenticator exported by hand). The last step spent is written back after every
    code, so separate runs within the same 30 s never offer the daemon a step it already accepted."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path).expanduser()
        self.recovery_codes: list = []

    def exists(self) -> bool:
        return self.path.exists()

    def load(self, clock: Callable[[], float] = time.time) -> Totp:
        mode = self.path.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise PermissionError(f"{self.path}: TOTP file must not be group/other accessible")
        text = self.path.read_text().strip()
        if text.startswith("{"):
            doc = json.loads(text)
            self.recovery_codes = list(doc.get("recovery_codes") or [])
            totp = Totp.from_json(doc, clock=clock)
        else:
            totp = Totp(text, clock=clock)
        totp.on_spend = self.save
        return totp

    def save(self, totp: Totp, recovery_codes: list | None = None) -> None:
        if recovery_codes is not None:
            self.recovery_codes = list(recovery_codes)
        doc = totp.to_json()
        if self.recovery_codes:
            doc["recovery_codes"] = self.recovery_codes
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(doc, fh)
            os.replace(tmp, self.path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

    def enrolled(self, totp: Totp, recovery_codes: list) -> None:
        """on_enrolled for sign_in: keep the new factor (refuses to overwrite one already on disk)."""
        if self.path.exists():
            raise MfaError(f"{self.path} already holds a factor: refusing to overwrite it")
        self.save(totp, recovery_codes)
        totp.on_spend = self.save
