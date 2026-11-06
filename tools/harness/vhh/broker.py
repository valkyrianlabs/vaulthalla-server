"""Identity broker: sessions and agents name principals and shares by opaque id; secrets stay here.

Credentials are held in memory only, every value is registered with the Redactor the moment it arrives, and drivers
ask for them at send time (`credential(...)`). Nothing in this module writes a secret anywhere.
"""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from vhh.redact import Redactor

import vhh._repo  # noqa: F401  (puts the repo root on sys.path for tools.lab)
from tools.lab.mfa import Totp


class MissingCredential(LookupError):
    """No secret for a principal or share: the engine turns this into a failing harness verdict."""


@dataclass(frozen=True)
class Credential:
    ref: str                  # opaque id: "u-carol", "public:sl-public-dl"
    kind: str                 # "password" | "share_token" | "session"
    username: str = ""        # admin-side login name (not secret, but never published)
    _secret: str = ""

    def secret(self) -> str:
        return self._secret

    def __repr__(self) -> str:  # never show the secret, even in tracebacks
        return f"Credential(ref={self.ref!r}, kind={self.kind!r})"


class IdentityBroker:
    def __init__(self, redactor: Redactor):
        self.redactor = redactor
        self._creds: dict[str, Credential] = {}
        self._totp: dict[str, Totp] = {}

    def register(self, ref: str, kind: str, secret: str, username: str = "") -> None:
        if not secret:
            raise MissingCredential(f"empty secret for {ref}")
        self.redactor.register_secret(secret)
        self._creds[ref] = Credential(ref, kind, username, secret)

    def register_totp(self, ref: str, totp: Totp) -> None:
        """The principal's TOTP authenticator (#357: an admin signs in with a second factor). The Totp object keeps the
        last step spent, so every session of this principal draws codes from the one instance."""
        self.redactor.register_secret(totp.secret_base32)
        self._totp[ref] = totp

    def totp(self, ref: str) -> Totp | None:
        return self._totp.get(ref)

    def register_canaries(self, canaries: dict[str, str]) -> None:
        """Canary markers are secrets per the fixture format: traces and reports must never contain them."""
        for c in canaries.values():
            if c:
                self.redactor.register_secret(c)

    def has(self, ref: str) -> bool:
        return ref in self._creds

    def credential(self, ref: str) -> Credential:
        try:
            return self._creds[ref]
        except KeyError:
            raise MissingCredential(f"no credential for {ref}") from None

    def refs(self) -> list[str]:
        return sorted(self._creds)

    def load_private_file(self, path: str | os.PathLike) -> int:
        """Load a fixture-format private credentials file (principals.<id>.password, shares.<id>.token).
        Refuses a file readable by group/other. Returns the number of credentials loaded."""
        p = Path(path)
        mode = p.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise PermissionError(f"{p}: credentials file must not be group/other accessible")
        doc = json.loads(p.read_text())
        n = 0
        for pid, rec in (doc.get("principals") or {}).items():
            if isinstance(rec, dict) and rec.get("password"):
                self.register(pid, "password", rec["password"], rec.get("username", ""))
                n += 1
                if isinstance(rec.get("totp"), dict) and rec["totp"].get("secret_base32"):
                    self.register_totp(pid, Totp.from_json(rec["totp"]))
        for sid, rec in (doc.get("shares") or {}).items():
            token = rec.get("token") if isinstance(rec, dict) else rec
            if token:
                self.register(f"public:{sid}", "share_token", token)
                n += 1
        canary = doc.get("canary") or {}
        if isinstance(canary, dict):
            for v in canary.values():
                if isinstance(v, str) and v:
                    self.redactor.register_secret(v)
        return n
