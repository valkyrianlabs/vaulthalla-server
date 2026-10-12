"""Central redaction: nothing secret reaches a trace, report or log line.

Two layers: (1) values registered by the identity broker (passwords, share tokens, session tokens, canary markers)
are masked wherever they appear in text; (2) sensitive keys (token, cookie, authorization, password, secret, ...)
are masked whatever their value. `redact` deep-copies, so callers' objects are never mutated.
"""
from __future__ import annotations

import re
import threading

MASK = "[REDACTED]"
# Sensitive by key name. Matched against word parts (split on non-alphanumerics) and the collapsed key, so
# "access_token", "api_key" and "Set-Cookie" match while plain words like "passed" or "author" do not.
_SENSITIVE_PARTS = frozenset({"password", "passwd", "passphrase", "token", "secret", "cookie", "authorization",
                              "auth", "apikey", "sessionid", "credential", "credentials", "privatekey", "bearer"})
_SENSITIVE_SUBSTR = ("password", "passwd", "passphrase", "secret", "token", "apikey", "privatekey", "sessionid",
                     "authorization")
_SPLIT = re.compile(r"[^a-z0-9]+")


class _KeyMatcher:
    @staticmethod
    def search(key: str):
        low = key.lower()
        parts = set(_SPLIT.split(low))
        collapsed = _SPLIT.sub("", low)
        return (parts & _SENSITIVE_PARTS) or any(s in collapsed for s in _SENSITIVE_SUBSTR)


SENSITIVE_KEYS = _KeyMatcher
# Header-ish fragments that may appear inside rendered requests.
_INLINE = [
    re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer\s+|basic\s+)?[^\s\"',;]+"),
    re.compile(r"(?i)((?:set-)?cookie\s*[:=]\s*)[^\r\n\"']+"),
    re.compile(r"(?i)(\"?(?:password|token|secret|public_token|refresh_token|access_token)\"?\s*[:=]\s*\"?)"
               r"[^\"\s,}]+"),
]
MIN_SECRET_LEN = 4


class Redactor:
    def __init__(self) -> None:
        self._secrets: set[str] = set()
        self._re: re.Pattern | None = None
        self._lock = threading.Lock()

    def register_secret(self, value: str) -> None:
        if not isinstance(value, str) or len(value) < MIN_SECRET_LEN:
            if isinstance(value, str) and value:
                # Too short to mask safely by substring; refuse rather than leak quietly.
                raise ValueError("secret too short to redact reliably")
            return
        with self._lock:
            if value not in self._secrets:
                self._secrets.add(value)
                alts = sorted((re.escape(s) for s in self._secrets), key=len, reverse=True)
                self._re = re.compile("|".join(alts))

    def secrets_count(self) -> int:
        return len(self._secrets)

    def redact_text(self, text: str) -> str:
        if not isinstance(text, str):
            return text
        if self._re is not None:
            text = self._re.sub(MASK, text)
        for pat in _INLINE:
            text = pat.sub(lambda m: m.group(1) + MASK, text)
        return text

    def redact(self, obj):
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                sensitive = isinstance(k, str) and SENSITIVE_KEYS.search(k) and v not in (None, "")
                out[self.redact_text(str(k))] = MASK if sensitive else self.redact(v)
            return out
        if isinstance(obj, (list, tuple)):
            return [self.redact(v) for v in obj]
        if isinstance(obj, str):
            return self.redact_text(obj)
        if isinstance(obj, (bytes, bytearray)):
            return self.redact_text(bytes(obj).decode("utf-8", "replace"))
        return obj
