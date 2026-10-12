"""Guardrails: per-session budgets, a scope allowlist, per-op deadlines and a kill switch.

They sit in front of every op, seeded or agent-made. A blocked op is recorded (outcome "blocked") and never sent.
Tripping the kill switch stops every session and marks the run aborted, which is always a failing run.
"""
from __future__ import annotations

import os
import signal
import threading
from dataclasses import dataclass, field
from pathlib import Path

from vhh.model import Op


@dataclass
class Budget:
    max_ops: int | None = None
    max_bytes: int | None = None
    ops: int = 0
    bytes: int = 0

    def check(self) -> str | None:
        if self.max_ops is not None and self.ops >= self.max_ops:
            return f"op budget exhausted ({self.max_ops})"
        if self.max_bytes is not None and self.bytes >= self.max_bytes:
            return f"byte budget exhausted ({self.max_bytes})"
        return None


@dataclass
class Scope:
    """Which ops and targets a session may touch. Empty sets mean "no restriction" for that dimension, except
    `ops`, which must always be given for agent sessions (the gateway passes the actor-side tool list)."""
    ops: frozenset[str] = frozenset()
    vaults: frozenset[str] = frozenset()
    path_prefixes: tuple[str, ...] = ()
    denied_ops: frozenset[str] = frozenset()

    def check(self, op: Op) -> str | None:
        if op.op in self.denied_ops:
            return f"operation {op.op} is never allowed in this scope"
        if self.ops and op.op not in self.ops:
            return f"operation {op.op} is out of scope"
        vault = op.args.get("vault")
        if self.vaults and vault is not None and vault not in self.vaults:
            return f"vault {vault} is out of scope"
        if self.path_prefixes:
            for key in ("path", "to", "root"):
                p = op.args.get(key)
                if p is not None and not any(p == pre.rstrip("/") or p.startswith(pre.rstrip("/") + "/")
                                             for pre in self.path_prefixes):
                    return f"path {p} is out of scope"
        return None


class KillSwitch:
    """Trips on `trip()`, on SIGUSR1 (if installed), or when `path` exists."""

    def __init__(self, path: str | os.PathLike | None = None):
        self.path = Path(path) if path else None
        self._event = threading.Event()
        self.reason = ""

    def trip(self, reason: str = "kill switch") -> None:
        if not self._event.is_set():
            self.reason = reason
            self._event.set()

    def install_signal(self, signum: int = signal.SIGUSR1) -> None:
        signal.signal(signum, lambda *_: self.trip(f"signal {signum}"))

    @property
    def tripped(self) -> bool:
        if not self._event.is_set() and self.path is not None and self.path.exists():
            self.trip(f"kill file {self.path}")
        return self._event.is_set()


@dataclass
class Guardrails:
    kill: KillSwitch = field(default_factory=KillSwitch)
    default_scope: Scope = field(default_factory=Scope)
    max_deadline_s: float = 120.0
    budgets: dict[str, Budget] = field(default_factory=dict)
    scopes: dict[str, Scope] = field(default_factory=dict)

    def set_session(self, session: str, budget: Budget | None = None, scope: Scope | None = None) -> None:
        self.budgets[session] = budget or Budget()
        if scope is not None:
            self.scopes[session] = scope

    def check(self, op: Op) -> str | None:
        if self.kill.tripped:
            return f"aborted: {self.kill.reason}"
        reason = self.scopes.get(op.session, self.default_scope).check(op)
        if reason:
            return reason
        return self.budgets.setdefault(op.session, Budget()).check()

    def charge(self, op: Op, nbytes: int = 0) -> None:
        b = self.budgets.setdefault(op.session, Budget())
        b.ops += 1
        b.bytes += nbytes

    def deadline(self, catalog_deadline: float) -> float:
        return min(catalog_deadline, self.max_deadline_s)
