"""Core value types shared by every part of the engine. Pure data: no I/O here."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

# Surfaces an operation can be bound to.
SURFACES = ("cli_sock", "cli_bin", "ws", "http", "share", "fuse", "admin")

# Normalized outcome of one operation, whatever the surface. Refusal mappings (errno, ws code, HTTP status, CLI exit)
# collapse into these so cross-surface parity can be judged.
OUTCOMES = ("ok", "denied", "not_found", "conflict", "invalid", "needs_confirmation", "error", "timeout",
            "disconnected", "crash")


@dataclass
class Op:
    """One operation attempt. `args` are canonical (catalog field names, opaque world ids), never secrets."""
    seq: int
    session: str
    principal: str            # opaque world id, e.g. "u-carol"
    surface: str              # one of SURFACES
    op: str                   # catalog id, e.g. "fs.write"
    args: dict[str, Any] = field(default_factory=dict)
    intent: str = "seeded"    # "seeded" | "agent" | "replay" | "provision"
    causes: list[int] = field(default_factory=list)   # seqs this op depends on (causal links)
    barrier: int | None = None

    def to_json(self) -> dict:
        return asdict(self)


@dataclass
class Result:
    outcome: str                         # one of OUTCOMES
    detail: str = ""                     # short, redacted
    code: str | int | None = None        # surface-native code (errno, ws data.code, HTTP status, exit code)
    data: dict[str, Any] = field(default_factory=dict)   # small structured payload (ids, listings), redacted
    rendered: str = ""                   # the request actually sent (CLI line, ws command, syscall), redacted
    bytes_sha256: str | None = None      # content read/written, for integrity checks
    t0_ns: int = 0
    t1_ns: int = 0

    def to_json(self) -> dict:
        return asdict(self)


@dataclass
class Verdict:
    """A judge's finding about one op or a quiesce point."""
    judge: str                 # "oracle" | "parity" | "canary" | "integrity" | "invariant" | "liveness" | "harness"
    ok: bool
    seq: int | None
    message: str
    expected: Any = None
    actual: Any = None
    classification: str = "unknown"   # "product" | "oracle" | "harness" | "unknown"

    def to_json(self) -> dict:
        return asdict(self)
