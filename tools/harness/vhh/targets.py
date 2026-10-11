"""Target resolution and the fail-closed rule for destructive commands.

A destructive command (`run`, `replay`, `shrink`, `agent`) needs one of:
- `sim`: the in-memory simulated daemon (nothing real is touched), or
- a target descriptor (`target.json`, or the artifacts dir holding it) written by `vhh/instance.py` for a private
  local instance the engine itself launched, which must validate and whose daemon PID must be alive.
Anything else, including `vh-storage`, a hostname or a URL, is refused.

`Target` / `validate_target` come from `vhh/instance.py` (integrator-owned). Until it is merged, the stand-in below
uses the same names and fields; the integrator reconciles on merge.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, fields
from pathlib import Path

try:  # pragma: no cover - depends on the integrator branch
    from vhh.instance import Target, validate_target  # type: ignore
except ImportError:
    @dataclass
    class Target:  # stand-in with the integrator's field names
        kind: str
        run_id: str
        pid: int
        server: str
        db_name: str
        run_dir: str
        mount: str
        backing: str
        cli_socket: str
        ws_port: int
        http_port: int
        artifacts: str

        @classmethod
        def load(cls, path: str | os.PathLike) -> "Target":
            d = json.loads(Path(path).read_text())
            known = {f.name for f in fields(cls)}
            missing = known - set(d)
            if missing:
                raise ValueError(f"target descriptor missing fields: {sorted(missing)}")
            return cls(**{k: d[k] for k in known})

    def validate_target(t: "Target") -> str | None:
        if t.kind != "vhh-private-local":
            return f"target kind {t.kind!r} is not a private local instance"
        for name in ("run_dir", "mount", "backing", "cli_socket", "artifacts"):
            p = os.path.normpath(str(getattr(t, name)))
            if not p.startswith("/tmp/"):
                return f"target {name} {p!r} is not under /tmp/"
        if not str(t.db_name).startswith("vh_harness_"):
            return f"target database {t.db_name!r} is not a per-run harness database"
        for name in ("ws_port", "http_port"):
            if not isinstance(getattr(t, name), int) or not 0 < getattr(t, name) < 65536:
                return f"target {name} is not a port"
        return None

REFUSED_NAMES = {"vh-storage", "vh-local", "production", "prod"}


class TargetRefused(RuntimeError):
    pass


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(int(pid), 0)
        return True
    except (ProcessLookupError, ValueError, TypeError):
        return False
    except PermissionError:
        return True   # exists, owned by another user (the daemon may run as root)


def _load(path: Path) -> "Target":
    if hasattr(Target, "load"):
        return Target.load(path)
    return Target(**json.loads(path.read_text()))


def resolve(spec: str | None) -> tuple[str, "Target | None"]:
    """('sim', None) or ('private', Target). Raises TargetRefused with the reason otherwise."""
    if not spec:
        raise TargetRefused("no target given (use --target sim or a target.json written by the launcher)")
    if spec == "sim":
        return "sim", None
    low = spec.lower()
    if low in REFUSED_NAMES or "vh-storage" in low or "://" in spec or "@" in spec:
        raise TargetRefused(f"target {spec!r} is not a private instance launched by this engine: refused")
    p = Path(spec)
    if p.is_dir():
        p = p / "target.json"
    if not p.is_file():
        raise TargetRefused(f"unknown target {spec!r}: not 'sim' and no target descriptor there: refused")
    try:
        t = _load(p)
    except (ValueError, TypeError, json.JSONDecodeError, OSError) as e:
        raise TargetRefused(f"unreadable target descriptor {p}: {e}") from e
    reason = validate_target(t)
    if reason:
        raise TargetRefused(f"target {p}: {reason}: refused")
    if not _pid_alive(getattr(t, "pid", 0)):
        raise TargetRefused(f"target {p}: daemon pid {getattr(t, 'pid', None)} is not running: refused")
    return "private", t
