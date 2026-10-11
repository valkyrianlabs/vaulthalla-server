"""One seeded run, end to end: world -> plan -> sessions -> schedule -> judges -> trace + summary.

`DriverFactory(surface, principal) -> Driver` is the only thing that differs between the simulator and a real private
instance, so every guarantee here (zero ops fails, aborts fail, harness errors fail) holds for both.
"""
from __future__ import annotations

import asyncio
import json
import os
import platform
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from vhh import planner, scheduler
from vhh.broker import IdentityBroker
from vhh.catalog import Catalog
from vhh.engine import Engine, Session
from vhh.guardrails import Guardrails, KillSwitch
from vhh.recorder import TraceWriter
from vhh.redact import Redactor
from vhh.seeds import fmt_seed
from vhh.world import World

DriverFactory = Callable[[str, str], object]


@dataclass
class RunConfig:
    seed: int
    profile: str = "smoke"
    schedule: str = "lockstep"
    sessions: int = 4
    ops_per_session: int = 25
    surfaces: tuple[str, ...] = ("ws",)
    batch: tuple[int, int] = (2, 8)
    cap: int = 16
    grace_s: float = 2.0
    quiesce_every: int = 0
    kill_file: str | None = None
    build: dict = field(default_factory=dict)


def build_info() -> dict:
    info = {"host": platform.node(), "python": platform.python_version()}
    try:
        info["git_commit"] = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                                            timeout=5, cwd=Path(__file__).parent).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        info["git_commit"] = None
    return info


@dataclass
class RunResult:
    summary: dict
    trace_path: Path | None
    engine: Engine

    @property
    def passed(self) -> bool:
        return bool(self.summary.get("passed"))


async def run_async(world: World, cfg: RunConfig, broker: IdentityBroker, redactor: Redactor,
                    drivers: DriverFactory, out_dir: str | os.PathLike | None, catalog: Catalog | None = None,
                    target: dict | None = None) -> RunResult:
    catalog = catalog or Catalog()
    plan = planner.make_plan(world, catalog, cfg.seed, cfg.sessions, cfg.ops_per_session, cfg.surfaces)
    trace_path = None
    recorder = None
    if out_dir is not None:
        trace_path = Path(out_dir) / "trace.jsonl"
        recorder = TraceWriter(trace_path, redactor, {
            "seed": fmt_seed(cfg.seed), "profile": cfg.profile, "schedule": cfg.schedule,
            "world": {"name": world.name, "seed": world.seed, "profile": world.profile,
                      "world_hash": world.world_hash()},
            "build": {**build_info(), **cfg.build}, "plan": plan.to_json(), "target": target or {},
            "replay_note": "replay reproduces the recorded op sequence and overlap, not the daemon's internal "
                           "thread interleavings"})
    engine = Engine(world, catalog, broker, redactor, recorder,
                    Guardrails(kill=KillSwitch(cfg.kill_file)), grace_s=cfg.grace_s)
    for s in plan.sessions:
        try:
            driver = drivers(s.surface, s.principal)
        except Exception as e:  # noqa: BLE001 - a driver that cannot be built fails the run, loudly
            from vhh.model import Verdict
            engine.fail(Verdict("harness", False, None, f"session {s.id}: cannot create {s.surface} driver: {e!r}",
                                classification="harness"))
            continue
        engine.add_session(Session(s.id, s.principal, s.surface, driver))
    streams = {sid: ops for sid, ops in plan.streams.items() if sid in engine.sessions}
    try:
        await engine.open_all()
        await scheduler.run(engine, streams, cfg.seed, cfg.schedule, batch=cfg.batch, cap=cfg.cap,
                            quiesce_every=cfg.quiesce_every)
    finally:
        await engine.close_all()
        summary = {"seed": fmt_seed(cfg.seed), "schedule": cfg.schedule, "world": world.name,
                   "world_hash": world.world_hash(), "planned": plan.total, **engine.summary()}
        if recorder:
            recorder.summary(summary)
            recorder.close()
            (Path(out_dir) / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True))
    return RunResult(summary, trace_path, engine)


def run(*args, **kwargs) -> RunResult:
    return asyncio.run(run_async(*args, **kwargs))


def new_run_dir(base: str | os.PathLike = "runs") -> Path:
    p = Path(base) / time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    n = 0
    while True:
        cand = p if n == 0 else p.with_name(f"{p.name}-{n}")
        try:
            cand.mkdir(parents=True)
            return cand
        except FileExistsError:
            n += 1
