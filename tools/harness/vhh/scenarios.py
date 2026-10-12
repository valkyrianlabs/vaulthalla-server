"""Fault scenarios that need no patched build: the daemon hangs or dies while a FUSE request is in flight.

The scenario passes when the engine *detects and contains* the failure: the in-flight op ends within its deadline
(timeout + wedge for a hang, a disconnect for a crash), evidence is captured, only this run's FUSE connection is
aborted, and the instance still tears down (mount gone, database dropped). A hang that blocked the engine, or a
crash it reported as success, fails the scenario.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import time
from pathlib import Path

from vhh.drivers.fuse import FuseDriver
from vhh.instance import Instance, mount_entry
from vhh.model import Op


async def _in_flight(inst: Instance, kind: str, deadline_s: float) -> dict:
    t = inst.target
    actor = FuseDriver(Path(t.build_dir) / "core" / "vh_fs_actor", t.mount, t.admin_uid, t.admin_uid,
                       supervisor=inst, kill_grace_s=2.0)
    await actor.open()
    warm = await actor.execute(Op(0, "x", "admin", "fuse", "fs.list", {"path": "/"}), deadline_s)
    if warm.outcome != "ok":
        return {"ok": False, "why": f"warm-up listing failed: {warm.outcome} {warm.detail}"}
    pid = inst.proc.pid
    op = Op(1, "x", "admin", "fuse", "fs.list", {"path": "/"})
    if kind == "hang":
        os.kill(pid, signal.SIGSTOP)
        t0 = time.monotonic()
        res = await actor.execute(op, deadline_s)
        took = time.monotonic() - t0
        os.kill(pid, signal.SIGCONT)
        ok = res.outcome == "timeout" and took < deadline_s + 10
        return {"ok": ok, "outcome": res.outcome, "wedge": bool(res.data.get("wedge")), "took_s": round(took, 2),
                "why": "" if ok else f"expected a bounded timeout, got {res.outcome} after {took:.1f}s"}
    # crash: the daemon dies outright; its auto_unmount tears the mount down and in-flight requests fail
    task = asyncio.create_task(actor.execute(op, deadline_s))
    await asyncio.sleep(0.05)
    os.kill(pid, signal.SIGKILL)
    t0 = time.monotonic()
    res = await task
    took = time.monotonic() - t0
    after = await actor.execute(Op(2, "x", "admin", "fuse", "fs.list", {"path": "/"}), deadline_s)
    await actor.close()
    ok = (not inst.alive()) and after.outcome != "ok" and took < deadline_s + 10
    return {"ok": ok, "outcome": res.outcome, "after": after.outcome, "took_s": round(took, 2),
            "why": "" if ok else f"crash not contained: in-flight {res.outcome}, next {after.outcome}"}


def run(kind: str, build: str, out: Path, deadline_s: float = 4.0) -> tuple[bool, dict]:
    out.mkdir(parents=True, exist_ok=True)
    inst = Instance(Path(build), artifacts=out / "instance")
    inst.start()
    report: dict = {"scenario": kind, "run_id": inst.run_id}
    try:
        with inst.watchdog(deadline_s * 6 + 30) as dog:
            report.update(asyncio.run(_in_flight(inst, kind, deadline_s)))
        if dog.fired:
            report.update(ok=False, why="engine blocked past its hard deadline; watchdog aborted the FUSE connection")
        report["evidence"] = sorted(str(p) for p in (inst.artifacts / "evidence").glob("*")) \
            if (inst.artifacts / "evidence").exists() else []
        if kind == "hang" and report.get("wedge") and not report["evidence"]:
            report["ok"], report["why"] = False, "wedge reported without evidence"
        report["died"] = not inst.alive()
    except Exception as e:  # noqa: BLE001 - a scenario that raises is a failed scenario, never a pass
        report.update(ok=False, why=f"scenario raised: {e!r}")
    finally:
        stop = inst.stop()
        report["stop"] = stop
        report["mount_gone"] = mount_entry(inst.mount) is None
        report["db_dropped"] = stop.get("db_dropped", False)
    ok = bool(report.get("ok")) and report["mount_gone"] and report["db_dropped"]
    if kind == "crash":
        ok = ok and report.get("died", False)
    (out / "scenario.json").write_text(json.dumps(report, indent=2, default=str))
    return ok, report
