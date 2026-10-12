"""Replayable overlap of FUSE sealing and HTTP uploads; no product fault injection lives in this module."""
from __future__ import annotations

import json
from pathlib import Path

from vhh import scheduler
from vhh.broker import IdentityBroker
from vhh.catalog import Catalog
from vhh.drivers import real
from vhh.engine import Engine, Session
from vhh.judges import Judges
from vhh.model import Op, Verdict
from vhh.provision import provision
from vhh.recorder import TraceWriter, read_trace
from vhh.redact import Redactor
from vhh.run import build_info
from vhh.seeds import fmt_seed, h64
from vhh.world import pentest_v1


class MagicJudges(Judges):
    """Every operation in this owned, uncontested workload must succeed and every transfer must have a hash."""

    def judge(self, ob):
        verdicts = super().judge(ob)
        if ob.result.outcome != "ok":
            verdicts.append(Verdict("workload", False, ob.op.seq, "magic workload operation did not succeed",
                                    "ok", ob.result.outcome, "product"))
        elif ob.op.op in ("fs.read", "fs.write") and not ob.result.bytes_sha256:
            verdicts.append(Verdict("integrity", False, ob.op.seq, "magic workload transfer has no integrity hash",
                                    classification="harness"))
        return verdicts


def plan(seed: int, sessions: int, rounds: int) -> tuple[Op, dict[str, list[Op]]]:
    if type(sessions) is not int or sessions < 2 or sessions > 64 or sessions % 2:
        raise ValueError("magic scenario requires an even session count between 2 and 64")
    if type(rounds) is not int or not 1 <= rounds <= 1000:
        raise ValueError("magic scenario requires 1..1000 rounds")
    root = f"/harness-magic-{seed:016x}"
    streams = {}
    for i in range(sessions):
        sid, surface = f"magic-{i:02d}", "ws" if i % 2 == 0 else "fuse"
        ops = []
        for n in range(rounds):
            path = f"{root}/r{n:04d}-s{i:02d}.bin"
            other = f"{root}/r{n:04d}-s{i ^ 1:02d}.bin"
            # A barrier seals every file before the opposite surface reads it. Writers never share a pathname.
            ops.extend([Op(-1, sid, "u-alice", surface, "fs.write",
                           {"vault": "v-alice", "path": path, "version": 1 + h64(seed, i, n) % 1000000}),
                        Op(-1, sid, "u-alice", surface, "fs.read", {"vault": "v-alice", "path": other})])
        streams[sid] = ops
    setup = Op(0, "magic-00", "u-alice", "ws", "fs.mkdir", {"vault": "v-alice", "path": root},
               intent="setup", barrier=-1)
    return setup, streams


def overlapping_writes(pairs) -> int:
    groups = {}
    for op, result in pairs:
        if op.op == "fs.write":
            groups.setdefault(op.barrier, []).append((op, result))
    return sum(any(a.surface != b.surface and max(ra.t0_ns, rb.t0_ns) < min(ra.t1_ns, rb.t1_ns)
                   for a, ra in group for b, rb in group) for group in groups.values())


async def run_magic(inst, seed: int, sessions: int = 8, rounds: int = 20) -> dict:
    setup, streams = plan(seed, sessions, rounds)
    red = inst.redactor
    if red is None:
        red = inst.redactor = Redactor()
    world, broker = pentest_v1(), IdentityBroker(red)
    binding = await provision(inst.target, world, broker, red)
    make = real.factory(inst, binding, world, broker, red)
    out = Path(inst.artifacts) / "magic"
    trace_path = out / "trace.jsonl"
    rec = TraceWriter(trace_path, red, {
        "scenario": "magic", "seed": fmt_seed(seed), "schedule": "barrier",
        "world": {"name": world.name, "world_hash": world.world_hash()},
        "build": build_info(), "sessions": sessions, "rounds": rounds,
        "replay_note": "barriers reproduce operation overlap, not internal libmagic interleavings"})
    engine = Engine(world, Catalog().restricted(real.SUPPORTED), broker, red, rec, judges=MagicJudges())
    overlap = 0
    expected = 1 + sessions * rounds * 2
    try:
        for sid, ops in streams.items():
            engine.add_session(Session(sid, "u-alice", ops[0].surface, make(ops[0].surface, "u-alice")))
        await engine.open_all()
        if not engine.failures:
            result = await engine.execute(engine.sessions[setup.session], setup)
            if result.outcome == "ok":
                await scheduler.run(engine, streams, seed, "barrier", batch=(sessions, sessions), start=1)
        if engine.counts["executed"] != expected:
            engine.fail(Verdict("workload", False, None, "magic workload did not execute every planned operation",
                                expected, engine.counts["executed"], "harness"))
        overlap = overlapping_writes(read_trace(trace_path).ops)
        if overlap == 0:
            engine.fail(Verdict("workload", False, None, "no HTTP/FUSE write overlap was observed",
                                classification="harness"))
    finally:
        await engine.close_all()
        rec.summary(engine.summary())
        rec.close()
    report = {"ok": engine.passed, "seed": fmt_seed(seed), "sessions": sessions, "rounds": rounds,
              "trace": str(trace_path), "overlapping_write_batches": overlap, **engine.summary(),
              "why": None if engine.passed else "magic workload failed; inspect trace verdicts",
              "replay": ["replay", "--target", "launch", "--build", inst.target.build_dir, "--trace", str(trace_path),
                         "--schedule", "barrier", "--repeat", "10", "--predicate", "any"]}
    (out / "summary.json").write_text(json.dumps(red.redact(report), indent=2))
    return report
