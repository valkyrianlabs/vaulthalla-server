"""Replay a trace window and shrink a failing one.

Replay re-issues the recorded ops (same sessions, principals, surfaces, canonical args) through a fresh engine, in
lockstep (recorded seq order) or barrier mode (recorded barriers, or groups of ops whose recorded time intervals
overlapped). It reproduces the op sequence and which ops were in flight together; it does NOT reproduce the
daemon's internal thread interleavings (use a TSan build or rr for those).

Shrink is ddmin: first over sessions, then over ops, keeping a failure predicate.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from vhh.engine import Engine
from vhh.model import Op, Result, Verdict
from vhh.recorder import Trace

NOTE = ("replay reproduces the recorded op sequence and overlap, not the daemon's internal thread interleavings")

# engine factory: returns a fresh engine with one Session per session id it is asked for
EngineFactory = Callable[[list[Op]], Engine]
Predicate = Callable[[Engine], bool]


def parse_window(text: str | None) -> tuple[int | None, int | None]:
    if not text:
        return None, None
    lo, _, hi = text.partition("..")
    return (int(lo) if lo else None), (int(hi) if hi else None)


def window(trace: Trace, lo: int | None = None, hi: int | None = None) -> list[tuple[Op, Result]]:
    # Setup ops (session namespaces, the contested directory) always come along: a window replayed into a fresh
    # world needs the directories its ops write into.
    out = [(o, r) for o, r in trace.ops if r.outcome != "blocked"
           and (o.intent == "setup" or ((lo is None or o.seq >= lo) and (hi is None or o.seq <= hi)))]
    return sorted(out, key=lambda x: x[0].seq)


def batches(pairs: list[tuple[Op, Result]], mode: str) -> list[list[Op]]:
    if mode == "lockstep":
        return [[o] for o, _ in pairs]
    if mode != "barrier":
        raise ValueError(f"replay supports lockstep|barrier, not {mode!r}")
    if pairs and all(o.barrier is not None for o, _ in pairs):
        groups: dict[int, list[Op]] = {}
        for o, _ in pairs:
            groups.setdefault(o.barrier, []).append(o)
        return [groups[b] for b in sorted(groups)]
    # free-mode trace: group by overlapping recorded intervals, one op per session per group
    out: list[list[Op]] = []
    end = -1
    for o, r in sorted(pairs, key=lambda x: (x[1].t0_ns, x[0].seq)):
        if out and r.t0_ns < end and o.session not in {x.session for x in out[-1]}:
            out[-1].append(o)
            end = max(end, r.t1_ns)
        else:
            out.append([o])
            end = r.t1_ns
    return out


def _fresh(op: Op) -> Op:
    return Op(op.seq, op.session, op.principal, op.surface, op.op, dict(op.args), "replay", list(op.causes),
              op.barrier)


async def execute(factory: EngineFactory, ops: list[Op], mode: str) -> Engine:
    """Run ops prepared by assign_barriers: lockstep ops one at a time, barrier ops batch by batch."""
    engine = factory(ops)
    await engine.open_all()
    try:
        for group in _groups(ops) if mode == "barrier" else [[o] for o in ops]:
            if engine.stopping:
                break
            await asyncio.gather(*(engine.execute(engine.sessions[o.session], _fresh(o)) for o in group))
        await engine.quiesce()
    finally:
        await engine.close_all()
        teardown = getattr(engine, "teardown", None)   # launched targets: stop the per-attempt instance
        if teardown is not None:
            await asyncio.to_thread(teardown)
    return engine


def _groups(ops: list[Op]) -> list[list[Op]]:
    groups: dict[int, list[Op]] = {}
    for o in ops:
        groups.setdefault(o.barrier if o.barrier is not None else o.seq, []).append(o)
    return [groups[k] for k in sorted(groups)]


def assign_barriers(pairs: list[tuple[Op, Result]], mode: str) -> list[Op]:
    """Fix the batch structure once (from the recording), so shrinking keeps the original overlap."""
    out = []
    for b, group in enumerate(batches(pairs, mode)):
        for o in group:
            fo = _fresh(o)
            fo.barrier = b if mode == "barrier" else None
            out.append(fo)
    return out


@dataclass
class ReplayReport:
    mode: str
    ops: int
    repeat: int
    reproduced: int = 0
    runs: list[dict] = field(default_factory=list)
    note: str = NOTE

    def to_json(self) -> dict:
        return vars(self)


async def replay(factory: EngineFactory, pairs: list[tuple[Op, Result]], mode: str, repeat: int,
                 predicate: Predicate) -> ReplayReport:
    ops = assign_barriers(pairs, mode)
    rep = ReplayReport(mode, len(ops), repeat)
    if not ops:
        rep.runs.append({"error": "empty window: nothing to replay"})
        return rep
    for i in range(repeat):
        engine = await execute(factory, ops, mode)
        hit = predicate(engine)
        rep.reproduced += int(hit)
        rep.runs.append({"run": i, "reproduced": hit, "failures": [v.message for v in engine.failures[:5]]})
    return rep


# ------------------------------------------------------------------------------------------------ shrinking

async def ddmin(items: list, test: Callable[[list], Awaitable[bool]]) -> list:
    """Zeller's ddmin: a 1-minimal subset of `items` for which `test` still returns True."""
    if not await test(items):
        raise ValueError("the full input does not reproduce the failure")
    n = 2
    while len(items) >= 2:
        chunk = max(1, len(items) // n)
        subsets = [items[i:i + chunk] for i in range(0, len(items), chunk)]
        reduced = False
        for s in subsets:
            if await test(s):
                items, n, reduced = s, 2, True
                break
        if not reduced:
            for i in range(len(subsets)):
                comp = [x for j, s in enumerate(subsets) if j != i for x in s]
                if await test(comp):
                    items, n, reduced = comp, max(n - 1, 2), True
                    break
        if not reduced:
            if n >= len(items):
                break
            n = min(len(items), n * 2)
    return items


async def shrink(factory: EngineFactory, pairs: list[tuple[Op, Result]], mode: str, predicate: Predicate,
                 attempts: int = 1) -> list[Op]:
    ops = assign_barriers(pairs, mode)

    async def reproduces(subset: list[Op]) -> bool:
        if not subset:
            return False
        for _ in range(attempts):
            if predicate(await execute(factory, sorted(subset, key=lambda o: o.seq), mode)):
                return True
        return False

    sessions = sorted({o.session for o in ops})
    keep = set(await ddmin(sessions, lambda ss: reproduces([o for o in ops if o.session in set(ss)])))
    ops = [o for o in ops if o.session in keep]
    return sorted(await ddmin(ops, reproduces), key=lambda o: o.seq)


# ------------------------------------------------------------------------------------------------ predicates

_ALIASES = {"canary_trip": "canary", "wedge": "liveness:timeout", "crash": "liveness:crash"}


def predicate(spec: str) -> Predicate:
    """'canary|wedge|oracle' -> True when the engine recorded a failure of any listed kind ('any' = any failure)."""
    wanted = [_ALIASES.get(p.strip(), p.strip()) for p in spec.split("|") if p.strip()]
    if not wanted:
        raise ValueError("empty predicate")

    def match(v: Verdict, w: str) -> bool:
        judge, _, outcome = w.partition(":")
        return (judge == "any" or v.judge == judge) and (not outcome or v.actual == outcome)

    return lambda engine: any(match(v, w) for v in engine.failures for w in wanted)
