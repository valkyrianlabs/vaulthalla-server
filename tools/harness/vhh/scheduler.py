"""Schedules: lockstep (one op at a time, seeded global order), barrier (seeded batches released together, then a
barrier), free (every session as fast as it can, under a concurrency cap; the interleaving is recorded, not
controlled). All three stop as soon as the engine is aborted."""
from __future__ import annotations

import asyncio
import itertools

from vhh.engine import Engine
from vhh.model import Op
from vhh.seeds import rng

SCHEDULES = ("lockstep", "barrier", "free")


async def run_lockstep(engine: Engine, streams: dict[str, list[Op]], seed: int, quiesce_every: int = 0,
                       start: int = 0) -> None:
    queues = {sid: list(ops) for sid, ops in streams.items()}
    for step in itertools.count():
        live = sorted(sid for sid, q in queues.items() if q)
        if not live or engine.stopping:
            break
        sid = live[rng(seed, "sched", step).randrange(len(live))]
        op = queues[sid].pop(0)
        op.seq = start + step
        await engine.execute(engine.sessions[sid], op)
        if quiesce_every and (step + 1) % quiesce_every == 0:
            await engine.quiesce()


async def run_barrier(engine: Engine, streams: dict[str, list[Op]], seed: int, batch: tuple[int, int] = (2, 8),
                      quiesce_every: int = 0, start: int = 0) -> None:
    queues = {sid: list(ops) for sid, ops in streams.items()}
    seq = start
    for b in itertools.count():
        live = sorted(sid for sid, q in queues.items() if q)
        if not live or engine.stopping:
            break
        r = rng(seed, "batch", b)
        k = min(len(live), r.randint(*batch))
        chosen = sorted(r.sample(live, k))      # at most one op per session per batch keeps per-session order
        ops = []
        for sid in chosen:
            op = queues[sid].pop(0)
            op.seq, op.barrier = seq, b
            seq += 1
            ops.append(op)
        await asyncio.gather(*(engine.execute(engine.sessions[o.session], o) for o in ops))
        if quiesce_every and (b + 1) % quiesce_every == 0:
            await engine.quiesce()


async def run_free(engine: Engine, streams: dict[str, list[Op]], cap: int = 16, start: int = 0) -> None:
    sem = asyncio.Semaphore(max(1, cap))
    counter = itertools.count(start)

    async def session(sid: str, ops: list[Op]) -> None:
        for op in ops:
            if engine.stopping:
                return
            async with sem:
                op.seq = next(counter)
                await engine.execute(engine.sessions[sid], op)

    await asyncio.gather(*(session(sid, ops) for sid, ops in sorted(streams.items())))


async def run(engine: Engine, streams: dict[str, list[Op]], seed: int, schedule: str, *,
              batch: tuple[int, int] = (2, 8), cap: int = 16, quiesce_every: int = 0, start: int = 0) -> None:
    """`start`: the first sequence number to assign (a setup phase runs before the main one)."""
    if schedule == "lockstep":
        await run_lockstep(engine, streams, seed, quiesce_every, start)
    elif schedule == "barrier":
        await run_barrier(engine, streams, seed, batch, quiesce_every, start)
    elif schedule == "free":
        await run_free(engine, streams, cap, start)
    else:
        raise ValueError(f"unknown schedule {schedule!r} (want one of {SCHEDULES})")
    await engine.quiesce()
