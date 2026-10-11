"""The engine: one path for every op, whoever decided it (seeded planner, external agent, replay).

execute(session, op): guardrails -> broker check -> driver (bounded by the op deadline) -> state effect -> trace ->
judges. Product behavior never raises out of here; a driver that raises is recorded as a harness failure. A run
passes only if it executed at least one op, was not aborted, and no judge failed.
"""
from __future__ import annotations

import asyncio
import itertools
import threading
import time
import traceback
from collections import Counter
from dataclasses import dataclass, field

from vhh.broker import IdentityBroker
from vhh.catalog import Catalog
from vhh.guardrails import Guardrails
from vhh.judges import Judges, Observation
from vhh.model import Op, Result, Verdict
from vhh.recorder import TraceWriter
from vhh.redact import Redactor
from vhh.state import Timeline
from vhh.world import World

DEADLINE_SLACK_S = 1.0     # the engine's own bound on top of the driver's deadline


@dataclass
class Session:
    id: str
    principal: str            # opaque world id (or "public:<share id>")
    surface: str
    driver: object            # vhh.drivers.base.Driver
    intent: str = "seeded"


@dataclass
class Engine:
    world: World
    catalog: Catalog
    broker: IdentityBroker
    redactor: Redactor
    recorder: TraceWriter | None = None
    guardrails: Guardrails = field(default_factory=Guardrails)
    grace_s: float = 2.0
    deadline_slack_s: float = DEADLINE_SLACK_S
    judges: Judges = field(default_factory=Judges)

    def __post_init__(self) -> None:
        self.timeline = Timeline(self.world)
        self.sessions: dict[str, Session] = {}
        self.failures: list[Verdict] = []
        self.counts: Counter = Counter()
        self.aborted: str | None = None
        self._seq = itertools.count(1_000_000)
        self._lock = threading.Lock()
        self._listeners: list = []

    # ------------------------------------------------------------------ sessions
    def add_session(self, s: Session) -> Session:
        if s.id in self.sessions:
            raise ValueError(f"duplicate session {s.id}")
        self.sessions[s.id] = s
        self.guardrails.set_session(s.id)
        return s

    async def open_all(self) -> None:
        for s in self.sessions.values():
            try:
                await s.driver.open()
            except Exception as e:  # noqa: BLE001
                self.fail(Verdict("harness", False, None, f"session {s.id}: driver open failed: {e!r}",
                                  classification="harness"))

    async def close_all(self) -> None:
        for s in self.sessions.values():
            try:
                await s.driver.close()
            except Exception as e:  # noqa: BLE001
                self.fail(Verdict("harness", False, None, f"session {s.id}: driver close failed: {e!r}",
                                  classification="harness"))

    # ------------------------------------------------------------------ verdicts
    def fail(self, v: Verdict) -> None:
        with self._lock:
            self.failures.append(v)
        if self.recorder:
            self.recorder.verdict(v)
        for fn in self._listeners:
            fn(v)

    def on_verdict(self, fn) -> None:
        self._listeners.append(fn)

    def abort(self, reason: str) -> None:
        if self.aborted is None:
            self.aborted = reason
            self.guardrails.kill.trip(reason)
            if self.recorder:
                self.recorder.event("aborted", reason=reason)

    @property
    def stopping(self) -> bool:
        if self.aborted is None and self.guardrails.kill.tripped:
            self.abort(self.guardrails.kill.reason)
        return self.aborted is not None

    def next_seq(self) -> int:
        return next(self._seq)

    # ------------------------------------------------------------------ the op path
    def _record(self, op: Op, result: Result) -> None:
        result.detail = self.redactor.redact_text(result.detail or "")
        if self.recorder:
            self.recorder.op(op, result)

    async def execute(self, session: Session, op: Op) -> Result:
        if op.seq < 0:
            op.seq = self.next_seq()
        try:
            spec = self.catalog.get(op.op)
        except KeyError as e:
            r = Result("blocked", str(e))
            self._record(op, r)
            if op.intent != "agent":
                self.fail(Verdict("harness", False, op.seq, f"plan contains unknown op {op.op}",
                                  classification="harness"))
            return r
        if self.stopping:
            r = Result("blocked", f"aborted: {self.aborted}")
            self._record(op, r)
            self.counts["blocked"] += 1
            return r
        reason = self.guardrails.check(op)
        if reason:
            self.counts["blocked"] += 1
            r = Result("blocked", reason)
            self._record(op, r)
            if self.guardrails.kill.tripped:
                self.abort(self.guardrails.kill.reason)
            return r
        missing = [f for f in spec.required if op.args.get(f) in (None, "")]
        if missing:
            # a malformed payload is a product-style refusal (invalid), never a harness crash
            r = Result("invalid", f"missing required field(s): {', '.join(missing)}", code=400)
            self._record(op, r)
            self.counts["executed"] += 1
            self.counts["outcome.invalid"] += 1
            return r
        if not self.broker.has(op.principal):
            r = Result("error", f"no credential for {op.principal}", data={"fault": "harness"})
            self._record(op, r)
            self.counts["harness_errors"] += 1
            self.fail(Verdict("harness", False, op.seq, f"missing secret: no credential for {op.principal} "
                              f"(session {session.id})", classification="harness"))
            return r

        deadline = self.guardrails.deadline(spec.deadline_s)
        v0 = self.timeline.version
        t0 = time.monotonic_ns()
        try:
            result = await asyncio.wait_for(session.driver.execute(op, deadline), deadline + self.deadline_slack_s)
            if not isinstance(result, Result):
                raise TypeError(f"driver returned {type(result).__name__}, not Result")
        except asyncio.TimeoutError:
            result = Result("timeout", f"no answer within {deadline + self.deadline_slack_s:.1f}s (engine bound)",
                            data={"fault": "unknown"})
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 - a raising driver is a harness defect, never a pass
            tb = traceback.format_exception_only(type(e), e)[-1].strip()
            result = Result("error", f"driver raised: {tb}", data={"fault": "harness"})
        t1 = time.monotonic_ns()
        result.t0_ns = result.t0_ns or t0
        result.t1_ns = result.t1_ns or t1
        v1 = self.timeline.version

        self.counts["executed"] += 1
        self.counts[f"outcome.{result.outcome}"] += 1
        if result.data.get("fault") == "harness":
            # A driver that could not do what was asked is a harness defect: it must fail the run, never pass it.
            self.counts["harness_errors"] += 1
            self.fail(Verdict("harness", False, op.seq, f"{op.op} on {op.surface}: harness fault: "
                              f"{self.redactor.redact_text(result.detail)[:200]}", classification="harness"))
        self.guardrails.charge(op, len(result.body or b""))
        if result.outcome == "ok" and spec.mutating:
            self.timeline.apply(op, result)

        ob = Observation(op, result, self.timeline.window(v0, v1), deadline,
                         self.timeline.grace(v0, t0, int(self.grace_s * 1e9)))
        try:
            verdicts = self.judges.judge(ob)
        except Exception as e:  # noqa: BLE001
            verdicts = [Verdict("harness", False, op.seq, f"judge raised: {e!r}", classification="harness")]
        result.data = self.redactor.redact(result.data)
        self._record(op, result)
        for v in verdicts:
            self.fail(v)
        return result

    async def quiesce(self) -> None:
        for v in self.judges.quiesce(self.timeline.current):
            self.fail(v)
        if self.recorder:
            self.recorder.event("quiesce", version=self.timeline.version)

    # ------------------------------------------------------------------ outcome
    @property
    def passed(self) -> bool:
        return self.aborted is None and self.counts["executed"] > 0 and not self.failures

    def summary(self) -> dict:
        by_judge = Counter(v.judge for v in self.failures)
        by_class = Counter(v.classification for v in self.failures)
        reasons = []
        if self.counts["executed"] == 0:
            reasons.append("zero ops executed")
        if self.aborted:
            reasons.append(f"aborted: {self.aborted}")
        if self.failures:
            reasons.append(f"{len(self.failures)} failing verdict(s)")
        return {"passed": self.passed, "verdict": "PASS" if self.passed else "FAIL", "reasons": reasons,
                "executed": self.counts["executed"], "blocked": self.counts["blocked"],
                "harness_errors": self.counts["harness_errors"], "failures_by_judge": dict(by_judge),
                "failures_by_class": dict(by_class), "checks": dict(self.judges.counts),
                "outcomes": {k[8:]: v for k, v in self.counts.items() if k.startswith("outcome.")},
                "aborted": self.aborted}
