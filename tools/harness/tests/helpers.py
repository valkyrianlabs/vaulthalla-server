"""Test helpers: an engine wired to the simulated daemon, plus a scratch directory."""
from __future__ import annotations

import asyncio
import shutil
import tempfile
from functools import lru_cache
from pathlib import Path

from vhh import world as W
from vhh.broker import IdentityBroker
from vhh.catalog import Catalog
from vhh.engine import Engine, Session
from vhh.guardrails import Guardrails
from vhh.model import Op
from vhh.recorder import TraceWriter
from vhh.redact import Redactor
from vhh.sim import Plants, SimDaemon, SimDriver


@lru_cache(maxsize=1)
def _pentest() -> W.World:
    return W.pentest_v1()


def pentest() -> W.World:
    return _pentest().copy()


class Rig:
    """Engine + simulator. `ops` are executed one at a time unless run concurrently by the caller."""

    def __init__(self, world: W.World | None = None, plants: Plants | None = None, grace_s: float = 0.0,
                 trace: Path | None = None, skip_creds: set[str] = frozenset(), max_deadline_s: float = 120.0,
                 deadline_slack_s: float = 1.0):
        self.world = world or pentest()
        self.redactor = Redactor()
        self.broker = IdentityBroker(self.redactor)
        self.broker.register_canaries(self.world.canaries)
        self.sim = SimDaemon(self.world, plants)
        self.sim.register_credentials(self.broker, skip=set(skip_creds))
        rec = TraceWriter(trace, self.redactor, {"seed": "0x0", "world": {"name": self.world.name}}) if trace else None
        self.engine = Engine(self.world, Catalog(), self.broker, self.redactor, rec,
                             Guardrails(max_deadline_s=max_deadline_s), grace_s=grace_s,
                             deadline_slack_s=deadline_slack_s)
        self._n = 0

    def session(self, principal: str, surface: str = "ws", sid: str | None = None) -> Session:
        sid = sid or f"t{len(self.engine.sessions):02d}"
        return self.engine.add_session(Session(sid, principal, surface, SimDriver(surface, self.sim, self.broker)))

    def op(self, session: Session, op: str, **args) -> Op:
        self._n += 1
        return Op(self._n, session.id, session.principal, session.surface, op, args)

    def do(self, session: Session, op: str, **args):
        return asyncio.run(self.engine.execute(session, self.op(session, op, **args)))

    def judges_of(self) -> set[str]:
        return {v.judge for v in self.engine.failures}


class TempDir:
    def setUp(self):  # noqa: N802 - unittest mixin
        self.tmp = Path(tempfile.mkdtemp(prefix="vhh-test-"))

    def tearDown(self):  # noqa: N802
        shutil.rmtree(self.tmp, ignore_errors=True)
