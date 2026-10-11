"""Replay and shrink: a recorded failure reproduces, and ddmin cuts it to a minimal op set."""
import asyncio
import unittest

from tests.helpers import pentest
from vhh import replay as R
from vhh.broker import IdentityBroker
from vhh.catalog import Catalog
from vhh.engine import Engine, Session
from vhh.model import Op, Result
from vhh.redact import Redactor
from vhh.sim import Plants, SimDaemon, SimDriver


def _pairs(ops):
    t = 0
    out = []
    for o in ops:
        out.append((o, Result("ok", t0_ns=t, t1_ns=t + 1)))
        t += 2
    return out


def _factory(plants):
    def make(ops):
        w = pentest()
        red = Redactor()
        broker = IdentityBroker(red)
        broker.register_canaries(w.canaries)
        sim = SimDaemon(w, plants)
        sim.register_credentials(broker)
        engine = Engine(w, Catalog(), broker, red)
        for sid in sorted({o.session for o in ops}):
            o = next(x for x in ops if x.session == sid)
            engine.add_session(Session(sid, o.principal, o.surface, SimDriver(o.surface, sim, broker)))
        return engine
    return make


class Replay(unittest.TestCase):
    def test_leak_read_reproduces_every_time(self):
        ops = [Op(i, "s0", "u-eve", "ws", "fs.list", {"vault": "v-team", "path": "/"}) for i in range(3)]
        ops.append(Op(3, "s0", "u-eve", "ws", "fs.read", {"vault": "v-alice", "path": "/CANARY.txt"}))
        rep = asyncio.run(R.replay(_factory(Plants(leak_reads={("u-eve", "v-alice")})), _pairs(ops), "lockstep",
                                   5, R.predicate("canary")))
        self.assertEqual(rep.reproduced, 5)
        self.assertIn("not the daemon's internal thread interleavings", rep.note)

    def test_empty_window_is_not_a_reproduction(self):
        rep = asyncio.run(R.replay(_factory(Plants()), [], "lockstep", 3, R.predicate("any")))
        self.assertEqual(rep.reproduced, 0)
        self.assertEqual(rep.ops, 0)

    def test_barrier_grouping_from_free_trace(self):
        # overlapping intervals (same t-window, different sessions) group together
        a = Op(0, "s0", "u-alice", "ws", "fs.list", {"vault": "v-alice", "path": "/"})
        b = Op(1, "s1", "u-bob", "ws", "fs.list", {"vault": "v-bob", "path": "/"})
        c = Op(2, "s0", "u-alice", "ws", "fs.list", {"vault": "v-alice", "path": "/"})
        pairs = [(a, Result("ok", t0_ns=0, t1_ns=10)), (b, Result("ok", t0_ns=5, t1_ns=15)),
                 (c, Result("ok", t0_ns=20, t1_ns=30))]
        groups = R.batches(pairs, "barrier")
        self.assertEqual([sorted(o.session for o in g) for g in groups], [["s0", "s1"], ["s0"]])


class Shrink(unittest.TestCase):
    def test_shrink_keeps_only_the_failing_op(self):
        noise = [Op(i, f"s{i}", "u-alice", "ws", "fs.list", {"vault": "v-alice", "path": "/"}) for i in range(6)]
        culprit = Op(99, "s9", "u-eve", "ws", "fs.read", {"vault": "v-alice", "path": "/CANARY.txt"})
        ops = noise[:3] + [culprit] + noise[3:]
        minimal = asyncio.run(R.shrink(_factory(Plants(leak_reads={("u-eve", "v-alice")})), _pairs(ops), "lockstep",
                                       R.predicate("canary")))
        self.assertEqual([o.op for o in minimal], ["fs.read"])
        self.assertEqual(minimal[0].principal, "u-eve")

    def test_shrink_requires_the_failure_to_be_present(self):
        ops = [Op(i, "s0", "u-alice", "ws", "fs.list", {"vault": "v-alice", "path": "/"}) for i in range(3)]
        with self.assertRaises(ValueError):
            asyncio.run(R.shrink(_factory(Plants()), _pairs(ops), "lockstep", R.predicate("canary")))


class Ddmin(unittest.TestCase):
    def test_ddmin_finds_a_minimal_pair(self):
        async def test(items):
            return {3, 7}.issubset(set(items))
        self.assertEqual(sorted(asyncio.run(R.ddmin(list(range(10)), test))), [3, 7])


if __name__ == "__main__":
    unittest.main()
