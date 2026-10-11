"""Engine, planner and scheduler against the simulated daemon."""
import asyncio
import unittest

from tests.helpers import Rig, pentest
from vhh import planner, scheduler
from vhh.catalog import Catalog
from vhh.model import Op
from vhh.worldgen import generate


class FaithfulSimPasses(unittest.TestCase):
    def _run(self, world, schedule, surfaces=("ws", "fuse", "http")):
        rig = Rig(world)
        cat = Catalog()
        plan = planner.make_plan(world, cat, seed=7, n_sessions=5, ops_per_session=30, surfaces=surfaces)
        for s in plan.sessions:
            rig.session(s.principal, s.surface, s.id)
        asyncio.run(scheduler.run(rig.engine, plan.streams, 7, schedule))
        return rig

    def test_every_schedule_is_clean_on_a_faithful_sim(self):
        for schedule in scheduler.SCHEDULES:
            for world in (pentest(), generate(42, "pressure")):
                rig = self._run(world, schedule)
                self.assertTrue(rig.engine.passed, f"{world.name}/{schedule}: {[v.message for v in rig.engine.failures]}")
                self.assertGreater(rig.engine.counts["executed"], 0)
                self.assertGreater(rig.engine.judges.counts["oracle.checked"], 0)


class Reproducibility(unittest.TestCase):
    def test_same_seed_same_plan(self):
        w = pentest()
        a = planner.make_plan(w, Catalog(), 123, 4, 20, ("ws", "fuse"))
        b = planner.make_plan(w, Catalog(), 123, 4, 20, ("ws", "fuse"))
        self.assertEqual(a.to_json(), b.to_json())
        self.assertEqual([(o.op, o.args) for o in a.streams["s00"]], [(o.op, o.args) for o in b.streams["s00"]])
        c = planner.make_plan(w, Catalog(), 124, 4, 20, ("ws", "fuse"))
        self.assertNotEqual(a.to_json(), c.to_json())

    def test_counter_based_streams_are_independent(self):
        # op k's args depend only on (seed, session, k): truncating the stream keeps the prefix identical
        w = pentest()
        full = [o for o in planner.make_plan(w, Catalog(), 5, 3, 30, ("ws",)).streams["s01"] if o.intent != "setup"]
        short = [o for o in planner.make_plan(w, Catalog(), 5, 3, 10, ("ws",)).streams["s01"] if o.intent != "setup"]
        self.assertEqual(len(short), 10)
        self.assertEqual([(o.op, o.args) for o in full[:10]], [(o.op, o.args) for o in short])

    def test_sessions_create_their_namespace_first(self):
        # Creates inside /<session> must never precede the namespace itself (POSIX ENOENT over FUSE).
        plan = planner.make_plan(pentest(), Catalog(), 9, 3, 12, ("fuse",))
        for sid, ops in plan.streams.items():
            self.assertEqual((ops[0].op, ops[0].args["path"], ops[0].intent), ("fs.mkdir", f"/{sid}", "setup"))


class Determinism(unittest.TestCase):
    def test_lockstep_run_is_reproducible(self):
        def summary():
            rig = Rig(pentest())
            cat = Catalog()
            plan = planner.make_plan(rig.world, cat, 9, 4, 25, ("ws", "fuse"))
            for s in plan.sessions:
                rig.session(s.principal, s.surface, s.id)
            asyncio.run(scheduler.run(rig.engine, plan.streams, 9, "lockstep"))
            return rig.engine.summary()
        self.assertEqual(summary(), summary())


class Isolation(unittest.TestCase):
    def test_driver_that_raises_is_a_harness_failure_not_a_pass(self):
        from vhh.sim import Plants
        rig = Rig(pentest(), plants=Plants(raise_ops={"fs.read"}))
        s = rig.session("u-alice", "ws")
        r = rig.do(s, "fs.read", vault="v-alice", path="/README.md")
        self.assertEqual(r.outcome, "error")
        self.assertEqual(r.data.get("fault"), "harness")
        self.assertFalse(rig.engine.passed)
        self.assertIn("harness", rig.judges_of())

    def test_zero_ops_executed_is_a_failure(self):
        rig = Rig(pentest())
        self.assertFalse(rig.engine.passed)
        self.assertIn("zero ops executed", rig.engine.summary()["reasons"])

    def test_unknown_op_in_plan_fails_the_run(self):
        rig = Rig(pentest())
        s = rig.session("u-alice", "ws")
        asyncio.run(rig.engine.execute(s, Op(1, s.id, "u-alice", "ws", "fs.teleport", {})))
        self.assertFalse(rig.engine.passed)


if __name__ == "__main__":
    unittest.main()
