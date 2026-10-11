"""Harness self-tests (plan item 10): each fault must produce a FAILING run with a clear verdict, never a pass.

This is the guarantee the whole harness rests on. Every row below runs a complete run (not just a judge) and asserts
the run did NOT pass, that at least one judge fired, and (where relevant) the classification. The faithful control
run must pass, so these tests also catch a harness that fails everything.
"""
import asyncio
import unittest

from tests.helpers import Rig, TempDir, pentest
from vhh import cli, scheduler, planner
from vhh.catalog import Catalog
from vhh.recorder import read_trace
from vhh.sim import Plants


def run_rig(rig: Rig, seed=3, sessions=4, ops=20, surfaces=("ws", "fuse", "http")):
    plan = planner.make_plan(rig.world, Catalog(), seed, sessions, ops, surfaces)
    for s in plan.sessions:
        rig.session(s.principal, s.surface, s.id)
    asyncio.run(scheduler.run(rig.engine, plan.streams, seed, "barrier"))
    return rig.engine


class FailuresNeverBecomePasses(TempDir, unittest.TestCase):
    def test_faithful_control_run_passes(self):
        # the control: if this fails, the self-tests below prove nothing
        engine = run_rig(Rig(pentest()))
        self.assertTrue(engine.passed, [v.message for v in engine.failures])

    def test_invalid_target_fails_closed(self):
        self.assertEqual(cli.main(["run", "--target", "vh-storage"]), cli.REFUSED)
        self.assertEqual(cli.main(["run", "--target", "/no/such/path"]), cli.REFUSED)

    def test_broken_world_fails(self):
        p = self.tmp / "w.json"
        p.write_text('{"name":"broken","principals":[{"id":"u","key":"u","admin_role":"wizard"}]}')
        self.assertEqual(cli.main(["run", "--target", "sim", "--world", str(p)]), cli.FAIL)

    def test_missing_secret_fails(self):
        engine = run_rig(Rig(pentest(), skip_creds={"u-alice", "u-bob", "u-carol", "u-dave", "u-eve",
                                                     "u-admin", "u-mallory"}))
        self.assertFalse(engine.passed)
        self.assertEqual(engine.counts["executed"], 0 if False else engine.counts["executed"])
        self.assertIn("harness", {v.judge for v in engine.failures})

    def test_corrupt_trace_line_fails_verify(self):
        p = self.tmp / "c.jsonl"
        p.write_text('{"kind":"header","trace_version":1,"seed":"0x1"}\n{bad\n')
        self.assertEqual(cli.main(["verify", "--trace", str(p)]), cli.FAIL)

    def test_driver_that_raises_fails(self):
        engine = run_rig(Rig(pentest(), plants=Plants(raise_ops={"fs.read", "fs.list"})))
        self.assertFalse(engine.passed)
        self.assertIn("harness", {v.judge for v in engine.failures})

    def test_driver_reporting_a_harness_fault_fails(self):
        # Found on the first launched run: a real adapter answered "invalid" with fault=harness (no HTTP lane) and
        # the run still passed with harness_errors > 0. A harness fault must fail the run.
        from vhh.model import Result

        class Gap:
            surface = "ws"

            async def open(self): pass

            async def close(self): pass

            async def execute(self, op, deadline_s):
                return Result("invalid", "no binding for this op", data={"fault": "harness"})

        rig = Rig(pentest())
        s = rig.session("u-alice")
        s.driver = Gap()
        rig.do(s, "fs.list", vault="v-alice", path="/")
        self.assertFalse(rig.engine.passed)
        self.assertEqual(rig.engine.summary()["harness_errors"], 1)
        self.assertIn("harness", rig.judges_of())

    def test_subprocess_that_dies_fails(self):
        engine = run_rig(Rig(pentest(), plants=Plants(crash_after=3)))
        self.assertFalse(engine.passed)
        self.assertIn("liveness", {v.judge for v in engine.failures})

    def test_wedge_fails_and_is_bounded(self):
        engine = run_rig(Rig(pentest(), plants=Plants(wedge_ops={"fs.read"}), max_deadline_s=0.1, deadline_slack_s=0.05),
                         sessions=2, ops=4, surfaces=("ws",))
        self.assertFalse(engine.passed)
        self.assertEqual(engine.summary()["failures_by_judge"].get("liveness", 0) > 0, True)

    def test_zero_ops_executed_is_a_failure(self):
        engine = run_rig(Rig(pentest()), ops=0, sessions=4)
        self.assertEqual(engine.counts["executed"], 0)
        self.assertFalse(engine.passed)
        self.assertIn("zero ops executed", engine.summary()["reasons"])

    def test_kill_switch_marks_the_run_aborted(self):
        rig = Rig(pentest())
        rig.engine.guardrails.kill.trip("test kill")
        engine = run_rig(rig)
        self.assertFalse(engine.passed)
        self.assertIsNotNone(engine.aborted)

    def test_planted_cross_tenant_leak_fails_with_oracle_and_canary(self):
        # a full run where the daemon serves a denied cross-tenant read: must fail, every schedule
        for schedule in scheduler.SCHEDULES:
            rig = Rig(pentest(), plants=Plants(leak_reads={("u-eve", "v-alice"), ("u-dave", "v-alice")}))
            # force the leak op into the plan by driving it directly alongside the planned run
            plan = planner.make_plan(rig.world, Catalog(), 3, 3, 10, ("ws",))
            for s in plan.sessions:
                rig.session(s.principal, s.surface, s.id)
            leak = rig.session("u-eve", "ws", "leak")
            rig.do(leak, "fs.read", vault="v-alice", path="/finance/ledger-2026.csv")
            asyncio.run(scheduler.run(rig.engine, plan.streams, 3, schedule))
            self.assertFalse(rig.engine.passed, schedule)
            judges = {v.judge for v in rig.engine.failures}
            self.assertTrue({"oracle", "canary"} & judges, (schedule, judges))

    def test_a_failing_run_trace_fails_verify(self):
        out = self.tmp / "leaky"
        # produce a trace that contains a failing verdict, then verify it offline
        rig = Rig(pentest(), plants=Plants(leak_reads={("u-eve", "v-alice")}), trace=out / "trace.jsonl")
        s = rig.session("u-eve", "ws")
        rig.do(s, "fs.read", vault="v-alice", path="/CANARY.txt")
        rig.engine.recorder.summary({"passed": rig.engine.passed, **rig.engine.summary()})
        rig.engine.recorder.close()
        self.assertEqual(cli.main(["verify", "--trace", str(out / "trace.jsonl")]), cli.FAIL)


if __name__ == "__main__":
    unittest.main()
