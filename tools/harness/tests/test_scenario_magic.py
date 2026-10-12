from __future__ import annotations

import asyncio
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from vhh.cli import _launched_engine_factory
from vhh.model import Op
from vhh.recorder import read_trace
from vhh.redact import Redactor
from vhh.replay import assign_barriers, predicate
from vhh.scenario_magic import plan, run_magic
from vhh.sim import Plants, SimDaemon, SimDriver
from vhh.world import pentest_v1


class MagicTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.inst = SimpleNamespace(artifacts=Path(self.tmp), target=SimpleNamespace(build_dir="/private/build"),
                                    redactor=Redactor())
        self.plants = Plants()

        async def provision(target, world, broker, red):
            broker.register_canaries(world.canaries)
            self.daemon = SimDaemon(world, self.plants)
            self.daemon.register_credentials(broker)

        def factory(instance, binding, world, broker, red):
            def make(surface, principal):
                d = SimDriver(surface, self.daemon, broker)
                execute = d.execute
                async def delayed(op, deadline):
                    start = time.time_ns()
                    await asyncio.sleep(.001)
                    result = await execute(op, deadline)
                    result.t0_ns, result.t1_ns = start, time.time_ns()
                    return result
                d.execute = delayed
                return d
            return make

        self.enterContext(patch("vhh.scenario_magic.provision", side_effect=provision))
        self.enterContext(patch("vhh.scenario_magic.real.factory", side_effect=factory))

    def test_plan_is_reproducible_and_reads_cross_surface_after_writes(self):
        setup, streams = plan(197, 4, 3)
        self.assertEqual((setup, streams), plan(197, 4, 3))
        self.assertNotEqual(streams, plan(198, 4, 3)[1])
        self.assertEqual(setup.intent, "setup")
        self.assertEqual(setup.barrier, -1)
        for n in range(3):
            writes = {ops[2 * n].args["path"]: ops[2 * n].surface for ops in streams.values()}
            for ops in streams.values():
                read = ops[2 * n + 1]
                self.assertNotEqual(writes[read.args["path"]], read.surface)

    def test_invalid_parameters_are_refused(self):
        for sessions, rounds in ((1, 1), (3, 1), (66, 1), (4, 0), (4, 1001)):
            with self.assertRaises(ValueError):
                plan(1, sessions, rounds)

    async def test_workload_trace_integrity_overlap_and_replay_batches(self):
        report = await run_magic(self.inst, 197, 4, 3)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["executed"], 25)
        self.assertEqual(report["overlapping_write_batches"], 3)
        self.assertEqual(report["checks"]["integrity.checked"], 24)
        trace = read_trace(report["trace"])
        ops = assign_barriers(trace.ops, "barrier")
        self.assertEqual(ops[0].op, "fs.mkdir")
        self.assertEqual(len({o.barrier for o in ops}), 7)
        raw = Path(report["trace"]).read_text()
        self.assertEqual(raw, self.inst.redactor.redact_text(raw))
        self.assertTrue(trace.summary["passed"])

    async def test_corrupt_reads_fail_and_record_replayable_evidence(self):
        self.plants.corrupt_reads = True
        report = await run_magic(self.inst, 197, 4, 2)
        self.assertFalse(report["ok"])
        trace = read_trace(report["trace"])
        self.assertTrue(any(v.judge == "integrity" for v in trace.verdicts))
        self.assertFalse(trace.summary["passed"])
        self.assertEqual(len(trace.ops), 17)

    async def test_crash_never_reports_success(self):
        self.plants.crash_after = 3
        report = await run_magic(self.inst, 197, 4, 2)
        self.assertFalse(report["ok"])
        self.assertGreater(report["failures_by_judge"].get("liveness", 0), 0)

    async def test_failed_provision_does_not_create_a_passing_trace(self):
        with (patch("vhh.scenario_magic.provision", AsyncMock(side_effect=RuntimeError("failed"))),
              self.assertRaises(RuntimeError)):
            await run_magic(self.inst, 1, 4, 2)
        self.assertFalse((Path(self.tmp) / "magic" / "trace.jsonl").exists())


class ReplayDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.artifacts = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def test_surviving_sanitizer_finding_is_a_replay_failure(self):
        inst = Mock()
        inst.artifacts = self.artifacts
        inst.alive.return_value = True
        inst.stop.return_value = {"stop": "clean", "returncode": 0, "db_dropped": True}
        inst.sanitizer_reports.return_value = ["/private/artifacts/tsan.123"]
        args = SimpleNamespace(build="/private/build", catalog=None, _scenario="magic")
        with (patch("vhh.instance.Instance", return_value=inst),
              patch("vhh.provision.provision", AsyncMock()),
              patch("vhh.drivers.real.factory", return_value=Mock())):
            engine = _launched_engine_factory(pentest_v1(), args)([
                Op(0, "s", "u-alice", "ws", "fs.list", {"vault": "v-alice", "path": "/"})])
            engine.teardown()
        self.assertTrue(predicate("sanitizer")(engine))
        self.assertTrue(predicate("any")(engine))
        self.assertEqual(engine.artifacts, str(self.artifacts))
        self.assertTrue((self.artifacts / "instance.json").is_file())
        inst.stop.assert_called_once()

    def test_crashed_daemon_or_unclean_teardown_fail_replay(self):
        for alive, stop in [(False, {"returncode": -11, "db_dropped": True}),
                            (True, {"stop": "clean", "returncode": 0, "db_dropped": False})]:
            inst = Mock()
            inst.artifacts = self.artifacts
            inst.alive.return_value = alive
            inst.stop.return_value = stop
            inst.sanitizer_reports.return_value = []
            with (patch("vhh.instance.Instance", return_value=inst),
                  patch("vhh.provision.provision", AsyncMock()),
                  patch("vhh.drivers.real.factory", return_value=Mock())):
                engine = _launched_engine_factory(pentest_v1(), SimpleNamespace(build="/b", catalog=None))([])
                engine.teardown()
            self.assertTrue(predicate("any")(engine))


class ScenarioEnvelopeTests(unittest.TestCase):
    def test_sanitizer_or_bad_teardown_fails_even_when_workload_passed(self):
        from contextlib import nullcontext

        from vhh.scenarios import run
        for reports, stop in [(["/private/asan.123"], {"stop": "clean", "returncode": 0, "db_dropped": True}),
                              ([], {"stop": "forced", "returncode": -9, "db_dropped": True})]:
            with tempfile.TemporaryDirectory() as tmp:
                inst = Mock(artifacts=Path(tmp), mount=Path(tmp) / "mnt", run_id="test")
                inst.watchdog.return_value = nullcontext(SimpleNamespace(fired=False))
                inst.alive.return_value = True
                inst.stop.return_value = stop
                inst.sanitizer_reports.return_value = reports
                with (patch("vhh.scenarios.Instance", return_value=inst),
                      patch("vhh.scenario_magic.run_magic", AsyncMock(return_value={"ok": True})),
                      patch("vhh.scenarios.mount_entry", return_value=None)):
                    ok, report = run("magic", "/private/build", Path(tmp))
                self.assertFalse(ok)
                self.assertFalse(report["ok"])
                inst.stop.assert_called_once()

    def test_startup_failure_is_cleaned_and_exception_text_is_suppressed(self):
        from vhh.scenarios import run
        with tempfile.TemporaryDirectory() as tmp:
            inst = Mock(artifacts=Path(tmp), mount=Path(tmp) / "mnt", run_id="test")
            inst.start.side_effect = RuntimeError("private-password")
            inst.stop.return_value = {"db_dropped": True}
            inst.sanitizer_reports.return_value = []
            with (patch("vhh.scenarios.Instance", return_value=inst),
                  patch("vhh.scenarios.mount_entry", return_value=None)):
                ok, report = run("magic", "/private/build", Path(tmp))
            self.assertFalse(ok)
            self.assertNotIn("private-password", str(report))
            inst.stop.assert_called_once()
