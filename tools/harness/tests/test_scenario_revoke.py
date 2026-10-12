from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from vhh.drivers.real import Binding
from vhh.model import Result
from vhh.redact import Redactor
from vhh.scenario_revoke import run_revoke


class RevokeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.inst = SimpleNamespace(target=SimpleNamespace(cli_socket="/tmp/vhh_test/cli.sock"), redactor=Redactor())
        self.inst.redactor.register_secret("private-test-password")
        self.phase = "before"
        self.mode = ""
        self.ops = []
        self.drivers = []
        self.after = 0

        def make(surface, principal):
            async def execute(op, deadline):
                self.ops.append(op)
                if principal == "u-alice":
                    return Result("ok")
                if self.mode in ("timeout", "disconnected", "error"):
                    return Result(self.mode)
                if self.phase == "before":
                    return Result("denied")
                if self.phase == "granted":
                    return Result("denied" if self.mode == "no-grant" else "ok")
                self.after += 1
                stale = self.mode == "stale" or (self.mode == "unstable" and self.after >= 5)
                return Result("ok" if stale and surface == "fuse" else "denied")
            d = SimpleNamespace(open=AsyncMock(), close=AsyncMock(), execute=AsyncMock(side_effect=execute))
            self.drivers.append(d)
            return d

        async def command(argv, deadline):
            if argv[2] == "assign":
                self.phase = "granted"
                return Result("error" if self.mode == "assign-fails" else "ok")
            self.phase = "revoked"
            return Result("error" if self.mode == "revoke-fails" else "ok")

        self.admin = SimpleNamespace(open=AsyncMock(), close=AsyncMock(), run_line=AsyncMock(side_effect=command))
        self.enterContext(patch("vhh.scenario_revoke.CliSockDriver", return_value=self.admin))
        self.factory = self.enterContext(patch("vhh.scenario_revoke.real.factory", return_value=make))
        binding = Binding(principals={"u-eve": {"username": "pt_eve"}, "u-alice": {"username": "pt_alice"}})
        self.provision = self.enterContext(patch("vhh.scenario_revoke.provision", AsyncMock(return_value=binding)))
        self.enterContext(patch("vhh.scenario_revoke.PROPAGATION_S", .04))
        self.enterContext(patch("vhh.scenario_revoke.POLL_S", .001))

    async def test_grant_revoke_and_three_stable_probes(self):
        report = await run_revoke(self.inst)
        self.assertTrue(report["ok"], report)
        self.assertIsNone(report["why"])
        for key in ("grant_latency_s", "revoke_latency_s"):
            self.assertGreaterEqual(report[key], 0)
            self.assertLess(report[key], .04)
        stable = [s for s in report["steps"] if s["phase"].startswith("stable-revoke")]
        self.assertEqual(len(stable), 6)
        for op in self.ops:
            self.assertEqual(op.args, {"vault": "v-team", "path": "/restricted"})
        self.assertEqual(self.admin.run_line.call_args_list[0].args[0],
                         ["vault", "role", "assign", "pt-team-shared", "reader", "-u", "pt_eve", "--owner", "pt_alice"])
        self.assertEqual(self.admin.run_line.call_args_list[1].args[0][2], "unassign")
        for d in self.drivers:
            d.open.assert_awaited_once()
            d.close.assert_awaited_once()

    async def test_stale_authorization_must_fail(self):
        self.mode = "stale"
        report = await run_revoke(self.inst)
        self.assertFalse(report["ok"])
        self.assertIn("after-revoke", report["why"])

    async def test_revocation_that_regresses_after_first_denial_fails(self):
        self.mode = "unstable"
        report = await run_revoke(self.inst)
        self.assertFalse(report["ok"])
        self.assertIn("remain effective", report["why"])

    async def test_grant_does_not_propagate_is_cleaned(self):
        self.mode = "no-grant"
        report = await run_revoke(self.inst)
        self.assertFalse(report["ok"])
        self.assertEqual(report["steps"][-1]["phase"], "cleanup-unassign")
        self.assertEqual(self.phase, "revoked")

    async def test_transport_errors_are_never_authorization_denials(self):
        for mode in ("error", "timeout", "disconnected"):
            self.mode = mode
            report = await run_revoke(self.inst)
            self.assertFalse(report["ok"])
            self.assertIn("not an authorization answer", report["why"])
        self.admin.run_line.assert_not_awaited()

    async def test_failed_provision_is_not_a_pass_and_suppresses_secret(self):
        self.provision.side_effect = RuntimeError("private-test-password")
        report = await run_revoke(self.inst)
        self.assertFalse(report["ok"])
        self.assertNotIn("private-test-password", str(report))
        self.factory.assert_not_called()

    async def test_failed_auth_closes_partial_sessions(self):
        make = self.factory.return_value
        def fail_auth(surface, principal):
            driver = make(surface, principal)
            if surface == "ws" and principal == "u-eve":
                driver.open.side_effect = RuntimeError("private-test-password")
            return driver
        self.factory.return_value = fail_auth
        report = await run_revoke(self.inst)
        self.assertFalse(report["ok"])
        self.assertNotIn("private-test-password", str(report))
        self.assertFalse(self.ops)
        for driver in self.drivers:
            driver.close.assert_awaited_once()

    async def test_failed_assignment_still_attempts_scoped_cleanup(self):
        self.mode = "assign-fails"
        report = await run_revoke(self.inst)
        self.assertFalse(report["ok"])
        self.assertEqual(self.admin.run_line.await_count, 2)
        self.assertEqual(report["steps"][-1]["phase"], "cleanup-unassign")

    async def test_failed_revoke_and_cleanup_fail_loudly(self):
        self.mode = "revoke-fails"
        report = await run_revoke(self.inst)
        self.assertFalse(report["ok"])
        self.assertIn("cleanup failed", report["why"])
        self.assertEqual(self.admin.run_line.await_count, 3)
