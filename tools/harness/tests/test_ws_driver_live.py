"""Opt-in daemon proof, always launching its own private Instance (never attach to an existing installation).

Set VHH_WS_LIVE_BUILD to a build containing VH_TEST_MODE support and run as root with VH_TEST_DB_* loaded from
the harness db.env. Requires vhh.broker/redact/recorder from engine-core. See the workstream plan for the safe
sudo environment-loading command. With no VHH_WS_LIVE_BUILD this test is skipped.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import unittest
from pathlib import Path
from unittest.mock import patch

from vhh.drivers.cli_sock import CliSockDriver
from vhh.drivers.ws import WsDriver
from vhh.instance import Instance, mount_entry
from vhh.model import Op

from tools.lab.pentest.client import Target as NetTarget
from tools.lab.pentest.client import http_request


@unittest.skipUnless(os.environ.get("VHH_WS_LIVE_BUILD"), "set VHH_WS_LIVE_BUILD for a private daemon proof")
class PrivateDaemonTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        from vhh.broker import IdentityBroker
        from vhh.redact import Redactor

        if os.geteuid() != 0:
            raise RuntimeError("private daemon proof requires root")
        cls.redactor = Redactor()
        cls.broker = IdentityBroker(cls.redactor)
        cls.instance = Instance(Path(os.environ["VHH_WS_LIVE_BUILD"]), redactor=cls.redactor)
        cls.addClassCleanup(cls.stop_instance)
        # The coordination plan requires sourcing db.env in the sudo shell, never printing or parsing it here.
        keys = ("VH_TEST_DB_USER", "VH_TEST_DB_PASS", "VH_TEST_DB_HOST", "VH_TEST_DB_PORT")
        db = {key: os.environ[key] for key in keys}
        if db["VH_TEST_DB_USER"] != "vh_harness":
            raise RuntimeError("private proof requires the dedicated vh_harness database role")
        with patch("vhh.instance._read_env_file", return_value=db):
            cls.target = cls.instance.start()
        password = (cls.instance.backing / "super_admin_initial_password").read_text().strip()
        cls.broker.register("u-admin", "password", password, "admin")

    @classmethod
    def stop_instance(cls):
        report = cls.instance.stop()
        if cls.instance.alive() or mount_entry(cls.instance.mount) or cls.instance._db_created:
            raise AssertionError("private daemon cleanup incomplete")
        print("private WS proof cleanup: " + json.dumps(report, sort_keys=True))

    async def test_real_operations_authentication_cookie_and_trace(self):
        from vhh.broker import IdentityBroker
        from vhh.recorder import TraceWriter

        cli = CliSockDriver(self.target.cli_socket, None, redactor=self.redactor)
        await cli.open()
        self.addAsyncCleanup(cli.close)
        created = await cli.run_line(["vault", "create", "ws-driver-proof", "--local", "--owner", "admin"], 30)
        self.assertEqual(created.outcome, "ok", created.detail)
        info = await cli.run_line(["vault", "info", "ws-driver-proof", "--owner", "admin"], 10)
        self.assertEqual(info.outcome, "ok", info.detail)
        match = re.search(r"^ID:\s*(\d+)", info.data["stdout"], re.MULTILINE)
        self.assertIsNotNone(match, "private vault id missing from CLI info")
        vault_id = int(match.group(1))

        driver = WsDriver(self.target.ws_port, "u-admin", broker=self.broker)
        self.addAsyncCleanup(driver.close)
        await driver.open()
        self.assertEqual(driver.login_result.outcome, "ok")
        results = [driver.login_result]

        # The HTTP driver consumes this exact client API; the refresh cookie is never added to a Result/trace.
        cookie = driver.cookie_header()
        self.assertTrue(bool(cookie), "no refresh cookie after login")
        target = NetTarget("127.0.0.1", http_port=self.target.http_port)
        http = await asyncio.to_thread(http_request, target, "GET", "/auth/session", cookie=cookie, timeout=5)
        self.assertEqual(http.status, 200)
        self.assertTrue(http.json().get("ok"))
        no_cookie = await asyncio.to_thread(http_request, target, "GET", "/auth/session", timeout=5)
        self.assertNotEqual(no_cookie.status, 200)

        trace_path = self.instance.artifacts / "ws-driver.jsonl"
        trace = TraceWriter(trace_path, self.redactor, {"proof": "ws-driver"})
        self.addCleanup(trace.close)
        attempts = [
            ("fs.mkdir", "/source", {}),
            ("fs.list", "/", {}),
            ("fs.stat", "/source", {}),
            ("fs.rename", "/source", {"to": "/renamed"}),
            ("fs.copy", "/renamed", {"to": "/copied"}),
            ("fs.delete", "/renamed", {}),
            ("fs.delete", "/copied", {}),
        ]
        for seq, (name, path, extra) in enumerate(attempts, 1):
            op = Op(seq, "s-admin", "u-admin", "ws", name, {"vault": vault_id, "path": path, **extra})
            result = await driver.execute(op, 10)
            trace.op(op, result)
            results.append(result)
            self.assertEqual(result.outcome, "ok", f"{name}: {result.detail}")
            if name == "fs.list":
                self.assertIn("source", [entry["name"] for entry in result.data["files"]])
            if name == "fs.stat":
                self.assertEqual(result.data["entry"]["name"], "source")

        missing = await driver.execute(Op(8, "s-admin", "u-admin", "ws", "fs.stat",
                                         {"vault": vault_id, "path": "/renamed"}), 10)
        self.assertEqual(missing.outcome, "not_found")
        trace.close()
        raw = trace_path.read_text() + json.dumps([result.to_json() for result in results])
        secrets = [self.broker.credential("u-admin").secret(), driver.ws.token, cookie, *driver.ws.cookies.values()]
        for secret in secrets:
            # assertNotIn would print the secret on failure.
            self.assertFalse(bool(secret) and secret in raw, "secret reached a Result or trace")

        bad_broker = IdentityBroker(self.redactor)
        bad_broker.register("u-admin", "password", "intentionally-invalid-password", "admin")
        bad = WsDriver(self.target.ws_port, "u-admin", broker=bad_broker)
        self.addAsyncCleanup(bad.close)
        with self.assertRaises(RuntimeError):
            await bad.open()
        self.assertNotEqual(bad.login_result.outcome, "ok")
        self.assertIsNone(bad.ws)
        self.assertFalse(bool(bad.cookie_header()))

        anonymous = WsDriver(self.target.ws_port, None, redactor=self.redactor)
        self.addAsyncCleanup(anonymous.close)
        await anonymous.open()
        denied = await anonymous.execute(Op(9, "s-anon", "u-anon", "ws", "fs.list",
                                            {"vault": vault_id, "path": "/"}), 5)
        self.assertEqual(denied.outcome, "denied")
        await anonymous.close()
        await driver.close()
        await driver.close()
        self.assertFalse(bool(driver.cookie_header()))
        print("private WS proof: login, six bindings, refusal, HTTP cookie, redacted trace, close passed")


if __name__ == "__main__":
    unittest.main()
