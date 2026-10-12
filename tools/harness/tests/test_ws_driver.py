"""WS driver boundary tests. Run with PYTHONPATH=tools/harness:. python -m unittest discover -s tools/harness/tests."""
from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, Mock, patch

from vhh.drivers.ws import WsDriver, classify
from vhh.model import Op
from websockets.exceptions import ConnectionClosedError

from tools.lab.pentest.client import Ws, http_request


class ClassificationTests(unittest.TestCase):
    def test_existing_classifications(self):
        cases = [
            ({"status": "SUCCESS"}, ("ok", "SUCCESS")),
            ({"status": "ready"}, ("ok", "READY")),
            ({"status": "UNAUTHORIZED"}, ("denied", "unauthorized")),
            *[({"status": "ERROR", "data": {"code": code}}, (code, code))
              for code in ("denied", "not_found", "invalid", "conflict")],
            ({"status": "ERROR", "data": {"code": "user_delete"}}, ("needs_confirmation", "user_delete")),
            ({"status": "ERROR", "error": "Permission denied"}, ("denied", "ERROR")),
            ({"status": "ERROR", "error": "Path does not exist"}, ("not_found", "ERROR")),
            ({"status": "ERROR", "error": "other fault"}, ("error", "ERROR")),
        ]
        for msg, expected in cases:
            with self.subTest(msg=msg):
                self.assertEqual(classify(msg), expected)


class WsDriverTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Mock precisely the published IdentityBroker / Credential / Redactor interfaces. Real implementations
        # are exercised by test_ws_driver_live once the engine-core workstream is on the import path.
        self.secrets = set()
        self.redactor = Mock(spec=["register_secret", "redact_text", "redact"])
        self.redactor.register_secret.side_effect = lambda value: self.secrets.add(value) if value else None
        self.redactor.redact_text.side_effect = self.redact_text
        self.redactor.redact.side_effect = self.redact
        self.credential = Mock(kind="password", username="test-user", spec=["kind", "username", "secret"])
        self.credential.secret.return_value = "test-password-12345"
        self.broker = Mock(redactor=self.redactor, spec=["credential", "redactor"])
        self.broker.credential.return_value = self.credential
        self.ws = Mock(spec=Ws)
        self.ws.token = ""
        self.ws.cookies = {"refresh": "test-refresh-cookie"}
        self.ws.conn = Mock()
        self.ws.__aenter__ = AsyncMock(return_value=self.ws)
        self.ws.__aexit__ = AsyncMock()
        self.ws.send = AsyncMock(return_value={"status": "SUCCESS", "data": {}})
        self.ws.cookie_header.side_effect = lambda: "; ".join(f"{k}={v}" for k, v in self.ws.cookies.items())
        self.factory = self.enterContext(patch("vhh.drivers.ws.Ws", return_value=self.ws))
        self.driver = WsDriver(43123, "u-test", broker=self.broker)
        self.addAsyncCleanup(self.driver.close)

    def redact_text(self, text):
        for value in sorted(self.secrets, key=len, reverse=True):
            text = text.replace(value, "[REDACTED]")
        return text

    def redact(self, obj):
        if isinstance(obj, dict):
            return {self.redact_text(k): "[REDACTED]" if k.lower() in
                    {"password", "token", "cookie", "authorization", "secret"} else self.redact(v)
                    for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.redact(v) for v in obj]
        return self.redact_text(obj) if isinstance(obj, str) else obj

    def op(self, name="fs.list", **args):
        return Op(1, "s-test", "u-test", "ws", name, {"vault": 7, "path": "/", **args})

    def assert_timed(self, result):
        self.assertGreater(result.t0_ns, 0)
        self.assertGreaterEqual(result.t1_ns, result.t0_ns)

    async def test_open_authenticates_and_registers_before_send(self):
        async def login(command, payload, timeout):
            self.assertIn(payload["password"], self.secrets)
            self.assertIn("test-refresh-cookie", self.secrets)
            self.ws.token = "test-access-token"
            return {"status": "SUCCESS", "token": self.ws.token, "data": {"user": {"id": 12}}}

        self.ws.send.side_effect = login
        await self.driver.open()
        self.factory.assert_called_once_with(self.driver.target, path="/ws", user_agent="vhh/1")
        self.assertEqual(self.driver.target.hostname, "127.0.0.1")
        self.assertEqual(self.driver.target.ws_port, 43123)
        self.ws.__aenter__.assert_awaited_once()
        self.broker.credential.assert_called_once_with("u-test")
        self.ws.send.assert_awaited_once_with("auth.login", {"name": "test-user", "password": "test-password-12345"},
                                             timeout=15.0)
        self.assertEqual(self.driver.login_result.outcome, "ok")
        self.assertEqual(self.driver.login_result.data, {"user": {"id": 12}})
        self.assertIn("test-access-token", self.secrets)
        self.assert_timed(self.driver.login_result)
        raw = json.dumps(self.driver.login_result.to_json())
        for secret in self.secrets:
            self.assertNotIn(secret, raw)

    async def test_open_is_idempotent(self):
        await self.driver.open()
        await self.driver.open()
        self.ws.__aenter__.assert_awaited_once()
        self.ws.send.assert_awaited_once()

    async def test_anonymous_session_skips_broker_and_login(self):
        self.driver.principal = None
        await self.driver.open()
        self.broker.credential.assert_not_called()
        self.ws.send.assert_not_awaited()
        self.assertIsNone(self.driver.login_result)

    async def test_authentication_failure_closes_and_preserves_typed_result(self):
        self.ws.send.return_value = {"status": "ERROR", "error": "Login refused", "data": {"code": "denied"}}
        with self.assertRaisesRegex(RuntimeError, "open failed: denied"):
            await self.driver.open()
        self.assertEqual(self.driver.login_result.code, "denied")
        self.assertIsNone(self.driver.ws)
        self.assertEqual(self.driver.cookie_header(), "")
        self.ws.__aexit__.assert_awaited_once()
        self.assertEqual((await self.driver.execute(self.op(), 1)).outcome, "disconnected")

    async def test_missing_credential_and_wrong_kind_clean_up_without_sending(self):
        for mode in ("missing", "wrong_kind", "empty_password", "missing_broker"):
            with self.subTest(mode=mode):
                self.broker.credential.side_effect = LookupError("private credential text") if mode == "missing" else None
                self.credential.kind = "session" if mode == "wrong_kind" else "password"
                self.credential.secret.return_value = "" if mode == "empty_password" else "test-password-12345"
                self.driver.broker = None if mode == "missing_broker" else self.broker
                with self.assertRaisesRegex(RuntimeError, "open failed: error") as caught:
                    await self.driver.open()
                self.assertNotIn("private credential text", str(caught.exception))
                self.assertIsNone(self.driver.ws)
        self.ws.send.assert_not_awaited()
        self.assertEqual(self.ws.__aexit__.await_count, 4)

    async def test_partial_enter_failure_is_closed(self):
        self.ws.__aenter__.side_effect = OSError("secret in handshake")
        with self.assertRaisesRegex(RuntimeError, "open failed: disconnected"):
            await self.driver.open()
        self.ws.__aexit__.assert_awaited_once()
        self.assertNotIn("secret in handshake", json.dumps(self.driver.login_result.to_json()))

    async def test_enter_failure_before_connection(self):
        self.ws.conn = None
        self.ws.__aenter__.side_effect = ConnectionRefusedError()
        with self.assertRaises(RuntimeError):
            await self.driver.open()
        await self.driver.close()
        self.ws.__aexit__.assert_not_awaited()

    async def test_login_timeout_cleans_up(self):
        self.ws.send.side_effect = TimeoutError()
        with self.assertRaisesRegex(RuntimeError, "open failed: timeout"):
            await self.driver.open()
        self.assertEqual(self.driver.login_result.outcome, "timeout")
        self.ws.__aexit__.assert_awaited_once()

    async def test_all_filesystem_bindings_and_success_data(self):
        await self.driver.open()
        cases = [
            ("fs.list", "fs.dir.list", {}, {"vault_id": 7, "path": "/source"}),
            ("fs.delete", "fs.entry.delete", {}, {"vault_id": 7, "path": "/source"}),
            ("fs.mkdir", "fs.dir.create", {}, {"vault_id": 7, "path": "/source"}),
            ("fs.stat", "fs.metadata", {}, {"vault_id": 7, "path": "/source"}),
            ("fs.rename", "fs.entry.rename", {"to": "/dest"}, {"vault_id": 7, "from": "/source", "to": "/dest"}),
            ("fs.copy", "fs.entry.copy", {"to": "/dest"}, {"vault_id": 7, "from": "/source", "to": "/dest"}),
        ]
        for name, command, extra, payload in cases:
            with self.subTest(op=name):
                data = {"files": [{"name": "one"}], "path": "/source"}
                self.ws.send.return_value = {"status": "SUCCESS", "data": data}
                op = self.op(name, path="/source", **extra)
                before = op.to_json()
                result = await self.driver.execute(op, 2)
                self.ws.send.assert_awaited_with(command, payload, timeout=2)
                self.assertEqual(result.outcome, "ok")
                self.assertEqual(result.code, "SUCCESS")
                self.assertEqual(result.data, data)
                self.assertEqual(json.loads(result.rendered.split(" ", 1)[1]), payload)
                self.assertEqual(op.to_json(), before)
                self.assert_timed(result)

    async def test_resolved_vault_id_and_default_root(self):
        await self.driver.open()
        op = self.op(vault="opaque-vault", vault_id=42)
        del op.args["path"]
        self.assertEqual((await self.driver.execute(op, 1)).outcome, "ok")
        self.ws.send.assert_awaited_with("fs.dir.list", {"vault_id": 42, "path": "/"}, timeout=1)

    async def test_server_refusals(self):
        await self.driver.open()
        for code in ("denied", "not_found", "conflict", "invalid", "user_delete"):
            with self.subTest(code=code):
                self.ws.send.return_value = {"status": "ERROR", "data": {"code": code}, "error": "refusal"}
                result = await self.driver.execute(self.op(), 1)
                self.assertEqual(result.outcome, "needs_confirmation" if code == "user_delete" else code)
                self.assertEqual(result.code, code)
                self.assertEqual(result.detail, "refusal")
                self.assertIs(self.driver.ws, self.ws)

    async def test_invalid_and_unsupported_operations_never_send(self):
        await self.driver.open()
        self.ws.send.reset_mock()
        ops = [self.op("fs.read"), self.op("fs.write"), self.op("auth.login"), self.op("made.up"),
               self.op("fs.rename"), self.op(vault="unresolved-vault"), self.op(vault=True), self.op(vault=-1),
               self.op(vault=2 ** 32), self.op(path=None), self.op(path="/null\0path"), self.op(password="secret")]
        for op in ops:
            with self.subTest(op=op.op, args=op.args):
                result = await self.driver.execute(op, 1)
                self.assertEqual(result.outcome, "invalid")
                self.assert_timed(result)
        self.ws.send.assert_not_awaited()

    async def test_wrong_session_or_surface_never_send(self):
        await self.driver.open()
        self.ws.send.reset_mock()
        for field, value in (("principal", "u-other"), ("surface", "http")):
            op = self.op()
            setattr(op, field, value)
            self.assertEqual((await self.driver.execute(op, 1)).outcome, "invalid")
        self.ws.send.assert_not_awaited()

    async def test_invalid_and_expired_deadlines_never_send(self):
        await self.driver.open()
        self.ws.send.reset_mock()
        for deadline in (float("inf"), float("nan"), True, "1"):
            self.assertEqual((await self.driver.execute(self.op(), deadline)).outcome, "invalid")
        for deadline in (0, -1):
            self.assertEqual((await self.driver.execute(self.op(), deadline)).outcome, "timeout")
        self.ws.send.assert_not_awaited()

    async def test_total_deadline_aborts_without_waiting_for_close_handshake(self):
        await self.driver.open()
        cancelled = asyncio.Event()

        async def slow_send(*args, **kwargs):
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        self.ws.send.side_effect = slow_send
        self.ws.__aexit__.side_effect = slow_send
        with patch("vhh.drivers.ws._CLOSE_TIMEOUT_S", 0.15):
            result = await asyncio.wait_for(self.driver.execute(self.op(), 0.01), timeout=0.1)
            self.assertEqual(result.outcome, "timeout")
            self.assertTrue(cancelled.is_set())
            self.assertIsNone(self.driver.ws)
            self.ws.conn.transport.abort.assert_called()
            await self.driver.close()
        self.assert_timed(result)

    async def test_disconnections_are_typed_and_secrets_in_exceptions_suppressed(self):
        for exc in (ConnectionClosedError(None, None), ConnectionResetError("secret close reason"), EOFError()):
            with self.subTest(kind=type(exc).__name__):
                self.ws.send.side_effect = None
                await self.driver.open()
                self.ws.send.side_effect = exc
                result = await self.driver.execute(self.op(), 1)
                self.assertEqual(result.outcome, "disconnected")
                self.assertNotIn("secret close reason", result.detail)
                await self.driver.close()

    async def test_malformed_responses_are_errors(self):
        for msg in ([], {}, {"status": "SUCCESS", "data": []}, {"status": "ERROR", "data": {"code": []}}):
            self.ws.send.return_value = {"status": "SUCCESS", "data": {}}
            await self.driver.open()
            self.ws.send.return_value = msg
            self.assertEqual((await self.driver.execute(self.op(), 1)).outcome, "error")
            await self.driver.close()

    async def test_cookie_passes_directly_to_http_transport(self):
        await self.driver.open()
        with patch("tools.lab.pentest.client.http.client.HTTPConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.getheaders.return_value = []
            response.read.return_value = b'{"ok":true}'
            self.driver.target.http_port = 43124
            http_request(self.driver.target, "GET", "/auth/session", cookie=self.driver.cookie_header())
            self.assertEqual(connection.return_value.request.call_args.kwargs["headers"]["Cookie"],
                             "refresh=test-refresh-cookie")
        self.assertNotIn("test-refresh-cookie", json.dumps(self.driver.login_result.to_json()))

    async def test_redacts_results_rendering_rotated_tokens_and_nested_data(self):
        await self.driver.open()

        async def response(*args, **kwargs):
            self.ws.token = 'rotated-token-"\\-value'
            return {"status": "ERROR", "token": self.ws.token,
                    "error": f"test-password-12345 test-refresh-cookie {self.ws.token}",
                    "data": {"code": "denied", "nested": [{"token": "unknown-token", "password": "unknown-password"},
                                                           self.ws.token, "test-refresh-cookie"]}}

        self.ws.send.side_effect = response
        result = await self.driver.execute(self.op(path="/test-password-12345"), 1)
        raw = json.dumps(result.to_json())
        for value in (*self.secrets, "unknown-token", "unknown-password"):
            self.assertNotIn(value, raw)
        self.assertIn("[REDACTED]", raw)
        self.assertEqual(result.outcome, "denied")

    async def test_without_redactor_server_diagnostics_and_payload_are_withheld(self):
        self.driver.principal = None
        self.driver.redactor = None
        await self.driver.open()
        self.ws.send.return_value = {"status": "ERROR", "error": "private text", "data": {"code": "private code"}}
        result = await self.driver.execute(self.op(path="/private path"), 1)
        self.assertEqual(result.rendered, "fs.dir.list")
        self.assertEqual((result.detail, result.code, result.data), ("", None, {}))

    async def test_close_is_idempotent_and_clears_session_secrets(self):
        await self.driver.close()
        await self.driver.open()
        await asyncio.gather(self.driver.close(), self.driver.close())
        await self.driver.close()
        self.ws.__aexit__.assert_awaited_once()
        self.assertEqual(self.ws.cookies, {})
        self.assertEqual(self.ws.token, "")
        self.assertEqual(self.driver.cookie_header(), "")

    async def test_failed_close_aborts_transport(self):
        await self.driver.open()
        self.ws.__aexit__.side_effect = RuntimeError("private close reason")
        await self.driver.close()
        self.ws.conn.transport.abort.assert_called_once()
        self.assertIsNone(self.driver.ws)

    async def test_cancelled_close_still_finishes_cleanup(self):
        await self.driver.open()
        entered, release = asyncio.Event(), asyncio.Event()

        async def finish(*args):
            entered.set()
            await release.wait()

        self.ws.__aexit__.side_effect = finish
        task = asyncio.create_task(self.driver.close())
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        release.set()
        await self.driver.close()
        self.ws.__aexit__.assert_awaited_once()
        self.assertIsNone(self.driver.ws)
        self.assertEqual(self.ws.cookies, {})

    async def test_cancellation_during_open_and_execute_closes_connection(self):
        for stage in ("open", "execute"):
            with self.subTest(stage=stage):
                self.ws.send.side_effect = None
                if stage == "execute":
                    await self.driver.open()
                entered = asyncio.Event()

                async def slow(*args, ready=entered, **kwargs):
                    ready.set()
                    await asyncio.Event().wait()

                self.ws.send.side_effect = slow
                call = self.driver.open() if stage == "open" else self.driver.execute(self.op(), 10)
                task = asyncio.create_task(call)
                await entered.wait()
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                await self.driver.close()
                self.assertIsNone(self.driver.ws)
                self.ws.conn.transport.abort.assert_called()

    async def test_requests_on_one_session_are_serialized(self):
        await self.driver.open()
        active = 0

        async def response(*args, **kwargs):
            nonlocal active
            active += 1
            self.assertEqual(active, 1)
            await asyncio.sleep(0)
            active -= 1
            return {"status": "SUCCESS", "data": {}}

        self.ws.send.side_effect = response
        results = await asyncio.gather(*(self.driver.execute(self.op(), 1) for _ in range(3)))
        self.assertEqual([r.outcome for r in results], ["ok"] * 3)


if __name__ == "__main__":
    unittest.main()
