"""HTTP lane tests exercise the shared upload protocol with controlled network responses."""
from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import unquote_plus

from vhh.drivers.http import HttpLane
from vhh.model import Result
from vhh.redact import Redactor

from tools.lab.pentest.client import HttpResult, Target, http_request, upload_files

COOKIE = "refresh=private-refresh-value"
VERSION = '"g7-0123abcd"'


def response(status=200, body=b""):
    return HttpResult(status, {}, body)


def entry(version=VERSION):
    return Result("ok", data={"vault": "v", "path": "/file",
                              "entry": {"name": "file"} if version is None else {"content_version": version}})


class HttpLaneTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.redactor = Redactor()
        self.lane = HttpLane(43124, self.redactor)
        self.ws = SimpleNamespace(principal="u-alice", ws=object(), login_result=Result("ok"),
                                  target=Target("127.0.0.1", ws_port=43123),
                                  cookie_header=Mock(return_value=COOKIE),
                                  execute=AsyncMock(return_value=Result("not_found")))
        self.lane.attach(self.ws)
        self.addAsyncCleanup(self.lane.close)
        self.send = self.enterContext(patch("vhh.drivers.http.http_request"))

    def assert_safe(self, result):
        serialized = json.dumps(result.to_json()) + repr(result)
        for secret in (COOKIE, "private-refresh-value", "private-password-value"):
            self.assertNotIn(secret, serialized)

    async def test_download_integrity_encoding_cookie_and_timing(self):
        data = b"\x00\xfffile bytes"
        self.send.return_value = response(body=data)
        result = await self.lane.download(42, "/a b+?#é", 2)
        self.assertEqual(result.outcome, "ok")
        self.assertEqual(result.body, data)
        self.assertEqual(result.bytes_sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(result.data, {"size": len(data)})
        self.assertGreaterEqual(result.t1_ns, result.t0_ns)
        self.assertGreater(result.t0_ns, 0)
        args, kwargs = self.send.call_args
        self.assertEqual(args[1:], ("GET", "/download"))
        self.assertEqual(kwargs["query"], {"vault_id": 42, "path": "/a b+?#é"})
        self.assertEqual(kwargs["cookie"], COOKIE)
        self.assertLessEqual(kwargs["timeout"], 2)
        self.assertIn("%2Fa+b%2B%3F%23%C3%A9", result.rendered)
        self.assertNotIn("body", result.to_json())
        self.assert_safe(result)

    async def test_download_status_classification_and_error_body_suppression(self):
        for code, expected in [(401, "denied"), (403, "denied"), (404, "not_found"), (409, "conflict"),
                               (412, "conflict"), (413, "invalid"), (415, "invalid"), (422, "invalid"),
                               (400, "error"), (500, "error"), (302, "error")]:
            with self.subTest(code=code):
                self.send.return_value = response(code, b"private-password-value")
                result = await self.lane.download(42, "/file", 1)
                self.assertEqual((result.outcome, result.code), (expected, code))
                self.assertIsNone(result.body)
                self.assert_safe(result)

    async def test_upload_shared_protocol_integrity(self):
        self.send.side_effect = [response(body=b'{"upload_id":"abc-123"}'), response(), response()]
        result = await self.lane.upload(42, "/file", b"contents", 2)
        self.assertEqual(result.outcome, "ok")
        self.assertEqual(result.bytes_sha256, hashlib.sha256(b"contents").hexdigest())
        calls = self.send.call_args_list
        self.assertEqual([c.args[1:] for c in calls], [("POST", "/upload/session"),
                         ("PUT", "/upload/abc-123/files/f0"), ("POST", "/upload/abc-123/finish")])
        manifest = json.loads(calls[0].kwargs["body"])
        self.assertEqual(manifest, {"vault_id": 42, "files": [
            {"file_id": "f0", "path": "/file", "size": 8, "mime_type": None}]})
        self.assertEqual(calls[1].kwargs["body"], b"contents")
        self.assertTrue(all(c.kwargs["cookie"] == COOKIE for c in calls))
        self.assert_safe(result)

    async def test_upload_reads_the_target_entry_over_the_session_websocket(self):
        self.send.side_effect = [response(body=b'{"upload_id":"abc"}'), response(), response()]
        self.assertEqual((await self.lane.upload(42, "/new", b"contents", 2)).outcome, "ok")
        probe, deadline = self.ws.execute.call_args.args
        self.assertEqual((probe.surface, probe.principal, probe.op, probe.args),
                         ("ws", "u-alice", "fs.stat", {"vault_id": 42, "path": "/new"}))
        self.assertLessEqual(deadline, 2)

    async def test_overwrite_replaces_through_conditional_content_lane(self):
        # #404: a file that exists is replaced with PUT /upload/content and If-Match, never the create-only session.
        self.ws.execute.return_value = entry()
        self.send.return_value = response()
        result = await self.lane.upload(42, "/a b+é", b"version two", 2)
        self.assertEqual((result.outcome, result.code), ("ok", 200))
        self.assertEqual(result.bytes_sha256, hashlib.sha256(b"version two").hexdigest())
        self.assertEqual(result.data, {"size": 11})
        self.send.assert_called_once()
        call = self.send.call_args
        self.assertEqual(call.args[1:], ("PUT", "/upload/content"))
        self.assertEqual(call.kwargs["query"], {"vault_id": 42, "path": "/a b+é"})
        self.assertEqual(call.kwargs["body"], b"version two")
        self.assertEqual(call.kwargs["cookie"], COOKIE)
        self.assertEqual(call.kwargs["headers"]["If-Match"], VERSION)
        self.assertNotIn("If-None-Match", call.kwargs["headers"])
        self.assertLessEqual(call.kwargs["timeout"], 2)
        self.assertTrue(result.rendered.startswith("PUT /upload/content?"))
        self.assert_safe(result)

    async def test_empty_overwrite(self):
        self.ws.execute.return_value = entry()
        self.send.return_value = response()
        result = await self.lane.upload(42, "/file", b"", 1)
        self.assertEqual(result.outcome, "ok")
        self.assertEqual(self.send.call_args.kwargs["body"], b"")
        self.assertEqual(result.bytes_sha256, hashlib.sha256(b"").hexdigest())

    async def test_overwrite_refusals_are_typed_and_never_cancel_a_session(self):
        # 412: the file changed (or was opened on the mount) after it was read, a legitimate concurrent-write conflict.
        for code, expected in [(412, "conflict"), (403, "denied"), (401, "denied"), (409, "conflict"),
                               (413, "invalid"), (428, "error"), (400, "error"), (500, "error")]:
            with self.subTest(code=code):
                self.send.reset_mock()
                self.ws.execute.return_value = entry()
                self.send.side_effect = None
                self.send.return_value = response(code, b'{"content_version":"private-password-value"}')
                result = await self.lane.upload(42, "/file", b"contents", 1)
                self.assertEqual((result.outcome, result.code), (expected, code))
                self.assertEqual(result.detail, f"HTTP replace failed ({code})")
                self.assertIsNone(result.body)
                self.assertIsNone(result.bytes_sha256)
                self.send.assert_called_once()
                self.assert_safe(result)

    async def test_overwrite_of_a_removed_file_creates_it_once(self):
        self.ws.execute.return_value = entry()
        self.send.side_effect = [response(404), response(body=b'{"upload_id":"abc"}'), response(), response()]
        result = await self.lane.upload(42, "/file", b"contents", 2)
        self.assertEqual((result.outcome, result.code), ("ok", 200))
        self.assertEqual([c.args[1:] for c in self.send.call_args_list], [
            ("PUT", "/upload/content"), ("POST", "/upload/session"), ("PUT", "/upload/abc/files/f0"),
            ("POST", "/upload/abc/finish")])
        self.assertTrue(result.rendered.startswith("POST /upload/session?"))

        self.send.reset_mock()
        self.send.side_effect = [response(404), response(403)]
        result = await self.lane.upload(42, "/file", b"contents", 2)
        self.assertEqual((result.outcome, result.code), ("denied", 403))
        self.assertEqual(self.send.call_count, 2)

    async def test_targets_without_a_file_version_use_the_create_lane(self):
        for probe in (Result("not_found"), Result("denied"), Result("invalid"), entry(None)):
            with self.subTest(probe=probe.outcome):
                self.send.reset_mock()
                self.ws.execute.return_value = probe
                self.send.side_effect = [response(body=b'{"upload_id":"abc"}'), response(), response()]
                result = await self.lane.upload(42, "/file", b"contents", 1)
                self.assertEqual(result.outcome, "ok")
                self.assertEqual(self.send.call_args_list[0].args[1:], ("POST", "/upload/session"))

    async def test_failed_version_lookup_never_writes(self):
        for probe, expected in [(Result("timeout"), "timeout"), (Result("disconnected"), "disconnected"),
                                (Result("error", detail="private-password-value"), "error"),
                                (entry('"g1"\r\nCookie: x'), "error"), (entry(7), "error"), (entry(""), "error"),
                                (entry("g1-unquoted"), "error")]:
            with self.subTest(probe=probe):
                self.ws.execute.return_value = probe
                result = await self.lane.upload(42, "/file", b"contents", 1)
                self.assertEqual(result.outcome, expected)
                self.assertTrue(result.rendered.startswith("fs.metadata?"))
                self.assert_safe(result)
        self.send.assert_not_called()

    async def test_version_lookup_counts_against_the_deadline(self):
        async def slow(*_):
            await asyncio.sleep(.15)
            return entry()

        self.ws.execute.side_effect = slow
        result = await self.lane.upload(42, "/file", b"contents", .1)
        self.assertEqual(result.outcome, "timeout")
        self.send.assert_not_called()

    async def test_empty_upload(self):
        self.send.side_effect = [response(body=b'{"upload_id":"abc"}'), response()]
        result = await self.lane.upload(42, "/empty", b"", 1)
        self.assertEqual(result.outcome, "ok")
        self.assertEqual(result.bytes_sha256, hashlib.sha256(b"").hexdigest())
        self.assertEqual(self.send.call_count, 2)

    async def test_upload_failures_cancel_partial_session(self):
        for stage, code, expected in [("session", 403, "denied"), ("put", 422, "invalid"),
                                      ("finish", 409, "conflict")]:
            with self.subTest(stage=stage):
                self.send.reset_mock()
                start = response(body=b'{"upload_id":"abc"}')
                bad = response(code, b"private-password-value")
                self.send.side_effect = ([bad] if stage == "session" else
                                         [start, bad, response()] if stage == "put" else
                                         [start, response(), bad, response()])
                result = await self.lane.upload(42, "/file", b"contents", 1)
                self.assertEqual((result.outcome, result.code), (expected, code))
                if stage != "session":
                    self.assertEqual(self.send.call_args.args[1:], ("DELETE", "/upload/abc"))
                self.assert_safe(result)

    async def test_upload_transport_failure_still_cancels(self):
        self.send.side_effect = [response(body=b'{"upload_id":"abc"}'), OSError(COOKIE), response()]
        result = await self.lane.upload(42, "/file", b"contents", 1)
        self.assertEqual(result.outcome, "disconnected")
        self.assertEqual(self.send.call_args.args[1:], ("DELETE", "/upload/abc"))
        self.assert_safe(result)

    async def test_malformed_session_response_cannot_inject_request_path(self):
        for body in (b'{}', b'[]', b'not json', b'{"upload_id":"../secret"}'):
            self.send.reset_mock()
            self.send.return_value = response(body=body)
            result = await self.lane.upload(42, "/file", b"contents", 1)
            self.assertEqual(result.outcome, "error")
            self.assertEqual(self.send.call_count, 1)

    async def test_disconnection_timeout_and_unknown_exception_are_secret_free(self):
        for exc, expected in [(ConnectionResetError(COOKIE), "disconnected"),
                              (TimeoutError(COOKIE), "timeout"), (ValueError(COOKIE), "error")]:
            self.send.side_effect = exc
            result = await self.lane.download(42, "/file", 1)
            self.assertEqual(result.outcome, expected)
            self.assert_safe(result)

    async def test_deadline_interrupts_active_socket_and_cleans_upload(self):
        for upload in (False, True):
            with self.subTest(upload=upload):
                interrupted = threading.Event()
                sock = Mock()
                sock.shutdown.side_effect = lambda *_, event=interrupted: event.set()
                calls = []

                def stalled(target, method, path, *, calls=calls, sock=sock, interrupted=interrupted, **kwargs):
                    calls.append((method, path))
                    if path == "/upload/session":
                        return response(body=b'{"upload_id":"abc"}')
                    if method == "DELETE":
                        return response()
                    kwargs["on_connection"](SimpleNamespace(sock=sock, close=sock.close))
                    if not interrupted.wait(1):
                        raise AssertionError("socket was not interrupted")
                    raise ConnectionResetError()

                self.send.side_effect = stalled
                start = time.monotonic()
                result = await (self.lane.upload(42, "/file", b"data", .2) if upload else
                                self.lane.download(42, "/file", .2))
                await self.lane.close()
                self.assertEqual(result.outcome, "timeout")
                self.assertLess(time.monotonic() - start, .7)
                self.assertTrue(interrupted.is_set())
                self.assertFalse(self.lane._pending)
                if upload:
                    self.assertEqual(calls[-1], ("DELETE", "/upload/abc"))
                    self.assertNotIn(("POST", "/upload/abc/finish"), calls)
                self.lane.attach(self.ws)

    async def test_external_cancellation_interrupts_worker(self):
        started = threading.Event()
        stopped = threading.Event()
        sock = Mock()
        sock.shutdown.side_effect = lambda *_: stopped.set()

        def stalled(*args, **kwargs):
            kwargs["on_connection"](SimpleNamespace(sock=sock, close=sock.close))
            started.set()
            stopped.wait(1)
            raise ConnectionResetError()

        self.send.side_effect = stalled
        task = asyncio.create_task(self.lane.download(42, "/file", 2))
        await asyncio.to_thread(started.wait, 1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        await self.lane.close()
        self.assertTrue(stopped.is_set())

    async def test_invalid_arguments_never_transmit(self):
        for vault, path, deadline in [(True, "/", 1), (0, "/", 1), (42, None, 1), (42, "/\0", 1),
                                      (42, "/", float("nan")), (42, "/", True)]:
            self.assertEqual((await self.lane.download(vault, path, deadline)).outcome, "invalid")
        self.assertEqual((await self.lane.upload(42, "/", "not bytes", 1)).outcome, "invalid")
        self.assertEqual((await self.lane.download(42, "/", 0)).outcome, "timeout")
        self.send.assert_not_called()

    async def test_expired_and_unattached_sessions(self):
        self.ws.cookie_header.return_value = ""
        self.assertEqual((await self.lane.download(42, "/file", 1)).outcome, "denied")
        await self.lane.close()
        self.assertEqual((await self.lane.upload(42, "/file", b"a", 1)).outcome, "denied")
        self.send.assert_not_called()

    async def test_reauthentication_requires_explicit_attachment(self):
        self.ws.principal = "u-eve"
        self.assertEqual((await self.lane.download(42, "/file", 1)).outcome, "denied")
        self.ws.principal = "u-alice"
        self.ws.ws = object()
        self.assertEqual((await self.lane.download(42, "/file", 1)).outcome, "denied")
        self.send.assert_not_called()

    def test_attach_refuses_unauthenticated_or_remote_session(self):
        for attribute, value in [("ws", None), ("login_result", Result("denied")),
                                 ("target", Target("example.com"))]:
            old = getattr(self.ws, attribute)
            setattr(self.ws, attribute, value)
            with self.assertRaises(ValueError):
                self.lane.attach(self.ws)
            setattr(self.ws, attribute, old)
        self.ws.cookie_header.return_value = ""
        with self.assertRaises(ValueError):
            self.lane.attach(self.ws)

    async def test_cookie_rotation_and_rendered_secret_redaction(self):
        self.ws.cookie_header.return_value = "refresh=rotated-secret-value"
        self.send.return_value = response()
        result = await self.lane.download(42, "/rotated-secret-value/a", 1)
        self.assertEqual(self.send.call_args.kwargs["cookie"], "refresh=rotated-secret-value")
        self.assertNotIn("rotated-secret-value", unquote_plus(result.rendered))
        self.assertEqual(self.redactor.redact_text("rotated-secret-value"), "[REDACTED]")
        self.assert_safe(result)


class SharedTransportTests(unittest.TestCase):
    def test_connection_hook_encoding_and_close(self):
        conn = Mock()
        conn.getresponse.return_value.status = 200
        conn.getresponse.return_value.getheaders.return_value = []
        conn.getresponse.return_value.read.return_value = b"data"
        hook = Mock()
        with patch("tools.lab.pentest.client.http.client.HTTPConnection", return_value=conn):
            result = http_request(Target("127.0.0.1", http_port=43124), "GET", "/download",
                                  query={"vault_id": 42, "path": "/a b+?"}, cookie=COOKIE, on_connection=hook)
        conn.connect.assert_called_once()
        hook.assert_called_once_with(conn)
        self.assertEqual(conn.request.call_args.args, ("GET", "/download?vault_id=42&path=%2Fa+b%2B%3F"))
        self.assertEqual(conn.request.call_args.kwargs["headers"]["Cookie"], COOKIE)
        conn.close.assert_called_once()
        self.assertEqual(result.body, b"data")

    def test_default_upload_transport_remains_compatible(self):
        with patch("tools.lab.pentest.client.http_request", side_effect=[
                response(body=b'{"upload_id":"abc"}'), response(), response()]) as send:
            result = upload_files(Target("127.0.0.1", http_port=43124), COOKIE, 42, [("/file", b"bytes")])
        self.assertEqual(result, {"/file": None})
        self.assertEqual(send.call_count, 3)

    def test_hook_failure_closes_connection(self):
        conn = Mock()
        with (patch("tools.lab.pentest.client.http.client.HTTPConnection", return_value=conn),
              self.assertRaises(TimeoutError)):
            http_request(Target("127.0.0.1", http_port=43124), "GET", "/download",
                         on_connection=Mock(side_effect=TimeoutError))
        conn.close.assert_called_once()
        conn.request.assert_not_called()
