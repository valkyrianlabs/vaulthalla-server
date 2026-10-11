"""Recorder and redactor: secrets never reach the trace; corrupt lines are errors, not silent skips."""
import json
import unittest

from tests.helpers import TempDir
from vhh.model import Op, Result, Verdict
from vhh.recorder import TraceError, TraceWriter, read_trace
from vhh.redact import MASK, Redactor


class Redaction(unittest.TestCase):
    def setUp(self):
        self.r = Redactor()
        self.r.register_secret("hunter2password")

    def test_registered_secret_masked_everywhere(self):
        self.assertEqual(self.r.redact_text("login hunter2password ok"), f"login {MASK} ok")
        out = self.r.redact({"note": "pw=hunter2password", "nested": ["hunter2password"]})
        self.assertNotIn("hunter2password", json.dumps(out))

    def test_sensitive_keys_masked_by_name(self):
        out = self.r.redact({"token": "abc123xyz", "Authorization": "Bearer zzz999", "password": "p", "ok": 1})
        self.assertEqual(out["token"], MASK)
        self.assertEqual(out["Authorization"], MASK)
        self.assertEqual(out["password"], MASK)
        self.assertEqual(out["ok"], 1)

    def test_inline_headers_masked_even_if_unregistered(self):
        t = self.r.redact_text('sent cookie: session=deadbeef; path=/ and Authorization: Bearer tok_unknown')
        self.assertNotIn("deadbeef", t)
        self.assertNotIn("tok_unknown", t)

    def test_deepcopy_does_not_mutate_caller(self):
        obj = {"token": "secret-value", "list": [{"password": "x"}]}
        self.r.redact(obj)
        self.assertEqual(obj["token"], "secret-value")

    def test_too_short_secret_refused(self):
        with self.assertRaises(ValueError):
            self.r.register_secret("ab")


class TraceIO(TempDir, unittest.TestCase):
    def test_planted_secret_never_reaches_trace_file(self):
        r = Redactor()
        r.register_secret("TOPSECRET-TOKEN-123")
        w = TraceWriter(self.tmp / "t.jsonl", r, {"seed": "0x1", "note": "TOPSECRET-TOKEN-123 in header"})
        op = Op(1, "s0", "u-a", "ws", "fs.read", {"vault": "v", "path": "/f", "token": "TOPSECRET-TOKEN-123"})
        w.op(op, Result("ok", detail="used TOPSECRET-TOKEN-123", data={"cookie": "TOPSECRET-TOKEN-123"},
                        rendered="GET /f token=TOPSECRET-TOKEN-123"))
        w.verdict(Verdict("oracle", False, 1, "leaked TOPSECRET-TOKEN-123?"))
        w.close()
        raw = (self.tmp / "t.jsonl").read_text()
        self.assertNotIn("TOPSECRET-TOKEN-123", raw)
        self.assertIn(MASK, raw)
        # the trace still parses and the op is intact apart from the secret
        tr = read_trace(self.tmp / "t.jsonl")
        self.assertEqual(len(tr.ops), 1)

    def test_bytes_body_never_serialized(self):
        r = Redactor()
        w = TraceWriter(self.tmp / "b.jsonl", r, {})
        w.op(Op(1, "s", "u", "ws", "fs.read", {}), Result("ok", body=b"\x00rawbytes", bytes_sha256="ab"))
        w.close()
        self.assertNotIn("rawbytes", (self.tmp / "b.jsonl").read_text())

    def test_corrupt_line_is_an_error_with_line_number(self):
        p = self.tmp / "c.jsonl"
        p.write_text('{"kind":"header","trace_version":1}\n{not json}\n')
        with self.assertRaises(TraceError) as cm:
            read_trace(p)
        self.assertIn(":2:", str(cm.exception))

    def test_missing_header_is_an_error(self):
        p = self.tmp / "h.jsonl"
        p.write_text('{"kind":"op","op":{},"result":{}}\n')
        with self.assertRaises(TraceError):
            read_trace(p)

    def test_trace_is_never_overwritten(self):
        TraceWriter(self.tmp / "x.jsonl", Redactor(), {}).close()
        with self.assertRaises(FileExistsError):
            TraceWriter(self.tmp / "x.jsonl", Redactor(), {})


if __name__ == "__main__":
    unittest.main()
