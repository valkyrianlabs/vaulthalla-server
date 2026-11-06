"""The offline audit export verifier (tools/audit/verify_export.py) and the daemon's hash chain
(core/include/audit/Chain.hpp) agree byte for byte: both pin the same vector (AuditChain.MatchesTheDocumentedVector)."""

import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("verify_export", ROOT / "tools" / "audit" / "verify_export.py")
verify_export = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify_export)


def _event(seq, prev, **fields):
    e = {"type": "event", "seq": seq, "occurred_us": 1000 + seq, "level": "info", "action": "test.event",
         "outcome": "info", "actor_id": None, "actor": "", "origin": "", "vault_id": None, "entry_id": None,
         "message": f"event {seq}", "details": "{}", "prev_hash": prev}
    e.update(fields)
    e["hash"] = verify_export.event_hash(e)
    return e


def _export(n=4):
    header = {"type": "export", "format": "vh-audit-export-v1", "node_id": "n", "since_us": None, "until_us": None,
              "anchor": None}
    events, prev = [], "00" * 32
    for seq in range(1, n + 1):
        e = _event(seq, prev)
        events.append(e)
        prev = e["hash"]
    return header, events


def _lines(header, events, heads=()):
    return [json.dumps(x) for x in (header, *events, *heads)]


class AuditExportVerifierTests(unittest.TestCase):
    def test_matches_the_documented_vector(self):
        e = {"seq": 7, "prev_hash": bytes(range(32)).hex(), "occurred_us": 1762300800123456, "level": "info",
             "action": "auth.login.success", "outcome": "success", "actor_id": 9, "actor": "alice", "origin": "web",
             "vault_id": None, "entry_id": None, "message": "[auth] alice signed in",
             "details": '{"method":"password"}'}
        self.assertEqual(verify_export.event_hash(e),
                         "d533d9d58a09ec57c4c6edc5ddc77f48379663f032a8f154646d0cc9f754549e")

    def test_intact_export_verifies(self):
        header, events = _export()
        head = {"type": "head", "seq": 4, "hash": events[-1]["hash"], "signed_us": 1, "node_id": "n", "key_id": 1,
                "signature": "00" * 64}
        ok, report = verify_export.verify(_lines(header, events, [head]), [])
        self.assertTrue(ok, report)

    def test_altered_missing_and_truncated_events_fail(self):
        header, events = _export()
        altered = [dict(e) for e in events]
        altered[1]["message"] = "edited"
        self.assertFalse(verify_export.verify(_lines(header, altered), [])[0])

        self.assertFalse(verify_export.verify(_lines(header, events[:1] + events[2:]), [])[0])

        head = {"type": "head", "seq": 4, "hash": events[-1]["hash"], "signed_us": 1, "node_id": "n", "key_id": 1,
                "signature": "00" * 64}
        ok, report = verify_export.verify(_lines(header, events[:3], [head]), [])
        self.assertFalse(ok)
        self.assertIn("missing", " ".join(report))

    def test_rejects_files_that_are_not_exports(self):
        self.assertFalse(verify_export.verify(['{"type": "event"}'], [])[0])


if __name__ == "__main__":
    unittest.main()
