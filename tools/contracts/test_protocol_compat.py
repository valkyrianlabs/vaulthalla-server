"""Contract: the ws protocol's surface is frozen per version (core/usage/protocol/v<N>.json) and only grows.

tools/contracts/protocol_compat.py compares the contract's normalized ws surface with the baseline of
kProtocolVersion. These tests feed it synthetic contracts: every breaking class must be caught (and named), every
additive change accepted; and the committed web snapshot (web/src/util/generated/wsContract.json) must pass against
the committed baseline. The build-side half is the meson test `protocol_compat` (the build's vh_usage output).

Run by module: python3 -m unittest tools.contracts.test_protocol_compat
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.contracts import protocol_compat as pc


def field(name: str, types: list[str], required: bool = True, **extra) -> dict:
    return {"name": name, "types": types, "required": required, "description": "prose is ignored", **extra}


def contract() -> dict:
    """A small vh_usage --json shaped document: two commands, two models, the envelope, two capabilities."""
    return {
        "contract_version": 3,
        "protocol": {"version": 1, "min": 1},
        "capabilities": [{"name": "fs.entry.metadata_version", "since": "1.17.0", "description": "d"},
                         {"name": "device.mcp", "since": "1.16.0", "description": "d"}],
        "ws": [
            {"command": "fs.dir.list", "input": "payload", "auth": "human", "client_timeout_ms": 15000,
             "description": "List a folder.",
             "payload": [field("vault_id", ["integer"]), field("path", ["string"]),
                         field("sort", ["string"], False, enum=["name", "size"])],
             "response": [field("entries", ["array"], items="object", model="Entry"),
                          field("total", ["integer"]),
                          field("state", ["string"], enum=["ok", "partial"])],
             "variants": [{"mode": "share", "description": "x", "payload": [field("path", ["string"])],
                           "response": [field("entries", ["array"], items="object", model="Entry")]}],
             "refusal_kinds": ["denied", "not_found", "unauthorized"], "confirmations": [],
             "response_model": None},
            {"command": "vault.get", "input": "payload", "auth": "human", "client_timeout_ms": 15000,
             "description": "One vault.", "payload": [field("id", ["integer"])],
             "response": [field("vault", ["object"], model="Vault")], "variants": [],
             "refusal_kinds": ["not_found"],
             "confirmations": [{"code": "vault_delete_now", "accept_field": None, "description": "d"}],
             "response_model": None},
        ],
        "models": [
            {"name": "Entry", "description": "d",
             "fields": [field("id", ["integer"]), field("name", ["string"]),
                        field("kind", ["string"], enum=["file", "directory"]),
                        field("size", ["integer", "null"], False)]},
            {"name": "Vault", "description": "d", "fields": [field("id", ["integer"]), field("name", ["string"])]},
        ],
        "envelope": {
            "request": [field("command", ["string"]), field("payload", ["object", "null"], False)],
            "response": [field("command", ["string"]), field("status", ["string"], enum=["OK", "ERROR"])],
            "error_frame": [field("status", ["string"], enum=["parse_error"])],
            "error_codes": [{"code": "unknown_command", "description": "d"}, {"code": "invalid", "description": "d"}],
        },
    }


def command(doc: dict, name: str) -> dict:
    return next(c for c in doc["ws"] if c["command"] == name)


def model(doc: dict, name: str) -> dict:
    return next(m for m in doc["models"] if m["name"] == name)


def member(fields: list[dict], name: str) -> dict:
    return next(f for f in fields if f["name"] == name)


def breaks(mutate) -> list[str]:
    base, cur = contract(), contract()
    mutate(cur)
    return pc.compare(pc.surface(base), pc.surface(cur)).breaks


class ProtocolCompatBreakingTests(unittest.TestCase):
    def assertBreaks(self, mutate, *needles: str) -> None:
        found = breaks(mutate)
        self.assertTrue(found, "expected a breaking change")
        for needle in needles:
            self.assertTrue(any(needle in b for b in found), f"{needle!r} not in {found}")

    def test_a_removed_command(self) -> None:
        self.assertBreaks(lambda d: d["ws"].remove(command(d, "vault.get")), "vault.get: command removed")

    def test_a_removed_variant(self) -> None:
        self.assertBreaks(lambda d: command(d, "fs.dir.list")["variants"].clear(), "share variant removed")

    def test_a_request_field_newly_required(self) -> None:
        self.assertBreaks(lambda d: member(command(d, "fs.dir.list")["payload"], "sort").update(required=True),
                          "fs.dir.list payload.sort: request field newly required")

    def test_a_new_required_request_field(self) -> None:
        self.assertBreaks(lambda d: command(d, "vault.get")["payload"].append(field("token", ["string"])),
                          "vault.get payload.token: new request field is required")

    def test_a_removed_request_field(self) -> None:
        self.assertBreaks(lambda d: command(d, "fs.dir.list")["payload"].pop(), "payload.sort: request field removed")

    def test_a_retyped_request_field(self) -> None:
        self.assertBreaks(lambda d: member(command(d, "vault.get")["payload"], "id").update(types=["string"]),
                          "vault.get payload.id: request field retyped")

    def test_a_request_enum_value_removed(self) -> None:
        self.assertBreaks(lambda d: member(command(d, "fs.dir.list")["payload"], "sort").update(enum=["name"]),
                          "request enum value removed: size")

    def test_a_removed_response_field(self) -> None:
        self.assertBreaks(lambda d: command(d, "fs.dir.list")["response"].pop(1),
                          "fs.dir.list response.total: response field removed")

    def test_a_retyped_response_field(self) -> None:
        self.assertBreaks(lambda d: member(command(d, "fs.dir.list")["response"], "total").update(types=["string"]),
                          "response.total: response field retyped")
        self.assertBreaks(lambda d: member(command(d, "fs.dir.list")["response"], "entries").update(model="Vault"),
                          "response field retyped: model Entry -> Vault")
        self.assertBreaks(lambda d: member(model(d, "Entry")["fields"], "size").update(types=["integer", "string"]),
                          "model Entry.size: response field retyped")

    def test_a_required_response_field_made_optional(self) -> None:
        self.assertBreaks(lambda d: member(model(d, "Entry")["fields"], "name").update(required=False),
                          "model Entry.name: required response field made optional")

    def test_a_response_enum_value_removed(self) -> None:
        self.assertBreaks(lambda d: member(model(d, "Entry")["fields"], "kind").update(enum=["file"]),
                          "model Entry.kind: response enum value removed: directory")
        self.assertBreaks(lambda d: member(command(d, "fs.dir.list")["response"], "state").update(enum=["ok"]),
                          "response enum value removed: partial")

    def test_a_model_removed_while_still_referenced(self) -> None:
        self.assertBreaks(lambda d: d["models"].remove(model(d, "Vault")),
                          "model Vault: model removed while still referenced")

    def test_an_error_code_removed(self) -> None:
        self.assertBreaks(lambda d: d["envelope"]["error_codes"].pop(0), "error code unknown_command: error code removed")
        self.assertBreaks(lambda d: command(d, "vault.get")["confirmations"].clear(), "error code vault_delete_now")

    def test_a_capability_removed(self) -> None:
        self.assertBreaks(lambda d: d["capabilities"].pop(0), "capability fs.entry.metadata_version")

    def test_an_envelope_field_removed(self) -> None:
        self.assertBreaks(lambda d: d["envelope"]["response"].pop(), "envelope response.status: response field removed")

    def test_every_break_is_listed(self) -> None:
        def many(d: dict) -> None:
            d["ws"].remove(command(d, "vault.get"))
            member(model(d, "Entry")["fields"], "kind").update(enum=["file"])
            d["capabilities"].pop()
        # The removed command takes its confirmation code (vault_delete_now) with it: four breaks.
        self.assertEqual(len(breaks(many)), 4, breaks(many))


class ProtocolCompatAdditiveTests(unittest.TestCase):
    def assertAdditive(self, mutate) -> None:
        base, cur = contract(), contract()
        mutate(cur)
        d = pc.compare(pc.surface(base), pc.surface(cur))
        self.assertEqual(d.breaks, [])
        self.assertTrue(d.additions, "the change should be reported as an addition")

    def test_a_new_command(self) -> None:
        def add(d: dict) -> None:
            d["ws"].append({**copy.deepcopy(command(d, "vault.get")), "command": "meta.hello"})
        self.assertAdditive(add)

    def test_a_new_optional_request_field(self) -> None:
        self.assertAdditive(lambda d: command(d, "vault.get")["payload"].append(field("verbose", ["boolean"], False)))

    def test_a_new_response_field(self) -> None:
        self.assertAdditive(lambda d: model(d, "Entry")["fields"].append(field("metadata_version", ["string"])))

    def test_new_enum_values(self) -> None:
        self.assertAdditive(lambda d: member(model(d, "Entry")["fields"], "kind").update(enum=["file", "directory", "link"]))
        self.assertAdditive(lambda d: member(command(d, "fs.dir.list")["payload"], "sort").update(enum=["name", "size", "date"]))

    def test_a_new_model_capability_and_error_code(self) -> None:
        def add(d: dict) -> None:
            d["models"].append({"name": "Hello", "description": "d", "fields": [field("x", ["string"])]})
            command(d, "vault.get")["response"].append(field("hello", ["object"], False, model="Hello"))
            d["capabilities"].append({"name": "errors.unknown_command_code", "since": "1.19.0", "description": "d"})
            d["envelope"]["error_codes"].append({"code": "protocol_unsupported", "description": "d"})
        self.assertAdditive(add)

    def test_prose_and_timeouts_are_not_the_surface(self) -> None:
        def prose(d: dict) -> None:
            command(d, "vault.get")["description"] = "Something else entirely."
            command(d, "vault.get")["client_timeout_ms"] = 60000
            member(model(d, "Entry")["fields"], "id")["description"] = "new words"
        base, cur = contract(), contract()
        prose(cur)
        self.assertEqual(pc.surface(base), pc.surface(cur))

    def test_a_request_field_accepting_more_and_an_optional_one_becoming_required_in_a_response(self) -> None:
        def widen(d: dict) -> None:
            member(command(d, "vault.get")["payload"], "id").update(types=["integer", "string"])
            member(model(d, "Entry")["fields"], "size").update(required=True, types=["integer"])
        self.assertAdditive(widen)

    def test_an_unreferenced_model_may_go(self) -> None:
        def drop(d: dict) -> None:
            d["models"].remove(model(d, "Vault"))
            member(command(d, "vault.get")["response"], "vault").update(model="Entry")
        found = breaks(drop)
        self.assertTrue(all("model removed" not in b for b in found), found)
        self.assertTrue(any("model Vault -> Entry" in b for b in found), "the retyped reference is the break")


class ProtocolCompatBaselineTests(unittest.TestCase):
    def test_the_committed_snapshot_is_compatible_with_the_committed_baseline(self) -> None:
        usage = json.loads(pc.SNAPSHOT_JSON.read_text(encoding="utf-8"))
        problems, _ = pc.check(usage)
        self.assertFalse(problems, "\n".join(problems))
        self.assertTrue(pc.baseline_path(usage["protocol"]["version"]).exists())

    def test_the_v1_baseline_holds_the_handshake(self) -> None:
        base = pc.load_baseline(1)
        self.assertIsNotNone(base)
        self.assertEqual(base["protocol"], 1)
        self.assertIn("meta.hello", base["commands"])
        for code in ("unknown_command", "protocol_unsupported", "device_unknown", "invalid"):
            self.assertIn(code, base["error_codes"])
        self.assertNotIn("unauthorized", base["error_codes"], "a status, not a data.code")
        self.assertIn("errors.unknown_command_code", base["capabilities"])
        self.assertNotIn("description", json.dumps(base["commands"]["meta.hello"]))

    def test_a_breaking_change_fails_with_the_bump_instructions_and_write_refuses_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(pc, "BASELINE_DIR", Path(tmp)):
            doc = contract()
            pc.baseline_path(1).write_text(pc.baseline_text(pc.surface(doc)), encoding="utf-8")
            self.assertEqual(pc.check(doc)[0], [])

            broken = contract()
            broken["ws"].remove(command(broken, "vault.get"))
            problems, _ = pc.check(broken)
            self.assertEqual(len(problems), 1)
            self.assertIn("vault.get: command removed", problems[0])
            self.assertIn("bump kProtocolVersion to 2", problems[0])
            self.assertIn("kProtocolMin", problems[0])

            source = Path(tmp) / "usage.json"
            source.write_text(json.dumps(broken), encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(pc.main(["--check", "--usage-json", str(source)]), 1)
                self.assertEqual(pc.main(["--write", "--usage-json", str(source)]), 1)
            self.assertIn("vault.get", json.loads(pc.baseline_path(1).read_text(encoding="utf-8"))["commands"])

            # An additive change may be frozen into the baseline.
            grown = contract()
            grown["capabilities"].append({"name": "x.new", "since": "1.19.0", "description": "d"})
            source.write_text(json.dumps(grown), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(pc.main(["--write", "--usage-json", str(source)]), 0)
            self.assertIn("x.new", json.loads(pc.baseline_path(1).read_text(encoding="utf-8"))["capabilities"])

    def test_a_bumped_protocol_needs_its_baseline_and_keeps_the_served_ones(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(pc, "BASELINE_DIR", Path(tmp)):
            doc = contract()
            doc["protocol"] = {"version": 2, "min": 1}
            problems, _ = pc.check(doc)
            self.assertTrue(any("no baseline for protocol 2" in p for p in problems), problems)
            self.assertTrue(any("protocol 1 is still served" in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
