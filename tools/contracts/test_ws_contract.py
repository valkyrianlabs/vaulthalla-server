"""Contract: the web console's ws types come from the server-owned ws command book (core/usage) and can't drift.

core/usage declares every covered ws command (payload, response, refusals, client timeout); `vh_usage --json`
publishes it; tools/contracts/ws_contract.py generates web/src/util/generated/wsContract.{json,ts}; and
web/src/util/wsContractCheck.ts makes `pnpm typecheck` fail while WebSocketCommandMap disagrees with it. This test
needs no build: it checks the committed snapshot against itself and the code. The build-side half is the meson
test `ws_contract_drift` (the build's vh_usage output vs the snapshot); set VH_USAGE_JSON=<build>/core/usage.json to
run that comparison here too.

Run by module: python3 -m unittest tools.contracts.test_ws_contract
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import unittest

from tools.contracts import ws_contract
from tools.contracts.test_ws_command_map_contract import core_commands, web_commands

REPO_ROOT = Path(__file__).resolve().parents[2]
CLIENT_TS = REPO_ROOT / "web" / "src" / "lib" / "ws" / "client.ts"
HANDLER_CPP = REPO_ROOT / "core" / "src" / "protocols" / "ws" / "Handler.cpp"


# Registered commands the book deliberately leaves out, with the reason (mirrors unbookedWsCommands() in
# core/tests/unit/test_usage_contract.cpp). Keep it empty unless a command truly can't be described.
UNBOOKED: dict[str, str] = {}


def committed() -> dict:
    return json.loads(ws_contract.CONTRACT_JSON.read_text(encoding="utf-8"))


def with_hash(snapshot: dict) -> dict:
    out = copy.deepcopy(snapshot)
    out["ws_hash"] = ws_contract.sha256_hex(ws_contract.canonical(out["ws"]))
    return out


class WsContractTests(unittest.TestCase):
    def test_committed_snapshot_is_intact_and_generates_the_committed_ts(self) -> None:
        problems = ws_contract.drift(None)
        self.assertFalse(problems, "\n".join(problems))

    def test_snapshot_covers_the_engine_and_console_commands(self) -> None:
        names = {c["command"] for c in committed()["ws"]}
        self.assertGreaterEqual(len(names), 40, "the ws book shrank unexpectedly")
        for name in ("auth.login", "auth.register", "group.add", "group.member.add", "role.vault.assign",
                     "storage.vault.add", "fs.dir.list", "fs.entry.copy", "share.link.create", "meta.contract.get"):
            self.assertIn(name, names)

    def test_every_contract_command_is_registered_in_core(self) -> None:
        registered = core_commands()
        missing = sorted(c["command"] for c in committed()["ws"] if c["command"] not in registered)
        self.assertFalse(missing, "in the ws book but not registered in core/src/protocols/ws: " + ", ".join(missing))
        self.assertIn("meta.contract.get", HANDLER_CPP.read_text(encoding="utf-8"))

    def test_every_registered_command_is_in_the_contract(self) -> None:
        booked = {c["command"] for c in committed()["ws"]}
        registered = set(core_commands())
        missing = sorted(registered - booked - set(UNBOOKED))
        self.assertFalse(missing, "registered in core/src/protocols/ws but not in the ws book (core/usage/src/contract/ws): "
                         + ", ".join(missing))
        stale = sorted(name for name in UNBOOKED if name in booked or name not in registered)
        self.assertFalse(stale, "UNBOOKED entries that are booked or no longer registered: " + ", ".join(stale))

    def test_every_contract_command_is_typed_in_the_web_command_map(self) -> None:
        typed = set(web_commands())
        missing = sorted(c["command"] for c in committed()["ws"] if c["command"] not in typed)
        self.assertFalse(missing, "missing from WebSocketCommandMap: " + ", ".join(missing))

    def test_contract_commands_take_their_timeout_from_the_server(self) -> None:
        source = CLIENT_TS.read_text(encoding="utf-8")
        self.assertIn("...WS_CONTRACT_TIMEOUTS", source)
        block = source[source.index("const COMMAND_TIMEOUTS"):]
        block = block[:block.index("\n}\n")]
        local = set(re.findall(r"^\s*'([^']+)':", block, flags=re.M))
        overridden = sorted(local & {c["command"] for c in committed()["ws"]})
        self.assertFalse(overridden, "client.ts overrides server-declared timeouts (change core/usage instead): "
                         + ", ".join(overridden))

    def test_a_server_side_change_is_drift(self) -> None:
        changed = copy.deepcopy(committed())
        group_add = next(c for c in changed["ws"] if c["command"] == "group.add")
        group_add["payload"].append({"name": "colour", "types": ["string"], "required": True})
        changed = with_hash(changed)

        problems = ws_contract.drift(changed)
        self.assertTrue(problems)
        self.assertIn("was not regenerated", problems[0])
        self.assertIn("colour", "\n".join(problems))
        self.assertIn("colour: string", ws_contract.generate_ts(ws_contract.ws_snapshot(changed)))

    def test_a_hand_edited_snapshot_is_refused(self) -> None:
        tampered = copy.deepcopy(committed())
        tampered["ws"][0]["description"] += " (edited)"
        with self.assertRaises(SystemExit):
            ws_contract.ws_snapshot(tampered)
        tampered = copy.deepcopy(committed())
        tampered["models"][0]["description"] += " (edited)"
        with self.assertRaises(SystemExit):
            ws_contract.ws_snapshot(tampered)

    def test_snapshot_carries_the_envelope(self) -> None:
        envelope = committed()["envelope"]
        self.assertEqual({f["name"] for f in envelope["request"]}, {"command", "payload", "requestId", "token"})
        data = next(f for f in envelope["response"] if f["name"] == "data")
        self.assertFalse(data["required"], "a missing data reads as {}")

    def test_models_named_by_the_book_are_in_the_snapshot(self) -> None:
        snapshot = committed()
        names = {m["name"] for m in snapshot["models"]}

        def walk(fields: list) -> None:
            for f in fields:
                if f.get("model"):
                    self.assertIn(f["model"], names, f"{f['name']} names an undeclared model")
                walk(f.get("fields", []))
                walk(f.get("one_of", []))
                walk([f[k] for k in ("values", "element") if k in f])

        for c in snapshot["ws"]:
            walk(c["payload"])
            walk(c["response"])
        for m in snapshot["models"]:
            walk(m["fields"])

    def test_typescript_rendering(self) -> None:
        ws_contract.DECLARED_MODELS.update({"VaultDeletion", "User", "AuthConfig"})
        field = {"name": "allowed_ops", "types": ["integer", "array"], "required": False, "items": "string",
                 "item_enum": ["list", "download"]}
        self.assertEqual(ws_contract.ts_field_type(field, 4), "number | ('list' | 'download')[]")
        self.assertEqual(ws_contract.ts_object([], 4), "Record<string, never>")
        nullable = {"name": "deletion", "types": ["object", "null"], "required": True, "model": "VaultDeletion"}
        self.assertEqual(ws_contract.ts_object([nullable], 4), "{ deletion: WsModels['VaultDeletion'] | null }")
        union = {"name": "retention", "types": ["string", "integer", "object", "null"], "required": False,
                 "one_of": [{"name": "", "types": ["string"], "required": True},
                            {"name": "", "types": ["integer"], "required": True},
                            {"name": "", "types": ["object"], "required": True,
                             "fields": [{"name": "days", "types": ["integer"], "required": False}]}]}
        self.assertEqual(ws_contract.ts_field_type(union, 4), "string | number | { days?: number } | null")
        counts = {"name": "counts", "types": ["object"], "required": True,
                  "values": {"name": "", "types": ["integer"], "required": True}}
        self.assertEqual(ws_contract.ts_field_type(counts, 4), "Record<string, number>")
        points = {"name": "points", "types": ["array"], "required": True,
                  "element": {"name": "", "types": ["array"], "required": True, "items": "number"}}
        self.assertEqual(ws_contract.ts_field_type(points, 4), "(number[])[]")
        users = {"name": "users", "types": ["array"], "required": True, "items": "object", "model": "User"}
        self.assertEqual(ws_contract.ts_field_type(users, 4), "WsModels['User'][]")
        patch = {"name": "auth", "types": ["object"], "required": False, "model": "AuthConfig", "partial": True}
        self.assertEqual(ws_contract.ts_field_type(patch, 4), "WsPartial<WsModels['AuthConfig']>")
        ws_contract.DECLARED_MODELS.discard("NotDeclaredAnywhere")
        self.assertEqual(ws_contract.ts_field_type({**users, "model": "NotDeclaredAnywhere"}, 4), "object[]")
        command = {"input": "none"}
        self.assertEqual(ws_contract.ts_payload(command, [], 4), "null")

    @unittest.skipUnless(os.environ.get("VH_USAGE_JSON"), "set VH_USAGE_JSON=<build>/core/usage.json")
    def test_build_contract_matches_the_snapshot(self) -> None:
        usage = json.loads(Path(os.environ["VH_USAGE_JSON"]).read_text(encoding="utf-8"))
        problems = ws_contract.drift(usage)
        self.assertFalse(problems, "\n".join(problems))


if __name__ == "__main__":
    unittest.main()
