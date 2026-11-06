#!/usr/bin/env python3
"""`vh-recovery` (core/main/recovery.cpp), the offline recovery-kit tool (design/encryption/03-metadata-recovery.md §5.3).

Runs the real binary in a temporary directory: `kit create` writes a mode-0600 kit and prints only the public key,
never overwrites a file, `kit public-key` derives the same key, `kit add-vault` pins a vault from
`vh vault keys status --json` output, and `kit show` never prints the seed.

  python3 core/tests/cli/test_recovery_tool.py <path to vh-recovery>      (meson test `recovery_tool`)
"""
from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = sys.argv.pop(1) if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else os.environ.get("VH_RECOVERY", "")
TOOL = os.path.abspath(TOOL) if TOOL else TOOL


def run(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([TOOL, *args], input=stdin, capture_output=True, text=True, timeout=30)


class RecoveryTool(unittest.TestCase):
    def setUp(self) -> None:
        if not TOOL:
            self.skipTest("no vh-recovery binary given")
        self.dir = tempfile.TemporaryDirectory(prefix="vh-recovery-test-")
        self.kit = Path(self.dir.name) / "kit.json"

    def tearDown(self) -> None:
        self.dir.cleanup()

    def create(self) -> str:
        r = run("kit", "create", "--output", str(self.kit))
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def test_create_writes_a_private_kit_and_prints_only_the_public_key(self) -> None:
        pk = self.create()
        self.assertEqual(len(base64.b64decode(pk)), 32)
        self.assertEqual(stat.S_IMODE(self.kit.stat().st_mode), 0o600)
        doc = json.loads(self.kit.read_text())
        self.assertEqual(doc["type"], "vh.recovery-kit")
        self.assertEqual(doc["v"], 1)
        self.assertEqual(len(doc["recovery_seed"]), 27)
        self.assertEqual(doc["vaults"], [])
        r = run("kit", "public-key", str(self.kit))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), pk)
        shown = run("kit", "show", str(self.kit))
        self.assertEqual(shown.returncode, 0, shown.stderr)
        self.assertNotIn(doc["recovery_seed"], shown.stdout + shown.stderr)
        self.assertEqual(json.loads(shown.stdout)["public_key"], pk)

    def test_a_kit_is_never_overwritten(self) -> None:
        self.create()
        before = self.kit.read_text()
        r = run("kit", "create", "--output", str(self.kit))
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.kit.read_text(), before)

    def test_add_vault_pins_what_status_reports(self) -> None:
        self.create()
        status = {"vaults": [{"vault_id": 42, "vault_uid": "as4f38nkrkaydxr834n3pk2xdr",
                              "node_id": "00000000-0000-4000-8000-000000000001",
                              "attestation_public_keys": [{"key_id": 3, "public_key": base64.b64encode(bytes(range(32))).decode(),
                                                           "retired_at": None}],
                              "checkpoint": {"epoch": 812, "root_sha256": "ab" * 32}}]}
        r = run("kit", "add-vault", str(self.kit), "--status", "-", stdin=json.dumps(status))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(stat.S_IMODE(self.kit.stat().st_mode), 0o600)
        vaults = json.loads(self.kit.read_text())["vaults"]
        self.assertEqual(len(vaults), 1)
        self.assertEqual(vaults[0]["vault_uid"], "as4f38nkrkaydxr834n3pk2xdr")
        self.assertEqual(vaults[0]["origin"], {"node_id": "00000000-0000-4000-8000-000000000001", "vault_id": 42})
        self.assertEqual(vaults[0]["attestation_public_keys"][0]["key_id"], 3)
        self.assertEqual(vaults[0]["checkpoint"]["epoch"], 812)
        # Pinning it again replaces the entry instead of adding a second one.
        r = run("kit", "add-vault", str(self.kit), "--status", "-", stdin=json.dumps(status))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(json.loads(self.kit.read_text())["vaults"]), 1)

    def test_a_damaged_kit_is_refused(self) -> None:
        self.create()
        doc = json.loads(self.kit.read_text())
        seed = doc["recovery_seed"]
        doc["recovery_seed"] = seed[:-1] + ("0" if seed[-1] != "0" else "1")
        bad = Path(self.dir.name) / "bad.json"
        bad.write_text(json.dumps(doc))
        r = run("kit", "public-key", str(bad))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("recovery seed", r.stderr)


if __name__ == "__main__":
    unittest.main()
