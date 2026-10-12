"""Exercise the workflow command entry point without sudo or daemon access."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CiEntryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.tmp / "bin").mkdir()
        (self.tmp / "python/bin").mkdir(parents=True)
        (self.tmp / "python/bin/python").symlink_to(sys.executable)
        sudo = self.tmp / "bin/sudo"
        sudo.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\nexit "${MOCK_STATUS:-0}"\n')
        sudo.chmod(0o755)
        self.env = {**os.environ, "PATH": f"{self.tmp}/bin:{os.environ['PATH']}", "VHH_WORK": str(self.tmp),
                    "VHH_BUILD": "/private/build", "VHH_ARTIFACTS": "/private/artifacts",
                    "CALLS": str(self.tmp / "calls"), "SEED": "0x197", "SESSIONS": "4", "ROUNDS": "3"}
        self.script = Path(__file__).resolve().parents[1] / "ci_run.sh"

    def run_profile(self, profile, **env):
        return subprocess.run(["bash", str(self.script)], env={**self.env, "PROFILE": profile, **env},
                              capture_output=True, text=True, timeout=5, check=False)

    def calls(self):
        path = self.tmp / "calls"
        return path.read_text().splitlines() if path.exists() else []

    def test_smoke_includes_revoke_and_uses_only_launched_targets(self):
        result = self.run_profile("smoke")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 2)
        self.assertIn("run --target launch --build /private/build --seed 0x197 --sessions 4", calls[0])
        self.assertIn("scenario revoke", calls[1])
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", calls[0])

    def test_pressure_includes_magic_and_retains_requested_controls(self):
        result = self.run_profile("pressure")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--schedule barrier", self.calls()[0])
        self.assertIn("scenario magic --build /private/build --seed 0x197 --sessions 4 --rounds 3", self.calls()[1])

    def test_failed_harness_exits_nonzero_without_hiding_failure(self):
        result = self.run_profile("smoke", MOCK_STATUS="1")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(self.calls()), 1)

    def test_regress_keeps_attempt_artifacts(self):
        self.assertEqual(self.run_profile("regress").returncode, 0)
        self.assertIn("--artifacts /private/artifacts/regress", self.calls()[0])

    def test_bad_parameters_never_launch(self):
        for env in ({"SESSIONS": "0"}, {"ROUNDS": "no"}, {"SEED": "$(false)"}):
            self.assertNotEqual(self.run_profile("smoke", **env).returncode, 0)
        self.assertFalse(self.calls())
