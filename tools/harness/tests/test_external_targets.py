"""External targets (the pentest path against a real lab or production install): declared, non-destructive commands
only, and production needs two keys. Destructive commands never accept them."""
import json
import os
import unittest
from unittest import mock

from tests.helpers import TempDir
from vhh import cli, targets


class ExternalTargets(TempDir, unittest.TestCase):
    def desc(self, **over):
        d = {"kind": "vhh-external", "name": "lab", "env": "lab", "hostname": "vh-local.example.org",
             "connect_ip": "10.0.0.33"}
        d.update(over)
        p = self.tmp / "target.json"
        p.write_text(json.dumps(d))
        return f"external:{p}"

    def test_lab_target_for_verify_fixture(self):
        t = targets.resolve_external(self.desc(), "verify-fixture")
        self.assertEqual((t.env, t.hostname, t.connect_ip), ("lab", "vh-local.example.org", "10.0.0.33"))

    def test_production_needs_both_keys(self):
        spec = self.desc(env="production")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("VHH_ALLOW_PRODUCTION", None)
            with self.assertRaises(targets.TargetRefused):
                targets.resolve_external(spec, "verify-fixture", allow_production=True)
        with mock.patch.dict(os.environ, {"VHH_ALLOW_PRODUCTION": "1"}):
            with self.assertRaises(targets.TargetRefused):
                targets.resolve_external(spec, "verify-fixture", allow_production=False)
            t = targets.resolve_external(spec, "verify-fixture", allow_production=True)
            self.assertEqual(t.env, "production")

    def test_destructive_commands_never_take_an_external_target(self):
        spec = self.desc()
        for command in ("run", "replay", "shrink", "regress", "scenario", "agent", "provision", "reset"):
            with self.assertRaises(targets.TargetRefused):
                targets.resolve_external(spec, command)
        with self.assertRaises(targets.TargetRefused):
            targets.resolve(spec)   # the private-target resolver used by run/replay/shrink refuses it outright
        self.assertEqual(cli.main(["run", "--target", spec, "--world", "pentest-v1"]), cli.REFUSED)

    def test_bad_descriptors_are_refused(self):
        for over in ({"kind": "vhh-private-local"}, {"env": "staging"}, {"hostname": "https://x"}, {"hostname": ""}):
            with self.assertRaises(targets.TargetRefused):
                targets.resolve_external(self.desc(**over), "verify-fixture")
        with self.assertRaises(targets.TargetRefused):
            targets.resolve_external("external:/nonexistent.json", "verify-fixture")


if __name__ == "__main__":
    unittest.main()
