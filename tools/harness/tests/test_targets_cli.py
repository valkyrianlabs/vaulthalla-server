"""Target validation (fail-closed) and the CLI surface."""
import json
import os
import unittest

from tests.helpers import TempDir
from vhh import cli, targets


class TargetValidation(TempDir, unittest.TestCase):
    def _descriptor(self, **over):
        d = {"kind": "vhh-private-local", "run_id": "r1", "pid": os.getpid(),
             "server": "127.0.0.1", "db_name": "vh_harness_r1", "run_dir": "/tmp/vhh/r1",
             "mount": "/tmp/vhh/r1/mnt", "backing": "/tmp/vhh/r1/back", "cli_socket": "/tmp/vhh/r1/cli.sock",
             "ws_port": 40001, "http_port": 40002, "artifacts": "/tmp/vhh/r1/artifacts"}
        d.update(over)
        return d

    def test_sim_is_allowed(self):
        self.assertEqual(targets.resolve("sim"), ("sim", None))

    def test_vh_storage_and_hosts_refused(self):
        for spec in ("vh-storage", "https://vh-local.cooperhlarson.com", "user@host", "production", None, ""):
            with self.assertRaises(targets.TargetRefused):
                targets.resolve(spec)

    def test_valid_private_descriptor_accepted(self):
        p = self.tmp / "target.json"
        p.write_text(json.dumps(self._descriptor()))
        kind, t = targets.resolve(str(p))
        self.assertEqual(kind, "private")
        self.assertEqual(t.run_id, "r1")
        # a directory holding target.json works too
        self.assertEqual(targets.resolve(str(self.tmp))[0], "private")

    def test_descriptor_failing_a_rule_is_refused(self):
        for bad in ({"kind": "something-else"}, {"run_dir": "/var/lib/vaulthalla"}, {"db_name": "vaulthalla"},
                    {"pid": 999999}, {"ws_port": 0}):
            p = self.tmp / "t.json"
            p.write_text(json.dumps(self._descriptor(**bad)))
            with self.assertRaises(targets.TargetRefused):
                targets.resolve(str(p))

    def test_missing_fields_refused(self):
        p = self.tmp / "t.json"
        p.write_text(json.dumps({"kind": "vhh-private-local"}))
        with self.assertRaises(targets.TargetRefused):
            targets.resolve(str(p))


class Cli(TempDir, unittest.TestCase):
    def test_oracle_check_passes_for_pentest_v1(self):
        self.assertEqual(cli.main(["world", "oracle-check", "--world", "pentest-v1"]), cli.PASS)

    def test_run_on_sim_passes_and_verifies(self):
        out = self.tmp / "run"
        rc = cli.main(["run", "--target", "sim", "--seed", "0x1", "--schedule", "barrier", "--sessions", "4",
                       "--ops", "15", "--surfaces", "ws,fuse", "--out", str(out)])
        self.assertEqual(rc, cli.PASS)
        self.assertTrue((out / "trace.jsonl").is_file())
        self.assertEqual(cli.main(["verify", "--trace", str(out / "trace.jsonl")]), cli.PASS)

    def test_run_refuses_vh_storage(self):
        self.assertEqual(cli.main(["run", "--target", "vh-storage"]), cli.REFUSED)

    def test_fixture_emission(self):
        out = self.tmp / "fix"
        rc = cli.main(["world", "fixture", "--world", "pentest-v1", "--out", str(out), "--build-version", "1.2.3"])
        self.assertEqual(rc, cli.PASS)
        manifest = json.loads((out / "manifest.json").read_text())
        self.assertEqual(manifest["fixture_version"], 1)
        self.assertEqual(len(manifest["expectations"]), 59)

    def test_broken_world_fails(self):
        p = self.tmp / "bad.json"
        p.write_text('{"name":"bad"}')
        self.assertEqual(cli.main(["world", "show", "--world", str(p)]), cli.FAIL)


if __name__ == "__main__":
    unittest.main()
