"""The provisioner's run-directory guard: exactly /tmp/vhh_<run_id>, no symlink below /tmp. /tmp itself may be a
symlink (macOS: /private/tmp), which must neither break the guard nor loosen it."""
import os
import secrets
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from vhh.provision import _private_root

TMP = Path("/tmp").resolve()


def target(run_dir, run_id):
    return SimpleNamespace(run_dir=str(run_dir), run_id=run_id)


class PrivateRoot(unittest.TestCase):
    def setUp(self):
        self.run_id = "test" + secrets.token_hex(4)
        self.name = f"vhh_{self.run_id}"

    def assertRefused(self, run_dir, run_id=None):
        with self.assertRaises(ValueError, msg=str(run_dir)):
            _private_root(target(run_dir, run_id or self.run_id))

    def test_the_run_dir_under_tmp_is_canonical(self):
        self.assertEqual(_private_root(target(f"/tmp/{self.name}", self.run_id)), TMP / self.name)
        # Named through the resolved /tmp too (on Linux the same path).
        self.assertEqual(_private_root(target(TMP / self.name, self.run_id)), TMP / self.name)

    def test_name_and_parent_must_match(self):
        self.assertRefused(f"/tmp/vhh_other{self.run_id}")
        self.assertRefused(f"/tmp/{self.name}", run_id=self.run_id + "x")
        self.assertRefused(f"/var/tmp/{self.name}")
        self.assertRefused(f"/tmp/nested/{self.name}")
        self.assertRefused(f"/tmp/x/../{self.name}")
        self.assertRefused(f"{self.name}")
        self.assertRefused(f"/{self.name}")

    def test_a_symlinked_run_dir_is_refused(self):
        elsewhere = Path(tempfile.mkdtemp(prefix="vhh-root-test-", dir=os.path.expanduser("~")))
        self.addCleanup(shutil.rmtree, elsewhere, ignore_errors=True)
        link = TMP / self.name
        link.symlink_to(elsewhere, target_is_directory=True)
        self.addCleanup(link.unlink)
        self.assertRefused(f"/tmp/{self.name}")
        self.assertRefused(link)

    def test_a_real_run_dir_is_accepted(self):
        real = TMP / self.name
        real.mkdir(mode=0o700)
        self.addCleanup(real.rmdir)
        self.assertEqual(_private_root(target(f"/tmp/{self.name}", self.run_id)), real)
        sock = real / "cli.sock"
        self.assertTrue(sock.resolve().is_relative_to(_private_root(target(f"/tmp/{self.name}", self.run_id))))


if __name__ == "__main__":
    unittest.main()
