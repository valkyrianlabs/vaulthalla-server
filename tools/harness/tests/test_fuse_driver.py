"""FuseDriver path mapping: lexical only (the engine must never touch the mount; a stopped daemon blocks it)."""
import os
import unittest
from unittest import mock

from vhh.drivers.fuse import FuseDriver


class FusePaths(unittest.TestCase):
    def setUp(self):
        self.d = FuseDriver("/nonexistent/vh_fs_actor", "/tmp/vhh_x/mnt", 2100000001, 2100000001)

    def test_paths_are_mapped_without_any_filesystem_call(self):
        boom = mock.Mock(side_effect=AssertionError("touched the filesystem"))
        with mock.patch.object(os, "stat", boom), mock.patch.object(os, "lstat", boom), \
                mock.patch.object(os.path, "realpath", boom):
            self.assertEqual(self.d.path("vault/a/b.txt"), "/tmp/vhh_x/mnt/vault/a/b.txt")
            self.assertEqual(self.d.path("/vault/./c/../d"), "/tmp/vhh_x/mnt/vault/d")
            self.assertEqual(self.d.path("/"), "/tmp/vhh_x/mnt")

    def test_escapes_are_refused(self):
        for rel in ("../etc/passwd", "vault/../../x", "/../../tmp"):
            with self.assertRaises(ValueError):
                self.d.path(rel)


if __name__ == "__main__":
    unittest.main()
