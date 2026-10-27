"""Contract: CI neither runs nor compiles the DB-only unit test files.

DB-backed suites are manual validation (`make test`, tools/macos/test-db.sh): without VH_TEST_DB_* they skip. Files
whose every test is DB-backed start with the marker line; `-Ddb_tests=false` (both CI builds) leaves them out of
vh_unit_tests. A marked file must actually be DB-backed, or CI would silently lose its tests.
"""

from __future__ import annotations

from pathlib import Path
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
MARKER = "// vh-test-tier: db-only"
# Headers whose fixtures carry the VH_TEST_DB_* guard for the files that include them.
DB_HARNESS_HEADERS = ("recovery_local.hpp", "sync_conflict_harness.hpp")


def _read(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


class DbTestTierContractTests(unittest.TestCase):
    def test_marked_files_are_db_backed(self) -> None:
        marked = [p for p in sorted((REPO_ROOT / "core/tests/unit").rglob("*.cpp"))
                  if MARKER in p.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(marked)
        for path in marked:
            text = path.read_text(encoding="utf-8")
            with self.subTest(file=path.name):
                self.assertTrue("VH_TEST_DB_" in text or any(h in text for h in DB_HARNESS_HEADERS),
                                f"{path.name} is marked db-only but has no VH_TEST_DB_* guard")

    def test_meson_filters_on_the_marker(self) -> None:
        self.assertIn(f'grep -L -F -x "{MARKER}"', _read("core/meson.build"))
        self.assertIn("'db_tests'", _read("meson.options"))

    def test_ci_builds_leave_db_only_files_out(self) -> None:
        for rel in (".github/actions/build/action.yml", ".github/workflows/macos.yml"):
            with self.subTest(file=rel):
                self.assertIn("-Dbuild_unit_tests=true -Ddb_tests=false", _read(rel))
        # And no CI job starts a test database for them.
        self.assertNotIn("test-db.sh up", _read(".github/workflows/macos.yml"))


if __name__ == "__main__":
    unittest.main()
