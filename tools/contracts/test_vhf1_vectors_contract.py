"""#365, #368: the golden vectors and their reference reader agree, and the format library is checked against them.

`design/encryption/vectors/vh_crypto_vectors.py --check` regenerates vectors.json and verifies every vector with the
reference reader (it needs `cryptography`, which the CI image carries). The C++ that the vhf1 and manifest sections
describe moved to vl-vaultfmt (design/core/vault-format-library.md, work item 7), whose own suites and
tests/vectors_contract.py hold them to every section, error code and chain outcome. Here: the reference check passes,
the library's copy of the vectors is required identical to this one (test_vaultfmt_vectors.cpp, as
test_keykit_vectors.cpp does for vl-keykit's), and the unit tests are pointed at this vectors directory.
"""

import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VECTORS_DIR = REPO / "design" / "encryption" / "vectors"
REFERENCE = VECTORS_DIR / "vh_crypto_vectors.py"
# vl-vaultfmt 0.3.0's own vectors for the manifest root's writer floor, copied beside the verbatim pair.
WRITER_FLOOR_REFERENCE = VECTORS_DIR / "writer_floor_vectors.py"
# Key provenance (spec 03 §6.5), copied verbatim to vl-keykit, which implements it for this server and Desktop.
KEY_PROVENANCE_REFERENCE = VECTORS_DIR / "key_provenance_vectors.py"
CPP_COPY_TEST = REPO / "core" / "tests" / "unit" / "test_vaultfmt_vectors.cpp"
CPP_VECTORS_HELPER = REPO / "core" / "tests" / "helpers" / "bytes.hpp"
MESON = REPO / "core" / "meson.build"


class Vhf1VectorsContract(unittest.TestCase):
    def test_reference_check_passes(self) -> None:
        if importlib.util.find_spec("cryptography") is None:
            if os.environ.get("CI"):
                self.fail("the CI image must carry python3-cryptography so vh_crypto_vectors.py --check runs")
            self.skipTest("python cryptography is not installed (CI runs this)")
        result = subprocess.run([sys.executable, str(REFERENCE), "--check"], capture_output=True, text=True,
                                timeout=300, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("OK:", result.stdout)

    def test_writer_floor_reference_check_passes(self) -> None:
        if importlib.util.find_spec("cryptography") is None:
            if os.environ.get("CI"):
                self.fail("the CI image must carry python3-cryptography so writer_floor_vectors.py --check runs")
            self.skipTest("python cryptography is not installed (CI runs this)")
        result = subprocess.run([sys.executable, str(WRITER_FLOOR_REFERENCE), "--check"], capture_output=True,
                                text=True, timeout=300, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_key_provenance_reference_check_passes(self) -> None:
        if importlib.util.find_spec("cryptography") is None:
            if os.environ.get("CI"):
                self.fail("the CI image must carry python3-cryptography so key_provenance_vectors.py --check runs")
            self.skipTest("python cryptography is not installed (CI runs this)")
        result = subprocess.run([sys.executable, str(KEY_PROVENANCE_REFERENCE), "--check"], capture_output=True,
                                text=True, timeout=300, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_the_format_librarys_copy_is_required_identical(self) -> None:
        cpp = CPP_COPY_TEST.read_text(encoding="utf-8")
        self.assertIn("VH_TEST_VAULTFMT_VECTORS_DIR", cpp)
        self.assertIn("TheWriterFloorVectorsAreTheLinkedLibrarysRules", cpp, "the writer floor vectors are consumed")
        for name in ("vectors.json", "vh_crypto_vectors.py", "writer_floor.json", "writer_floor_vectors.py"):
            self.assertIn(f'"{name}"', cpp)
        self.assertIn("goldenVectors()", cpp, "one vector through the linked library")

    def test_unit_tests_read_this_vectors_directory(self) -> None:
        meson = MESON.read_text(encoding="utf-8")
        self.assertIn("-DVH_TEST_VECTORS_DIR=\"' + join_paths(repo_root, 'design', 'encryption', 'vectors')", meson)
        self.assertIn("-DVH_TEST_VAULTFMT_VECTORS_DIR=", meson)
        # The suites read the file through the shared helper (vh::test::bin::goldenVectors()).
        self.assertIn("VH_TEST_VECTORS_DIR", CPP_VECTORS_HELPER.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
