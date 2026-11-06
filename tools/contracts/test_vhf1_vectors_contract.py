"""#365, #368: the golden vectors, their reference reader and the C++ suites mean the same thing.

`design/encryption/vectors/vh_crypto_vectors.py --check` regenerates vectors.json and verifies every vector with the
reference reader; `Vhf1Vectors` (core/tests/unit/test_vhf1.cpp) and `ManifestVectors` (core/tests/unit/test_manifest.cpp)
read the same vectors.json at test time. These checks keep them from drifting: --check passes (it needs `cryptography`,
which the CI image carries), every VHF1 and manifest section the reference verifies is consumed by a C++ suite or
explicitly deferred to the workstream that owns it, every error code the vectors use exists in crypto::vhf1 or in the
manifest chain rules (sync::manifest::ChainError), every acceptance warning is one the C++ reader reports, and the unit
tests are pointed at this vectors directory.
"""

import importlib.util
import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VECTORS_DIR = REPO / "design" / "encryption" / "vectors"
VECTORS = VECTORS_DIR / "vectors.json"
REFERENCE = VECTORS_DIR / "vh_crypto_vectors.py"
CPP_TEST = REPO / "core" / "tests" / "unit" / "test_vhf1.cpp"
CPP_MANIFEST_TEST = REPO / "core" / "tests" / "unit" / "test_manifest.cpp"
CPP_TESTS = (CPP_TEST, CPP_MANIFEST_TEST)
CPP_FORMAT = REPO / "core" / "src" / "crypto" / "vhf1" / "Format.cpp"
CPP_CHAIN = REPO / "core" / "src" / "sync" / "manifest" / "Chain.cpp"
MESON = REPO / "core" / "meson.build"

# Sections of the vectors that --check verifies but no C++ suite reads yet; each names who owns them. A new VHF1 or
# manifest section must be consumed by test_vhf1.cpp or test_manifest.cpp, never added here. (The manifest chain,
# deferred by #365, is WS3-a's and read by ManifestVectors since #368.)
DEFERRED: dict[tuple[str, str], str] = {}
VHF1_GROUPS = ("vhf1", "manifest")


def reference_sections() -> set[tuple[str, str]]:
    """The (group, section) pairs the reference verify() reads, e.g. doc["vhf1"]["negative"]."""
    text = REFERENCE.read_text(encoding="utf-8")
    verify = text[text.index("def verify("):text.index("def render(")]
    found = set()
    for group in VHF1_GROUPS:
        found |= {(group, s) for s in re.findall(r'doc\["%s"\]\["(\w+)"\]' % group, verify)}
    return found


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

    def test_every_vhf1_section_the_reference_verifies_is_consumed_by_the_cpp_suite(self) -> None:
        doc = json.loads(VECTORS.read_text(encoding="utf-8"))
        cpp = "\n".join(p.read_text(encoding="utf-8") for p in CPP_TESTS)
        consumed = {(g, s) for g in VHF1_GROUPS for s in re.findall(r'\["%s"\]\["(\w+)"\]' % g, cpp)}
        verified = reference_sections()
        self.assertTrue(verified, "found no sections in the reference verify(); did its structure change?")
        in_file = {(g, s) for g in VHF1_GROUPS for s in doc[g]}
        missing = sorted((verified | in_file) - consumed - DEFERRED.keys())
        self.assertEqual(missing, [], "vector sections no C++ test reads (test_vhf1.cpp, test_manifest.cpp)")
        stale = sorted(k for k in DEFERRED if k not in in_file)
        self.assertEqual(stale, [], "DEFERRED names sections the vectors no longer have")

    def test_every_vector_error_code_exists_in_the_codec(self) -> None:
        doc = json.loads(VECTORS.read_text(encoding="utf-8"))
        codes = set(re.findall(r'\{ErrorCode::\w+, "(\w+)"\}', CPP_FORMAT.read_text(encoding="utf-8")))
        self.assertIn("chunk_auth_failed", codes, "error-name table not found in Format.cpp")
        used = set()
        for entry in doc["vhf1"]["negative"] + doc["vhf1"]["range_negative"] + doc["manifest"]["negative"]:
            if "error" in entry["expect"]:
                used.add(entry["expect"]["error"])
        self.assertEqual(sorted(used - codes), [], "vector error codes without a crypto::vhf1::ErrorCode")

    def test_every_manifest_chain_outcome_exists_in_the_reader(self) -> None:
        doc = json.loads(VECTORS.read_text(encoding="utf-8"))
        names = set(re.findall(r'\{ChainError::\w+, "(\w+)"\}', CPP_CHAIN.read_text(encoding="utf-8")))
        self.assertIn("rollback", names, "chain error-name table not found in Chain.cpp")
        cases = doc["manifest"]["chain"]
        errors = {c["expect"]["error"] for c in cases if "error" in c["expect"]}
        self.assertEqual(sorted(errors - names), [], "chain vector errors without a sync::manifest::ChainError")
        warnings = {c["expect"]["warning"] for c in cases if "warning" in c["expect"]}
        self.assertEqual(warnings, {"gap"}, "the chain vectors' warnings changed; teach ManifestVectors the new one")
        self.assertIn('got["warning"] = "gap"', CPP_MANIFEST_TEST.read_text(encoding="utf-8"))
        # Every rule of spec 03 §4.1 the vectors can state has a case: accept, advance, rollback, fork, gap and both
        # segment pins.
        self.assertTrue({"rollback", "fork", "segment_missing", "segment_mismatch"} <= errors)
        self.assertTrue(any(c["known"] is None and "epoch" in c["expect"] for c in cases))

    def test_manifest_suite_iterates_every_vector_of_each_section(self) -> None:
        cpp = CPP_MANIFEST_TEST.read_text(encoding="utf-8")
        for section in ("objects", "chain", "negative"):
            self.assertRegex(cpp, r'for \(const auto& \w+ : vectors\(\)\["manifest"\]\["%s"\]\)' % section,
                             f"ManifestVectors must loop over every manifest {section} vector")

    def test_unit_tests_read_this_vectors_directory(self) -> None:
        meson = MESON.read_text(encoding="utf-8")
        self.assertIn("-DVH_TEST_VECTORS_DIR=\"' + join_paths(repo_root, 'design', 'encryption', 'vectors')", meson)
        for path in CPP_TESTS:
            self.assertIn("VH_TEST_VECTORS_DIR", path.read_text(encoding="utf-8"), path.name)


if __name__ == "__main__":
    unittest.main()
