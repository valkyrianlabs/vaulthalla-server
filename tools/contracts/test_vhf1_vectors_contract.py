"""#365: the golden vectors, their reference reader and the C++ VHF1 suite mean the same thing.

`design/encryption/vectors/vh_crypto_vectors.py --check` regenerates vectors.json and verifies every vector with the
reference reader; `Vhf1Vectors` (core/tests/unit/test_vhf1.cpp) reads the same vectors.json at test time. These checks
keep the two from drifting: --check passes (it needs `cryptography`, which the CI image carries), every VHF1 section
the reference verifies is consumed by the C++ suite or explicitly deferred to the workstream that owns it, every error
code the vectors use exists in crypto::vhf1, and the unit tests are pointed at this vectors directory.
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
CPP_FORMAT = REPO / "core" / "src" / "crypto" / "vhf1" / "Format.cpp"
MESON = REPO / "core" / "meson.build"

# Sections of the vectors that --check verifies but that are not VHF1 objects; each names who owns them. A new VHF1
# section must be consumed by test_vhf1.cpp, never added here.
DEFERRED = {
    ("manifest", "chain"): "WS3-a: manifest root chain acceptance (spec 03), not the VHF1 codec",
}
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
        cpp = CPP_TEST.read_text(encoding="utf-8")
        consumed = {(g, s) for g in VHF1_GROUPS for s in re.findall(r'\["%s"\]\["(\w+)"\]' % g, cpp)}
        verified = reference_sections()
        self.assertTrue(verified, "found no sections in the reference verify(); did its structure change?")
        in_file = {(g, s) for g in VHF1_GROUPS for s in doc[g]}
        missing = sorted((verified | in_file) - consumed - DEFERRED.keys())
        self.assertEqual(missing, [], "VHF1 vector sections no C++ test reads (test_vhf1.cpp)")
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

    def test_unit_tests_read_this_vectors_directory(self) -> None:
        meson = MESON.read_text(encoding="utf-8")
        self.assertIn("-DVH_TEST_VECTORS_DIR=\"' + join_paths(repo_root, 'design', 'encryption', 'vectors')", meson)
        self.assertIn("VH_TEST_VECTORS_DIR", CPP_TEST.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
