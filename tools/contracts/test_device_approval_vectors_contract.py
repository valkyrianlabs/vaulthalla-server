"""#361: the device approval payload vector Vaulthalla Desktop shares is internally consistent and read by the C++ suite.

`tools/dev/device_approval_vectors.py --check` recomputes every payload of core/test-assets/device/approval-vectors.json
and verifies every signature (it needs `cryptography`, which the CI image carries); DeviceApprovalVectors
(core/tests/unit/test_device_approvals.cpp) asserts the same file against device::crypto::approvalMessage. These checks
keep the two from drifting apart.
"""

import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VECTORS = REPO / "core" / "test-assets" / "device" / "approval-vectors.json"
REFERENCE = REPO / "tools" / "dev" / "device_approval_vectors.py"
CPP_TEST = REPO / "core" / "tests" / "unit" / "test_device_approvals.cpp"


class DeviceApprovalVectorsContract(unittest.TestCase):
    def test_reference_check_passes(self) -> None:
        if importlib.util.find_spec("cryptography") is None:
            if os.environ.get("CI"):
                self.fail("the CI image must carry python3-cryptography so device_approval_vectors.py --check runs")
            self.skipTest("python cryptography is not installed (CI runs this)")
        result = subprocess.run([sys.executable, str(REFERENCE), "--check"], capture_output=True, text=True,
                                timeout=120, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_the_vector_names_one_change_per_field(self) -> None:
        doc = json.loads(VECTORS.read_text())
        fields = set(doc["positive"]["fields"])
        self.assertEqual({n["name"] for n in doc["negative"]}, {"wrong_" + f for f in fields})
        for n in doc["negative"]:
            changed = {k for k in fields if n["fields"][k] != doc["positive"]["fields"][k]}
            self.assertEqual(changed, {n["name"].removeprefix("wrong_")}, n["name"])

    def test_the_cpp_suite_reads_this_file(self) -> None:
        source = CPP_TEST.read_text()
        self.assertIn('"device" / "approval-vectors.json"', source)
        for section in ("positive", "negative", "wrong_key", "no_payload"):
            self.assertIn('"%s"' % section, source, section)


if __name__ == "__main__":
    unittest.main()
