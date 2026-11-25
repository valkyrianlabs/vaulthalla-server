"""design/peers/link.md: the server link's pairing vector is what its independent reference computes, and the C++ suite
reads it.

`tools/dev/peer_pairing_vectors.py --check` recomputes core/test-assets/peer/pairing-vectors.json (standard library
only); PeerCryptoVectors (core/tests/unit/test_peer_crypto.cpp) asserts the same file against peer::crypto.
"""

import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REFERENCE = REPO / "tools" / "dev" / "peer_pairing_vectors.py"
CPP_TEST = REPO / "core" / "tests" / "unit" / "test_peer_crypto.cpp"


class PeerPairingVectorsContract(unittest.TestCase):
    def test_reference_check_passes(self) -> None:
        result = subprocess.run([sys.executable, str(REFERENCE), "--check"], capture_output=True, text=True,
                                timeout=60, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_the_cpp_suite_reads_the_vector(self) -> None:
        self.assertIn("peer/pairing-vectors.json", CPP_TEST.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
