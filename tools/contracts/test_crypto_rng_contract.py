"""#318: key material and security-relevant names come from libsodium's CSPRNG, never from <random>.

std::random_device's source is implementation-defined and the <random> engines (mt19937 & co.) are predictable from
their output. This guard keeps them out of the daemon's source, where a reintroduction would most likely end up
generating a key, token, nonce or plaintext file name.
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCANNED = [REPO / "core" / "src", REPO / "core" / "include"]
FORBIDDEN = re.compile(r"\bstd::(random_device|mt19937(_64)?|minstd_rand0?|default_random_engine|ranlux\w*)\b|\bs?rand\s*\(")
# Paths that may use <random> for non-security purposes (test-only jitter, simulations). Keep this list empty unless
# a reviewer agrees the use can never produce key material or a name an attacker benefits from predicting.
ALLOWED: set[str] = set()


class CryptoRngContract(unittest.TestCase):
    def test_no_non_crypto_rng_in_daemon_sources(self) -> None:
        offenders = []
        for root in SCANNED:
            for path in sorted(root.rglob("*")):
                if path.suffix not in {".cpp", ".hpp", ".h"} or "vendor" in path.parts:
                    continue
                rel = str(path.relative_to(REPO))
                if rel in ALLOWED:
                    continue
                for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    code = line.split("//", 1)[0]
                    if FORBIDDEN.search(code):
                        offenders.append(f"{rel}:{lineno}: {line.strip()}")
        self.assertEqual(offenders, [], "use randombytes_buf / randombytes_uniform (libsodium) instead:\n" + "\n".join(offenders))


if __name__ == "__main__":
    unittest.main()
