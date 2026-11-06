"""#367 IntegrityContract (design/encryption/02-authenticated-file-format.md §3.7, §7): no VHF1 read reaches the GCM CTR
keystream.

crypto::util::gcmCtrDecryptAt releases plaintext of a legacy AES-GCM message before its tag is checked. VHF1 readers
authenticate whole chunks before any byte leaves them, so the keystream must never appear on a VHF1 path. This guard
pins where the call may appear at all (legacy GCM readers and staging formats that are not vault file content), and
that it never appears in the VHF1 read path. The runtime half is Vhf1AtRestTest.IntegrityContract* (it counts calls
while every VHF1 reader runs) and CloudRemoteReadTest.Vhf1RangedReadsAreAuthenticatedChunkWindows.
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "core" / "src"
CALL = re.compile(r"\bgcmCtrDecryptAt\s*\(")

# Every caller, and why it is not a VHF1 path.
ALLOWED = {
    "core/src/crypto/util/Gcm.cpp": "the primitive itself",
    "core/src/storage/GcmFileReader.cpp": "legacy GCM vault files and VHDERIV1 derived artifacts",
    "core/src/storage/RemoteRangedReader.cpp": "legacy GCM remote objects (the VHF1 mode uses RangeReader)",
    "core/src/protocols/s3/PartCipher.cpp": "S3 gateway multipart parts (a staging format, #345)",
    "core/src/protocols/http/upload/Resumable.cpp": "resumable parts and the legacy-format cursor (uploads created before #367)",
}

# The VHF1 read path: none of these may use the keystream.
VHF1_PATH = [
    "core/src/crypto/vhf1",
    "core/src/vault/Content.cpp",
    "core/src/vault/PrefixSealer.cpp",
    "core/src/storage/Vhf1FileReader.cpp",
]


def _calls(path: Path) -> list[int]:
    lines = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if CALL.search(line.split("//", 1)[0]):
            lines.append(lineno)
    return lines


class IntegrityContract(unittest.TestCase):
    def test_gcm_ctr_keystream_has_only_allowlisted_callers(self) -> None:
        offenders = []
        for path in sorted(SRC.rglob("*.cpp")):
            rel = str(path.relative_to(REPO))
            if rel in ALLOWED:
                continue
            offenders += [f"{rel}:{n}" for n in _calls(path)]
        self.assertEqual(offenders, [], "gcmCtrDecryptAt releases unauthenticated plaintext; a new caller needs review:\n"
                         + "\n".join(offenders))

    def test_vhf1_read_path_never_uses_the_keystream(self) -> None:
        offenders = []
        for entry in VHF1_PATH:
            target = REPO / entry
            files = sorted(target.rglob("*.cpp")) if target.is_dir() else [target]
            self.assertTrue(files and all(f.exists() for f in files), f"{entry} is missing")
            for path in files:
                offenders += [f"{path.relative_to(REPO)}:{n}" for n in _calls(path)]
        self.assertEqual(offenders, [], "\n".join(offenders))

    def test_the_legacy_ranged_branch_is_the_only_keystream_use_in_the_remote_reader(self) -> None:
        source = (REPO / "core/src/storage/RemoteRangedReader.cpp").read_text(encoding="utf-8")
        self.assertIn("if (params_.key && !vhf1_)", source,
                      "the ranged reader must take the keystream branch only for legacy (non-VHF1) objects")


if __name__ == "__main__":
    unittest.main()
