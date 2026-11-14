"""#443: the code that becomes the shared vault format library includes nothing of the server.

The VHF1 file format, object naming and the manifest (with its publish protocol and the Session logic) will be
extracted into vl-vaultfmt, which the server, a Desktop-only engine and a browser reader link. Until then the
candidates live in this repository, and this contract keeps them extractable: they may include only each other,
vl-keykit, OpenSSL, nlohmann and the standard library. Anything else (the database, logging, the S3 controller,
libsodium, fmt, pugixml, a POSIX header) is the server's and belongs on its side of the seam:
storage::s3::ManifestStore, sync::vault_manifest and db::query::sync::Manifest.
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
INCLUDE_ROOT = REPO / "core" / "include"

# Directories (every .cpp/.hpp under them) and single files.
CANDIDATES = [
    "core/include/crypto/vhf1",
    "core/src/crypto/vhf1",
    "core/include/sync/manifest",
    "core/src/sync/manifest",
    "core/include/storage/ObjectKeys.hpp",
    "core/src/storage/ObjectKeys.cpp",
    # What moves with the library's own tests: the fuzz target and the store test helpers.
    "core/tests/fuzz",
    "core/tests/helpers/hooked_store.hpp",
    "core/tests/helpers/memory_store.hpp",
]

ALLOWED_LIBRARIES = ("vl/keykit/", "openssl/", "nlohmann/")
INCLUDE = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]', re.MULTILINE)


def candidate_files() -> list[Path]:
    files: list[Path] = []
    for rel in CANDIDATES:
        path = REPO / rel
        if path.is_dir():
            files += sorted(p for p in path.rglob("*") if p.suffix in {".cpp", ".hpp"})
        else:
            files.append(path)
    return files


def is_standard_header(name: str) -> bool:
    # <vector>, <cstdint>: no directory and no extension. <unistd.h>, <sys/mman.h>, <fmt/format.h> are not.
    return "/" not in name and "." not in name


class FormatLibraryContract(unittest.TestCase):
    def test_every_candidate_exists(self) -> None:
        for rel in CANDIDATES:
            self.assertTrue((REPO / rel).exists(), f"{rel} is a candidate of the format library (#443)")
        self.assertGreater(len(candidate_files()), 30)

    def test_candidates_include_only_each_other_keykit_openssl_nlohmann_and_the_standard_library(self) -> None:
        files = candidate_files()
        candidates = {f.resolve() for f in files}
        offenders = []
        for path in files:
            rel = path.relative_to(REPO)
            for kind, name in INCLUDE.findall(path.read_text(encoding="utf-8")):
                if kind == "<":
                    if is_standard_header(name) or name.startswith(ALLOWED_LIBRARIES):
                        continue
                else:
                    # A project header (from core/include) or a neighbour: either way a candidate itself.
                    targets = [(INCLUDE_ROOT / name).resolve(), (path.parent / name).resolve()]
                    if any(t in candidates for t in targets):
                        continue
                offenders.append(f"{rel}: #include {'<' if kind == '<' else chr(34)}{name}{'>' if kind == '<' else chr(34)}")
        self.assertEqual(offenders, [], "the format library's candidates include something of the server (#443):\n"
                         + "\n".join(offenders))

    def test_the_servers_side_of_the_seam_is_outside_the_candidates(self) -> None:
        for rel in ("core/include/storage/s3/ManifestStore.hpp", "core/src/storage/s3/ManifestStore.cpp",
                    "core/include/sync/vault_manifest/Service.hpp", "core/src/sync/vault_manifest/Service.cpp"):
            self.assertTrue((REPO / rel).is_file(), rel)
        for rel in ("core/include/sync/manifest/Service.hpp", "core/src/sync/manifest/Service.cpp"):
            self.assertFalse((REPO / rel).exists(), f"{rel}: the server's wiring is sync::vault_manifest")
        # The fuzz target builds from the format's own sources and its two libraries, not from libvaulthalla.
        fuzz = (REPO / "core/tests/fuzz/meson.build").read_text(encoding="utf-8")
        self.assertNotIn("libsodium", fuzz)
        self.assertNotIn("crypto/util", fuzz)


if __name__ == "__main__":
    unittest.main()
