"""#443: the vault format is vl-vaultfmt, pinned and packaged (design/core/vault-format-library.md, work items 7 and 8).

The VHF1 file format, object naming and the encrypted manifest (with its publish protocol, reader, reconcile and the
Session logic) moved to valkyrianlabs/vl-vaultfmt (AGPL-3.0-or-later), which the server, the Desktop-only engine and the
browser reader link. The daemon links the commit pinned in subprojects/vl-vaultfmt.wrap, whose tarball is committed for
the offline Debian build, keeps no in-tree copy, and reaches the format only through the library's headers
(<vl/vaultfmt/...>). What stays here is the server's side of the seam: storage::s3::ManifestStore (the ObjectStore over
the metered controller), sync::vault_manifest (the wiring and the PostgreSQL StateStore) and db::query::sync::Manifest.
"""

import hashlib
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# What moved to vl-vaultfmt (its include/vl/vaultfmt/, src/, tests/, fuzz/).
MOVED = [
    "core/include/crypto/vhf1",
    "core/src/crypto/vhf1",
    "core/include/sync/manifest",
    "core/src/sync/manifest",
    "core/include/storage/ObjectKeys.hpp",
    "core/src/storage/ObjectKeys.cpp",
    "core/tests/fuzz",
    "core/tests/helpers/hooked_store.hpp",
    "core/tests/helpers/memory_store.hpp",
    "core/tests/unit/test_vhf1.cpp",
    "core/tests/unit/test_manifest_reconcile.cpp",
]

# The old spellings of the moved code: an include path or a namespace of the server.
OLD_INCLUDE = re.compile(r'#\s*include\s*["<](crypto/vhf1/|sync/manifest/|storage/ObjectKeys\.hpp|'
                         r'(\.\./)?helpers/(hooked|memory)_store\.hpp)')
OLD_NAMESPACE = re.compile(r"\b(vh::)?(crypto::vhf1|sync::manifest|storage::object_keys|"
                           r"test_support::manifest_store)\b|(?<![\w:])object_keys::")
QUOTED_LIBRARY_INCLUDE = re.compile(r'#\s*include\s*"vl/vaultfmt/')


def read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def server_sources() -> list[Path]:
    return sorted(p for p in (REPO / "core").rglob("*") if p.suffix in {".cpp", ".hpp", ".h"} and p.is_file())


class FormatLibraryContract(unittest.TestCase):
    def test_the_format_is_the_pinned_vl_vaultfmt(self) -> None:
        wrap = read("subprojects/vl-vaultfmt.wrap")
        directory = re.search(r"(?m)^directory = (vl-vaultfmt-[0-9.]+)$", wrap)
        filename = re.search(r"(?m)^source_filename = (\S+)$", wrap)
        digest = re.search(r"(?m)^source_hash = ([0-9a-f]{64})$", wrap)
        self.assertTrue(directory and filename and digest, wrap)
        self.assertEqual(filename.group(1), directory.group(1) + ".tar.xz")
        tarball = REPO / "subprojects" / "packagecache" / filename.group(1)
        self.assertTrue(tarball.is_file(), f"{tarball} is committed for the offline Debian build")
        self.assertEqual(hashlib.sha256(tarball.read_bytes()).hexdigest(), digest.group(1))
        self.assertIn("vl-vaultfmt = vl_vaultfmt_dep", wrap)
        meson = read("core/meson.build")
        self.assertIn("dependency('vl-vaultfmt', version: '>=0.4.0', fallback: ['vl-vaultfmt', 'vl_vaultfmt_dep'])", meson)
        self.assertIn("VH_TEST_VAULTFMT_VECTORS_DIR", meson)
        self.assertIn("subprojects/vl-vaultfmt.wrap", read("debian/copyright"))
        # The library's copy of the vectors is checked identical to ours, as vl-keykit's is.
        self.assertIn("VH_TEST_VAULTFMT_VECTORS_DIR", read("core/tests/unit/test_vaultfmt_vectors.cpp"))

    def test_no_in_tree_copy_remains(self) -> None:
        for rel in MOVED:
            self.assertFalse((REPO / rel).exists(), f"{rel} moved to vl-vaultfmt")

    def test_the_server_reaches_the_format_only_through_the_library(self) -> None:
        offenders = []
        for path in server_sources():
            rel = path.relative_to(REPO)
            text = path.read_text(encoding="utf-8", errors="replace")
            for line_no, line in enumerate(text.splitlines(), 1):
                code = line.split("//", 1)[0]
                if OLD_INCLUDE.search(code) or OLD_NAMESPACE.search(code) or QUOTED_LIBRARY_INCLUDE.search(code):
                    offenders.append(f"{rel}:{line_no}: {line.strip()}")
        self.assertEqual(offenders, [], "the vault format is vl-vaultfmt's (<vl/vaultfmt/...>, vl::vaultfmt::):\n"
                         + "\n".join(offenders))

    def test_the_servers_side_of_the_seam_stays_here(self) -> None:
        for rel in ("core/include/storage/s3/ManifestStore.hpp", "core/src/storage/s3/ManifestStore.cpp",
                    "core/include/sync/vault_manifest/Service.hpp", "core/src/sync/vault_manifest/Service.cpp",
                    "core/include/db/query/sync/Manifest.hpp", "core/tests/helpers/versioned_bucket.hpp"):
            self.assertTrue((REPO / rel).is_file(), rel)
        # The interleavings suites keep running here on the HTTP-level fake behind the server's adapter.
        self.assertIn("storage::s3::ManifestStore", read("core/tests/unit/test_manifest_interleavings.cpp"))

    def test_the_fuzz_target_moved_with_the_codec(self) -> None:
        self.assertNotIn("'fuzz'", read("meson.options"))
        self.assertNotIn("get_option('fuzz')", read("meson.build"))
        self.assertNotIn("-Dfuzz=true", read(".github/workflows/build_and_test.yml"))


if __name__ == "__main__":
    unittest.main()
