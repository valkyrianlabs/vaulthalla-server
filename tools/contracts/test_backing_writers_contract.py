"""Contract: nothing writes a vault backing file in place (file recovery, .claude/context/recovery.md).

Local versioning and snapshots retain a generation by hard-linking the sealed backing file into the recovery store
(zero-copy). The blob then shares the live file's inode until the next rename-replace, so a writer that opens an
existing backing file for writing (O_TRUNC / O_WRONLY / O_RDWR, an ofstream, pwrite, ftruncate) would silently
rewrite history. Every backing writer creates a new name exclusively (fs::ops::writeFileExclusive) or replaces by
rename (fs::ops::replaceFileAtomic / writeFileAtomic, the content sidecar + rename of overwrites, FUSE seals and
rotation).

The check is pattern-based over core/src: every in-place-capable write primitive must be listed below with the reason
it can never touch a backing file, and with how many there are in that file, so a new one (even in a listed file)
fails until someone looks at it. If you add one: write the backing file by rename instead, or, when it truly never
touches vault bytes, add it here with the reason.

Run by module: python3 -m unittest tools.contracts.test_backing_writers_contract
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE_SOURCES = REPO_ROOT / "core" / "src"

PATTERNS: dict[str, re.Pattern[str]] = {
    "ofstream": re.compile(r"\b(?:std::)?o?fstream\b"),
    "o_trunc": re.compile(r"\bO_TRUNC\b"),
    # open(2) for writing, unless it can only create a new name (O_EXCL) or an anonymous file (O_TMPFILE)
    "write_open": re.compile(r"::open\s*\([^;]*\bO_(?:WRONLY|RDWR)\b"),
    "write_file": re.compile(r"\bwriteFile\s*\("),
    "pwrite": re.compile(r"\bpwrite\s*\("),
    "truncate": re.compile(r"\b(?:ftruncate|resize_file)\s*\("),
    "fopen": re.compile(r"\bfopen\s*\("),
}

# (file, kind) -> (count, why it never writes a backing file in place)
ALLOWED: dict[tuple[str, str], tuple[int, str]] = {
    ("core/src/config/Config.cpp", "ofstream"): (1, "writes the YAML config file"),
    ("core/src/crypto/util/encrypt.cpp", "ofstream"): (1, "decrypt_aes256_gcm_file writes plaintext to a working copy / temp, never a backing path"),
    ("core/src/crypto/util/reseal.cpp", "o_trunc"): (1, "resealFile dst: callers pass a content sidecar or a fresh temp, renamed over the backing file"),
    ("core/src/crypto/util/reseal.cpp", "write_open"): (1, "same open as above"),
    ("core/src/fs/file/ops.cpp", "o_trunc"): (1, "writeFileAtomic writes its own private O_EXCL temp before the rename"),
    ("core/src/fs/file/ops.cpp", "write_open"): (1, "same open as above"),
    ("core/src/fuse/Bridge.cpp", "o_trunc"): (1, "reads the kernel's open flags (a working copy truncates, never the backing file)"),
    ("core/src/fuse/WorkingCopies.cpp", "o_trunc"): (1, "reads the kernel's open flags"),
    ("core/src/fuse/WorkingCopies.cpp", "pwrite"): (1, "writes the plaintext working copy under .fuse-plaintext; the seal renames a sidecar over the backing file"),
    ("core/src/fuse/WorkingCopies.cpp", "truncate"): (2, "truncates the working copy, not the backing file"),
    ("core/src/log/Rotator.cpp", "write_open"): (1, "log files"),
    ("core/src/log/Rotator.cpp", "fopen"): (1, "log files"),
    ("core/src/platform/darwin/FileSealer.cpp", "o_trunc"): (1, "TPM-substitute sealed secret files, written to a temp then renamed"),
    ("core/src/platform/darwin/FileSealer.cpp", "write_open"): (1, "same open as above"),
    ("core/src/platform/linux/Mount.cpp", "ofstream"): (1, "fusectl abort file"),
    ("core/src/platform/linux/TpmSealer.cpp", "ofstream"): (1, "sealed TPM blobs under the state directory"),
    ("core/src/protocols/http/upload/Coordinator.cpp", "ofstream"): (2, "HTTP upload temp parts; the commit goes through Filesystem::createFile"),
    ("core/src/protocols/s3/MultipartStore.cpp", "ofstream"): (3, "S3 gateway multipart staging files; the commit goes through Filesystem::createFile"),
    ("core/src/protocols/s3/MultipartStore.cpp", "write_file"): (2, "its own staging-file writer (definition + one use)"),
    ("core/src/protocols/s3/Session.cpp", "ofstream"): (2, "S3 gateway request body temp files"),
    ("core/src/protocols/shell/commands/helpers.cpp", "o_trunc"): (1, "CLI output files the operator names (exports)"),
    ("core/src/protocols/shell/commands/helpers.cpp", "write_open"): (1, "same open as above"),
    ("core/src/storage/s3/file.cpp", "ofstream"): (2, "Controller::downloadObject output path; no caller passes a backing path (hydrate streams into an O_TMPFILE and links it)"),
    ("core/src/storage/s3/pricing/PriceBotClient.cpp", "ofstream"): (1, "price-cache artifacts"),
    ("core/src/storage/s3/pricing/PriceCatalogStore.cpp", "ofstream"): (1, "price-cache catalog"),
    ("core/src/vault/EncryptionManager.cpp", "ofstream"): (1, "encryptFileToFile target: callers pass a content sidecar or a replaceFileAtomic temp"),
    ("core/src/vault/EncryptionManager.cpp", "o_trunc"): (1, "resealFileToCurrent dst: callers pass a content sidecar or a fresh temp"),
    ("core/src/vault/EncryptionManager.cpp", "write_open"): (1, "same open as above"),
}


def writers(text: str) -> Counter[str]:
    """Write primitives per kind in one source file (comments and #include lines ignored)."""
    found: Counter[str] = Counter()
    for raw in text.splitlines():
        code = raw.split("//", 1)[0]
        if code.lstrip().startswith("#include"):
            continue
        for kind, pattern in PATTERNS.items():
            if not pattern.search(code):
                continue
            if kind == "write_open" and ("O_EXCL" in code or "O_TMPFILE" in code):
                continue
            found[kind] += 1
    return found


class BackingWritersContractTests(unittest.TestCase):
    def test_detector_catches_in_place_writers(self) -> None:
        self.assertEqual(writers('std::ofstream(f->backing_path).close();')["ofstream"], 1)
        self.assertEqual(writers('writeFile(entry->backing_path, ciphertext);')["write_file"], 1)
        self.assertEqual(writers('int fd = ::open(p.c_str(), O_RDWR);')["write_open"], 1)
        self.assertEqual(writers('::pwrite(fd, b, n, 0);')["pwrite"], 1)
        self.assertEqual(writers('std::filesystem::resize_file(backing, 0);')["truncate"], 1)
        # ... creating a new name is not in place, and neither are reads, includes or comments.
        self.assertFalse(writers('int fd = ::open(p.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);'))
        self.assertFalse(writers('std::ifstream in(path, std::ios::binary);'))
        self.assertFalse(writers('#include <fstream>'))
        self.assertFalse(writers('// std::ofstream(f->backing_path)'))
        self.assertFalse(writers('writeFileAtomic(p, bytes); writeFileExclusive(p, {}, 0600);'))

    def test_every_write_primitive_is_accounted_for(self) -> None:
        unexpected: list[str] = []
        seen: dict[tuple[str, str], int] = {}
        for path in sorted(CORE_SOURCES.rglob("*.cpp")):
            rel = path.relative_to(REPO_ROOT).as_posix()
            for kind, count in writers(path.read_text(encoding="utf-8")).items():
                seen[(rel, kind)] = count
                allowed = ALLOWED.get((rel, kind))
                if allowed is None:
                    unexpected.append(f"{rel}: {count} new '{kind}' writer(s)")
                elif count > allowed[0]:
                    unexpected.append(f"{rel}: {count} '{kind}' writer(s), {allowed[0]} reviewed")
        self.assertEqual(
            unexpected, [],
            "A write primitive that could write a vault backing file in place (recovery.md, no-in-place-writer "
            "invariant). Replace by rename or create exclusively; if it never touches vault bytes, add it to ALLOWED "
            "with the reason:\n" + "\n".join(unexpected))

        stale = [f"{rel}: {kind}" for (rel, kind), (count, _) in ALLOWED.items() if seen.get((rel, kind), 0) < count]
        self.assertEqual(stale, [], "ALLOWED lists writers that are gone; lower or remove the entries:\n" + "\n".join(stale))

    def test_the_non_atomic_backing_writer_stays_gone(self) -> None:
        header = (REPO_ROOT / "core" / "include" / "fs" / "ops" / "file.hpp").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"\bvoid\s+writeFile\s*\(", header),
                          "fs::ops::writeFile (ofstream + O_TRUNC over a backing path) was removed; use writeFileAtomic")


if __name__ == "__main__":
    unittest.main()
