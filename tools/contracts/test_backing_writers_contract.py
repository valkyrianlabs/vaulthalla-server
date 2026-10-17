"""Contract: nothing writes a vault backing file in place (file recovery, .claude/context/recovery.md).

Local versioning and snapshots retain a generation by hard-linking the sealed backing file into the recovery store
(zero-copy). The blob then shares the live file's inode until the next rename-replace, so a writer that opens an
existing backing file for writing (open/openat with O_TRUNC / O_WRONLY / O_RDWR, creat, an ofstream, fopen/fdopen,
pwrite, ftruncate, copy_file_range, copy_file over an existing file, a PROT_WRITE mapping) would silently rewrite
history. Every backing writer creates a new name exclusively (fs::ops::writeFileExclusive) or replaces by
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
from typing import Callable
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE_SOURCES = REPO_ROOT / "core" / "src"

# Each pattern is matched over the whole file (comments and #include lines removed), so a call spread over several
# lines is still one call; the statement it starts (up to the next ';') is what STATEMENT_CHECKS look at.
PATTERNS: dict[str, re.Pattern[str]] = {
    "ofstream": re.compile(r"\b(?:std::)?o?fstream\b"),
    "o_trunc": re.compile(r"\bO_TRUNC\b"),
    # open(2) / openat(2) that may write: see STATEMENT_CHECKS (a member function named open is not a match)
    "write_open": re.compile(r"(?:(?<![\w:.>])::|(?<![\w:.>]))open(?:at)?\s*\("),
    "creat": re.compile(r"(?<![\w:.>])(?:::)?creat\s*\("),
    "write_file": re.compile(r"\bwriteFile\s*\("),
    "pwrite": re.compile(r"\bpwrite\s*\("),
    "truncate": re.compile(r"\b(?:ftruncate|resize_file)\s*\("),
    "fopen": re.compile(r"\b(?:fopen|fdopen|freopen)\s*\("),
    "copy_file_range": re.compile(r"\bcopy_file_range\s*\("),
    # std::filesystem::copy_file / copy onto an existing destination writes that file in place
    "copy_overwrite": re.compile(r"\bcopy(?:_file)?\s*\("),
    "mmap_write": re.compile(r"\bmmap\s*\("),
}

# A statement-level condition for the kinds whose call alone doesn't say whether it writes in place.
STATEMENT_CHECKS: dict[str, Callable[[str], bool]] = {
    # Writable unless it can only create a new name (O_EXCL) or an anonymous file (O_TMPFILE); flags that aren't
    # spelled out (a variable) count as writable unless the call says O_RDONLY. An unqualified open( is the system
    # call only when an O_ flag appears (otherwise it is a member function, or its definition).
    "write_open": lambda stmt: (stmt.startswith("::") or bool(re.search(r"\bO_[A-Z]", stmt))) and
        not re.search(r"\bO_(?:EXCL|TMPFILE)\b", stmt) and (
        bool(re.search(r"\bO_(?:WRONLY|RDWR)\b", stmt)) or not re.search(r"\bO_RDONLY\b", stmt)),
    "copy_overwrite": lambda stmt: bool(re.search(r"\b(?:overwrite_existing|update_existing)\b", stmt)),
    "mmap_write": lambda stmt: bool(re.search(r"\bPROT_WRITE\b", stmt)),
}

# (file, kind) -> (count, why it never writes a backing file in place)
ALLOWED: dict[tuple[str, str], tuple[int, str]] = {
    ("core/src/config/Config.cpp", "ofstream"): (1, "writes the YAML config file"),
    ("core/src/crypto/util/encrypt.cpp", "ofstream"): (1, "decrypt_aes256_gcm_file writes plaintext to a working copy / temp, never a backing path"),
    ("core/src/crypto/util/reseal.cpp", "o_trunc"): (1, "resealFile dst: callers pass a content sidecar or a fresh temp, renamed over the backing file"),
    ("core/src/crypto/util/reseal.cpp", "write_open"): (1, "same open as above"),
    ("core/src/fs/file/ops.cpp", "o_trunc"): (1, "writeFileAtomic writes its own private O_EXCL temp before the rename"),
    ("core/src/fs/file/ops.cpp", "write_open"): (2, "the writeFileAtomic open above, and fsyncOpened (fsyncFile / fsyncDirectory pass O_RDONLY [| O_DIRECTORY])"),
    ("core/src/fs/Filesystem.cpp", "copy_overwrite"): (1, "copyBackingBytes copies into replaceFileAtomic's own private temp, renamed over the destination"),
    ("core/src/fuse/Bridge.cpp", "o_trunc"): (1, "reads the kernel's open flags (a working copy truncates, never the backing file)"),
    ("core/src/fuse/WorkingCopies.cpp", "o_trunc"): (1, "reads the kernel's open flags"),
    ("core/src/fuse/WorkingCopies.cpp", "write_open"): (1, "opens the plaintext working copy under .fuse-plaintext with the kernel's access mode"),
    ("core/src/fuse/WorkingCopies.cpp", "copy_overwrite"): (1, "materializes a legacy plaintext file into its working copy (the destination), never a backing path"),
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
    ("core/src/protocols/s3/MultipartStore.cpp", "copy_overwrite"): (1, "stores a multipart part under the gateway's staging directory"),
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


def _code(text: str) -> str:
    """The source without comments and #include lines (line structure kept)."""
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    lines = []
    for raw in text.splitlines():
        code = raw.split("//", 1)[0]
        lines.append("" if code.lstrip().startswith("#include") else code)
    return "\n".join(lines)


def writers(text: str) -> Counter[str]:
    """Write primitives per kind in one source file (comments and #include lines ignored)."""
    code = _code(text)
    found: Counter[str] = Counter()
    for kind, pattern in PATTERNS.items():
        check = STATEMENT_CHECKS.get(kind)
        for match in pattern.finditer(code):
            if check is not None:
                end = code.find(";", match.start())
                if not check(code[match.start(): end if end >= 0 else len(code)]):
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
        # ... and the forms that used to slip through: calls over several lines, flags in a variable, openat, creat,
        # fdopen, copy_file_range, copy_file over an existing file, a writable mapping.
        self.assertEqual(writers('const int fd = ::open(backing.c_str(),\n    O_RDWR | O_CLOEXEC);')["write_open"], 1)
        self.assertEqual(writers('const int fl = O_WRONLY; int fd = ::open(p.c_str(), fl);')["write_open"], 1)
        self.assertEqual(writers('int fd = openat(dirfd, name, O_WRONLY);')["write_open"], 1)
        self.assertEqual(writers('int fd = ::creat(p.c_str(), 0600);')["creat"], 1)
        self.assertEqual(writers('FILE* f = fdopen(fd, "w");')["fopen"], 1)
        self.assertEqual(writers('copy_file_range(in, nullptr, out, nullptr, n, 0);')["copy_file_range"], 1)
        self.assertEqual(writers('std::filesystem::copy_file(a, b,\n    std::filesystem::copy_options::overwrite_existing);')
                         ["copy_overwrite"], 1)
        self.assertEqual(writers('void* m = mmap(nullptr, n, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);')["mmap_write"], 1)
        self.assertFalse(writers('int fd = ::open(p.c_str(),\n    O_RDONLY | O_CLOEXEC);'))
        self.assertFalse(writers('int fd = ::openat(d, n, O_WRONLY | O_CREAT | O_EXCL, 0600);'))
        self.assertFalse(writers('std::filesystem::copy_file(a, b);'))
        self.assertFalse(writers('void* m = mmap(nullptr, n, PROT_READ, MAP_PRIVATE, fd, 0);'))
        self.assertFalse(writers('auto h = copies.open(ino, file, flags); Handle WorkingCopies::open(int x) {}'))
        self.assertFalse(writers('/* ::open(p, O_RDWR); */'))

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
