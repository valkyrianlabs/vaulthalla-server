"""Contract: every durability flush goes through platform::durable::sync (#205).

On macOS fsync(2) only hands the writes to the drive, whose cache can still lose or reorder them on power loss, so the
write-temp / commit-row / rename sequences (rotation, seals, recovery blobs, hydrate, secrets) would lose their crash
guarantee there. platform::durable::sync is fsync on Linux and F_FULLFSYNC on macOS; a raw fsync, fdatasync,
sync_file_range or F_*FSYNC fcntl outside core/src/platform/ bypasses that choice, so this fails until the call goes
through the seam.

Run by module: python3 -m unittest tools.contracts.test_durable_sync_contract
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE_SOURCES = REPO_ROOT / "core" / "src"
PLATFORM_SOURCES = CORE_SOURCES / "platform"

# A call (not a member call, not the FUSE handler's definition `void fsync(fuse_req_t ...)`).
RAW_FLUSH = re.compile(r"(?<![\w.>])(?:::)?(?:fsync|fdatasync|sync_file_range)\s*\(|\bF_(?:FULL|BARRIER)FSYNC\b")
DEFINITION = re.compile(r"\bvoid\s+$")


# Comments and string/char literals, scanned together so a quote in a comment or a // in a string can't confuse
# either (SQL mentions the fsync table).
NOISE = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', re.S)


def _code(text: str) -> str:
    """The source without comments and literals (line structure kept)."""
    return NOISE.sub(lambda m: "\n" * m.group(0).count("\n") if m.group(0)[0] == "/" else '""', text)


def raw_flushes(text: str) -> list[str]:
    code = _code(text)
    found = []
    for match in RAW_FLUSH.finditer(code):
        if DEFINITION.search(code[max(0, match.start() - 16): match.start()]):
            continue
        line = code.count("\n", 0, match.start()) + 1
        found.append(f"{line}: {match.group(0).strip()}")
    return found


class DurableSyncContractTests(unittest.TestCase):
    def test_detector(self) -> None:
        self.assertTrue(raw_flushes("if (::fsync(fd) != 0) throw;"))
        self.assertTrue(raw_flushes("(void)fsync(dfd);"))
        self.assertTrue(raw_flushes("fdatasync(fd);"))
        self.assertTrue(raw_flushes("::fcntl(fd, F_FULLFSYNC);"))
        self.assertTrue(raw_flushes("::fcntl(fd, F_BARRIERFSYNC);"))
        self.assertFalse(raw_flushes("if (platform::durable::sync(fd) != 0) throw;"))
        self.assertFalse(raw_flushes("void fsync(const fuse_req_t req, const fuse_ino_t ino);"))
        self.assertFalse(raw_flushes("ops.fsync = &Bridge::fsync; handle.fsync();"))
        self.assertFalse(raw_flushes("// ::fsync(fd) is not enough on macOS"))
        self.assertFalse(raw_flushes("fs::ops::fsyncFile(path); fsyncDirectory(dir);"))
        self.assertFalse(raw_flushes('prepare("x", "INSERT INTO fsync (sync_id) VALUES ($1)");'))
        self.assertTrue(raw_flushes('log("done"); ::fsync(fd); // "quoted"'))

    def test_no_raw_flush_outside_the_platform_seam(self) -> None:
        offenders = []
        for path in sorted(CORE_SOURCES.rglob("*.cpp")):
            if PLATFORM_SOURCES in path.parents:
                continue
            for hit in raw_flushes(path.read_text(encoding="utf-8")):
                offenders.append(f"{path.relative_to(REPO_ROOT).as_posix()}:{hit}")
        self.assertEqual(offenders, [],
                         "Flush through platform::durable::sync (platform/Durable.hpp), not a raw fsync (#205):\n" +
                         "\n".join(offenders))

    def test_each_platform_implements_the_seam(self) -> None:
        for os_dir in ("linux", "darwin"):
            self.assertTrue((PLATFORM_SOURCES / os_dir / "Durable.cpp").is_file(), os_dir)
        darwin = _code((PLATFORM_SOURCES / "darwin" / "Durable.cpp").read_text(encoding="utf-8"))
        self.assertIn("F_FULLFSYNC", darwin, "macOS durability needs F_FULLFSYNC, not a bare fsync")


if __name__ == "__main__":
    unittest.main()
