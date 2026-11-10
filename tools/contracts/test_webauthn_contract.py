"""The WebAuthn verifier is vl-webauthn, pinned and packaged (docs/dev/mfa-design.md section 4.1, decision D5).

- The verifier (#355) moved to valkyrianlabs/vl-webauthn (MIT, shared with vaulthalla-cloud). The daemon links the
  release pinned in subprojects/vl-webauthn.wrap, whose tarball is committed for the offline Debian build, and keeps
  no in-tree copy.
- UserVerification::Preferred (the spec policy knob the W3C vectors need) is never selected by the daemon: it always
  requires UV. Only the test fixtures may name it.
- libcbor, which vl-webauthn needs, is packaged everywhere the build needs it.
- The parsers are fuzzed in vl-webauthn's CI; here the remaining libFuzzer target (VHF1) builds on every run.
"""

import hashlib
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


class WebAuthnLibraryContract(unittest.TestCase):
    def test_the_verifier_is_the_pinned_vl_webauthn_release(self) -> None:
        wrap = read("subprojects/vl-webauthn.wrap")
        directory = re.search(r"(?m)^directory = (vl-webauthn-[0-9.]+)$", wrap)
        filename = re.search(r"(?m)^source_filename = (\S+)$", wrap)
        digest = re.search(r"(?m)^source_hash = ([0-9a-f]{64})$", wrap)
        self.assertTrue(directory and filename and digest, wrap)
        self.assertEqual(filename.group(1), directory.group(1) + ".tar.xz")
        tarball = REPO / "subprojects" / "packagecache" / filename.group(1)
        self.assertTrue(tarball.is_file(), f"{tarball} is committed for the offline Debian build")
        self.assertEqual(hashlib.sha256(tarball.read_bytes()).hexdigest(), digest.group(1))
        self.assertIn("vl-webauthn = vl_webauthn_dep", wrap)
        self.assertIn("dependency('vl-webauthn', version: '>=0.1.0', fallback: ['vl-webauthn', 'vl_webauthn_dep'])",
                      read("core/meson.build"))
        self.assertIn("subprojects/vl-webauthn.wrap", read("debian/copyright"))

    def test_no_in_tree_copy_remains(self) -> None:
        for rel in ("core/include/auth/webauthn", "core/src/auth/webauthn", "core/test-assets/webauthn"):
            self.assertFalse((REPO / rel).exists(), f"{rel} moved to vl-webauthn")
        offenders = []
        for path in sorted((REPO / "core").rglob("*")):
            if path.suffix in {".cpp", ".hpp", ".h"} and re.search(
                    r'"auth/webauthn/|vh::auth::webauthn', path.read_text(encoding="utf-8", errors="replace")):
                offenders.append(str(path.relative_to(REPO)))
        self.assertEqual(offenders, [])

    def test_user_verification_is_never_relaxed_by_the_daemon(self) -> None:
        offenders = []
        for path in sorted((REPO / "core").rglob("*")):
            if path.suffix not in {".cpp", ".hpp", ".h"}:
                continue
            rel = path.relative_to(REPO)
            if rel.parts[:2] == ("core", "tests"):
                continue
            if "UserVerification::Preferred" in path.read_text(encoding="utf-8", errors="replace"):
                offenders.append(str(rel))
        self.assertEqual(offenders, [])


class WebAuthnPackagingContract(unittest.TestCase):
    def test_libcbor_is_packaged_for_every_build(self) -> None:
        control = read("debian/control")
        build_depends = control.split("Build-Depends:", 1)[1].split("Standards-Version", 1)[0]
        self.assertRegex(build_depends, r"(?m)^ libcbor-dev \(>= 0\.10\),$")
        # The runtime library comes from ${shlibs:Depends}; never a hand-written libcbor0.x dependency.
        self.assertNotRegex(control.split("Package: vaulthalla\n", 1)[1], r"libcbor0")
        self.assertRegex(read("ci/Containerfile"), r"(?m)^\s+.*\blibcbor-dev\b")
        self.assertRegex(read("tools/macos/Brewfile"), r'(?m)^brew "libcbor"')
        self.assertIn('check_pkg libcbor-dev "libcbor-dev"', read("bin/setup/install_deps.sh"))
        self.assertIn('name = "libcbor"', read("docs/stack.toml"))

    def test_ci_builds_the_remaining_fuzz_target(self) -> None:
        self.assertRegex(read("ci/Containerfile"), r"(?m)^\s+clang-18 libclang-rt-18-dev \\$")
        workflow = read(".github/workflows/build_and_test.yml")
        self.assertIn("CXX=clang++-18 meson setup build-fuzz -Dfuzz=true", workflow)
        self.assertIn("bash tools/dev/quiet-build.sh build-fuzz fuzz-setup.log", workflow)
        self.assertFalse((REPO / ".github" / "actions" / "fuzz").exists())


if __name__ == "__main__":
    unittest.main()
