"""#355: the WebAuthn verifier stays extractable, strict and fuzzed (docs/dev/mfa-design.md section 4.1, decision D5).

- Its sources (core/{include,src}/auth/webauthn) include only each other, the standard library, libcbor, OpenSSL,
  libsodium and the vendored nlohmann/json: no daemon header, so it can become a vl-* library like vl-sigv4.
- It is its own static library: libvaulthalla's source discovery skips it, core/meson.build links it.
- UserVerification::Preferred (the spec policy knob the W3C vectors need) is never selected outside the verifier and
  its tests: the daemon always requires UV.
- libcbor is packaged everywhere the build needs it, and the CI image carries the clang/libFuzzer the fuzz job uses.
- CI runs the fuzz targets on every pull request, and every target has a committed seed corpus.
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
INCLUDE = REPO / "core" / "include" / "auth" / "webauthn"
SRC = REPO / "core" / "src" / "auth" / "webauthn"
ALLOWED_INCLUDE = re.compile(
    r'^#include (?:"auth/webauthn/[A-Za-z0-9]+\.hpp"|<(?:openssl/[a-z0-9_]+\.h|cbor\.h|sodium\.h|nlohmann/json(?:_fwd)?\.hpp|'
    r"[a-z_]+)>)$"
)


def sources() -> list[Path]:
    return sorted(p for root in (INCLUDE, SRC) for p in root.rglob("*") if p.suffix in {".cpp", ".hpp"})


def read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


class WebAuthnBoundaryContract(unittest.TestCase):
    def test_sources_include_nothing_from_the_daemon(self) -> None:
        self.assertGreater(len(sources()), 20)
        offenders = []
        for path in sources():
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if line.startswith("#include") and not ALLOWED_INCLUDE.match(line):
                    offenders.append(f"{path.relative_to(REPO)}:{lineno}: {line}")
        self.assertEqual(offenders, [], "\n".join(offenders))

    def test_no_file_scope_using_namespace(self) -> None:
        for path in sources():
            with self.subTest(path=str(path.relative_to(REPO))):
                self.assertNotRegex(path.read_text(encoding="utf-8"), r"(?m)^using namespace")

    def test_built_as_its_own_library(self) -> None:
        core = read("core/meson.build")
        self.assertIn("own_library_prefixes = ['auth/webauthn/']", core)
        self.assertIn("subdir('src/auth/webauthn')", core)
        self.assertIn("deps += vh_webauthn_dep", core)
        lib = read("core/src/auth/webauthn/meson.build")
        self.assertIn("dependency('libcbor', version: '>=0.10', required: true)", lib)
        self.assertIn("static_library(\n    'vh_webauthn'", lib)
        root = read("meson.build")
        self.assertIn("if get_option('fuzz')", root)
        self.assertIn("subdir_done()", root)

    def test_user_verification_is_never_relaxed_outside_the_verifier(self) -> None:
        offenders = []
        for path in sorted((REPO / "core").rglob("*")):
            if path.suffix not in {".cpp", ".hpp", ".h"}:
                continue
            rel = path.relative_to(REPO)
            if rel.parts[:4] in {("core", "src", "auth", "webauthn"), ("core", "include", "auth", "webauthn")}:
                continue
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

    def test_ci_fuzzes_every_pull_request(self) -> None:
        self.assertRegex(read("ci/Containerfile"), r"(?m)^\s+clang-18 libclang-rt-18-dev \\$")
        workflow = read(".github/workflows/build_and_test.yml")
        # The tooling job runs the fuzz action on every pull request: the targets always build, and it runs them for
        # the 60 s budget when the diff touches the parsers or build inputs (and on every push to main).
        self.assertIn("uses: ./.github/actions/fuzz", workflow)
        action = read(".github/actions/fuzz/action.yml")
        self.assertIn("bash tools/dev/fuzz-webauthn.sh --seconds 60", action)
        self.assertIn("bash tools/dev/fuzz-webauthn.sh --build-only", action)
        self.assertIn("core/src/auth/webauthn/", action)
        script = read("tools/dev/fuzz-webauthn.sh")
        self.assertIn("-Dfuzz=true -Db_sanitize=address,undefined", script)
        for target in ("cbor_cose", "authenticator_data", "client_data"):
            with self.subTest(target=target):
                self.assertTrue((SRC / "fuzz" / f"fuzz_{target}.cpp").is_file())
                self.assertIn(target, script)
                corpus = SRC / "fuzz" / "corpus" / target
                self.assertTrue(corpus.is_dir() and any(corpus.iterdir()), f"{corpus} needs a committed seed corpus")


if __name__ == "__main__":
    unittest.main()
