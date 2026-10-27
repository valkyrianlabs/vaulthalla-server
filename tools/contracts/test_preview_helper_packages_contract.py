"""Contract for the optional preview converter helpers and their Debian packages.

The daemon must never link OCCT, libav* or libseccomp: hostile-file converters run out of process
(core/tools, preview::derive::Runner) and ship in their own binary packages, so the core package keeps
installing on hosts without those (universe, t64-versioned) libraries.

Run by module: python3 -m unittest tools.contracts.test_preview_helper_packages_contract
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest

HELPERS = ("vaulthalla-preview-cad", "vaulthalla-preview-media")
HEAVY_LIBRARIES = ("libocct", "libav", "libswscale", "libswresample", "libseccomp", "ffmpeg", "opencascade")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _read(relative: str) -> str:
    return (_repo_root() / relative).read_text(encoding="utf-8")


def _stanzas() -> dict[str, str]:
    control = _read("debian/control")
    stanzas: dict[str, str] = {}
    for block in control.split("\n\n"):
        match = re.search(r"(?m)^Package: (\S+)$", block)
        if match:
            stanzas[match.group(1)] = block
    return stanzas


def _field(stanza: str, name: str) -> list[str]:
    match = re.search(rf"(?ms)^{name}:(.*?)(?=^\S|\Z)", stanza)
    if not match:
        return []
    return [item.strip() for item in match.group(1).replace("\n", " ").split(",") if item.strip()]


class PreviewHelperPackagesContractTests(unittest.TestCase):
    def test_core_package_never_depends_on_converter_libraries(self) -> None:
        core = _stanzas()["vaulthalla"]
        for field in ("Pre-Depends", "Depends", "Recommends"):
            for item in _field(core, field):
                for library in HEAVY_LIBRARIES:
                    self.assertNotIn(library, item, f"{field}: {item}")
        for helper in HELPERS:
            self.assertNotIn(helper, _field(core, "Depends"))

    def test_core_suggests_the_helpers_after_the_pinned_recommends(self) -> None:
        control = _read("debian/control")
        self.assertIn(
            "Recommends:\n valkyrianlabs-archive-keyring,\n postgresql,\n nginx,\n certbot,\n python3-certbot-nginx,\n python3-certbot-dns-cloudflare,\n"
            " swtpm,\n swtpm-tools\nSuggests:\n vaulthalla-preview-cad,\n vaulthalla-preview-media\n",
            control,
        )

    def test_helper_packages_depend_on_the_exact_core_version(self) -> None:
        stanzas = _stanzas()
        for helper in HELPERS:
            with self.subTest(package=helper):
                stanza = stanzas[helper]
                self.assertEqual(
                    _field(stanza, "Depends"),
                    ["vaulthalla (= ${binary:Version})", "${shlibs:Depends}", "${misc:Depends}"],
                )
                self.assertRegex(stanza, r"(?m)^Architecture: any$")
                profile = "nocad" if helper.endswith("cad") else "nomedia"
                self.assertRegex(stanza, rf"(?m)^Build-Profiles: <!pkg\.vaulthalla\.{profile}>$")

    def test_helper_build_depends_are_dropped_by_their_build_profile(self) -> None:
        control = _read("debian/control")
        build_depends = control.split("Build-Depends:", 1)[1].split("Standards-Version", 1)[0]
        for package in ("libocct-data-exchange-dev", "libocct-foundation-dev", "libocct-modeling-algorithms-dev",
                        "libocct-modeling-data-dev", "libocct-ocaf-dev"):
            self.assertIn(f"{package} <!pkg.vaulthalla.nocad>", build_depends)
        for package in ("libavcodec-dev", "libavformat-dev", "libavutil-dev", "libswresample-dev", "libswscale-dev"):
            self.assertIn(f"{package} <!pkg.vaulthalla.nomedia>", build_depends)
        self.assertIn("libseccomp-dev <!pkg.vaulthalla.nocad> <!pkg.vaulthalla.nomedia>", build_depends)
        self.assertNotIn("cmake", build_depends)   # OCCT is located without its CMake config

    def test_helpers_install_into_their_own_packages_only(self) -> None:
        root = _repo_root()
        for helper in HELPERS:
            install = (root / "debian" / f"{helper}.install").read_text(encoding="utf-8").split()
            self.assertEqual(install, [f"usr/lib/vaulthalla/helpers/{helper}"])
        core_install = _read("debian/install")
        self.assertNotIn("usr/lib/vaulthalla/helpers", core_install)
        self.assertNotIn("usr/lib/vaulthalla\n", core_install)   # never the whole libexec tree

    def test_rules_build_the_helpers_unless_a_profile_drops_them(self) -> None:
        rules = _read("debian/rules")
        self.assertIn("-Dpreview_cad=$(VH_PREVIEW_CAD) -Dpreview_media=$(VH_PREVIEW_MEDIA)", rules)
        self.assertIn("$(filter pkg.vaulthalla.nocad,$(DEB_BUILD_PROFILES)),disabled,enabled", rules)
        self.assertIn("$(filter pkg.vaulthalla.nomedia,$(DEB_BUILD_PROFILES)),disabled,enabled", rules)

    def test_meson_keeps_converter_libraries_out_of_the_daemon(self) -> None:
        options = _read("meson.options")
        for option in ("preview_cad", "preview_media"):
            self.assertRegex(options, rf"'{option}',\s*type: 'feature',\s*value: 'auto'")
        core = _read("core/meson.build")
        daemon_deps = core.split("deps = [", 1)[1].split("]", 1)[0]
        for library in ("seccomp", "TK", "OpenCASCADE", "libav", "swscale"):
            self.assertNotIn(library, daemon_deps)
        self.assertIn("subdir('tools')", core)
        tools = _read("core/tools/meson.build")
        self.assertIn("helper_dir = get_option('prefix') / 'lib' / meson.project_name() / 'helpers'", tools)
        self.assertIn("project('vaulthalla'", _read("meson.build"))
        cad = _read("core/tools/preview-cad/meson.build")
        self.assertIn("install_dir: helper_dir", cad)
        self.assertIn("link_with: helper_common_lib", cad)
        # The daemon side of the seam includes no converter headers.
        for path in sorted((_repo_root() / "core").glob("**/preview/derive/*")):
            text = path.read_text(encoding="utf-8")
            for header in ("<seccomp.h>", "opencascade", ".hxx>", "<libav", "linux/landlock.h"):
                self.assertNotIn(header, text, path)

    def test_helper_dir_default_matches_the_install_dir(self) -> None:
        config_header = _read("core/include/config/Config.hpp")
        self.assertIn('std::filesystem::path helper_dir = "/usr/lib/vaulthalla/helpers";', config_header)
        shipped = _read("deploy/config/config.yaml")
        self.assertIn("helper_dir: /usr/lib/vaulthalla/helpers", shipped)


if __name__ == "__main__":
    unittest.main()
