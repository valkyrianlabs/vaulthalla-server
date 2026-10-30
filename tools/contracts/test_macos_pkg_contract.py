"""macOS package scripts (tools/macos/pkg): invariants the first clean-runner cask smoke caught.

- uninstall.sh must apply the provisioner's removal (`--apply`; without it vaulthalla-provision only prints a plan,
  and the uninstaller then deleted the support directory under running daemons);
- the installed payload and the web console must be readable by the service account (the web bundle comes from a CI
  container with a restrictive umask: EACCES on public/);
- the Homebrew cask uses the current `depends_on macos:` syntax.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

PKG = Path(__file__).resolve().parents[2] / "tools" / "macos" / "pkg"


class MacosPackageScripts(unittest.TestCase):
    def test_uninstall_applies_the_removal_before_deleting_anything(self) -> None:
        text = (PKG / "uninstall.sh").read_text()
        calls = re.findall(r'"\$SUPPORT/vaulthalla-provision" (--remove[^;\n]*)', text)
        self.assertEqual(len(calls), 2, calls)
        for call in calls:
            self.assertIn("--apply", call)
        self.assertLess(text.index("--remove --apply"), text.index("pkgutil --only-files"))
        self.assertIn("is still loaded", text)

    def test_payload_and_web_console_are_readable(self) -> None:
        self.assertIn('chmod -R u+rwX,go+rX,go-w "$ROOT"', (PKG / "build-pkg.sh").read_text())
        self.assertIn('chmod -R u+rwX,go+rX,go-w "$work/vaulthalla-web"', (PKG / "web-for-macos.sh").read_text())

    def test_casks_use_the_current_macos_requirement_syntax(self) -> None:
        server = (PKG / "homebrew" / "vaulthalla-server.rb.in").read_text()
        full = (PKG / "homebrew" / "vaulthalla.rb.in").read_text()
        self.assertIn("depends_on macos: :sonoma", server)
        # Vaulthalla Desktop needs macOS 27.
        self.assertIn("depends_on macos: :golden_gate", full)
        for cask in (server, full):
            self.assertNotRegex(cask, r'depends_on macos: ">=')

    def test_desktop_is_an_optional_off_by_default_choice(self) -> None:
        # `sudo installer -pkg` and vaulthalla-server stay headless; only the vaulthalla cask turns Desktop on.
        choice = (PKG / "distribution-desktop.xml.in").read_text()
        self.assertRegex(choice, r'<choice id="sh\.vaulthalla\.desktop"[^>]*start_selected="false"')
        self.assertIn("desktop_supported()", choice)
        self.assertIn('customize="allow"', (PKG / "distribution.xml.in").read_text())
        full = (PKG / "homebrew" / "vaulthalla.rb.in").read_text()
        self.assertIn('"choiceIdentifier" => "sh.vaulthalla.desktop"', full)
        self.assertIn('"attributeSetting" => 1', full)
        self.assertNotIn("choices:", (PKG / "homebrew" / "vaulthalla-server.rb.in").read_text())

    def test_bundled_desktop_never_downgrades_or_relocates(self) -> None:
        text = (PKG / "build-pkg.sh").read_text()
        self.assertIn("BundleIsVersionChecked=True", text)
        self.assertIn('bundle["BundleIsRelocatable"] = False', text)
        self.assertIn("--install-location /Applications", text)

    def test_casks_conflict_where_they_install_the_same_things(self) -> None:
        self.assertIn('conflicts_with cask: "vaulthalla"', (PKG / "homebrew" / "vaulthalla-server.rb.in").read_text())
        self.assertIn(
            'conflicts_with cask: ["vaulthalla-server", "vaulthalla-desktop"]',
            (PKG / "homebrew" / "vaulthalla.rb.in").read_text(),
        )

    def test_bundled_desktop_is_verified_before_packaging(self) -> None:
        text = (PKG / "fetch-desktop.sh").read_text()
        for check in ("shasum -a 256 -c", "source=Notarized Developer ID", "TeamIdentifier=$TEAM", "stapler validate"):
            self.assertIn(check, text)


if __name__ == "__main__":
    unittest.main()
