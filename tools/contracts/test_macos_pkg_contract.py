"""macOS package scripts (tools/macos/pkg): invariants the first clean-runner cask smoke caught.

- uninstall.sh must apply the provisioner's removal (`--apply`; without it vaulthalla-provision only prints a plan,
  and the uninstaller then deleted the support directory under running daemons);
- the installed payload and the web console must be readable by the service account (the web bundle comes from a CI
  container with a restrictive umask: EACCES on public/);
- the Homebrew casks use the current `depends_on macos:` syntax;
- `vaulthalla` is a meta cask over vaulthalla-server and vaulthalla-desktop: the server package never carries the
  Desktop app, so neither release pins the other.
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
        meta = (PKG / "homebrew" / "vaulthalla.rb.in").read_text()
        self.assertIn("depends_on macos: :sonoma", server)
        for cask in (server, meta):
            self.assertNotRegex(cask, r'depends_on macos: ">=')

    def test_vaulthalla_is_a_meta_cask(self) -> None:
        # It installs nothing itself: each dependency installs and upgrades to its own latest release.
        meta = (PKG / "homebrew" / "vaulthalla.rb.in").read_text()
        self.assertIn('"valkyrianlabs/tap/vaulthalla-server"', meta)
        self.assertIn('"valkyrianlabs/tap/vaulthalla-desktop"', meta)
        self.assertIn("stage_only true", meta)
        self.assertRegex(meta, r'url "[^"]*-arm64\.pkg\.sha256"')
        for artifact in (r"^\s*pkg ", r"^\s*app ", r"^\s*uninstall ", r"^\s*zap ", "choices:", "conflicts_with"):
            self.assertNotRegex(meta, re.compile(artifact, re.M))
        self.assertNotIn("conflicts_with", (PKG / "homebrew" / "vaulthalla-server.rb.in").read_text())

    def test_the_meta_cask_records_the_checksum_of_what_it_downloads(self) -> None:
        text = (PKG / "render-cask.sh").read_text()
        self.assertIn('shasum -a 256 "$PKG.sha256"', text)
        self.assertIn("@SHA256_FILE_SHA256@", text)

    def test_the_package_carries_no_desktop_app(self) -> None:
        self.assertFalse((PKG / "fetch-desktop.sh").exists())
        self.assertFalse((PKG / "distribution-desktop.xml.in").exists())
        distribution = (PKG / "distribution.xml.in").read_text()
        self.assertIn('customize="never"', distribution)
        self.assertNotIn("desktop", distribution.lower())
        self.assertNotIn("desktop", (PKG / "build-pkg.sh").read_text().lower())


if __name__ == "__main__":
    unittest.main()
