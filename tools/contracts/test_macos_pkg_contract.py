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

    def test_cask_uses_the_current_macos_requirement_syntax(self) -> None:
        cask = (PKG / "homebrew" / "vaulthalla.rb.in").read_text()
        self.assertIn("depends_on macos: :sonoma", cask)
        self.assertNotRegex(cask, r'depends_on macos: ">=')


if __name__ == "__main__":
    unittest.main()
