"""Contract: the pending-MFA allowlist is the same in core and the console (#357).

A pending-MFA socket (a correct password, a factor still owed) runs exactly core's kPendingCommands, plus
kPendingEnrollmentCommands while it enrolls a first factor (core/include/auth/mfa/Pending.hpp, enforced by
protocols/ws/Router.cpp). The console's LIFECYCLE set (web/src/lib/session.ts) is "commands that work without an
access token": it must hold the session lifecycle and exactly that allowlist, or the web client would try to refresh a
session that doesn't exist yet, or send a pending command the router refuses.
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
SESSION_LIFECYCLE = {"auth.login", "auth.logout", "auth.refresh", "auth.isAuthenticated"}


def core_array(source: str, name: str) -> set[str]:
    match = re.search(name + r"\{(.*?)\};", source, re.S)
    if not match:
        raise AssertionError(f"{name} not found in Pending.hpp")
    return set(re.findall(r'"([a-z.]+)"', match.group(1)))


class MfaPendingContractTests(unittest.TestCase):
    pending = (REPO_ROOT / "core/include/auth/mfa/Pending.hpp").read_text(encoding="utf-8")
    session = (REPO_ROOT / "web/src/lib/session.ts").read_text(encoding="utf-8")
    router = (REPO_ROOT / "core/src/protocols/ws/Router.cpp").read_text(encoding="utf-8")

    def test_the_console_lifecycle_is_the_session_lifecycle_plus_the_pending_allowlist(self) -> None:
        lifecycle = re.search(r"const LIFECYCLE: ReadonlySet<Command> = new Set<Command>\(\[(.*?)\]\)", self.session, re.S)
        self.assertIsNotNone(lifecycle)
        web = set(re.findall(r"'([a-zA-Z.]+)'", lifecycle.group(1)))
        core = core_array(self.pending, "kPendingCommands") | core_array(self.pending, "kPendingEnrollmentCommands")
        self.assertEqual(web, SESSION_LIFECYCLE | core)

    def test_the_allowlist_is_exact_and_never_signs_in_again(self) -> None:
        always = core_array(self.pending, "kPendingCommands")
        enrolling = core_array(self.pending, "kPendingEnrollmentCommands")
        self.assertEqual(always, {"auth.mfa.verify", "auth.mfa.cancel", "auth.logout"})
        self.assertFalse({"auth.login", "auth.refresh", "auth.isAuthenticated", "meta.hello"} & (always | enrolling))
        self.assertTrue(all(c.startswith("auth.mfa.") for c in enrolling))

    def test_the_router_checks_pending_before_the_signed_in_mode(self) -> None:
        pending_at = self.router.find("pendingAllows(")
        signed_in_at = self.router.find("if (session.user) {\n        // The session holds the canonical user")
        self.assertGreater(pending_at, 0)
        self.assertGreater(signed_in_at, pending_at)


if __name__ == "__main__":
    unittest.main()
