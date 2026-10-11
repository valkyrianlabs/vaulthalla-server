"""Contract: identity and authorization writes go through identities::Manager.

The daemon keeps one canonical User/Group object per identity and publishes every committed change into it. A write
that bypasses the Manager leaves those objects (held by sessions, engines, FUSE) stale until the revision watcher
catches up, and that kind of bypass is how auth::Manager's old user cache came to keep renamed, deactivated and deleted
accounts logged in (1117ed3b). So:

  * identity row writers (db::query::identities::User/Group) are called only from core/src/identities/Manager.cpp;
  * every vault role assignment, permission override and role template write in core/src runs inside a
    `manager().mutate(...)` call, which republishes what it touched;
  * canonical identities expose no mutable state: User and Group keep their state in a private atomic.

Seeding (core/seed) runs before the daemon serves anything and republishes with a full refresh; tests may write behind
the Manager on purpose (out-of-band coverage).

Run by module: python3 -m unittest tools.contracts.test_identity_writes_contract
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE_SRC = REPO_ROOT / "core" / "src"
MANAGER = CORE_SRC / "identities" / "Manager.cpp"

IDENTITY_WRITE_RE = re.compile(
    r"db::query::identities::(?:User|Group)::"
    r"(createUser|updateUser|updateUserPassword|deleteUser|updateLastLoggedInUser|bootstrapSetAdminLinuxUID|"
    r"createGroup|updateGroup|deleteGroup|addMembersToGroup|removeMembersFromGroup)\s*\("
)
RBAC_WRITE_RE = re.compile(
    r"\b(?:VaultAssignments|Assignments)::(?:assign|unassign)\s*\(|"
    r"\bpermission::Override::(?:add|update|remove)\s*\(|"
    r"\b(?:AdminRoleQuery|VaultRoleQuery|role::Admin|role::Vault|vault::Global)::upsert\s*\("
)
MUTATE_WINDOW = 4  # lines: the write sits inside the lambda passed to mutate(...)


def sources() -> list[Path]:
    return [p for p in sorted(CORE_SRC.rglob("*.cpp")) if "db" not in p.relative_to(CORE_SRC).parts[:1]]


def identity_write_offenders() -> list[str]:
    found = []
    for path in sources():
        if path == MANAGER:
            continue
        text = path.read_text(encoding="utf-8")
        for match in IDENTITY_WRITE_RE.finditer(text):
            found.append(f"{path.relative_to(REPO_ROOT)}:{text.count(chr(10), 0, match.start()) + 1} {match.group(1)}")
    return found


def unrepublished_rbac_writes(text: str) -> list[int]:
    lines = text.splitlines()
    bad = []
    for i, line in enumerate(lines):
        if RBAC_WRITE_RE.search(line):
            window = "\n".join(lines[max(0, i - MUTATE_WINDOW): i + 1])
            if "mutate(" not in window:
                bad.append(i + 1)
    return bad


class IdentityWritesContractTests(unittest.TestCase):
    def test_detectors(self) -> None:
        self.assertTrue(IDENTITY_WRITE_RE.search("db::query::identities::User::updateUser(id, next);"))
        self.assertFalse(IDENTITY_WRITE_RE.search("db::query::identities::User::userExists(name)"))
        self.assertEqual(unrepublished_rbac_writes("    VaultAssignments::assign(v, t, s, r);"), [1])
        self.assertEqual(unrepublished_rbac_writes(
            "    identities::manager().mutate(touched, [&] {\n        VaultAssignments::assign(v, t, s, r);\n    });"), [])

    def test_identity_rows_are_written_only_by_the_manager(self) -> None:
        self.assertEqual(identity_write_offenders(), [],
                         "identity rows written outside identities::Manager (its canonical objects go stale)")

    def test_authorization_writes_republish(self) -> None:
        offenders = []
        for path in sources():
            for line in unrepublished_rbac_writes(path.read_text(encoding="utf-8")):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{line}")
        self.assertEqual(offenders, [], "role/override/assignment writes outside identities::Manager::mutate")

    def test_canonical_identities_expose_no_mutable_state(self) -> None:
        for header, state in (("User.hpp", "UserState"), ("Group.hpp", "GroupState")):
            text = (REPO_ROOT / "core" / "include" / "identities" / header).read_text(encoding="utf-8")
            klass = text[text.index(f"class {header[:-4]} final"):]
            klass = klass[: re.search(r"\n\s*};", klass).start()]
            public, _, private = klass.partition("private:")
            self.assertIn(f"std::atomic<std::shared_ptr<const {state}>> state_;", private, header)
            # Public data members: only the immutable id.
            members = re.findall(r"^\s{4,8}(?!//)(?:const\s+)?(?:unsigned\s+)?[\w:<>]+\s+(\w+)\s*(?:\{[^}]*\})?;\s*$", public, re.M)
            self.assertEqual(members, ["id"], f"{header}: public data members {members}")


if __name__ == "__main__":
    unittest.main()
