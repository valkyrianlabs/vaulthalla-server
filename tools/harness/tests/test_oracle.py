"""The reference model: cross-checked against every hand-written pentest expectation, plus targeted rules."""
import unittest

from tests.helpers import pentest
from vhh import glob, oracle, roles
from vhh._repo import pentest as P
from vhh.world import Grant, Override


class PentestCrossCheck(unittest.TestCase):
    def test_model_equals_all_59_expectations(self):
        w = pentest()
        self.assertEqual(len(P.fixture.EXPECTATIONS), 59)
        self.assertEqual(len(w.expectations), 59)
        rows = []
        for e in w.expectations:
            d = oracle.decide_fixture(w, e.principal, e.resource, e.operation, e.path)
            if d.expect != e.expect:
                rows.append(f"{e.principal} {e.operation} {e.resource}:{e.path} expect={e.expect} "
                            f"model={d.expect} ({d.reason})")
        # A disagreement is reported row by row, never papered over by bending the model.
        self.assertEqual(rows, [], "model disagrees with fixture.EXPECTATIONS:\n" + "\n".join(rows))

    def test_share_links_match_verify_semantics(self):
        w = pentest()
        cases = {"sl-public-dl": ("v-sh-active", "allow", "allow"), "sl-preview": ("v-sh-preview", "allow", "deny"),
                 "sl-expired": ("v-sh-expired", "deny", "deny"), "sl-revoked": ("v-sh-revoked", "deny", "deny")}
        for sid, (vault, want_list, want_dl) in cases.items():
            p = f"public:{sid}"
            self.assertEqual(oracle.decide_fixture(w, p, vault, "list", "/").expect, want_list, sid)
            self.assertEqual(oracle.decide_fixture(w, p, vault, "download", "/").expect, want_dl, sid)
            # no link reaches public_exchange
            self.assertEqual(oracle.decide_fixture(w, p, "v-public", "list", "/").expect, "deny", sid)

    def test_deactivated_account_is_denied_everything(self):
        w = pentest()
        w.grants.append(Grant("user", "u-mallory", "v-team", "full"))
        for op in ("list", "read", "write", "share"):
            self.assertEqual(oracle.decide_fixture(w, "u-mallory", "v-team", op).expect, "deny")

    def test_user_role_beats_group_role(self):
        w = pentest()
        self.assertEqual(oracle.decide_fixture(w, "u-dave", "v-team", "write").expect, "deny")
        w.grants.append(Grant("user", "u-dave", "v-team", "contributor"))
        self.assertEqual(oracle.decide_fixture(w, "u-dave", "v-team", "write").expect, "allow")
        # and a direct reader role takes away what the editors group gives carol
        w.grants.append(Grant("user", "u-carol", "v-team", "reader"))
        self.assertEqual(oracle.decide_fixture(w, "u-carol", "v-team", "write").expect, "deny")

    def test_disagreeing_groups_have_no_oracle(self):
        w = pentest()
        w.groups[1].members.append("u-carol")      # carol in editors and readers
        d = oracle.decide_fixture(w, "u-carol", "v-team", "write")
        self.assertIsNone(d.expect)
        self.assertIn("group order", d.reason)
        self.assertEqual(oracle.decide_fixture(w, "u-carol", "v-team", "read").expect, "allow")  # both agree

    def test_most_specific_override_wins(self):
        w = pentest()
        w.overrides.append(Override("group", "g-editors", "v-team", "editor", "allow-files-download",
                                    "/restricted/salaries.csv"))
        self.assertEqual(oracle.decide_fs(w, "u-carol", "v-team", "read", "/restricted/salaries.csv",
                                          False).expect, "allow")
        self.assertEqual(oracle.decide_fs(w, "u-carol", "v-team", "read", "/restricted/board-minutes.pdf",
                                          False).expect, "deny")

    def test_list_traversal_to_an_allow_override(self):
        w = pentest()
        w.grants.append(Grant("user", "u-eve", "v-team", "implicit_deny"))
        w.overrides.append(Override("user", "u-eve", "v-team", "implicit_deny", "allow-dirs-list", "/specs/**"))
        self.assertEqual(oracle.decide_fs(w, "u-eve", "v-team", "list", "/", True).expect, "allow")
        self.assertEqual(oracle.decide_fs(w, "u-eve", "v-team", "list", "/bulk", True).expect, "deny")

    def test_admin_globals_and_unmodeled_admin_ops(self):
        w = pentest()
        self.assertEqual(oracle.decide_fixture(w, "u-admin", "v-alice", "read").expect, "allow")
        self.assertEqual(oracle.decide_op(w, "u-admin", "users.create", {}).expect, "allow")
        self.assertEqual(oracle.decide_op(w, "u-eve", "users.create", {}).expect, "deny")
        self.assertIsNone(oracle.decide_op(w, "u-eve", "vaults.create", {}).expect)
        self.assertIsNone(oracle.decide_op(w, "u-alice", "fs.rename",
                                           {"vault": "v-alice", "path": "/README.md", "to": "/x"}).expect)

    def test_missing_entry_and_invalid_type(self):
        w = pentest()
        self.assertEqual(oracle.decide_op(w, "u-alice", "fs.read", {"vault": "v-alice", "path": "/nope"}).reason,
                         "missing entry")
        self.assertEqual(oracle.decide_fs(w, "u-alice", "v-alice", "list", "/README.md", False).reason,
                         "invalid action for entry type")


class GlobAndRoles(unittest.TestCase):
    def test_glob_semantics(self):
        self.assertTrue(glob.matches("/restricted/**", "/restricted/a/b.txt"))
        self.assertFalse(glob.matches("/restricted/**", "/restricted"))
        self.assertTrue(glob.matches("/docs/*", "/docs/a"))
        self.assertFalse(glob.matches("/docs/*", "/docs/a/b"))
        self.assertFalse(glob.matches("/docs/*", "/docs/"))
        self.assertTrue(glob.matches("/**/*.txt", "/x.txt"))
        self.assertTrue(glob.matches("/**/*.txt", "/a/b/x.txt"))
        self.assertTrue(glob.matches("/docs/f?.txt", "/docs/f1.txt"))
        self.assertFalse(glob.matches("/docs/f?.txt", "/docs/f12.txt"))
        self.assertGreater(glob.score("/restricted/salaries.csv"), glob.score("/restricted/**"))
        self.assertTrue(glob.requires_traversal("/specs/**", "/"))
        self.assertFalse(glob.requires_traversal("/specs/**", "/bulk"))
        with self.assertRaises(glob.GlobError):
            glob.tokenize("relative/**")
        with self.assertRaises(glob.GlobError):
            glob.tokenize("/a/***")

    def test_flags_and_templates(self):
        self.assertEqual(roles.parse_flag("allow-files-share-public"), (True, "files.share.public"))
        self.assertEqual(roles.parse_flag("deny-dirs-list"), (False, "dirs.list"))
        with self.assertRaises(roles.FlagError):
            roles.parse_flag("allow-files-teleport")
        reader, manager = roles.template_perms("reader"), roles.template_perms("manager")
        self.assertIn("files.download", reader)
        self.assertNotIn("files.upload", reader)
        self.assertIn("files.delete", manager)
        self.assertNotIn("files.delete", roles.template_perms("editor"))
        self.assertEqual(roles.template_perms("power_user"), roles.template_perms("full"))
        owner = roles.apply_flags(manager, ["allow-files-share-public", "allow-dirs-share-public"])
        self.assertIn("dirs.share.public", owner)


if __name__ == "__main__":
    unittest.main()
