"""Identity broker (secrets in memory, injected at send time) and guardrails (budgets, scope, kill switch)."""
import json
import os
import unittest

from tests.helpers import Rig, TempDir, pentest
from vhh.broker import IdentityBroker, MissingCredential
from vhh.guardrails import Budget, Guardrails, KillSwitch, Scope
from vhh.model import Op
from vhh.redact import Redactor


class Broker(TempDir, unittest.TestCase):
    def test_credentials_stay_out_of_repr_and_are_registered(self):
        r = Redactor()
        b = IdentityBroker(r)
        b.register("u-a", "password", "super-secret-pw")
        self.assertNotIn("super-secret-pw", repr(b.credential("u-a")))
        self.assertEqual(r.redact_text("x super-secret-pw y").count("super-secret-pw"), 0)
        self.assertTrue(b.has("u-a"))
        with self.assertRaises(MissingCredential):
            b.credential("u-unknown")

    def test_private_file_must_be_0600(self):
        p = self.tmp / "creds.json"
        p.write_text(json.dumps({"principals": {"u-a": {"password": "pw-123456"}},
                                 "shares": {"sl-1": {"token": "tok-abcdef"}}, "canary": {"v": "VHPT-x"}}))
        os.chmod(p, 0o644)
        b = IdentityBroker(Redactor())
        with self.assertRaises(PermissionError):
            b.load_private_file(p)
        os.chmod(p, 0o600)
        self.assertEqual(b.load_private_file(p), 2)
        self.assertTrue(b.has("u-a") and b.has("public:sl-1"))


class Guardrail(unittest.TestCase):
    def test_op_budget_blocks_without_sending(self):
        rig = Rig(pentest())
        s = rig.session("u-alice", "ws")
        rig.engine.guardrails.set_session(s.id, Budget(max_ops=2))
        outs = [rig.do(s, "fs.list", vault="v-alice", path="/") for _ in range(4)]
        self.assertEqual([o.outcome for o in outs], ["ok", "ok", "blocked", "blocked"])
        self.assertEqual(rig.engine.counts["blocked"], 2)

    def test_scope_allowlist_blocks_out_of_scope_ops_and_vaults(self):
        rig = Rig(pentest())
        s = rig.session("u-alice", "ws")
        rig.engine.guardrails.set_session(s.id, scope=Scope(ops=frozenset({"fs.list"}), vaults=frozenset({"v-alice"})))
        self.assertEqual(rig.do(s, "fs.list", vault="v-alice", path="/").outcome, "ok")
        self.assertEqual(rig.do(s, "fs.read", vault="v-alice", path="/README.md").outcome, "blocked")
        self.assertEqual(rig.do(s, "fs.list", vault="v-bob", path="/").outcome, "blocked")

    def test_kill_switch_aborts_the_run(self):
        rig = Rig(pentest())
        s = rig.session("u-alice", "ws")
        rig.do(s, "fs.list", vault="v-alice", path="/")
        rig.engine.guardrails.kill.trip("operator stop")
        self.assertEqual(rig.do(s, "fs.list", vault="v-alice", path="/").outcome, "blocked")
        self.assertFalse(rig.engine.passed)
        self.assertIn("aborted: operator stop", rig.engine.summary()["reasons"])

    def test_kill_file(self):
        import tempfile
        f = tempfile.NamedTemporaryFile(delete=True)
        ks = KillSwitch(f.name)
        self.assertTrue(ks.tripped)      # file exists
        f.close()


class MissingSecret(unittest.TestCase):
    def test_missing_secret_is_a_harness_failure(self):
        rig = Rig(pentest(), skip_creds={"u-eve"})
        s = rig.session("u-eve", "ws")
        r = rig.do(s, "fs.list", vault="v-team", path="/")
        self.assertEqual(r.outcome, "error")
        self.assertEqual(r.data.get("fault"), "harness")
        self.assertIn("harness", rig.judges_of())
        self.assertFalse(rig.engine.passed)


if __name__ == "__main__":
    unittest.main()
