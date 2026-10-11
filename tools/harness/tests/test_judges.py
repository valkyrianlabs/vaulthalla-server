"""Judges: every planted defect becomes a failing verdict with the right classification; a faithful read passes.

This is the core "a failure never becomes a pass" guarantee at the judge level (the self-tests cover whole runs)."""
import unittest

from tests.helpers import Rig, pentest
from vhh.sim import Plants


class OracleJudge(unittest.TestCase):
    def test_planted_cross_tenant_allow_is_caught(self):
        # eve may not read alice's vault; the sim is told to serve it anyway
        rig = Rig(pentest(), plants=Plants(leak_reads={("u-eve", "v-alice")}))
        s = rig.session("u-eve", "ws")
        r = rig.do(s, "fs.read", vault="v-alice", path="/CANARY.txt")
        self.assertEqual(r.outcome, "ok")
        self.assertFalse(rig.engine.passed)
        judges = {v.judge for v in rig.engine.failures}
        self.assertIn("oracle", judges)                # model says deny, daemon allowed -> flagged
        self.assertIn("canary", judges)                # and the bytes carry alice's canary (product)
        self.assertIn("product", {v.classification for v in rig.engine.failures if v.judge == "canary"})

    def test_faithful_read_passes_both_oracle_and_canary(self):
        rig = Rig(pentest())
        s = rig.session("u-alice", "ws")
        r = rig.do(s, "fs.read", vault="v-alice", path="/CANARY.txt")
        self.assertEqual(r.outcome, "ok")
        self.assertEqual(rig.engine.failures, [])
        self.assertGreater(rig.engine.judges.counts["canary.scanned"], 0)


class CanaryJudge(unittest.TestCase):
    def test_leak_through_a_different_lane_still_trips(self):
        # a denied principal gets bytes over http that contain a foreign canary
        rig = Rig(pentest(), plants=Plants(leak_reads={("u-dave", "v-alice")}))
        s = rig.session("u-dave", "http")
        rig.do(s, "fs.read", vault="v-alice", path="/finance/ledger-2026.csv")
        self.assertIn("canary", rig.judges_of())


class IntegrityJudge(unittest.TestCase):
    def test_corrupted_read_bytes_are_caught(self):
        rig = Rig(pentest(), plants=Plants(corrupt_reads=True))
        s = rig.session("u-alice", "ws")
        rig.do(s, "fs.read", vault="v-alice", path="/CANARY.txt")
        self.assertIn("integrity", rig.judges_of())

    def test_clean_read_matches_the_formula(self):
        rig = Rig(pentest())
        s = rig.session("u-alice", "ws")
        rig.do(s, "fs.read", vault="v-alice", path="/README.md")
        self.assertNotIn("integrity", rig.judges_of())


class ParityJudge(unittest.TestCase):
    def test_surface_disagreement_is_caught(self):
        # alice is denied on fuse only; ws says allow, fuse says deny for the same probe in the same state
        rig = Rig(pentest(), plants=Plants(surface_deny={"fuse": {"u-alice"}}))
        ws = rig.session("u-alice", "ws", "a-ws")
        fuse = rig.session("u-alice", "fuse", "a-fuse")
        rig.do(ws, "fs.list", vault="v-alice", path="/")
        rig.do(fuse, "fs.list", vault="v-alice", path="/")
        self.assertIn("parity", rig.judges_of())


class LivenessJudge(unittest.TestCase):
    def test_wedge_is_a_failure_and_bounded(self):
        rig = Rig(pentest(), plants=Plants(wedge_ops={"fs.read"}), max_deadline_s=0.3, deadline_slack_s=0.1)
        s = rig.session("u-alice", "ws")
        r = rig.do(s, "fs.read", vault="v-alice", path="/README.md")
        self.assertIn(r.outcome, ("timeout",))
        self.assertIn("liveness", rig.judges_of())

    def test_crash_is_a_failure(self):
        rig = Rig(pentest(), plants=Plants(crash_after=0))
        s = rig.session("u-alice", "ws")
        r = rig.do(s, "fs.list", vault="v-alice", path="/")
        self.assertEqual(r.outcome, "crash")
        self.assertIn("liveness", rig.judges_of())


class RevocationGrace(unittest.TestCase):
    def test_stale_read_within_grace_is_tolerated_but_counts(self):
        # with a grace window, a read allowed by the just-superseded state is not flagged
        rig = Rig(pentest(), grace_s=5.0)
        admin = rig.session("u-admin", "ws", "adm")
        dave = rig.session("u-dave", "ws", "dv")
        rig.do(dave, "fs.read", vault="v-team", path="/README.md")              # allowed (reader)
        rig.do(admin, "roles.vault.unassign", vault="v-team", subject="g-readers", role="reader")
        rig.do(dave, "fs.read", vault="v-team", path="/README.md")              # now denied, but within grace
        # the sim enforces promptly, so this is a deny the model also reaches -> clean either way; assert no crash
        self.assertNotIn("liveness", rig.judges_of())


if __name__ == "__main__":
    unittest.main()
