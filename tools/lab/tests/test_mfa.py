"""tools/lab/mfa.py: RFC 6238 codes, step allocation under the daemon's replay guard, the two-step sign-in, guided
enrollment, step-up, and the private TOTP file. Offline: a scripted daemon stands in for the ws side of #357/#359."""
from __future__ import annotations

import asyncio
import base64
import json
import os
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.lab import mfa

RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()  # RFC 6238 appendix B, SHA-1 seed


class Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class FakeDaemon:
    """The ws answers of core/protocols/ws/handler/{Auth,Mfa,StepUp}.cpp for one account, with the same TOTP window
    (current step +-1) and replay guard (a step at or below the last accepted is refused)."""

    def __init__(self, clock: Clock, *, password="pw-correct-horse", enrolled_secret=None, required=True):
        self.clock, self.password, self.required = clock, password, required
        self.secret = enrolled_secret
        self.last_step = -1
        self.pending = None
        self.signed_in = False
        self.pending_secret = None
        self.batch = None
        self.grants = set()
        self.sent: list[tuple[str, object]] = []

    def accept(self, secret: str, code: str) -> bool:
        current = int(self.clock() // 30)
        for step in range(current - 1, current + 2):
            if step > self.last_step and mfa.hotp(mfa.decode_secret(secret), step) == code:
                self.last_step = step
                return True
        return False

    @staticmethod
    def refuse(code, text="refused", **data):
        return {"status": "ERROR", "error": text, "data": {"code": code, **data}}

    async def __call__(self, command, payload):
        self.sent.append((command, payload))
        payload = payload or {}
        if command == "auth.login":
            if payload.get("password") != self.password:
                return {"status": "ERROR", "error": "Invalid credentials", "data": {}}
            if self.secret:
                self.pending = "mfa"
                return self.refuse("mfa_required", pending={"kind": "mfa", "methods": ["totp"]})
            if self.required:
                self.pending = "enrollment"
                return self.refuse("mfa_enrollment_required", pending={"kind": "enrollment", "methods": ["totp"]})
            self.signed_in = True
            return {"status": "OK", "data": {"user": {"name": "admin"}}}
        if command == "auth.mfa.verify":
            if self.pending != "mfa" or payload.get("method") != "totp":
                return self.refuse("denied")
            if not self.accept(self.secret, payload.get("code", "")):
                return self.refuse("mfa_invalid", attempts_remaining=4)
            self.pending, self.signed_in = None, True
            return {"status": "OK", "data": {"user": {"name": "admin"}, "aal": 2}}
        if command == "auth.mfa.totp.enroll.start":
            if self.pending != "enrollment":
                return self.refuse("denied")
            self.pending_secret = base64.b32encode(os.urandom(20)).decode()
            return {"status": "OK", "data": {"enrollment_id": 7, "secret_base32": self.pending_secret}}
        if command == "auth.mfa.totp.enroll.confirm":
            if payload.get("enrollment_id") != 7 or not self.accept(self.pending_secret, payload.get("code", "")):
                return self.refuse("invalid")
            self.secret, self.batch = self.pending_secret, "batch-1"
            return {"status": "OK", "data": {"factor": {"id": 7}, "recovery_codes": {
                "batch_id": self.batch, "codes": ["rc-aaaa-bbbb", "rc-cccc-dddd"]}}}
        if command == "auth.mfa.recovery.acknowledge":
            if payload.get("batch_id") != self.batch or self.pending != "enrollment":
                return self.refuse("not_found")
            self.pending, self.signed_in = None, True
            return {"status": "OK", "data": {"user": {"name": "admin"}, "aal": 2, "remaining": 2}}
        if not self.signed_in:
            return {"status": "UNAUTHORIZED", "error": "Sign in first", "data": {}}
        if command == "auth.stepup.begin":
            return {"status": "OK", "data": {"stepup_id": "c1", "family": payload["family"],
                                             "target": payload.get("target"),
                                             "methods": ["password_totp"] if self.secret else ["password"]}}
        if command == "auth.stepup.finish":
            good = payload.get("password") == self.password and (
                payload.get("method") == "password" or self.accept(self.secret, payload.get("code", "")))
            if not good:
                return self.refuse("step_up_failed", attempts_remaining=4)
            self.grants.add("data.destroy")
            return {"status": "OK", "data": {"family": "data.destroy", "uses": 1}}
        if command == "storage.vault.remove":
            if "data.destroy" not in self.grants:
                return self.refuse("step_up_required", family="data.destroy", target="vault:3",
                                   methods=["password_totp"], max_age_seconds=300)
            self.grants.discard("data.destroy")
            return {"status": "OK", "data": {"id": 3}}
        return {"status": "OK", "data": {}}


def run(coro):
    return asyncio.run(coro)


class CodeTests(unittest.TestCase):
    def test_rfc6238_sha1_vectors(self):
        secret = mfa.decode_secret(RFC_SECRET)
        # Appendix B's 8-digit values, truncated to the 6 digits the daemon uses (core/auth/mfa/Totp.hpp).
        for t, expected in ((59, "287082"), (1111111109, "081804"), (1234567890, "005924"),
                            (2000000000, "279037")):
            self.assertEqual(mfa.hotp(secret, t // 30), expected)
        self.assertEqual(mfa.hotp(secret, 59 // 30, digits=8), "94287082")

    def test_secret_decoding_tolerates_spacing_case_and_padding(self):
        self.assertEqual(mfa.decode_secret(RFC_SECRET.lower()), b"12345678901234567890")
        self.assertEqual(mfa.decode_secret(" ".join(RFC_SECRET[i:i + 4] for i in range(0, 32, 4))),
                         b"12345678901234567890")
        with self.assertRaises(ValueError):
            mfa.decode_secret("not base32 !")
        with self.assertRaises(ValueError):
            mfa.decode_secret("   ")

    def test_repr_and_errors_never_show_the_seed(self):
        totp = mfa.Totp(RFC_SECRET)
        self.assertNotIn(RFC_SECRET, repr(totp))
        self.assertNotIn(RFC_SECRET, str(totp))


class AllocationTests(unittest.TestCase):
    def test_each_step_is_handed_out_once_then_the_next_is_awaited(self):
        clock = Clock(30 * 1000 + 5)  # step 1000, 25 s left
        totp = mfa.Totp(RFC_SECRET, clock=clock)
        self.assertEqual(totp.allocate(), (999, 0.0))   # the previous step is still inside the window
        self.assertEqual(totp.allocate(), (1000, 0.0))
        self.assertEqual(totp.allocate(), (1001, 0.0))
        step, wait = totp.allocate()
        self.assertEqual(step, 1002)
        self.assertAlmostEqual(wait, 30 * 1001 - clock.t + 0.25)  # until step 1001 is current
        self.assertEqual(totp.last_step, 1002)

    def test_previous_step_is_skipped_near_the_end_of_a_step(self):
        totp = mfa.Totp(RFC_SECRET, clock=Clock(30 * 1000 + 28))
        self.assertEqual(totp.allocate()[0], 1000)

    def test_last_step_from_an_earlier_run_is_honoured(self):
        totp = mfa.Totp(RFC_SECRET, last_step=1000, clock=Clock(30 * 1000 + 5))
        self.assertEqual(totp.allocate(), (1001, 0.0))

    def test_codes_are_accepted_by_the_replay_guard(self):
        clock = Clock(30 * 2000 + 2)
        daemon = FakeDaemon(clock, enrolled_secret=RFC_SECRET)
        totp = mfa.Totp(RFC_SECRET, clock=clock)
        for _ in range(3):
            self.assertTrue(daemon.accept(RFC_SECRET, run(totp.next_code())))
        self.assertFalse(daemon.accept(RFC_SECRET, totp.code(totp.last_step)))  # a replay is refused

    def test_on_spend_sees_the_new_step(self):
        seen = []
        totp = mfa.Totp(RFC_SECRET, clock=Clock(30 * 5 + 1), on_spend=lambda t: seen.append(t.last_step))
        totp.allocate()
        self.assertEqual(seen, [4])


class SignInTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock(30 * 3000 + 4)

    def test_mfa_required_is_finished_with_a_code(self):
        daemon = FakeDaemon(self.clock, enrolled_secret=RFC_SECRET)
        totp = mfa.Totp(RFC_SECRET, clock=self.clock)
        msg, used = run(mfa.sign_in(daemon, "admin", "pw-correct-horse", totp))
        self.assertTrue(mfa.ok(msg))
        self.assertIs(used, totp)
        self.assertEqual([c for c, _ in daemon.sent], ["auth.login", "auth.mfa.verify"])

    def test_two_sign_ins_in_one_step_use_different_steps(self):
        daemon = FakeDaemon(self.clock, enrolled_secret=RFC_SECRET)
        totp = mfa.Totp(RFC_SECRET, clock=self.clock)
        for _ in range(2):
            daemon.signed_in = False
            self.assertTrue(mfa.ok(run(mfa.sign_in(daemon, "admin", "pw-correct-horse", totp))[0]))

    def test_without_a_factor_the_pending_refusal_is_returned(self):
        daemon = FakeDaemon(self.clock, enrolled_secret=RFC_SECRET)
        msg, used = run(mfa.sign_in(daemon, "admin", "pw-correct-horse"))
        self.assertEqual(mfa.code_of(msg), "mfa_required")
        self.assertIsNone(used)
        self.assertFalse(daemon.signed_in)

    def test_wrong_password_never_reaches_the_second_step(self):
        daemon = FakeDaemon(self.clock, enrolled_secret=RFC_SECRET)
        msg, _ = run(mfa.sign_in(daemon, "admin", "wrong", mfa.Totp(RFC_SECRET, clock=self.clock)))
        self.assertFalse(mfa.ok(msg))
        self.assertEqual([c for c, _ in daemon.sent], ["auth.login"])

    def test_account_without_mfa_signs_in_with_the_password(self):
        daemon = FakeDaemon(self.clock, required=False)
        msg, used = run(mfa.sign_in(daemon, "alice", "pw-correct-horse", enroll=True))
        self.assertTrue(mfa.ok(msg))
        self.assertIsNone(used)

    def test_enrollment_is_completed_and_the_secret_handed_to_the_caller_first(self):
        daemon = FakeDaemon(self.clock)
        kept = {}

        def on_enrolled(totp, codes):
            self.assertFalse(daemon.signed_in)  # kept before the acknowledgement completes the sign-in
            kept.update(secret=totp.secret_base32, codes=codes)

        msg, totp = run(mfa.sign_in(daemon, "admin", "pw-correct-horse", enroll=True, on_enrolled=on_enrolled,
                                    clock=self.clock))
        self.assertTrue(mfa.ok(msg))
        self.assertTrue(daemon.signed_in)
        self.assertEqual(kept["secret"], daemon.secret)
        self.assertEqual(kept["codes"], ["rc-aaaa-bbbb", "rc-cccc-dddd"])
        self.assertEqual([c for c, _ in daemon.sent], ["auth.login", "auth.mfa.totp.enroll.start",
                                                       "auth.mfa.totp.enroll.confirm",
                                                       "auth.mfa.recovery.acknowledge"])
        # The next sign-in answers mfa_required with the enrolled factor, on a later step than the confirmation's.
        daemon.signed_in = False
        again, _ = run(mfa.sign_in(daemon, "admin", "pw-correct-horse", totp))
        self.assertTrue(mfa.ok(again))

    def test_enrollment_is_not_started_unless_asked(self):
        daemon = FakeDaemon(self.clock)
        msg, _ = run(mfa.sign_in(daemon, "admin", "pw-correct-horse"))
        self.assertEqual(mfa.code_of(msg), "mfa_enrollment_required")
        self.assertEqual(len(daemon.sent), 1)

    def test_a_failed_enrollment_raises_without_the_secret(self):
        daemon = FakeDaemon(self.clock)
        original = daemon.accept
        daemon.accept = lambda secret, code: False
        with self.assertRaises(mfa.MfaError) as caught:
            run(mfa.sign_in(daemon, "admin", "pw-correct-horse", enroll=True, clock=self.clock))
        daemon.accept = original
        self.assertNotIn(daemon.pending_secret, str(caught.exception))


class StepUpTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock(30 * 4000 + 4)

    def signed_in(self, secret=RFC_SECRET):
        daemon = FakeDaemon(self.clock, enrolled_secret=secret, required=secret is not None)
        totp = mfa.Totp(secret, clock=self.clock) if secret else None
        self.assertTrue(mfa.ok(run(mfa.sign_in(daemon, "admin", "pw-correct-horse", totp))[0]))
        return daemon, totp

    def test_refusal_is_confirmed_with_password_and_code_then_resent_once(self):
        daemon, totp = self.signed_in()
        msg = run(mfa.send_stepped(daemon, "storage.vault.remove", {"id": 3}, "pw-correct-horse", totp))
        self.assertTrue(mfa.ok(msg))
        sent = [c for c, _ in daemon.sent][2:]
        self.assertEqual(sent, ["storage.vault.remove", "auth.stepup.begin", "auth.stepup.finish",
                                "storage.vault.remove"])
        begin = daemon.sent[3][1]
        self.assertEqual(begin, {"family": "data.destroy", "target": "vault:3"})
        finish = daemon.sent[4][1]
        self.assertEqual(finish["method"], "password_totp")
        self.assertEqual(finish["stepup_id"], "c1")

    def test_failed_step_up_is_returned_and_not_resent(self):
        daemon, totp = self.signed_in()
        msg = run(mfa.send_stepped(daemon, "storage.vault.remove", {"id": 3}, "wrong", totp))
        self.assertEqual(mfa.code_of(msg), "step_up_failed")
        self.assertEqual([c for c, _ in daemon.sent].count("storage.vault.remove"), 1)

    def test_password_alone_where_the_daemon_offers_it(self):
        daemon, _ = self.signed_in(secret=None)
        msg = run(mfa.send_stepped(daemon, "storage.vault.remove", {"id": 3}, "pw-correct-horse", None))
        self.assertTrue(mfa.ok(msg))
        self.assertEqual(daemon.sent[-2][1]["method"], "password")

    def test_no_answerable_method_is_reported(self):
        async def daemon(command, payload):
            if command == "auth.stepup.begin":
                return {"status": "OK", "data": {"stepup_id": "c", "methods": ["webauthn"]}}
            return FakeDaemon.refuse("step_up_required", family="keys", target="vault:1")

        msg = run(mfa.send_stepped(daemon, "vault.keys.export", {}, "pw", mfa.Totp(RFC_SECRET)))
        self.assertEqual(mfa.code_of(msg), "step_up_unavailable")

    def test_other_commands_pass_through(self):
        daemon, totp = self.signed_in()
        msg = run(mfa.send_stepped(daemon, "storage.vault.list", None, "pw-correct-horse", totp))
        self.assertTrue(mfa.ok(msg))
        self.assertNotIn("auth.stepup.begin", [c for c, _ in daemon.sent])


class StoreTests(unittest.TestCase):
    def test_enrolled_factor_is_kept_private_and_reloaded_with_its_last_step(self):
        with TemporaryDirectory() as d:
            store = mfa.TotpStore(Path(d) / "admin.totp")
            totp = mfa.Totp(RFC_SECRET, last_step=41)
            store.enrolled(totp, ["rc-1", "rc-2"])
            self.assertEqual(stat.S_IMODE(store.path.stat().st_mode), 0o600)
            totp.allocate()  # spending a code writes the step back
            doc = json.loads(store.path.read_text())
            self.assertEqual(doc["secret_base32"], RFC_SECRET)
            self.assertEqual(doc["recovery_codes"], ["rc-1", "rc-2"])
            self.assertEqual(doc["last_step"], totp.last_step)
            loaded = mfa.TotpStore(store.path).load()
            self.assertEqual(loaded.last_step, totp.last_step)
            self.assertEqual(loaded.secret_base32, RFC_SECRET)
            self.assertEqual(sorted(os.listdir(d)), ["admin.totp"])  # no temp files left behind

    def test_refuses_to_overwrite_an_existing_factor(self):
        with TemporaryDirectory() as d:
            store = mfa.TotpStore(Path(d) / "admin.totp")
            store.enrolled(mfa.Totp(RFC_SECRET), [])
            with self.assertRaises(mfa.MfaError):
                store.enrolled(mfa.Totp(RFC_SECRET), [])

    def test_bare_secret_file_and_permission_check(self):
        with TemporaryDirectory() as d:
            path = Path(d) / "bare"
            path.write_text(RFC_SECRET + "\n")
            path.chmod(0o644)
            with self.assertRaises(PermissionError):
                mfa.TotpStore(path).load()
            path.chmod(0o600)
            totp = mfa.TotpStore(path).load()
            self.assertEqual(totp.secret_base32, RFC_SECRET)
            totp.allocate()
            self.assertEqual(json.loads(path.read_text())["secret_base32"], RFC_SECRET)


if __name__ == "__main__":
    unittest.main()
