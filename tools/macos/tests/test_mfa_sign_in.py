"""The macOS smokes' admin sign-in and step-up (#405), offline: tools/macos/session.py through the real
tools.lab.pentest.client.Ws and tools/lab/mfa.py, with a scripted daemon in place of the socket (the ws answers of
#357/#359 from tools/lab/tests/test_mfa.FakeDaemon, one per account, with its TOTP window and replay guard).

Nothing here starts a daemon or touches an installed service: install_acceptance.py and storage_smoke.py are only
imported, and their login() is driven against the script."""
from __future__ import annotations

import asyncio
import base64
import contextlib
import io
import json
import os
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tools.lab import mfa
from tools.lab.pentest.client import Target, Ws, WsError
from tools.lab.tests.test_mfa import Clock, FakeDaemon
from tools.macos import install_acceptance, session, storage_smoke

ADMIN_PW = "pw-correct-horse"
OTHER_PW = "pw-other-staple"
TARGET = Target(hostname="127.0.0.1", connect_ip="127.0.0.1", ws_port=1, http_port=2)


class ScriptedDaemon:
    """Accounts by name; every open_ws is a new connection whose session state starts empty (the account's factor and
    replay guard persist across connections, as in the daemon)."""

    def __init__(self, clock: Clock, **accounts: FakeDaemon):
        self.clock, self.accounts = clock, accounts
        self.connections: list["ScriptedConn"] = []

    async def open_ws(self, target: Target, path: str = "/ws") -> Ws:
        ws = Ws(target, path=path)
        ws.conn = ScriptedConn(self)
        self.connections.append(ws.conn)
        return ws


class ScriptedConn:
    def __init__(self, daemon: ScriptedDaemon):
        self.daemon, self.account, self.closed = daemon, None, False
        self.answers: asyncio.Queue = asyncio.Queue()
        self.sent: list[tuple[str, object]] = []

    async def send(self, text: str) -> None:
        req = json.loads(text)
        command, payload = req["command"], req["payload"]
        self.sent.append((command, payload))
        if command == "auth.login":
            self.account = self.daemon.accounts.get((payload or {}).get("name"))
            if self.account is not None:  # a new connection: no pending step, no sign-in, no grants
                self.account.pending, self.account.signed_in, self.account.grants = None, False, set()
        if self.account is None:
            answer = {"status": "ERROR", "error": "Invalid credentials", "data": {}}
        else:
            answer = await self.account(command, payload)
        await self.answers.put(json.dumps({**answer, "requestId": req["requestId"]}))

    async def recv(self) -> str:
        return await self.answers.get()

    async def close(self) -> None:
        self.closed = True


def run(coro):
    return asyncio.run(coro)


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock(1_800_000_015.0)  # 15 s into a step: the previous step is still usable
        self.admin = FakeDaemon(self.clock, password=ADMIN_PW)
        self.other = FakeDaemon(self.clock, password=OTHER_PW, required=False)
        self.daemon = ScriptedDaemon(self.clock, admin=self.admin, other=self.other)
        opened = patch.object(session, "open_ws", self.daemon.open_ws)
        opened.start()
        self.addCleanup(opened.stop)
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.totp_file = Path(self.tmp.name) / "admin-totp.json"

    def factor(self) -> session.AdminFactor:
        """A fresh process's view of the file (install_acceptance.py runs seed and every verify separately)."""
        return session.AdminFactor(mfa.TotpStore(self.totp_file), clock=self.clock)

    def commands(self, conn: ScriptedConn) -> list[str]:
        return [c for c, _ in conn.sent]


class InstallAcceptanceSignInTests(Base):
    def test_first_seed_enrolls_and_keeps_the_factor_private(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            ws = run(install_acceptance.login(TARGET, ADMIN_PW, self.factor()))
        self.assertTrue(self.admin.signed_in)
        self.assertEqual(self.commands(ws.conn), ["auth.login", "auth.mfa.totp.enroll.start",
                                                  "auth.mfa.totp.enroll.confirm", "auth.mfa.recovery.acknowledge"])
        self.assertEqual(stat.S_IMODE(self.totp_file.stat().st_mode), 0o600)
        doc = json.loads(self.totp_file.read_text())
        self.assertEqual(doc["secret_base32"], self.admin.secret.rstrip("="))
        self.assertEqual(doc["recovery_codes"], ["rc-aaaa-bbbb", "rc-cccc-dddd"])
        self.assertEqual(doc["last_step"], self.admin.last_step)
        self.assertNotIn(self.admin.secret.rstrip("="), out.getvalue())
        self.assertNotIn(ADMIN_PW, out.getvalue())

    def test_later_runs_answer_the_totp_step_from_the_file_and_never_reuse_a_step(self):
        run(install_acceptance.login(TARGET, ADMIN_PW, self.factor()))
        for _ in range(2):  # two verifies inside one 30 s step: the second takes the next step
            before = json.loads(self.totp_file.read_text())["last_step"]
            ws = run(install_acceptance.login(TARGET, ADMIN_PW, self.factor()))
            self.assertEqual(self.commands(ws.conn), ["auth.login", "auth.mfa.verify"])
            self.assertTrue(self.admin.signed_in)
            after = json.loads(self.totp_file.read_text())["last_step"]
            self.assertEqual(after, before + 1)
            self.assertEqual(self.admin.last_step, after)

    def test_an_admin_whose_factor_this_client_lacks_fails_without_enrolling(self):
        self.admin.secret = base64.b32encode(os.urandom(20)).decode()  # enrolled elsewhere (e.g. in the console)
        with self.assertRaises(session.SignInError) as cm:
            run(install_acceptance.login(TARGET, ADMIN_PW, self.factor()))
        self.assertIn("--totp-file", str(cm.exception))
        self.assertNotIn(ADMIN_PW, str(cm.exception))
        conn = self.daemon.connections[-1]
        self.assertEqual(self.commands(conn), ["auth.login"])
        self.assertTrue(conn.closed)
        self.assertFalse(self.totp_file.exists())

    def test_a_factor_left_from_an_earlier_install_is_reported_not_overwritten(self):
        run(install_acceptance.login(TARGET, ADMIN_PW, self.factor()))
        kept = self.totp_file.read_text()
        self.admin.secret = None  # a fresh install: the account has no factor yet
        with self.assertRaises(session.SignInError) as cm:
            run(install_acceptance.login(TARGET, ADMIN_PW, self.factor()))
        self.assertIn("remove that file", str(cm.exception))
        self.assertEqual(self.totp_file.read_text(), kept)
        self.assertNotIn("auth.mfa.totp.enroll.start", self.commands(self.daemon.connections[-1]))

    def test_a_wrong_password_never_reaches_the_second_step(self):
        with self.assertRaises(session.SignInError) as cm:
            run(install_acceptance.login(TARGET, "not-it", self.factor()))
        self.assertNotIn("not-it", str(cm.exception))
        self.assertEqual(self.commands(self.daemon.connections[-1]), ["auth.login"])
        self.assertFalse(self.totp_file.exists())

    def test_an_unprivileged_account_signs_in_with_its_password_alone(self):
        ws = run(install_acceptance.login(TARGET, OTHER_PW, name="other"))
        self.assertEqual(self.commands(ws.conn), ["auth.login"])
        self.assertTrue(self.other.signed_in)

    def test_an_account_that_asks_for_mfa_is_refused_without_a_factor(self):
        with self.assertRaises(session.SignInError) as cm:
            run(install_acceptance.login(TARGET, ADMIN_PW, name="admin"))
        self.assertIn("auth.login", self.commands(self.daemon.connections[-1]))
        self.assertNotIn("auth.mfa.totp.enroll.start", self.commands(self.daemon.connections[-1]))
        self.assertIn("mfa_enrollment_required", str(cm.exception))


class StepUpTests(Base):
    def signed_in(self) -> Ws:
        ws = run(install_acceptance.login(TARGET, ADMIN_PW, self.factor()))
        self.clock.t += 30
        return ws

    def test_a_step_up_refusal_is_answered_with_password_and_code_then_resent_once(self):
        ws = self.signed_in()

        async def go():
            return await session.must(ws, "storage.vault.remove", {"id": 3})

        self.assertEqual(run(go()), {"id": 3})
        tail = ws.conn.sent[-4:]
        self.assertEqual([c for c, _ in tail], ["storage.vault.remove", "auth.stepup.begin", "auth.stepup.finish",
                                                "storage.vault.remove"])
        finish = tail[2][1]
        self.assertEqual(finish["method"], "password_totp")
        self.assertEqual(finish["password"], ADMIN_PW)
        self.assertEqual(json.loads(self.totp_file.read_text())["last_step"], self.admin.last_step)

    def test_a_failed_step_up_raises_without_a_secret_and_is_not_resent(self):
        ws = self.signed_in()
        self.admin.password = "rotated-elsewhere"

        async def go():
            return await session.must(ws, "storage.vault.remove", {"id": 3})

        with self.assertRaises(WsError) as cm:
            run(go())
        self.assertIn("step_up_failed", str(cm.exception))
        self.assertNotIn(ADMIN_PW, str(cm.exception))
        self.assertEqual(self.commands(ws.conn).count("storage.vault.remove"), 1)

    def test_commands_without_step_up_pass_straight_through(self):
        ws = self.signed_in()
        before = len(ws.conn.sent)

        async def go():
            return await session.must(ws, "storage.vault.list")

        run(go())
        self.assertEqual(self.commands(ws.conn)[before:], ["storage.vault.list"])


class StorageSmokeSignInTests(Base):
    def test_the_enrolled_factor_lives_in_memory_and_signs_in_after_a_restart(self):
        admin = session.AdminFactor(clock=self.clock)
        cwd = os.getcwd()
        os.chdir(self.tmp.name)
        self.addCleanup(os.chdir, cwd)
        ws, _ = run(storage_smoke.login(TARGET, ADMIN_PW, admin))
        self.assertIn("auth.mfa.totp.enroll.confirm", self.commands(ws.conn))
        self.assertIsNotNone(admin.totp)
        self.assertEqual(os.listdir(self.tmp.name), [])  # nothing written
        self.clock.t += 45  # the daemon restarts
        ws, _ = run(storage_smoke.login(TARGET, ADMIN_PW, admin))
        self.assertEqual(self.commands(ws.conn), ["auth.login", "auth.mfa.verify"])
        self.assertTrue(self.admin.signed_in)

    def test_the_second_user_signs_in_with_its_password(self):
        ws, _ = run(storage_smoke.login(TARGET, OTHER_PW, name="other"))
        self.assertEqual(self.commands(ws.conn), ["auth.login"])

    def test_the_factor_never_shows_in_its_repr(self):
        admin = session.AdminFactor(clock=self.clock)
        run(storage_smoke.login(TARGET, ADMIN_PW, admin))
        self.assertNotIn(admin.totp.secret_base32, repr(admin.totp))


if __name__ == "__main__":
    unittest.main()
