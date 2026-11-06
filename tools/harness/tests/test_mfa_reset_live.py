"""Opt-in Tier B proof (#360): an MFA reset through the console's ws and through `vh` leaves the same state.

Always launches its own private Instance (never an existing installation), like test_ws_driver_live.py: set
VHH_WS_LIVE_BUILD to a build and run as root with VH_TEST_DB_* loaded from the harness db.env. Skipped otherwise.

Two accounts held to MFA (`vh user mfa require`) enroll an authenticator app through the lab client. One is reset by
the super admin over ws (`auth.mfa.admin.reset`, an account.credentials step-up answered with password + TOTP), the
other by an operator over the CLI socket (`vh user mfa reset`, as the Linux account bound to it: root is refused).
Both surfaces then report the same state (`auth.mfa.admin.status` and `vh user mfa status --json`), both accounts
sign in next through guided enrollment, and the audit trail holds both resets with their channels and verifies.
"""
from __future__ import annotations

import json
import os
import pwd
import re
import unittest
from pathlib import Path
from unittest.mock import patch

from vhh.drivers.cli_sock import CliSockDriver
from vhh.instance import Instance, mount_entry

from tools.lab.pentest.client import Target as NetTarget
from tools.lab.pentest.client import Ws, ok

OPERATOR_ACCOUNT = "vhh-actor-02"


@unittest.skipUnless(os.environ.get("VHH_WS_LIVE_BUILD"), "set VHH_WS_LIVE_BUILD for a private daemon proof")
class MfaResetParity(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        from vhh.redact import Redactor

        if os.geteuid() != 0:
            raise RuntimeError("private daemon proof requires root")
        cls.redactor = Redactor()
        cls.instance = Instance(Path(os.environ["VHH_WS_LIVE_BUILD"]), redactor=cls.redactor)
        cls.addClassCleanup(cls.stop_instance)
        keys = ("VH_TEST_DB_USER", "VH_TEST_DB_PASS", "VH_TEST_DB_HOST", "VH_TEST_DB_PORT")
        db = {key: os.environ[key] for key in keys}
        if db["VH_TEST_DB_USER"] != "vh_harness":
            raise RuntimeError("private proof requires the dedicated vh_harness database role")
        with patch("vhh.instance._read_env_file", return_value=db):
            cls.target = cls.instance.start()
        cls.admin_password = (cls.instance.backing / "super_admin_initial_password").read_text().strip()
        cls.redactor.register_secret(cls.admin_password)

    @classmethod
    def stop_instance(cls):
        report = cls.instance.stop()
        if cls.instance.alive() or mount_entry(cls.instance.mount) or cls.instance._db_created:
            raise AssertionError("private daemon cleanup incomplete")
        print("private MFA reset proof cleanup: " + json.dumps(report, sort_keys=True))

    def net(self) -> NetTarget:
        return NetTarget("127.0.0.1", ws_port=self.target.ws_port)

    async def cli(self, account: str | None) -> CliSockDriver:
        driver = CliSockDriver(self.target.cli_socket, account, redactor=self.redactor)
        await driver.open()
        self.addAsyncCleanup(driver.close)
        return driver

    async def must_cli(self, driver: CliSockDriver, argv: list[str]) -> str:
        result = await driver.run_line(argv, 30)
        self.assertEqual(result.outcome, "ok", f"{' '.join(argv[:3])}: {result.detail}")
        return result.data["stdout"]

    async def enrolled_account(self, root: CliSockDriver, operator: CliSockDriver, name: str) -> str:
        created = await self.must_cli(root, ["user", "create", name, "--role", "unprivileged"])
        password = re.search(r"^Password: (.+)$", created, re.MULTILINE).group(1)
        self.redactor.register_secret(password)
        await self.must_cli(operator, ["user", "mfa", "require", name])
        async with Ws(self.net(), user_agent="vhh-live/1") as ws:
            done = await ws.sign_in(name, password, enroll=True)
            self.assertTrue(ok(done), f"{name}: TOTP enrollment did not complete the sign-in")
            self.redactor.register_secret(ws.totp.secret_base32)
        return password

    async def test_ws_and_cli_resets_leave_the_same_state(self):
        root = await self.cli(None)
        # The super admin signs in once (TOTP enrollment), and the session stays open for the ws reset.
        async with Ws(self.net(), user_agent="vhh-live/1") as admin:
            first = await admin.sign_in("admin", self.admin_password, enroll=True)
            self.assertTrue(ok(first), "admin enrollment failed")
            self.redactor.register_secret(admin.totp.secret_base32)

            # An operator: an admin bound to a harness actor account, so `vh` runs as it (root may not reset MFA).
            uid = pwd.getpwnam(OPERATOR_ACCOUNT).pw_uid
            await self.must_cli(root, ["user", "create", "mfa-operator", "--role", "admin", "--linux-uid", str(uid)])
            operator = await self.cli(OPERATOR_ACCOUNT)

            ws_pw = await self.enrolled_account(root, operator, "mfa-target-ws")
            cli_pw = await self.enrolled_account(root, operator, "mfa-target-cli")

            # root (sudo) is refused, whoever it is.
            refused = await root.run_line(["user", "mfa", "reset", "mfa-target-cli", "--yes"], 30)
            self.assertNotEqual(refused.outcome, "ok")

            users = {u["name"]: u["id"] for u in (await admin.must("auth.users.list"))["users"]}
            reset_ws = await admin.stepped("auth.mfa.admin.reset", {"user_id": users["mfa-target-ws"],
                                                                     "reason": "tier-b parity"})
            self.assertTrue(ok(reset_ws), str(reset_ws.get("error"))[:200])
            await self.must_cli(operator, ["user", "mfa", "reset", "mfa-target-cli", "--reason", "tier-b parity",
                                           "--yes"])

            def facts(status: dict) -> dict:
                return {"factors": len(status["factors"]), "required_flag": status["required_flag"],
                        "codes": status["recovery"]["active"], "cooldown": status["cooldown_until"] is not None,
                        "reset": status["reset_at"] is not None}

            seen = {}
            for name in ("mfa-target-ws", "mfa-target-cli"):
                over_ws = await admin.must("auth.mfa.admin.status", {"user_id": users[name]})
                over_cli = json.loads(await self.must_cli(operator, ["user", "mfa", "status", name, "--json"]))
                self.assertEqual(facts(over_ws), facts(over_cli), f"{name}: ws and CLI disagree")
                seen[name] = facts(over_ws)
            self.assertEqual(seen["mfa-target-ws"], seen["mfa-target-cli"], "the two resets left different state")
            self.assertEqual(seen["mfa-target-ws"], {"factors": 0, "required_flag": True, "codes": False,
                                                     "cooldown": True, "reset": True})

        # Both sign in next through guided enrollment.
        for name, password in (("mfa-target-ws", ws_pw), ("mfa-target-cli", cli_pw)):
            async with Ws(self.net(), user_agent="vhh-live/1") as ws:
                answer = await ws.login(name, password)
                self.assertEqual(answer["data"].get("code"), "mfa_enrollment_required", name)

        # The trail holds both resets, by channel, and verifies.
        trail = json.loads(await self.must_cli(root, ["audit", "list", "--action", "auth.mfa.admin.reset", "--json"]))
        events = trail["events"] if isinstance(trail, dict) else trail
        channels = sorted(json.loads(e["details"])["channel"] if isinstance(e["details"], str) else e["details"]["channel"]
                          for e in events if e["outcome"] == "success")
        self.assertEqual(channels, ["admin_reset", "cli_reset"])
        self.assertTrue(any(e["outcome"] == "denied" for e in events), "root's refusal is in the trail")
        verified = await root.run_line(["audit", "verify"], 60)
        self.assertEqual(verified.outcome, "ok", verified.detail)
        print("private MFA reset proof: ws and CLI resets agree, enrollment next, trail verifies")


if __name__ == "__main__":
    unittest.main()
