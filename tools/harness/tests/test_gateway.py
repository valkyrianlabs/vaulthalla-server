"""Agent gateway: in-process tool API and the loopback HTTP gateway. Only actor-side tools, one session per agent,
no provisioning/reset/admin tools. A scripted fake agent (unseeded random calls) never crashes the engine and a
planted leak surfaces as a canary trip in its trace."""
import asyncio
import json
import random
import unittest
import urllib.request

from tests.helpers import pentest
from vhh.broker import IdentityBroker
from vhh.catalog import Catalog
from vhh.engine import Engine
from vhh.gateway import GatewayError, HttpGateway, ToolAPI
from vhh.redact import Redactor
from vhh.sim import Plants, SimDaemon, SimDriver


def _api(plants=None):
    w = pentest()
    red = Redactor()
    broker = IdentityBroker(red)
    broker.register_canaries(w.canaries)
    sim = SimDaemon(w, plants)
    sim.register_credentials(broker)
    engine = Engine(w, Catalog(), broker, red)
    return ToolAPI(engine), broker, sim


class ToolSurface(unittest.TestCase):
    def test_only_actor_side_tools_are_exposed(self):
        api, *_ = _api()
        names = {t["name"] for t in api.list_tools()}
        self.assertIn("fs.read", names)
        self.assertIn("shares.create", names)
        for admin in ("users.create", "users.delete", "vaults.create", "roles.vault.assign"):
            self.assertNotIn(admin, names)

    def test_agent_cannot_override_its_principal_or_call_admin_tools(self):
        api, broker, sim = _api()
        api.register_agent("a1", "u-eve", "ws", SimDriver("ws", sim, broker))
        # eve may not read alice's vault; trying to spoof principal is ignored
        r = asyncio.run(api.call("a1", "fs.read", {"vault": "v-alice", "path": "/CANARY.txt", "principal": "u-admin"}))
        self.assertEqual(r["outcome"], "denied")
        # an admin tool is rejected (not in the actor tool set) and scope-blocked
        r2 = asyncio.run(api.call("a1", "users.delete", {"principal": "u-bob"}))
        self.assertIn("error", r2)
        self.assertEqual(api.engine.counts["executed"], 1)      # the admin call never executed

    def test_read_own_trace(self):
        api, broker, sim = _api()
        api.register_agent("a1", "u-alice", "ws", SimDriver("ws", sim, broker))
        asyncio.run(api.call("a1", "fs.list", {"vault": "v-alice", "path": "/"}))
        self.assertEqual(len(api.read_trace("a1")), 1)
        with self.assertRaises(GatewayError):
            api.read_trace("nope")


class FakeAgent(unittest.TestCase):
    def test_scripted_agent_cannot_crash_engine_and_leak_trips_canary(self):
        api, broker, sim = _api(Plants(leak_reads={("u-eve", "v-alice")}))
        api.register_agent("bot", "u-eve", "ws", SimDriver("ws", sim, broker))
        tools = [t["name"] for t in api.list_tools()]
        rnd = random.Random()          # unseeded on purpose: agents are not reproducible, their trace is
        vaults = ["v-alice", "v-team", "v-eve"]
        paths = ["/", "/CANARY.txt", "/finance/ledger-2026.csv", "/README.md"]

        async def drive():
            for _ in range(40):
                tool = rnd.choice(tools)
                args = {}
                if tool != "auth.login":
                    args = {"vault": rnd.choice(vaults), "path": rnd.choice(paths)}
                    if tool in ("fs.rename", "fs.copy"):
                        args["to"] = "/x.txt"
                    if tool == "fs.write":
                        args["version"] = 1
                    if tool == "shares.create":
                        args = {"vault": rnd.choice(vaults)}
                await api.call("bot", tool, args)
            # the agent, whatever else it does, reaches for the cross-tenant file at least once
            await api.call("bot", "fs.read", {"vault": "v-alice", "path": "/CANARY.txt"})
        asyncio.run(drive())
        self.assertEqual(api.engine.counts["harness_errors"], 0)   # arbitrary agent calls never crash the engine
        self.assertFalse(api.engine.passed)                # the planted leak is caught
        self.assertIn("canary", {v.judge for v in api.engine.failures})


class HttpSurface(unittest.TestCase):
    def test_loopback_only_and_bearer_auth(self):
        with self.assertRaises(GatewayError):
            HttpGateway(None, asyncio.new_event_loop(), host="0.0.0.0")

    def test_http_round_trip(self):
        api, broker, sim = _api()

        async def main():
            token = api.register_agent("h1", "u-alice", "ws", SimDriver("ws", sim, broker))
            gw = HttpGateway(api, asyncio.get_running_loop()).start()
            try:
                def _req(method, path, body=None):
                    r = urllib.request.Request(gw.url + path, data=body, method=method,
                                               headers={"Authorization": f"Bearer {token}",
                                                        "Content-Type": "application/json"})
                    return json.loads(urllib.request.urlopen(r, timeout=5).read())

                async def req(*a):          # keep the event loop free while the blocking call runs
                    return await asyncio.to_thread(_req, *a)

                def _noauth():
                    urllib.request.urlopen(gw.url + "/v1/tools", timeout=5)
                try:
                    await asyncio.to_thread(_noauth)
                    self.fail("expected 401")
                except urllib.error.HTTPError as e:
                    self.assertEqual(e.code, 401)
                tools = await req("GET", "/v1/tools")
                self.assertIn("fs.read", {t["name"] for t in tools["tools"]})
                out = await req("POST", "/v1/call", json.dumps({"tool": "fs.list", "args": {"vault": "v-alice",
                                                                                            "path": "/"}}).encode())
                self.assertEqual(out["outcome"], "ok")
            finally:
                gw.stop()
        asyncio.run(main())


if __name__ == "__main__":
    unittest.main()
