"""Opt in with VHH_INTEGRATION_LIVE_BUILD; creates and tears down its own private daemon and fixture."""
from __future__ import annotations

import hashlib
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from vhh.drivers.http import HttpLane
from vhh.drivers.ws import WsDriver
from vhh.instance import Instance, mount_entry
from vhh.provision import provision
from vhh.redact import Redactor
from vhh.scenario_revoke import run_revoke


@unittest.skipUnless(os.environ.get("VHH_INTEGRATION_LIVE_BUILD"), "private multi-surface proof is opt-in")
class MultiSurfaceLiveTests(unittest.IsolatedAsyncioTestCase):
    async def test_revoke_and_authenticated_http_integrity(self):
        red = Redactor()
        inst = Instance(Path(os.environ["VHH_INTEGRATION_LIVE_BUILD"]), redactor=red)
        captured = {}
        async def seed(target, world, broker, redactor):
            binding = await provision(target, world, broker, redactor)
            captured.update(binding=binding, broker=broker)
            return binding

        try:
            inst.start()
            with inst.watchdog(180):
                with patch("vhh.scenario_revoke.provision", side_effect=seed):
                    report = await run_revoke(inst)
                (inst.artifacts / "revoke.json").write_text(json.dumps(report, indent=2))
                self.assertTrue(report["ok"], report["why"])
                results = []
                for principal in ("u-alice", "u-eve"):
                    ws = WsDriver(inst.target.ws_port, principal, broker=captured["broker"], redactor=red)
                    lane = HttpLane(inst.target.http_port, red)
                    try:
                        await ws.open()
                        lane.attach(ws)
                        vid = captured["binding"].vault_id("v-alice")
                        data = b"private HTTP integration proof\x00\xff"
                        uploaded = await lane.upload(vid, "/http-proof +é.bin", data, 10)
                        downloaded = await lane.download(vid, "/http-proof +é.bin", 10)
                        results.extend((uploaded, downloaded))
                        if principal == "u-alice":
                            self.assertEqual(uploaded.outcome, "ok", uploaded.detail)
                            self.assertEqual(downloaded.outcome, "ok", downloaded.detail)
                            self.assertTrue(downloaded.body == data, "HTTP bytes differ")
                            self.assertEqual(downloaded.bytes_sha256, hashlib.sha256(data).hexdigest())
                        else:
                            self.assertEqual(uploaded.outcome, "denied")
                            self.assertIn(downloaded.outcome, ("denied", "not_found"))
                    finally:
                        await lane.close()
                        await ws.close()
                serialized = json.dumps([r.to_json() for r in results])
                self.assertEqual(serialized, red.redact_text(serialized), "HTTP result contains a registered secret")
                self.assertFalse(inst.sanitizer_reports(), "sanitizer finding in private instance")
                print("private multi-surface proof: " + json.dumps(
                    {k: report[k] for k in ("ok", "grant_latency_s", "revoke_latency_s")}))
        finally:
            stop = inst.stop()
            self.assertIsNone(mount_entry(inst.mount))
            self.assertFalse(inst._db_created, "private database cleanup incomplete")
            print("private multi-surface cleanup: " + json.dumps(stop))
