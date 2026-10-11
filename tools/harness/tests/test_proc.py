"""The bounded JSON-line helper process: a dying, silent or wedged child yields a typed error, never a hang.

A tiny inline Python child stands in for vh_fs_actor so the test needs no build."""
import sys
import unittest

from vhh.proc import JsonLineProcess, ProcError

try:  # Python 3.11+
    from unittest import IsolatedAsyncioTestCase
except ImportError:  # pragma: no cover
    IsolatedAsyncioTestCase = None

ECHO = r'''
import sys, json
print(json.dumps({"ready": True, "pid": 12345})); sys.stdout.flush()
for line in sys.stdin:
    req = json.loads(line)
    op = req.get("op")
    if op == "exit":
        break
    if op == "die":
        sys.exit(3)
    if op == "wedge":
        import time; time.sleep(3600)
    if op == "garbage":
        print("not json"); sys.stdout.flush(); continue
    print(json.dumps({"id": req["id"], "echo": req.get("op")})); sys.stdout.flush()
'''

NO_READY = 'import time; time.sleep(3600)'


def child(src):
    return JsonLineProcess([sys.executable, "-I", "-c", src], ready_timeout_s=3.0)


class ProcTests(IsolatedAsyncioTestCase if IsolatedAsyncioTestCase else unittest.TestCase):
    async def test_happy_path(self):
        p = child(ECHO)
        ready = await p.start()
        self.assertTrue(ready["ready"])
        self.assertEqual((await p.request({"op": "ls"}, 2.0))["echo"], "ls")
        self.assertEqual(await p.stop(), 0)      # clean exit

    async def test_dead_child_is_typed(self):
        p = child(ECHO)
        await p.start()
        with self.assertRaises(ProcError) as cm:
            await p.request({"op": "die"}, 2.0)
        self.assertEqual(cm.exception.kind, "died")

    async def test_wedge_times_out_not_hangs(self):
        p = child(ECHO)
        await p.start()
        with self.assertRaises(ProcError) as cm:
            await p.request({"op": "wedge"}, 0.3)
        self.assertEqual(cm.exception.kind, "timeout")
        await p.stop(grace_s=0.3)          # stop must not hang on a wedged child

    async def test_garbage_line_is_protocol_error(self):
        p = child(ECHO)
        await p.start()
        with self.assertRaises(ProcError) as cm:
            await p.request({"op": "garbage"}, 2.0)
        self.assertEqual(cm.exception.kind, "protocol")
        await p.stop()

    async def test_missing_ready_line_times_out(self):
        p = JsonLineProcess([sys.executable, "-I", "-c", NO_READY], ready_timeout_s=0.3)
        with self.assertRaises(ProcError) as cm:
            await p.start()
        self.assertEqual(cm.exception.kind, "timeout")
        await p.stop(grace_s=0.3)


if __name__ == "__main__":
    unittest.main()
