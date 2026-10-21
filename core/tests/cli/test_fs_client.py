#!/usr/bin/env python3
"""The `vh fs get|put` client (core/main/cli.cpp) against a scripted daemon (#229).

Drives the real vaulthalla-cli over VAULTHALLA_CLI_SOCKET with a fake daemon that speaks the frames of
core/include/protocols/shell/Transfer.hpp, and checks what only the client can get wrong: a named output appears only
complete and atomically (and an existing one survives a failed download), stdout is binary-safe, out-of-order or
short or oversized transfers are refused with the right exit status, standard input is spooled so its size is
announced, a refusal in the middle of an upload is reported, and nothing local is sent to the daemon but the line.

  python3 core/tests/cli/test_fs_client.py <path to vaulthalla-cli>      (meson test `cli_fs_client`)
"""
from __future__ import annotations

import base64
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

VH = sys.argv.pop(1) if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else os.environ.get("VH_CLI", "")
CHUNK = 256 * 1024
MAX_TRANSFER_FRAME = 512 * 1024


def send(conn: socket.socket, obj: dict) -> None:
    body = json.dumps(obj).encode()
    conn.sendall(struct.pack(">I", len(body)) + body)


def recv(conn: socket.socket) -> dict | None:
    head = b""
    while len(head) < 4:
        part = conn.recv(4 - len(head))
        if not part:
            return None
        head += part
    (n,) = struct.unpack(">I", head)
    body = b""
    while len(body) < n:
        part = conn.recv(n - len(body))
        if not part:
            return None
        body += part
    return json.loads(body)


def data_frames(payload: bytes, start_seq: int = 0) -> list[dict]:
    return [{"type": "data", "seq": start_seq + i, "b64": base64.b64encode(payload[o:o + CHUNK]).decode()}
            for i, o in enumerate(range(0, len(payload), CHUNK))]


class FakeDaemon:
    """Serves one connection with `script(conn, request)` on a private socket."""

    def __init__(self, tmp: Path, script):
        self.path = str(tmp / "cli.sock")
        if os.path.exists(self.path):
            os.unlink(self.path)  # the previous scripted connection's
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        self.sock.listen(1)
        self.request: dict | None = None
        self.received = b""
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._serve, args=(script,), daemon=True)
        self.thread.start()

    def _serve(self, script) -> None:
        try:
            conn, _ = self.sock.accept()
            with conn:
                conn.settimeout(20)
                send(conn, {"type": "hello", "version": "test"})
                self.request = recv(conn)
                script(self, conn, self.request)
        except BaseException as e:  # surfaced by the test
            self.error = e
        finally:
            self.sock.close()

    def join(self) -> None:
        self.thread.join(30)


def run_vh(args: list[str], sock: str, stdin: bytes | None = None, cwd: str | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ, VAULTHALLA_CLI_SOCKET=sock, VAULTHALLA_CLI_TIMEOUT="5")
    return subprocess.run([VH, *args], input=stdin if stdin is not None else b"", capture_output=True, env=env,
                          cwd=cwd, timeout=60)


@unittest.skipUnless(VH and os.access(VH, os.X_OK), "pass the vaulthalla-cli binary (argv[1] or VH_CLI)")
class FsClient(unittest.TestCase):
    def setUp(self) -> None:
        # A short directory: unix socket paths are limited to 104 bytes on macOS.
        self.tmp = Path(tempfile.mkdtemp(prefix="vhfs-", dir="/tmp"))
        self.payload = bytes(range(256)) * 4096 + b"\x00\xff\n\r" * 1000  # binary, not UTF-8, > 4 chunks

    def tearDown(self) -> None:
        for p in sorted(self.tmp.rglob("*"), reverse=True):
            p.unlink() if not p.is_dir() else p.rmdir()
        self.tmp.rmdir()

    def leftovers(self) -> list[str]:
        return [p.name for p in self.tmp.iterdir() if p.name.startswith(".") and ".vh-" in p.name]

    def serve_get(self, frames_after_transfer: list[dict], result: dict, size: int | None = None):
        def script(d, conn, req):
            if size is not None:
                send(conn, {"type": "transfer", "size": size})
            for f in frames_after_transfer:
                send(conn, f)
            send(conn, {"type": "result", **result})
        return FakeDaemon(self.tmp, script)

    # ---------------------------------------------------------------------------------------------------- get ----

    def test_get_writes_the_named_file_atomically_and_only_when_complete(self) -> None:
        d = self.serve_get(data_frames(self.payload), {"ok": True, "exit_code": 0}, size=len(self.payload))
        out = self.tmp / "out.bin"
        r = run_vh(["fs", "get", "42", "/x.bin", "-o", str(out)], d.path)
        d.join()
        self.assertIsNone(d.error)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(out.read_bytes(), self.payload)
        self.assertEqual(self.leftovers(), [])
        self.assertEqual(r.stdout, b"")
        # The request says it speaks the transfer frames; the daemon gets the vault path, and no local file content.
        self.assertEqual(d.request["transfer"], {"v": 1})
        self.assertFalse(d.request["interactive"])
        self.assertIn("/x.bin", d.request["line"])

    def test_get_to_stdout_is_binary_safe(self) -> None:
        d = self.serve_get(data_frames(self.payload), {"ok": True, "exit_code": 0}, size=len(self.payload))
        r = run_vh(["fs", "get", "42", "/x.bin", "-o", "-"], d.path)
        d.join()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, self.payload)

    def test_out_of_order_short_and_oversized_transfers_keep_nothing(self) -> None:
        frames = data_frames(self.payload)
        broken = {
            "out of order": (frames[:1] + frames[2:], {"ok": True, "exit_code": 0}, 65),
            "short": (frames[:-1], {"ok": True, "exit_code": 0}, 65),
            "more than announced": (frames + data_frames(b"x", len(frames)), {"ok": True, "exit_code": 0}, 65),
            "bad base64": ([{"type": "data", "seq": 0, "b64": "@@@@"}], {"ok": True, "exit_code": 0}, 65),
        }
        for name, (fs, result, code) in broken.items():
            with self.subTest(name):
                d = self.serve_get(fs, result, size=len(self.payload))
                out = self.tmp / "broken.bin"
                r = run_vh(["fs", "get", "42", "/x.bin", "-o", str(out)], d.path)
                d.join()
                self.assertEqual(r.returncode, code, r.stderr)
                self.assertFalse(out.exists())
                self.assertEqual(self.leftovers(), [])

        def oversized(d, conn, req):
            send(conn, {"type": "transfer", "size": 10})
            conn.sendall(struct.pack(">I", MAX_TRANSFER_FRAME + 1))  # and never the body
        d = FakeDaemon(self.tmp, oversized)
        out = self.tmp / "oversized.bin"
        r = run_vh(["fs", "get", "42", "/x.bin", "-o", str(out)], d.path)
        d.join()
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(out.exists())
        self.assertEqual(self.leftovers(), [])

    def test_a_refused_download_leaves_an_existing_file_alone(self) -> None:
        out = self.tmp / "keep.txt"
        out.write_text("precious")
        d = self.serve_get([], {"ok": False, "exit_code": 77, "stderr": "fs get: permission denied"})
        r = run_vh(["fs", "get", "42", "/x.bin", "-o", str(out)], d.path)
        d.join()
        self.assertEqual(r.returncode, 77)
        self.assertIn(b"permission denied", r.stderr)
        self.assertEqual(out.read_text(), "precious")
        self.assertEqual(self.leftovers(), [])

    def test_a_failure_after_bytes_arrived_keeps_nothing(self) -> None:
        out = self.tmp / "partial.bin"
        d = self.serve_get(data_frames(self.payload)[:2], {"ok": False, "exit_code": 1,
                                                           "stderr": "fs get: integrity check failed"},
                           size=len(self.payload))
        r = run_vh(["fs", "get", "42", "/x.bin", "-o", str(out)], d.path)
        d.join()
        self.assertEqual(r.returncode, 1)
        self.assertFalse(out.exists())
        self.assertEqual(self.leftovers(), [])

    def test_get_refuses_a_directory_or_an_unwritable_place_before_connecting(self) -> None:
        r = run_vh(["fs", "get", "42", "/x.bin", "-o", str(self.tmp)], str(self.tmp / "nobody.sock"))
        self.assertEqual(r.returncode, 73, r.stderr)
        r = run_vh(["fs", "get", "42", "/x.bin", "-o", str(self.tmp / "missing" / "out.bin")],
                   str(self.tmp / "nobody.sock"))
        self.assertEqual(r.returncode, 73, r.stderr)
        r = run_vh(["fs", "get", "42"], str(self.tmp / "nobody.sock"))
        self.assertEqual(r.returncode, 64, r.stderr)

    # ---------------------------------------------------------------------------------------------------- put ----

    def serve_put(self, refuse_after: int | None = None):
        def script(d, conn, req):
            size = req["transfer"]["put_size"]
            send(conn, {"type": "transfer-ready", "size": size})
            seq = 0
            while True:
                f = recv(conn)
                if f is None:
                    return
                if f["type"] == "data":
                    assert f["seq"] == seq, f["seq"]
                    d.received += base64.b64decode(f["b64"], validate=True)
                    seq += 1
                    if refuse_after is not None and seq == refuse_after:
                        send(conn, {"type": "result", "ok": False, "exit_code": 77,
                                    "stderr": "fs put: permission revoked during the transfer"})
                        return
                elif f["type"] == "transfer-end":
                    assert f["bytes"] == size == len(d.received)
                    send(conn, {"type": "result", "ok": True, "exit_code": 0, "stdout": "stored\n"})
                    return
                else:
                    return
        return FakeDaemon(self.tmp, script)

    def test_put_sends_the_file_in_order_with_its_size_announced(self) -> None:
        src = self.tmp / "src.bin"
        src.write_bytes(self.payload)
        d = self.serve_put()
        r = run_vh(["fs", "put", "42", str(src), "/dst.bin"], d.path)
        d.join()
        self.assertIsNone(d.error)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d.received, self.payload)
        self.assertEqual(d.request["transfer"], {"v": 1, "put_size": len(self.payload)})
        self.assertEqual(r.stdout, b"stored\n")

    def test_put_spools_standard_input(self) -> None:
        d = self.serve_put()
        r = run_vh(["fs", "put", "42", "-", "/stdin.bin"], d.path, stdin=self.payload)
        d.join()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d.received, self.payload)
        self.assertEqual(d.request["transfer"]["put_size"], len(self.payload))

    def test_a_refusal_in_the_middle_of_an_upload_is_reported(self) -> None:
        src = self.tmp / "big.bin"
        src.write_bytes(self.payload * 8)  # far more than the socket buffers hold
        d = self.serve_put(refuse_after=1)
        r = run_vh(["fs", "put", "42", str(src), "/dst.bin"], d.path)
        d.join()
        self.assertEqual(r.returncode, 77, r.stderr)
        self.assertIn(b"revoked", r.stderr)

    def test_put_without_a_readable_local_file_never_connects(self) -> None:
        r = run_vh(["fs", "put", "42", str(self.tmp / "missing.bin"), "/x"], str(self.tmp / "nobody.sock"))
        self.assertEqual(r.returncode, 66, r.stderr)
        r = run_vh(["fs", "put", "42", str(self.tmp), "/x"], str(self.tmp / "nobody.sock"))
        self.assertEqual(r.returncode, 66, r.stderr)
        r = run_vh(["fs", "put", "--overwrite", "42", "a.bin", "/a.bin"], str(self.tmp / "nobody.sock"))
        self.assertEqual(r.returncode, 64, r.stderr)


    # ------------------------------------------------------------------------------------- vault keys import ----

    def serve_result(self, stdout: str = "imported"):
        def script(d, conn, req):
            send(conn, {"type": "result", "ok": True, "exit_code": 0, "stdout": stdout})
        return FakeDaemon(self.tmp, script)

    def test_key_import_attaches_the_file_read_on_the_callers_side(self) -> None:
        export = b'{"vault_id": 12, "key": "AAAA", "key_info": {"key_version": 1}}'
        src = self.tmp / "keys.json"
        src.write_bytes(export)
        d = self.serve_result()
        r = run_vh(["vault", "keys", "import", "12", "--file", str(src), "--confirm-name", "a"], d.path)
        d.join()
        self.assertIsNone(d.error)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d.request["input"], {"v": 1, "text": export.decode()})
        self.assertIn("--file", d.request["line"])  # a label for the daemon, which never opens it

        d = self.serve_result()
        r = run_vh(["v", "k", "import", "12", "-f", "-", "--confirm-name", "a"], d.path, stdin=export)
        d.join()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(d.request["input"]["text"], export.decode())

    def test_key_import_without_a_readable_file_never_connects(self) -> None:
        nobody = str(self.tmp / "nobody.sock")
        r = run_vh(["vault", "keys", "import", "12", "--file", str(self.tmp / "missing.json")], nobody)
        self.assertEqual(r.returncode, 66, r.stderr)
        r = run_vh(["vault", "keys", "import", "12", "--file", str(self.tmp)], nobody)
        self.assertEqual(r.returncode, 66, r.stderr)
        r = run_vh(["vault", "keys", "import", "12"], nobody)
        self.assertEqual(r.returncode, 64, r.stderr)
        big = self.tmp / "big.json"
        big.write_bytes(b" " * (512 * 1024 + 1))
        r = run_vh(["vault", "keys", "import", "12", "--file", str(big)], nobody)
        self.assertEqual(r.returncode, 66, r.stderr)


if __name__ == "__main__":
    unittest.main()
