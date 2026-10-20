#!/usr/bin/env python3
"""`vh mcp` and `vh skill install` (core/main/cli_mcp.cpp, cli_skill.cpp) end to end.

Drives the real vaulthalla-cli: `vh mcp` speaks newline-delimited JSON-RPC on stdin/stdout while a scripted daemon
answers its control-socket requests (one connection per tool call), so this checks what crosses the wire: the line the
daemon is asked to run (--json added, no confirmation flag unless the agent passed `confirm`), that excluded commands
never reach the daemon, how exits and refusals become tool results, and that stdout carries nothing but protocol
messages. `vh skill install` runs against a temporary HOME with no agent CLI on PATH.

  python3 core/tests/cli/test_mcp_client.py <path to vaulthalla-cli>      (meson test `cli_mcp_client`)
"""
from __future__ import annotations

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
VH = os.path.abspath(VH) if VH else VH


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


class FakeDaemon:
    """Answers every connection with `answer(request) -> result frame fields` and records the requests."""

    def __init__(self, tmp: Path, answer):
        self.path = str(tmp / "cli.sock")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.answer = answer
        self.requests: list[dict] = []
        self.error: BaseException | None = None
        self.stopping = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while not self.stopping:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            try:
                with conn:
                    conn.settimeout(20)
                    send(conn, {"type": "hello", "version": "test"})
                    req = recv(conn)
                    self.requests.append(req)
                    send(conn, {"type": "result", **self.answer(req)})
            except BaseException as e:  # surfaced by the test
                self.error = e

    def stop(self) -> None:
        self.stopping = True
        self.thread.join(5)
        self.sock.close()


class McpSession:
    """One `vh mcp` process; call() sends a request and returns its response."""

    def __init__(self, sock: str):
        env = dict(os.environ, VAULTHALLA_CLI_SOCKET=sock, VAULTHALLA_CLI_TIMEOUT="5")
        self.proc = subprocess.Popen([VH, "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env=env, text=True, bufsize=1)
        self.next_id = 0

    def raw(self, line: str) -> dict:
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        out = self.proc.stdout.readline()
        return json.loads(out)

    def call(self, method: str, params: dict | None = None) -> dict:
        self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            msg["params"] = params
        resp = self.raw(json.dumps(msg))
        assert resp.get("id") == self.next_id, resp
        return resp

    def notify(self, method: str) -> None:
        assert self.proc.stdin
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
        self.proc.stdin.flush()

    def tool(self, name: str, arguments: dict) -> dict:
        resp = self.call("tools/call", {"name": name, "arguments": arguments})
        self.last_tool = resp
        return resp["result"]

    def close(self) -> tuple[str, str]:
        assert self.proc.stdin
        self.proc.stdin.close()
        rest = self.proc.stdout.read() if self.proc.stdout else ""
        err = self.proc.stderr.read() if self.proc.stderr else ""
        self.proc.wait(10)
        return rest, err


def text_of(result: dict) -> str:
    return "\n".join(c["text"] for c in result["content"] if c["type"] == "text")


@unittest.skipUnless(VH and os.access(VH, os.X_OK), "pass the vaulthalla-cli binary (argv[1] or VH_CLI)")
class McpServer(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="vhmcp-", dir="/tmp"))  # short: unix socket path limit on macOS
        self.answers: list[dict] = []
        self.daemon = FakeDaemon(self.tmp, self._answer)
        self.mcp = McpSession(self.daemon.path)

    def _answer(self, req: dict) -> dict:
        return self.answers.pop(0) if self.answers else {"ok": True, "exit_code": 0, "stdout": "ok"}

    def tearDown(self) -> None:
        rest, err = self.mcp.close()
        self.daemon.stop()
        self.assertIsNone(self.daemon.error)
        self.assertEqual(rest, "", "stdout carries only responses to requests")
        self.assertEqual(self.mcp.proc.returncode, 0, err)
        for p in sorted(self.tmp.rglob("*"), reverse=True):
            p.unlink() if not p.is_dir() else p.rmdir()
        self.tmp.rmdir()

    def initialize(self, version: str = "2025-11-25") -> dict:
        resp = self.mcp.call("initialize", {"protocolVersion": version, "capabilities": {},
                                            "clientInfo": {"name": "test", "version": "1"}})
        self.mcp.notify("notifications/initialized")
        return resp["result"]

    def test_initialize_negotiates_and_lists_tools(self) -> None:
        init = self.initialize("2025-06-18")
        self.assertEqual(init["protocolVersion"], "2025-06-18")
        self.assertEqual(init["serverInfo"]["name"], "vaulthalla")
        self.assertIn("tools", init["capabilities"])
        self.assertIn("confirm", init["instructions"])
        self.assertEqual(self.mcp.call("ping")["result"], {})

        tools = {t["name"]: t for t in self.mcp.call("tools/list")["result"]["tools"]}
        for name in ("vh_help", "vh_read", "vh_run", "users_create", "vaults_delete", "recovery_list"):
            self.assertIn(name, tools)
        self.assertTrue(tools["vh_read"]["annotations"]["readOnlyHint"])
        self.assertTrue(tools["vaults_delete"]["annotations"]["destructiveHint"])
        self.assertIn("confirm", tools["users_delete"]["inputSchema"]["properties"])
        self.assertEqual(self.daemon.requests, [], "initialize and tools/list need no daemon")

    def test_unknown_protocol_version_gets_the_newest(self) -> None:
        self.assertEqual(self.initialize("1999-01-01")["protocolVersion"], "2025-11-25")

    def test_read_command_runs_non_interactively_with_json(self) -> None:
        self.initialize()
        self.answers.append({"ok": True, "exit_code": 0, "stdout": '[{"id": 1, "name": "docs"}]'})
        result = self.mcp.tool("vh_read", {"command": "vh vault list"})
        self.assertFalse(result["isError"])
        self.assertIn('"docs"', text_of(result))
        (req,) = self.daemon.requests
        self.assertEqual(req["line"], "vault list --json")
        self.assertEqual(req["cmd"], "vault")
        self.assertIs(req["interactive"], False)
        self.assertNotIn("transfer", req)

    def test_typed_tool_renders_the_cli_line(self) -> None:
        self.initialize()
        result = self.mcp.tool("groups_create", {"name": "dev team", "description": "-dash first"})
        self.assertFalse(result["isError"])
        (req,) = self.daemon.requests
        self.assertEqual(req["line"], 'group create "dev team" --desc "-dash first"')

    def test_non_zero_exit_is_a_tool_error_with_stderr(self) -> None:
        self.initialize()
        self.answers.append({"ok": False, "exit_code": 2, "stderr": "group create: a group named 'x' exists"})
        result = self.mcp.tool("vh_run", {"command": "group create x"})
        self.assertTrue(result["isError"])
        self.assertIn("exit 2", text_of(result))
        self.assertIn("named 'x' exists", text_of(result))

    def test_confirmation_refusal_needs_the_human_then_confirm(self) -> None:
        self.initialize()
        self.answers.append({"ok": False, "exit_code": 2,
                             "stderr": "user delete: bob owns 2 vaults; they are destroyed.\nRe-run with --yes to confirm."})
        result = self.mcp.tool("users_delete", {"user": "bob"})
        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["needs_confirmation"], "yes")
        self.assertIn("explicitly approve", result["structuredContent"]["how_to_confirm"])
        self.assertEqual(self.daemon.requests[0]["line"], "user delete bob", "never --yes on its own")

        result = self.mcp.tool("users_delete", {"user": "bob", "confirm": {"yes": True}})
        self.assertFalse(result["isError"])
        self.assertEqual(self.daemon.requests[1]["line"], "user delete bob --yes")

    def test_confirmation_flags_in_a_command_are_refused(self) -> None:
        self.initialize()
        for command in ("user delete bob --yes", "vault delete 3 --accept-key-loss", "upstream cleanup k b --confirm-token t"):
            result = self.mcp.tool("vh_run", {"command": command})
            self.assertTrue(result["isError"], command)
            self.assertIn("confirm", text_of(result))
        self.assertEqual(self.daemon.requests, [])

    def test_excluded_commands_never_reach_the_daemon(self) -> None:
        self.initialize()
        for command in ("vault keys export 3", "vault key export 3 --output /tmp/k", "secrets export jwt-secret",
                        "secret set jwt-secret /tmp/x", "setup db", "teardown nginx", "setup super-admin-password",
                        "fs get 3 /a.txt", "fs put 3 ./a /a", "mcp", "skill install --agent claude"):
            result = self.mcp.tool("vh_run", {"command": command})
            self.assertTrue(result["isError"], command)
            self.assertIn("not available to agents", text_of(result), command)
        result = self.mcp.tool("vh_help", {"path": "vault keys export"})
        self.assertTrue(result["isError"])
        self.assertEqual(self.daemon.requests, [])

    def test_read_tool_refuses_writes_and_unknown_commands(self) -> None:
        self.initialize()
        self.assertIn("vh_read only runs read-only", text_of(self.mcp.tool("vh_read", {"command": "group create x"})))
        self.assertIn("unknown command", text_of(self.mcp.tool("vh_run", {"command": "frobnicate"})))
        self.assertIn("group of commands", text_of(self.mcp.tool("vh_run", {"command": "vault role"})))
        self.assertEqual(self.daemon.requests, [])

    def test_help_browses_the_usage_book(self) -> None:
        self.initialize()
        top = json.loads(text_of(self.mcp.tool("vh_help", {})))
        names = [c["name"] for c in top["commands"]]
        self.assertIn("vault", names)
        for hidden in ("setup", "teardown", "mcp", "skill"):
            self.assertNotIn(hidden, names)
        node = json.loads(text_of(self.mcp.tool("vh_help", {"path": "user delete"})))
        self.assertEqual(node["effect"], "destructive")
        self.assertEqual(node["confirmations"]["names"], ["yes"])

    def test_protocol_errors(self) -> None:
        self.assertEqual(self.mcp.raw("{not json")["error"]["code"], -32700)
        self.assertEqual(self.mcp.call("no/such/method")["error"]["code"], -32601)
        self.assertEqual(self.mcp.call("tools/call", {"name": "nope", "arguments": {}})["error"]["code"], -32602)


@unittest.skipUnless(VH and os.access(VH, os.X_OK), "pass the vaulthalla-cli binary (argv[1] or VH_CLI)")
class McpDaemonDown(unittest.TestCase):
    def test_tools_fail_but_the_server_answers(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="vhmcp-", dir="/tmp"))
        mcp = McpSession(str(tmp / "absent.sock"))
        init = mcp.call("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                       "clientInfo": {"name": "t", "version": "1"}})
        self.assertEqual(init["result"]["serverInfo"]["name"], "vaulthalla")
        self.assertGreater(len(mcp.call("tools/list")["result"]["tools"]), 3)
        result = mcp.tool("vh_read", {"command": "status"})
        self.assertTrue(result["isError"])
        self.assertIn("exit 69", text_of(result))
        rest, _ = mcp.close()
        self.assertEqual(rest, "")
        tmp.rmdir()


@unittest.skipUnless(VH and os.access(VH, os.X_OK), "pass the vaulthalla-cli binary (argv[1] or VH_CLI)")
class SkillInstall(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="vhskill-"))
        self.home = self.tmp / "home"
        self.project = self.tmp / "project"
        self.bin = self.tmp / "bin"  # PATH without any agent CLI
        for d in (self.home, self.project, self.bin):
            d.mkdir()

    def tearDown(self) -> None:
        for p in sorted(self.tmp.rglob("*"), reverse=True):
            p.unlink() if not p.is_dir() else p.rmdir()
        self.tmp.rmdir()

    def vh(self, *args: str) -> subprocess.CompletedProcess:
        env = {"HOME": str(self.home), "PATH": str(self.bin), "VAULTHALLA_CLI_SOCKET": str(self.tmp / "none.sock")}
        return subprocess.run([VH, "skill", "install", *args], capture_output=True, text=True, env=env,
                              cwd=self.project, timeout=60)

    def check_skill(self, d: Path) -> None:
        skill = (d / "SKILL.md").read_text()
        self.assertTrue(skill.startswith("---\nname: vaulthalla\ndescription: "))
        self.assertIn("vh vault keys export", skill)
        ref = (d / "references" / "commands.md").read_text()
        self.assertIn("vh vault list", ref)
        main, _, excluded = ref.partition("## Not available to agents")
        self.assertNotIn("vh secrets export", main)
        self.assertIn("vh secrets export", excluded)

    def test_claude_user_scope_is_idempotent_and_never_clobbers(self) -> None:
        r = self.vh("--agent", "claude", "--no-register")
        self.assertEqual(r.returncode, 0, r.stderr)
        d = self.home / ".claude" / "skills" / "vaulthalla"
        self.check_skill(d)

        r = self.vh("--agent", "claude", "--no-register")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("up to date", r.stdout)

        (d / "SKILL.md").write_text("edited by hand\n")
        r = self.vh("--agent", "claude", "--no-register")
        self.assertEqual(r.returncode, 1)
        self.assertIn("--force", r.stderr)
        self.assertEqual((d / "SKILL.md").read_text(), "edited by hand\n")

        r = self.vh("--agent", "claude", "--no-register", "--force")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.check_skill(d)

    def test_codex_user_and_project_scopes(self) -> None:
        r = self.vh("--agent", "codex", "--no-register")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.check_skill(self.home / ".agents" / "skills" / "vaulthalla")
        r = self.vh("--agent", "codex", "--scope", "project", "--no-register")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.check_skill(self.project / ".agents" / "skills" / "vaulthalla")

    def test_claude_project_scope(self) -> None:
        r = self.vh("--agent", "claude", "--scope", "project", "--no-register")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.check_skill(self.project / ".claude" / "skills" / "vaulthalla")

    def test_registration_without_the_agent_cli_prints_what_to_do(self) -> None:
        r = self.vh("--agent", "claude")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("claude mcp add --scope user vaulthalla -- vh mcp", r.stdout)

        r = self.vh("--agent", "codex")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[mcp_servers.vaulthalla]", r.stdout)
        config = self.home / ".codex" / "config.toml"
        self.assertFalse(config.exists(), "the TOML is only written with --force")

        config.parent.mkdir()
        config.write_text('model = "o3"\n')
        r = self.vh("--agent", "codex", "--force")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(config.read_text(), 'model = "o3"\n\n[mcp_servers.vaulthalla]\ncommand = "vh"\nargs = ["mcp"]\n')
        r = self.vh("--agent", "codex", "--force")
        self.assertIn("already configured", r.stdout)
        self.assertEqual(config.read_text().count("[mcp_servers.vaulthalla]"), 1)

    def test_bad_arguments(self) -> None:
        self.assertEqual(self.vh().returncode, 2)
        self.assertEqual(self.vh("--agent", "emacs").returncode, 2)
        self.assertEqual(self.vh("--agent", "claude", "--scope", "galaxy").returncode, 2)
        self.assertEqual(self.vh("--agent", "claude", "--bogus").returncode, 2)

    def test_help_needs_no_daemon(self) -> None:
        r = self.vh("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--agent", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
