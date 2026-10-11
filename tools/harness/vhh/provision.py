"""Provision pentest-v1 on a launcher-owned private instance using the existing pentest Seeder.

`await provision(target, world, broker, redactor)` returns a secret-free drivers.real.Binding. Passwords and share
tokens stay in memory. The caller owns the Instance and must call Instance.stop() in a finally block, including
after ProvisionError: a partial seed is not reusable, and this module never resets a shared installation.
Generated/modified worlds require their own Seeder and are explicitly refused here.
"""
from __future__ import annotations

import math
import os
import pwd
import re
import shlex
import socket
import time
from pathlib import Path
from types import SimpleNamespace

from vhh._repo import REPO_ROOT
from vhh.broker import IdentityBroker
from vhh.drivers.cli_sock import _recv_frame, _send_frame
from vhh.drivers.real import Binding
from vhh.instance import Target, validate_target
from vhh.redact import Redactor
from vhh.world import World, pentest_v1

from tools.lab.pentest import fixture
from tools.lab.pentest.client import Target as NetTarget
from tools.lab.pentest.seed import PASSWORD_RE, Seeder


class ProvisionError(RuntimeError):
    """Safe to record. Discard the private instance through its launcher's scoped teardown on failure."""


class LocalCli:
    """Seeder's synchronous CLI interface. Raw output is private input to its credential parser, never a Result.

    The optional on_secret callback registers generated passwords before returning them to Seeder. Failed-command
    output is never included in exceptions. failures counts even failures Seeder would otherwise ignore.
    """

    def __init__(self, socket_path):
        self.socket_path = str(socket_path)
        self.on_secret = None
        self.failures = 0

    def run(self, *args: str, timeout: float = 60) -> tuple[int, str]:
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("private CLI timeout must be positive and finite")
        end = time.monotonic() + timeout
        output = []
        code, text = 1, "private CLI returned no result"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect(self.socket_path)
                _send_frame(sock, {"cmd": args[0] if args else "help", "args": list(args[1:]), "argv": list(args),
                                   "line": shlex.join(args), "interactive": False})
                while True:
                    remaining = end - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError
                    sock.settimeout(remaining)
                    frame = _recv_frame(sock)
                    if not isinstance(frame, dict):
                        raise ValueError
                    kind = frame.get("type")
                    if kind == "hello":
                        continue
                    if kind == "output":
                        output.append(frame.get("text", ""))
                        continue
                    if kind == "prompt":
                        code, text = 1, "private CLI requires noninteractive confirmation"
                        break
                    if kind not in (None, "result"):
                        raise ValueError
                    code = frame.get("exit_code")
                    if type(code) is not int:
                        if type(frame.get("ok")) is not bool:
                            raise ValueError
                        code = 0 if frame["ok"] else 1
                    text = "".join(output) + (frame.get("stdout") or "") + (frame.get("stderr") or "")
                    break
        except TimeoutError:
            code, text = 124, "private CLI deadline exceeded"
        except (OSError, EOFError):
            code, text = 1, "private CLI disconnected"
        except (ValueError, TypeError):
            code, text = 1, "invalid private CLI response"
        if code != 0:
            self.failures += 1
        if self.on_secret:
            for match in PASSWORD_RE.finditer(text):
                self.on_secret(match.group(1))
        return code, text

    def must(self, *args: str, timeout: float = 60) -> str:
        code, output = self.run(*args, timeout=timeout)
        if code != 0:
            raise ProvisionError(f"private CLI failed with exit code {code} (output suppressed)")
        return output


def _validate_private(target: Target) -> None:
    """Also bind the descriptor's socket and loopback ports to the validated daemon, not just a /tmp prefix."""
    try:
        if validate_target(target):
            raise ValueError
        root = Path(target.run_dir)
        if root.parent != Path("/tmp") or root.name != f"vhh_{target.run_id}" or root.resolve() != root:
            raise ValueError
        if target.db_name != f"vh_harness_{target.run_id}".lower():
            raise ValueError
        proc = Path(f"/proc/{target.pid}")
        env = dict(item.split(b"=", 1) for item in (proc / "environ").read_bytes().split(b"\0") if b"=" in item)
        expected = {"VH_TEST_MODE": "1", "VH_TEST_DB_NAME": target.db_name, "VH_TEST_DB_USER": "vh_harness",
                    "VH_TEST_CLI_SOCKET": target.cli_socket, "VH_TEST_MOUNT_PATH": target.mount,
                    "VH_TEST_BACKING_PATH": target.backing}
        if any(env.get(key.encode()) != str(value).encode() for key, value in expected.items()):
            raise ValueError
        for path in (target.cli_socket, target.mount, target.backing,
                     os.fsdecode(env[b"VH_PATH_TO_CONFIG"]), os.fsdecode(env[b"VH_PATH_TO_SUPERADMIN_UID"]),
                     os.fsdecode(env[b"VH_TEST_LOG_PATH"])):
            if not Path(path).resolve().is_relative_to(root) or Path(path).resolve() == root:
                raise ValueError
        if not Path(target.cli_socket).is_socket() or target.mount == target.backing:
            raise ValueError
        ports = (target.ws_port, target.http_port)
        if any(type(port) is not int or not 0 < port < 65536 for port in ports) or ports[0] == ports[1]:
            raise ValueError
        owned = set()
        for fd in (proc / "fd").iterdir():
            try:
                link = os.readlink(fd)
            except FileNotFoundError:  # a concurrent accept/close can retire an unrelated descriptor
                continue
            if link.startswith("socket:["):
                owned.add(link[8:-1])
        listeners = {int(row[1].split(":")[1], 16)
                     for line in (proc / "net/tcp").read_text().splitlines()[1:]
                     if len(row := line.split()) > 9 and row[9] in owned and row[3] == "0A"
                     and row[1].split(":")[0] == "0100007F"}
        sockets = {row[7] for line in (proc / "net/unix").read_text().splitlines()[1:]
                   if len(row := line.split()) == 8 and row[6] in owned and row[3] == "00010000"}
        if not set(ports) <= listeners or target.cli_socket not in sockets:
            raise ValueError
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise ProvisionError("target is not an isolated, live private harness instance") from None


def _fixture_accounts(world: World) -> dict:
    # Seeder consumes fixture.py, not an arbitrary World. Refuse a mismatch before changing the target.
    actual, expected = world.to_json(), pentest_v1().to_json()
    for data in (actual, expected):
        for principal in data["principals"]:
            principal.pop("linux_uid", None)
    if world.validate() or actual != expected:
        raise ProvisionError("this provisioner requires the unmodified pentest-v1 world")
    try:
        accounts = {user.key: pwd.getpwnam(f"vhh-actor-{i:02d}") for i, user in enumerate(fixture.USERS, 1)}
    except KeyError:
        raise ProvisionError("a harness actor account is missing; run the harness bootstrap first") from None
    uids = [account.pw_uid for account in accounts.values()]
    if any(uid <= 0 for uid in uids) or len(set(uids)) != len(uids):
        raise ProvisionError("harness actor accounts require distinct non-root UIDs")
    return accounts


async def provision(target: Target, world: World, broker: IdentityBroker, redactor: Redactor) -> Binding:
    """Seed the private target, bind fixture ids, and update world's Linux UIDs only after complete success.

    No cleanup of daemon state is attempted here: the launcher must stop its Instance in finally on both success
    and failure. In particular, a failed/partial seed raises and must never proceed into an engine run.
    """
    _validate_private(target)
    accounts = _fixture_accounts(world)
    if any(broker.has(p.id) for p in world.principals) or any(broker.has(f"public:{s.id}") for s in world.shares):
        raise ProvisionError("fixture credentials are already bound; use a fresh broker and private instance")

    def register(value):
        redactor.register_secret(value)
        if broker.redactor is not redactor:
            broker.redactor.register_secret(value)

    broker.register_canaries(world.canaries)
    for canary in world.canaries.values():
        register(canary)
    cli = LocalCli(target.cli_socket)
    cli.on_secret = register
    args = SimpleNamespace(host="127.0.0.1", hostname="127.0.0.1", connect_ip="127.0.0.1", insecure=False,
                           media=None, repo=str(REPO_ROOT), state=None)
    net = NetTarget(hostname="127.0.0.1", ws_port=target.ws_port, http_port=target.http_port)
    seeder = Seeder(args, cli=cli, target=net, linux_uids={key: a.pw_uid for key, a in accounts.items()}, quiet=True)
    state = seeder.state
    try:
        state = await seeder.run()
        # The lab Seeder is best-effort. A harness run must not pass with skipped uploads, overrides or shares.
        if (cli.failures or any(not item.get("applied") for item in state.get("overrides", []))
                or len(state.get("overrides", [])) != len(world.overrides)
                or any(re.search(r"\b(failed|skipped)\b", line, re.IGNORECASE) for line in seeder.log)):
            raise ProvisionError("fixture seeding reported an incomplete step")
        binding = Binding()
        credentials = []
        for principal in world.principals:
            user = state["users"][principal.key]
            account = accounts[principal.key]
            if (not user.get("password") or type(user.get("id")) is not int
                    or user.get("opaque_id") != principal.id):
                raise ProvisionError("fixture user or generated credential is missing")
            binding.principals[principal.id] = {"id": user["id"], "username": user["username"],
                                                "account": account.pw_name, "linux_uid": account.pw_uid}
            credentials.append((principal.id, "password", user["password"], user["username"]))
        for vault in world.vaults:
            rec = state["vaults"][vault.key]
            fuse_name = rec.get("fuse_name")
            if (type(rec.get("id")) is not int or rec["id"] <= 0 or rec.get("opaque_id") != vault.id
                    or not isinstance(fuse_name, str) or not fuse_name or fuse_name in (".", "..")
                    or "/" in fuse_name or "\0" in fuse_name):
                raise ProvisionError("fixture vault id or FUSE name is missing or invalid")
            binding.vaults[vault.id] = {"id": rec["id"], "fuse_name": fuse_name}
        for share in world.shares:
            rec = state["shares"][share.key]
            if not rec.get("token") or not rec.get("share_id") or rec.get("opaque_id") != share.id:
                raise ProvisionError("fixture share or public token is missing")
            binding.shares[share.id] = {"share_id": rec["share_id"]}
            credentials.append((f"public:{share.id}", "share_token", rec["token"], ""))
        for obj in world.objects:
            key = f"{world.vault(obj.vault).key}:{obj.path}"
            if key not in state["files"]:
                raise ProvisionError("fixture content inventory is incomplete")
        for ref, kind, secret, username in credentials:
            register(secret)
            broker.register(ref, kind, secret, username)
        for principal in world.principals:
            principal.linux_uid = binding.principals[principal.id]["linux_uid"]
        return binding
    except ProvisionError:
        raise
    except Exception:  # noqa: BLE001 - Seeder errors may embed raw credentials, cookies or response bodies.
        raise ProvisionError("private fixture provisioning failed; discard the instance through scoped teardown") from None
    finally:
        # Also protect values minted before a partial failure. Never attach Seeder state/logs to an exception.
        for snapshot in (seeder.state, state):
            for kind, field in (("users", "password"), ("shares", "token")):
                for rec in snapshot.get(kind, {}).values():
                    if rec.get(field):
                        register(rec[field])
