"""Canonical ops -> real surface calls against a provisioned private instance.

The engine plans ops in world terms (vault "v-alice", vault-relative path "/docs/a.txt", file version N). A Binding
(from provisioning) maps world ids to the daemon's real ids; these adapters translate each op for one surface and
keep the engine's Driver contract: bounded by deadline_s, product behavior as a Result, never raise for it.

Surfaces:
  ws    the console: metadata ops over the ws driver; fs.read / fs.write over the console's HTTP lanes with that
        session's cookie (vhh.drivers.http)
  fuse  the mount, through a vh_fs_actor process running as the principal's Linux account
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field

from vhh import content
from vhh.model import Op, Result
from vhh.world import World


@dataclass
class Binding:
    """World ids -> real ids, produced by provisioning. No secrets here (credentials live in the broker)."""
    principals: dict[str, dict] = field(default_factory=dict)   # "u-alice" -> {username, account, linux_uid}
    vaults: dict[str, dict] = field(default_factory=dict)       # "v-alice" -> {id, fuse_name}
    shares: dict[str, dict] = field(default_factory=dict)       # "sl-public-dl" -> {share_id}

    def vault_id(self, world_vault: str) -> int:
        return int(self.vaults[world_vault]["id"])

    def fuse_path(self, world_vault: str, path: str) -> str:
        name = self.vaults[world_vault].get("fuse_name")
        if not name:
            raise KeyError(f"vault {world_vault} has no FUSE name")
        return f"{name}/{path.lstrip('/')}"


def write_bytes(world: World, args: dict) -> bytes:
    """The deterministic content an fs.write op writes (same formula the integrity judge checks)."""
    vault, path, version = args["vault"], args["path"], int(args.get("version", 1))
    return content.formula(world, vault, path, version, content.formula_size(world, vault, path, version))


class _Unbound(Exception):
    pass


def _invalid(op: Op, why: str) -> Result:
    now = time.time_ns()
    return Result("invalid", detail=why, data={"fault": "harness"}, rendered=op.op, t0_ns=now, t1_ns=now)


class WsConsole:
    """A console session: ws for metadata ops, the HTTP lanes (same session cookie) for file bytes."""
    surface = "ws"

    def __init__(self, ws_driver, http_driver, binding: Binding, world: World):
        self.ws, self.http, self.binding, self.world = ws_driver, http_driver, binding, world

    async def open(self) -> None:
        await self.ws.open()
        if self.http is not None:
            self.http.attach(self.ws)

    async def execute(self, op: Op, deadline_s: float) -> Result:
        try:
            vault = op.args.get("vault")
            vid = self.binding.vault_id(vault) if vault else None
        except (KeyError, ValueError, TypeError):
            return _invalid(op, f"vault {op.args.get('vault')!r} is not bound")
        if op.op in ("fs.read", "fs.write"):
            if self.http is None:
                return _invalid(op, "no HTTP lane for this console session")
            if op.op == "fs.read":
                return await self.http.download(vid, op.args["path"], deadline_s)
            data = write_bytes(self.world, op.args)
            return await self.http.upload(vid, op.args["path"], data, deadline_s)
        args = {k: v for k, v in op.args.items() if k not in ("vault", "version")}
        args["vault_id"] = vid
        real = Op(op.seq, op.session, op.principal, "ws", op.op, args, op.intent, op.causes, op.barrier)
        return await self.ws.execute(real, deadline_s)

    async def close(self) -> None:
        await self.ws.close()


class FuseSession:
    """Filesystem ops on the mount as the principal's Linux account."""
    surface = "fuse"

    def __init__(self, fuse_driver, binding: Binding, world: World):
        self.fuse, self.binding, self.world = fuse_driver, binding, world

    async def open(self) -> None:
        await self.fuse.open()

    async def execute(self, op: Op, deadline_s: float) -> Result:
        try:
            args = {"path": self.binding.fuse_path(op.args["vault"], op.args.get("path", "/"))}
            if "to" in op.args:
                args["to"] = self.binding.fuse_path(op.args["vault"], op.args["to"])
        except (KeyError, TypeError) as e:
            return _invalid(op, f"unbound: {e}")
        if op.op == "fs.write":
            args["data"] = write_bytes(self.world, op.args)
        real = Op(op.seq, op.session, op.principal, "fuse", op.op, args, op.intent, op.causes, op.barrier)
        res = await self.fuse.execute(real, deadline_s)
        if op.op == "fs.write" and res.outcome == "ok" and res.bytes_sha256 is None:
            res.bytes_sha256 = hashlib.sha256(args["data"]).hexdigest()
        return res

    async def close(self) -> None:
        await self.fuse.close()


def factory(instance, binding: Binding, world: World, broker, redactor):
    """DriverFactory(surface, principal) for a launched, provisioned private instance."""
    import pwd
    from pathlib import Path

    t = instance.target
    actor_bin = Path(t.build_dir) / "core" / "vh_fs_actor"

    def make(surface: str, principal: str):
        if surface == "ws":
            from vhh.drivers.ws import WsDriver
            try:
                from vhh.drivers.http import HttpLane
                http = HttpLane(t.http_port, redactor)
            except ImportError:
                http = None   # fs.read / fs.write then fail as harness gaps, never as passes
            return WsConsole(WsDriver(t.ws_port, principal, broker=broker, redactor=redactor), http, binding, world)
        if surface == "fuse":
            from vhh.drivers.fuse import FuseDriver
            p = binding.principals[principal]
            gid = p.get("gid")
            if gid is None and p.get("account"):
                gid = pwd.getpwnam(p["account"]).pw_gid
            return FuseSession(FuseDriver(actor_bin, t.mount, int(p["linux_uid"]), int(gid if gid is not None else
                                                                                      p["linux_uid"]),
                                          supervisor=instance), binding, world)
        raise ValueError(f"surface {surface!r} has no real binding yet")

    return make
