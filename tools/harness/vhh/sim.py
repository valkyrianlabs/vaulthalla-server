"""An in-memory simulated daemon and its driver, for tests, self-tests and `--target sim` dry runs.

The simulator authorizes with the reference model, so a faithful simulator produces a clean run. `Plants` inject the
defect classes the judges must catch (cross-tenant leak, stale revocation, surface skew, wedge, crash, corrupt bytes,
a raising driver), which is how the self-tests prove a failure can never turn into a pass.
"""
from __future__ import annotations

import asyncio
import hashlib
import secrets
from dataclasses import dataclass, field

from vhh import content, oracle
from vhh.broker import IdentityBroker
from vhh.model import Op, Result
from vhh.state import apply_effect
from vhh.world import World


REVOCATIONS = ("roles.vault.unassign", "users.deactivate", "groups.remove_user", "shares.revoke")


@dataclass
class Plants:
    leak_reads: set[tuple[str, str]] = field(default_factory=set)    # (principal, vault): reads served despite deny
    stale_revocation: bool = False                                    # keep serving revoked grants
    surface_deny: dict[str, set[str]] = field(default_factory=dict)  # surface -> principals denied on that surface
    wedge_ops: set[str] = field(default_factory=set)                  # ops that never answer
    raise_ops: set[str] = field(default_factory=set)                  # ops whose driver raises
    crash_after: int | None = None                                    # daemon "dies" after N ops
    corrupt_reads: bool = False                                       # flip a byte in every read


class SimDaemon:
    def __init__(self, world: World, plants: Plants | None = None):
        self.plants = plants or Plants()
        self.world = world.copy()
        # what authorization looks at: a separate copy that never sees revocations under stale_revocation
        self.authz_world = self.world.copy() if self.plants.stale_revocation else self.world
        self.passwords = {p.id: secrets.token_urlsafe(18) for p in world.principals}
        self.share_tokens = {s.id: secrets.token_urlsafe(24) for s in world.shares}
        self.ops = 0

    def register_credentials(self, broker: IdentityBroker, skip: set[str] = frozenset()) -> None:
        for pid, pw in self.passwords.items():
            if pid not in skip:
                broker.register(pid, "password", pw, username=pid)
        for sid, tok in self.share_tokens.items():
            if f"public:{sid}" not in skip:
                broker.register(f"public:{sid}", "share_token", tok)

    def _authenticate(self, principal: str, secret: str) -> bool:
        if principal.startswith("public:"):
            return self.share_tokens.get(principal[7:]) == secret
        return self.passwords.get(principal) == secret

    def _bytes(self, vault: str, path: str) -> bytes | None:
        for o in self.world.objects_in(vault):
            if o.path == path and o.kind != "dir":
                return content.object_bytes(self.world, o)
        return None

    async def handle(self, op: Op, surface: str, secret: str) -> Result:
        self.ops += 1
        p = self.plants
        if p.crash_after is not None and self.ops > p.crash_after:
            return Result("crash", "daemon exited", data={"fault": "product"})
        if op.op in p.wedge_ops:
            await asyncio.sleep(3600)
        if not self._authenticate(op.principal, secret):
            return Result("denied", "authentication failed", code=401)
        if op.op == "auth.login":
            ok = oracle.decide_op(self.authz_world, op.principal, op.op, op.args).allowed
            return Result("ok" if ok else "denied")

        d = oracle.decide_op(self.authz_world, op.principal, op.op, op.args)
        allowed = d.expect != oracle.DENY
        vault, path = op.args.get("vault", ""), op.args.get("path", "/")
        if op.principal in p.surface_deny.get(surface, set()):
            allowed = False
        leak = op.op == "fs.read" and (op.principal, vault) in p.leak_reads
        if not allowed and not leak:
            missing = "missing entry" in d.reason
            return Result("not_found" if missing else "denied", d.reason, code=404 if missing else 403)

        if op.op == "fs.read":
            data = self._bytes(vault, path)
            if data is None:
                return Result("not_found", "no such file", code=404)
            if p.corrupt_reads and data:
                data = bytes([data[0] ^ 1]) + data[1:]
            return Result("ok", body=data, bytes_sha256=hashlib.sha256(data).hexdigest())
        if op.op == "fs.list":
            names = sorted({o.path[len(path.rstrip('/')) + 1:].split("/")[0] for o in self.world.objects_in(vault)
                            if o.path.startswith(path.rstrip("/") + "/")})
            return Result("ok", data={"entries": names})
        if op.op == "fs.write":
            version = int(op.args.get("version", 1))
            data = content.formula(self.world, vault, path, version,
                                   content.formula_size(self.world, vault, path, version))
            res = Result("ok", bytes_sha256=hashlib.sha256(data).hexdigest())
        elif op.op == "shares.create":
            res = Result("ok", data={"share_id": f"sl-sim-{op.seq}"})
        else:
            res = Result("ok")
        apply_effect(self.world, op, res)
        if self.authz_world is not self.world and op.op not in REVOCATIONS:
            apply_effect(self.authz_world, op, res)
        return res


class SimDriver:
    """Driver for SimDaemon. Credentials come from the broker at send time, as with the real drivers."""

    def __init__(self, surface: str, sim: SimDaemon, broker: IdentityBroker):
        self.surface, self.sim, self.broker = surface, sim, broker
        self.opened = False

    async def open(self) -> None:
        self.opened = True

    async def execute(self, op: Op, deadline_s: float) -> Result:
        if op.op in self.sim.plants.raise_ops:
            raise RuntimeError(f"planted driver defect on {op.op}")
        secret = self.broker.credential(op.principal).secret()
        r = await self.sim.handle(op, self.surface, secret)
        r.rendered = f"{self.surface}:{op.op} {op.args}"
        return r

    async def close(self) -> None:
        self.opened = False
