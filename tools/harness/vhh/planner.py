"""Seeded intent source: per-session op streams drawn from catalog weights.

Op k of session s uses `rng(root, "op", s, k)` only, so its choice never depends on another session or on how ops
interleave. Each session owns a namespace (`/<session>/...` in its home vault) where it alone creates, mutates and
deletes; declared contested resources (`/contested/...`) are shared on purpose.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from vhh import oracle
from vhh.catalog import Catalog
from vhh.model import Op
from vhh.seeds import rng
from vhh.world import World


@dataclass(frozen=True)
class SessionSpec:
    id: str
    principal: str
    surface: str
    home_vault: str


@dataclass
class Plan:
    seed: int
    sessions: list[SessionSpec]
    streams: dict[str, list[Op]]
    contested: list[tuple[str, str]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(len(s) for s in self.streams.values())

    def to_json(self) -> dict:
        return {"seed": self.seed, "sessions": [vars(s) for s in self.sessions],
                "contested": [list(c) for c in self.contested], "ops": self.total}


def _home_vault(world: World, principal: str, sid: str) -> str:
    """A vault where the principal may write its namespace, else the first vault (its ops then probe denials)."""
    for v in world.vaults:
        if oracle.decide_fs(world, principal, v.id, "write", f"/{sid}/probe.txt", False, False).allowed:
            return v.id
    return world.vaults[0].id


def make_plan(world: World, catalog: Catalog, seed: int, n_sessions: int, ops_per_session: int,
              surfaces: tuple[str, ...], n_contested: int = 2) -> Plan:
    if n_sessions <= 0 or ops_per_session <= 0:
        return Plan(seed, [], {})
    actors = [p.id for p in world.principals if p.active]
    if not actors:
        raise ValueError("world has no active principals to drive")
    sessions = []
    for i in range(n_sessions):
        r = rng(seed, "session", i)
        sid = f"s{i:02d}"
        principal = actors[r.randrange(len(actors))]
        sessions.append(SessionSpec(sid, principal, surfaces[r.randrange(len(surfaces))],
                                    _home_vault(world, principal, sid)))
    first_home = sessions[0].home_vault
    contested = [(first_home, f"/contested/c{m}.bin") for m in range(n_contested)]
    streams = {s.id: _stream(world, catalog, seed, s, ops_per_session, contested) for s in sessions}
    return Plan(seed, sessions, streams, contested)


def _stream(world: World, catalog: Catalog, seed: int, s: SessionSpec, n: int,
            contested: list[tuple[str, str]]) -> list[Op]:
    specs = [o for o in catalog.for_surface(s.surface, actor_side_only=True) if o.id != "shares.revoke"]
    weights = [o.weight for o in specs]
    owned: dict[str, int] = {}          # own file path -> last planned version
    dirs: list[str] = []
    out: list[Op] = []
    vaults = [v.id for v in world.vaults]
    for k in range(n):
        r = rng(seed, "op", s.id, k)
        spec = r.choices(specs, weights)[0]
        args: dict = {}
        if "vault" in spec.fields:
            args["vault"] = s.home_vault if r.random() < 0.75 else vaults[r.randrange(len(vaults))]
        world_paths = sorted(o.path for o in world.objects_in(args.get("vault", s.home_vault)) if o.kind != "dir")
        own = sorted(owned)

        def pick_existing():
            pool = own if (own and (r.random() < 0.6 or not world_paths)) else world_paths
            return pool[r.randrange(len(pool))] if pool else f"/{s.id}/missing.txt"

        if spec.id == "fs.write":
            if contested and r.random() < 0.15:
                args["vault"], path = contested[r.randrange(len(contested))]
            else:
                args["vault"] = s.home_vault
                path = own[r.randrange(len(own))] if own and r.random() < 0.4 else f"/{s.id}/f{k}.txt"
            version = owned.get(path, 0) + 1 if not path.startswith("/contested/") else k + 1
            if not path.startswith("/contested/"):
                owned[path] = version
            args.update(path=path, version=version)
        elif spec.id == "fs.mkdir":
            args.update(vault=s.home_vault, path=f"/{s.id}/d{k}")
            dirs.append(args["path"])
        elif spec.id in ("fs.read", "fs.stat"):
            args["path"] = pick_existing()
        elif spec.id == "fs.list":
            args["path"] = "/" if r.random() < 0.5 else (dirs[r.randrange(len(dirs))] if dirs else f"/{s.id}")
        elif spec.id == "fs.delete":
            if own:
                path = own[r.randrange(len(own))]
                owned.pop(path)
                args.update(vault=s.home_vault, path=path)
            else:
                args["path"] = pick_existing()
        elif spec.id in ("fs.rename", "fs.copy"):
            if own:
                src = own[r.randrange(len(own))]
                dst = f"/{s.id}/{'r' if spec.id == 'fs.rename' else 'c'}{k}.txt"
                v = owned.pop(src) if spec.id == "fs.rename" else owned[src]
                owned[dst] = v
                args.update(vault=s.home_vault, path=src, to=dst)
            else:
                args.update(path=pick_existing(), to=f"/{s.id}/x{k}.txt")
        elif spec.id == "shares.create":
            args.update(root="/", allowed_ops=["metadata", "list", "download"], access_mode="public")
        out.append(Op(seq=-1, session=s.id, principal=s.principal, surface=s.surface, op=spec.id, args=args))
    return out
