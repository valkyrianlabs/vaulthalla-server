"""Operation catalog: canonical op ids, typed fields, surface bindings, weights, deadlines, agent exposure.

The source of truth is the C++ usage module (`vh_usage --json`, WS-U). Until that file is available the built-in
table below is used; `load(path)` overlays the exported `operations` (bindings, deadlines) onto it by id.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from pathlib import Path

FS_SURFACES = ("ws", "http", "fuse", "cli_sock", "cli_bin")


@dataclass(frozen=True)
class OpSpec:
    id: str
    fields: dict[str, str]                       # name -> type ("vault", "path", "principal", "str", "list")
    surfaces: tuple[str, ...]
    weight: float = 1.0
    mutating: bool = False
    actor_side: bool = True                      # may be exposed to external agents
    deadline_s: float = 10.0
    required: tuple[str, ...] = ()
    description: str = ""


_BUILTIN = [
    OpSpec("auth.login", {}, ("ws", "http"), 0.2, description="log in as the session's principal"),
    OpSpec("fs.list", {"vault": "vault", "path": "path"}, FS_SURFACES, 3, required=("vault", "path"),
           description="list a directory"),
    OpSpec("fs.stat", {"vault": "vault", "path": "path"}, FS_SURFACES, 1, required=("vault", "path"),
           description="metadata of an entry"),
    OpSpec("fs.read", {"vault": "vault", "path": "path"}, FS_SURFACES, 4, required=("vault", "path"),
           description="read (download) a file"),
    OpSpec("fs.write", {"vault": "vault", "path": "path", "version": "int"}, FS_SURFACES, 3, True,
           deadline_s=20, required=("vault", "path"), description="write a file (deterministic content)"),
    OpSpec("fs.mkdir", {"vault": "vault", "path": "path"}, FS_SURFACES, 1, True, required=("vault", "path"),
           description="create a directory"),
    OpSpec("fs.rename", {"vault": "vault", "path": "path", "to": "path"}, FS_SURFACES, 1, True,
           required=("vault", "path", "to"), description="rename or move an entry"),
    OpSpec("fs.copy", {"vault": "vault", "path": "path", "to": "path"}, ("ws", "fuse"), 0.5, True,
           required=("vault", "path", "to"), description="copy an entry"),
    OpSpec("fs.delete", {"vault": "vault", "path": "path"}, FS_SURFACES, 1, True, required=("vault", "path"),
           description="delete an entry"),
    OpSpec("shares.create", {"vault": "vault", "root": "path", "allowed_ops": "list", "access_mode": "str"},
           ("ws",), 0.3, True, required=("vault",), description="create a share link"),
    OpSpec("shares.revoke", {"share": "share"}, ("ws",), 0.1, True, required=("share",),
           description="revoke a share link"),
    # Admin-side operations: never exposed to agents.
    OpSpec("users.create", {"name": "str", "role": "str"}, ("cli_sock", "ws"), 0, True, actor_side=False),
    OpSpec("users.deactivate", {"principal": "principal"}, ("cli_sock", "ws"), 0, True, actor_side=False),
    OpSpec("users.delete", {"principal": "principal"}, ("cli_sock", "ws"), 0, True, actor_side=False),
    OpSpec("groups.create", {"name": "str"}, ("cli_sock", "ws"), 0, True, actor_side=False),
    OpSpec("groups.add_user", {"group": "group", "principal": "principal"}, ("cli_sock", "ws"), 0, True,
           actor_side=False),
    OpSpec("groups.remove_user", {"group": "group", "principal": "principal"}, ("cli_sock", "ws"), 0, True,
           actor_side=False),
    OpSpec("roles.vault.assign", {"vault": "vault", "subject": "str", "role": "str"}, ("cli_sock", "ws"), 0, True,
           actor_side=False),
    OpSpec("roles.vault.unassign", {"vault": "vault", "subject": "str", "role": "str"}, ("cli_sock", "ws"), 0,
           True, actor_side=False),
    OpSpec("vaults.create", {"name": "str"}, ("cli_sock", "ws"), 0, True, actor_side=False),
    OpSpec("vaults.delete", {"vault": "vault"}, ("cli_sock", "ws"), 0, True, actor_side=False),
]

# Operations that change who may do what: the revoker uses them, the oracle's state follows them.
PROVISIONING = {"users.create", "users.delete", "groups.create", "vaults.create", "vaults.delete"}


@dataclass
class Catalog:
    ops: dict[str, OpSpec] = field(default_factory=lambda: {o.id: o for o in _BUILTIN})
    contract_hash: str | None = None

    def get(self, op_id: str) -> OpSpec:
        if op_id not in self.ops:
            raise KeyError(f"unknown operation {op_id!r}")
        return self.ops[op_id]

    def for_surface(self, surface: str, actor_side_only: bool = False) -> list[OpSpec]:
        return [o for o in self.ops.values() if surface in o.surfaces and o.weight > 0
                and (o.actor_side or not actor_side_only)]

    def actor_tools(self) -> list[OpSpec]:
        return [o for o in self.ops.values() if o.actor_side]

    def deadline(self, op_id: str) -> float:
        return self.get(op_id).deadline_s

    def weighted(self, weights: dict[str, float]) -> "Catalog":
        """A copy with some op weights replaced (a pressure profile concentrating on writes, say)."""
        unknown = set(weights) - set(self.ops)
        if unknown:
            raise KeyError(f"unknown operation(s) in weights: {', '.join(sorted(unknown))}")
        return Catalog({k: replace(o, weight=weights.get(k, o.weight)) for k, o in self.ops.items()},
                       self.contract_hash)

    def restricted(self, supported: dict[str, set[str]]) -> "Catalog":
        """A copy whose ops only list the surfaces that really bind them (surface -> op ids). Planning a real run
        against it never schedules an op a driver can't execute; ops left with no surface are dropped."""
        ops = {}
        for o in self.ops.values():
            surfaces = tuple(s for s in o.surfaces if o.id in supported.get(s, set()))
            if surfaces:
                ops[o.id] = replace(o, surfaces=surfaces)
        return Catalog(ops, self.contract_hash)


def load(path: str | Path | None = None) -> Catalog:
    cat = Catalog()
    if path is None:
        return cat
    doc = json.loads(Path(path).read_text())
    cat.contract_hash = doc.get("contract_hash")
    for o in doc.get("operations", []):
        oid = o.get("id")
        if oid in cat.ops:
            spec = cat.ops[oid]
            deadline = o.get("deadline_ms")
            bound = tuple(s for s in ("cli", "ws", "http", "fuse") if o.get(s) or (o.get("bindings") or {}).get(s))
            surfaces = tuple({"cli": "cli_sock"}.get(s, s) for s in bound) or spec.surfaces
            cat.ops[oid] = replace(spec, surfaces=surfaces,
                                   deadline_s=deadline / 1000 if deadline else spec.deadline_s)
    return cat
