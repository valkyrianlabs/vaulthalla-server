"""World state over time: immutable snapshots, one per successful mutation, so every op can be judged against the
states that existed while it was in flight (and, for revocations, within a grace window before it started)."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from vhh.model import Op, Result
from vhh.world import Grant, Obj, Share, World


@dataclass(frozen=True)
class Snapshot:
    version: int
    t_ns: int
    world: World
    cause: int | None = None          # seq of the op that produced it


class Timeline:
    def __init__(self, world: World, keep: int = 256):
        self._lock = threading.Lock()
        self._snaps = [Snapshot(0, time.monotonic_ns(), world)]
        self.keep = keep

    @property
    def version(self) -> int:
        return self._snaps[-1].version

    @property
    def current(self) -> World:
        return self._snaps[-1].world

    def apply(self, op: Op, result: Result) -> bool:
        """Apply a successful mutating op's effect. Returns True when the state changed."""
        with self._lock:
            w = self._snaps[-1].world.copy()
            if not apply_effect(w, op, result):
                return False
            self._snaps.append(Snapshot(self._snaps[-1].version + 1, time.monotonic_ns(), w, op.seq))
            if len(self._snaps) > self.keep:
                self._snaps = self._snaps[-self.keep:]
            return True

    def window(self, v0: int, v1: int) -> list[Snapshot]:
        """Snapshots from version v0 through v1 (the states an op in flight between them may have observed)."""
        with self._lock:
            snaps = list(self._snaps)
        out = [s for s in snaps if v0 <= s.version <= v1]
        return out or [snaps[-1]]

    def grace(self, v0: int, t0_ns: int, grace_ns: int) -> list[Snapshot]:
        """Older snapshots superseded less than `grace_ns` before t0: a revocation may still be propagating."""
        if grace_ns <= 0:
            return []
        with self._lock:
            snaps = list(self._snaps)
        out = []
        for prev, nxt in zip(snaps, snaps[1:]):
            if nxt.version <= v0 and t0_ns - nxt.t_ns <= grace_ns:
                out.append(prev)
        return out


def _move(w: World, vault: str, src: str, dst: str, copy: bool) -> bool:
    src = src.rstrip("/") or "/"
    moved = False
    new = []
    for o in w.objects:
        if o.vault == vault and (o.path == src or o.path.startswith(src + "/")):
            moved = True
            target = dst.rstrip("/") + o.path[len(src):]
            clone = Obj(o.id if not copy else f"{o.id}+{target}", vault, target, o.kind, o.versions, list(o.tags),
                        dict(o.spec) if o.spec else None)
            if copy:
                new.append(clone)
            else:
                o.path = target
    w.objects.extend(new)
    return moved


def apply_effect(w: World, op: Op, result: Result) -> bool:
    a = op.args
    vault, path = a.get("vault"), a.get("path")
    if op.op == "fs.write":
        version = int(a.get("version", 1))
        spec = {"formula": {"vault": vault, "path": path, "version": version}}
        for o in w.objects:
            if o.vault == vault and o.path == path and o.kind != "dir":
                o.versions, o.spec, o.kind = version, spec, "text"
                return True
        w.objects.append(Obj(f"o-w-{op.seq}", vault, path, "text", version, [], spec))
        return True
    if op.op == "fs.mkdir":
        w.objects.append(Obj(f"o-d-{op.seq}", vault, path.rstrip("/"), "dir"))
        return True
    if op.op == "fs.delete":
        p = path.rstrip("/") or "/"
        before = len(w.objects)
        w.objects = [o for o in w.objects if not (o.vault == vault and (o.path == p or o.path.startswith(p + "/")))]
        return len(w.objects) != before
    if op.op in ("fs.rename", "fs.copy"):
        return _move(w, vault, path, a["to"], op.op == "fs.copy")
    if op.op == "shares.create":
        sid = str(result.data.get("share_id") or f"sl-run-{op.seq}")
        w.shares.append(Share(sid, vault, a.get("root", "/"), "directory", "download", "share_download_only",
                              list(a.get("allowed_ops", ["metadata", "list", "download"])), "active"))
        return True
    if op.op == "shares.revoke":
        s = w.share(a["share"])
        if s:
            s.state = "revoked"
        return bool(s)
    if op.op == "users.deactivate":
        p = w.principal(a["principal"])
        if p:
            p.active = False
        return bool(p)
    if op.op == "users.delete":
        w.principals = [p for p in w.principals if p.id != a["principal"]]
        w.grants = [g for g in w.grants if not (g.subject_kind == "user" and g.subject == a["principal"])]
        for g in w.groups:
            g.members = [m for m in g.members if m != a["principal"]]
        return True
    if op.op in ("groups.add_user", "groups.remove_user"):
        g = next((g for g in w.groups if g.id == a["group"]), None)
        if not g:
            return False
        if op.op == "groups.add_user" and a["principal"] not in g.members:
            g.members.append(a["principal"])
        if op.op == "groups.remove_user":
            g.members = [m for m in g.members if m != a["principal"]]
        return True
    if op.op in ("roles.vault.assign", "roles.vault.unassign"):
        kind, subject = a.get("subject_kind", "user"), a["subject"]
        if op.op == "roles.vault.assign":
            w.grants.append(Grant(kind, subject, vault, a["role"]))
        else:
            for g in w.grants:
                if g.subject_kind == kind and g.subject == subject and g.vault == vault and g.role == a["role"]:
                    g.active = False
        return True
    return False

