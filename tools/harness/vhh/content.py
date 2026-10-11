"""Deterministic content: any reader can verify bytes without coordinating with the writer.

- Objects of a pentest-derived world come byte-exact from tools/lab/pentest/content.py (FileSpec + materialize).
- Everything the engine writes is `formula(world, vault, path, version, size)`: a header naming the world's content
  seed, vault, path and version, the vault's canary, then SHAKE-256 bytes keyed on the same tuple. So a leak of any
  engine-written byte range that includes the header is a canary trip, and integrity is a pure function.
"""
from __future__ import annotations

import hashlib
import json
from functools import lru_cache

from vhh._repo import REPO_ROOT, pentest
from vhh.world import Obj, World


def formula(world: World, vault: str, path: str, version: int, size: int = 256) -> bytes:
    head = (f"vhh content seed={world.content_seed} vault={vault} path={path} v={version}\n"
            f"canary: {world.canaries.get(vault, '')}\n").encode()
    tail = hashlib.shake_256(f"{world.content_seed}:{vault}:{path}:{version}".encode()).digest(max(0, size - len(head)))
    return head + tail


def formula_size(world: World, vault: str, path: str, version: int) -> int:
    """A stable size for a written version (128 B .. 64 KiB, mostly small)."""
    h = int.from_bytes(hashlib.blake2b(f"{world.content_seed}:{vault}:{path}:{version}:size".encode(),
                                       digest_size=4).digest(), "little")
    return 128 + (h % 1024 if h % 8 else h % 65536)


def _spec(spec: dict):
    C = pentest.content
    return C.FileSpec(spec["vault"], spec["path"], spec["kind"], spec["source"], spec.get("note", ""),
                      spec.get("size_hint", 0), spec.get("versions", 1), spec.get("via", "http"),
                      list(spec.get("tags", [])))


@lru_cache(maxsize=8)
def _materialize(spec_json: str) -> bytes:
    return pentest.content.materialize(_spec(json.loads(spec_json)), None, REPO_ROOT)


def object_bytes(world: World, obj: Obj, version: int | None = None) -> bytes:
    """Bytes of a provisioned object (final version unless `version` is given)."""
    v = version or obj.versions
    if obj.spec is None or "formula" in obj.spec:
        # engine-written content: keyed on where and as which version it was written (survives rename/copy)
        f = (obj.spec or {}).get("formula") or {"vault": obj.vault, "path": obj.path, "version": v}
        fv = f["version"] if version is None else version
        return formula(world, f["vault"], f["path"], fv, formula_size(world, f["vault"], f["path"], fv))
    base = _materialize(json.dumps(obj.spec, sort_keys=True))
    if v >= obj.versions:
        return base
    return pentest.content.version_bytes(_spec(obj.spec), base, v)


def object_sha256(world: World, obj: Obj, version: int | None = None) -> str:
    return hashlib.sha256(object_bytes(world, obj, version)).hexdigest()


def canaries_in(world: World, data: bytes) -> set[str]:
    """Vault ids whose canary appears in `data`."""
    return {vid for vid, c in world.canaries.items() if c and c.encode() in data}
