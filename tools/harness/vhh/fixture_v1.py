"""Emit pentest fixture format v1 dictionaries (manifest.json, canaries.json) from a World.

Shape-compatible with tools/lab/pentest/publish.py (a test pins pentest-v1 against publish.build_manifest). Nothing
here is secret: credentials and share tokens are referenced by `secret_ref`/`credential_ref` pointers only.
"""
from __future__ import annotations

import hashlib
import time

from vhh import content, oracle
from vhh.world import World

CRED_PATH = "/srv/vaulthalla-pentest-private/flow-credentials.json"
TARGET_URL = "https://vh-local.cooperhlarson.com"

_ROLE_SUMMARY = {"reader": "read", "editor": "write", "manager": "write", "contributor": "write", "power_user": "write"}


def _fkey(world: World, obj) -> str:
    return f"{world.vault(obj.vault).key}:{obj.path}"


def computed_expectations(world: World, paths=("/",)) -> tuple[list[dict], list[dict]]:
    """(expectations, unmapped) for every principal x vault x fixture op x path. None answers go to `unmapped`."""
    rows, unmapped = [], []
    for p in world.principals:
        for v in world.vaults:
            for path in paths:
                for op in ("list", "read", "download", "write", "upload", "delete", "share"):
                    d = oracle.decide_fixture(world, p.id, v.id, op, path)
                    row = {"principal": p.id, "resource": v.id, "operation": op, "path": path}
                    if d.expect is None:
                        unmapped.append({**row, "reason": d.reason})
                    else:
                        rows.append({**row, "expect": d.expect, "rationale": d.reason})
    return rows, unmapped


def manifest(world: World, *, build_version: str, git_commit: str = "", built_at: str | None = None,
             real_vault_ids: dict[str, int] | None = None, target: str = TARGET_URL,
             credentials_path: str = CRED_PATH, generated_at: str | None = None) -> dict:
    gid_of = {p.id: [g.id for g in world.groups if p.id in g.members] for p in world.principals}
    principals = [{"id": p.id, "type": p.type, "label": p.key, "active": p.active, "handoff": p.handoff,
                   "groups": gid_of[p.id], "admin_role": p.admin_role,
                   "credential_ref": f"{credentials_path}#principals.{p.id}.password"} for p in world.principals]
    groups = [{"id": g.id, "label": g.key, "parent": g.parent, "members": list(g.members)} for g in world.groups]
    vaults = [{"id": v.id, "label": v.key, "owner": v.owner,
               "real_vault_id": (real_vault_ids or {}).get(v.key), "note": v.note} for v in world.vaults]

    objects = []
    for obj in sorted(world.objects, key=lambda o: _fkey(world, o)):
        if obj.kind == "dir" or not ({"known-content", "canary"} & set(obj.tags)):
            continue
        data = content.object_bytes(world, obj)
        objects.append({"id": "o-" + hashlib.sha256(_fkey(world, obj).encode()).hexdigest()[:10], "vault": obj.vault,
                        "kind": "file", "path": obj.path, "size_bytes": len(data), "encrypted": True,
                        "encryption": "aes-256-gcm (TPM-sealed keys)",
                        "plaintext_sha256": hashlib.sha256(data).hexdigest(), "tags": list(obj.tags)})

    grants = [{"principal": g.subject, "resource": g.vault, "role": g.role,
               "permission": _ROLE_SUMMARY.get(g.role, g.role), "inherited": g.subject_kind == "group",
               "active": g.active} for g in world.grants if g.published]
    grants += [{"principal": o.subject, "resource": o.vault, "override": o.flag, "glob": o.pattern, "note": o.note}
               for o in world.overrides]

    if world.expectations:
        expectations = [{"principal": e.principal, "resource": e.resource, "operation": e.operation, "path": e.path,
                         "expect": e.expect, "rationale": e.rationale} for e in world.expectations]
        unmapped = None
    else:
        expectations, unmapped = computed_expectations(world)

    revocation = [{"id": g.revocation["id"], "grant": {"principal": g.subject, "resource": g.vault,
                                                       "permission": "read"},
                   "action": "revoke", "expect_after": "deny", "checks": list(g.revocation.get("checks", []))}
                  for g in world.grants if g.revocation]

    share_links = [{"id": s.id, "resource": s.vault, "scope": s.link_type, "allowed_ops": list(s.allowed_ops),
                    "state": s.state, "url_template": "/share/<token-from-credentials>",
                    "secret_ref": f"{credentials_path}#shares.{s.id}.token"} for s in world.shares]

    out = {
        "fixture_version": 1, "target_env": "local", "target": target, "production_enabled": False,
        "generated_at": generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generated_by": "admin-fixture-agent",
        "build": {"service": "vaulthalla", "version": build_version, "git_commit": git_commit or "n/a",
                  "built_at": built_at},
        "credentials_path": credentials_path,
        "principals": principals, "groups": groups, "vaults": vaults, "objects": objects,
        "grants": grants, "expectations": expectations, "revocation_scenarios": revocation,
        "share_links": share_links,
        "notes": {"objects": "plaintext_sha256 is provided (a hash, not data) for download-integrity checks; "
                             "per-object ciphertext hashing is omitted because at-rest blobs are sharded and "
                             "AEAD-framed. At-rest encryption is AES-256-GCM under TPM-sealed keys.",
                  "defects": "See defects/ for product issues found during provisioning (DEF-01..03); these are "
                             "documented, not patched."}}
    if unmapped is not None:
        out["world"] = {"name": world.name, "seed": world.seed, "world_hash": world.world_hash(),
                        "unmapped_probes": unmapped}
    return out


def canaries(world: World, credentials_path: str = CRED_PATH) -> dict:
    out = []
    for obj in sorted(world.objects, key=lambda o: _fkey(world, o)):
        if "canary" in obj.tags and obj.kind != "dir":
            vkey = world.vault(obj.vault).key
            out.append({"id": "canary-" + hashlib.sha256(_fkey(world, obj).encode()).hexdigest()[:8],
                        "placement": f"vault {obj.vault} path {obj.path}", "hash_alg": "sha256",
                        "value_sha256": content.object_sha256(world, obj),
                        "trip_meaning": "an attacker reading this content accessed data it must not reach",
                        "must_not_appear_in": ["any report", "any off-box log"],
                        "value_ref": f"{credentials_path}#canary.{vkey}"})
    return {"canaries": out}
