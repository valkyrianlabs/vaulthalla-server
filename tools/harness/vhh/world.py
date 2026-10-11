"""The World: a declarative description of identities, vaults, grants, overrides, shares, content and expectations.

A world is a superset of pentest fixture format v1 (~/VAULTHALLA_FIXTURE_FORMAT.md). Every id is opaque (u-*, g-*,
v-*, sl-*, o-*); real names stay on the admin side. Worlds hold no secrets: credentials live in the identity broker.

`pentest_v1()` ports tools/lab/pentest/fixture.py + content.py (imported, not duplicated). `vhh.worldgen` makes seeded
random worlds. `vhh.fixture_v1` emits publishable fixture dictionaries.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import asdict, dataclass, field, fields
from typing import Any

from vhh import glob, roles
from vhh._repo import REPO_ROOT, pentest

WORLD_VERSION = 1
UID_BASE = 2_900_000_000          # reserved test uid range (shared with Tier A, VH_TEST_UID_BASE)


@dataclass
class Principal:
    id: str
    key: str
    type: str = "user"
    admin_role: str = "unprivileged"
    active: bool = True
    handoff: bool = False
    linux_uid: int | None = None
    note: str = ""


@dataclass
class Group:
    id: str
    key: str
    members: list[str] = field(default_factory=list)      # principal ids
    parent: str | None = None
    note: str = ""


@dataclass
class Vault:
    id: str
    key: str
    owner: str                                            # principal id
    quota: str = "1G"
    note: str = ""


@dataclass
class VaultRole:
    """A custom vault role: a template plus allow-/deny- flags."""
    name: str
    base: str
    flags: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class Grant:
    subject_kind: str                                     # "user" | "group"
    subject: str                                          # principal or group id
    vault: str
    role: str
    active: bool = True
    published: bool = True                                # False: provisioning detail (owner roles) not in fixture grants
    revocation: dict | None = None                        # {"id", "checks"} for revocation scenarios
    note: str = ""


@dataclass
class Override:
    subject_kind: str
    subject: str
    vault: str
    role: str                                             # the assigned role the override attaches to
    flag: str                                             # e.g. "deny-files-download"
    pattern: str
    enabled: bool = True
    note: str = ""


@dataclass
class Share:
    id: str
    vault: str
    root_path: str
    target_type: str                                      # "file" | "directory"
    link_type: str                                        # "download" | "upload" | "access"
    role_template: str
    allowed_ops: list[str]
    state: str = "active"                                 # "active" | "expired" | "revoked"
    key: str = ""
    note: str = ""


@dataclass
class Obj:
    id: str
    vault: str
    path: str
    kind: str = "text"
    versions: int = 1
    tags: list[str] = field(default_factory=list)
    spec: dict | None = None                              # pentest content.FileSpec fields, for byte-exact content


@dataclass
class Expectation:
    principal: str                                        # principal id or "public:<share id>"
    resource: str                                         # vault id
    operation: str                                        # read|write|delete|list|share|download|upload
    expect: str                                           # allow | deny
    rationale: str = ""
    path: str = "/"


_LISTS = {"principals": Principal, "groups": Group, "vaults": Vault, "vault_roles": VaultRole, "grants": Grant,
          "overrides": Override, "shares": Share, "objects": Obj, "expectations": Expectation}


@dataclass
class World:
    name: str
    world_version: int = WORLD_VERSION
    seed: str | None = None
    profile: str | None = None
    content_seed: str = ""
    canaries: dict[str, str] = field(default_factory=dict)  # vault id -> canary marker (registered as a secret)
    principals: list[Principal] = field(default_factory=list)
    groups: list[Group] = field(default_factory=list)
    vaults: list[Vault] = field(default_factory=list)
    vault_roles: list[VaultRole] = field(default_factory=list)
    grants: list[Grant] = field(default_factory=list)
    overrides: list[Override] = field(default_factory=list)
    shares: list[Share] = field(default_factory=list)
    objects: list[Obj] = field(default_factory=list)
    expectations: list[Expectation] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)

    # ---------------------------------------------------------------- lookups
    def principal(self, pid: str) -> Principal | None:
        return next((p for p in self.principals if p.id == pid), None)

    def vault(self, vid: str) -> Vault | None:
        return next((v for v in self.vaults if v.id == vid), None)

    def share(self, sid: str) -> Share | None:
        return next((s for s in self.shares if s.id == sid), None)

    def groups_of(self, pid: str) -> list[Group]:
        return [g for g in self.groups if pid in g.members]

    def role_perms(self, name: str) -> frozenset[str]:
        custom = next((r for r in self.vault_roles if r.name == name), None)
        if custom:
            return roles.apply_flags(roles.template_perms(custom.base), custom.flags)
        return roles.template_perms(name)

    def objects_in(self, vid: str) -> list[Obj]:
        return [o for o in self.objects if o.vault == vid]

    def copy(self) -> "World":
        return copy.deepcopy(self)

    # ---------------------------------------------------------------- (de)serialization
    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, d: dict) -> "World":
        known = {f.name for f in fields(cls)}
        unknown = set(d) - known
        if unknown:
            raise WorldError(f"unknown world fields: {sorted(unknown)}")
        kw: dict[str, Any] = {}
        for k, v in d.items():
            if k in _LISTS:
                kw[k] = [_LISTS[k](**item) for item in v]
            else:
                kw[k] = v
        w = cls(**kw)
        return w

    def world_hash(self) -> str:
        blob = json.dumps(self.to_json(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(blob.encode()).hexdigest()

    # ---------------------------------------------------------------- validation
    def validate(self) -> list[str]:
        """Every structural problem, so a broken world fails loudly instead of producing a vacuous run."""
        errs: list[str] = []
        if self.world_version != WORLD_VERSION:
            errs.append(f"unsupported world_version {self.world_version}")
        ids = [x.id for x in (*self.principals, *self.groups, *self.vaults, *self.shares, *self.objects)]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            errs.append(f"duplicate ids: {dupes}")
        pids = {p.id for p in self.principals}
        gids = {g.id for g in self.groups}
        vids = {v.id for v in self.vaults}
        if not self.principals:
            errs.append("world has no principals")
        if not self.vaults:
            errs.append("world has no vaults")
        for p in self.principals:
            if p.admin_role not in roles.ADMIN_ROLES:
                errs.append(f"principal {p.id}: unknown admin role {p.admin_role!r}")
        for g in self.groups:
            errs += [f"group {g.id}: unknown member {m}" for m in g.members if m not in pids]
            if g.parent is not None and g.parent not in gids:
                errs.append(f"group {g.id}: unknown parent {g.parent}")
        for v in self.vaults:
            if v.owner not in pids:
                errs.append(f"vault {v.id}: unknown owner {v.owner}")
            if v.id not in self.canaries:
                errs.append(f"vault {v.id}: no canary")
        role_names = set(roles.VAULT_ROLE_TEMPLATES) | {r.name for r in self.vault_roles}
        for r in self.vault_roles:
            if r.base not in roles.VAULT_ROLE_TEMPLATES:
                errs.append(f"vault role {r.name}: unknown base {r.base!r}")
            for f in r.flags:
                try:
                    roles.parse_flag(f)
                except roles.FlagError as e:
                    errs.append(f"vault role {r.name}: {e}")

        def subject_ok(kind, sid):
            return (kind == "user" and sid in pids) or (kind == "group" and sid in gids)

        for gr in self.grants:
            if not subject_ok(gr.subject_kind, gr.subject):
                errs.append(f"grant: unknown {gr.subject_kind} {gr.subject}")
            if gr.vault not in vids:
                errs.append(f"grant: unknown vault {gr.vault}")
            if gr.role not in role_names:
                errs.append(f"grant: unknown role {gr.role!r}")
        for o in self.overrides:
            if not subject_ok(o.subject_kind, o.subject):
                errs.append(f"override: unknown {o.subject_kind} {o.subject}")
            try:
                roles.parse_flag(o.flag)
                glob.tokenize(o.pattern)
            except (roles.FlagError, glob.GlobError) as e:
                errs.append(f"override {o.pattern}: {e}")
            if not any(g.subject_kind == o.subject_kind and g.subject == o.subject and g.vault == o.vault
                       and g.role == o.role for g in self.grants):
                errs.append(f"override {o.flag} {o.pattern}: no {o.role} assignment for {o.subject} on {o.vault}")
        for s in self.shares:
            if s.vault not in vids:
                errs.append(f"share {s.id}: unknown vault {s.vault}")
            if s.state not in ("active", "expired", "revoked"):
                errs.append(f"share {s.id}: unknown state {s.state!r}")
        for o in self.objects:
            if o.vault not in vids:
                errs.append(f"object {o.id}: unknown vault {o.vault}")
        for e in self.expectations:
            if e.expect not in ("allow", "deny"):
                errs.append(f"expectation {e}: expect must be allow|deny")
            if not (e.principal in pids or (e.principal.startswith("public:") and self.share(e.principal[7:]))):
                errs.append(f"expectation: unknown principal {e.principal}")
            if e.resource not in vids:
                errs.append(f"expectation: unknown vault {e.resource}")
        return errs


class WorldError(ValueError):
    pass


def load(d: dict) -> World:
    """Load and validate; raises WorldError listing every problem."""
    try:
        w = World.from_json(d)
    except TypeError as e:
        raise WorldError(f"malformed world: {e}") from e
    errs = w.validate()
    if errs:
        raise WorldError("invalid world:\n  " + "\n  ".join(errs))
    return w


# ------------------------------------------------------------------------------------------------ pentest-v1

def pentest_v1(with_objects: bool = True) -> World:
    """World `pentest-v1`: a one-to-one port of tools/lab/pentest/fixture.py (+ content.py for objects)."""
    F, C = pentest.fixture, pentest.content
    uid = {u.key: u.opaque_id for u in F.USERS}
    gid = {g.key: g.opaque_id for g in F.GROUPS}
    vid = {v.key: v.opaque_id for v in F.VAULTS}
    subj = lambda kind, key: uid[key] if kind == "user" else gid[key]  # noqa: E731

    w = World(name="pentest-v1", content_seed=C.FIXTURE_SEED,
              tags={"user_prefix": F.USER_PREFIX, "group_prefix": F.GROUP_PREFIX, "marker": F.TAG})
    w.principals = [Principal(u.opaque_id, u.key, "user", u.role, u.active, u.handoff, UID_BASE + 100 + i, u.note)
                    for i, u in enumerate(F.USERS)]
    w.groups = [Group(g.opaque_id, g.key, [uid[m] for m in g.members], None, g.note) for g in F.GROUPS]
    w.vaults = [Vault(v.opaque_id, v.key, uid[v.owner], v.quota, v.note) for v in F.VAULTS]
    w.canaries = {v.opaque_id: C.canary(v.key) for v in F.VAULTS}
    w.vault_roles = [VaultRole(r.name, r.base, list(r.flags), r.note) for r in F.VAULT_ROLES]
    # seed.py assigns the owner role on every vault before any other grant.
    w.grants = [Grant("user", uid[v.owner], v.opaque_id, F.OWNER_ROLE, published=False, note="owner role")
                for v in F.VAULTS]
    for g in F.GRANTS:
        rev = None
        if g.revoke_after_seed:
            rev = {"id": "rev-bob-team" if (g.subject, g.vault) == ("bob", "team_shared")
                   else f"rev-{g.subject}-{g.vault}",
                   "checks": [f"{g.subject} can no longer list/read/download {g.vault}"]}
        w.grants.append(Grant(g.subject_kind, subj(g.subject_kind, g.subject), vid[g.vault], g.role,
                              active=not g.revoke_after_seed, revocation=rev, note=g.note))
    w.overrides = [Override(o.subject_kind, subj(o.subject_kind, o.subject), vid[o.vault], o.role, o.flag, o.pattern,
                            note=o.note) for o in F.OVERRIDES]
    w.shares = [Share(s.opaque_id, vid[s.vault], s.path, s.target_type, s.link_type, s.role_template,
                      list(s.allowed_ops), s.state, s.key, s.note) for s in F.SHARES]
    w.expectations = [Expectation(uid[e.principal], vid[e.resource], e.operation, e.expect, e.rationale, e.path)
                      for e in F.EXPECTATIONS]
    if with_objects:
        for s in C.plan(None, REPO_ROOT):
            fkey = f"{s.vault}:{s.path}"
            w.objects.append(Obj("o-" + hashlib.sha256(fkey.encode()).hexdigest()[:10], vid[s.vault], s.path, s.kind,
                                 s.versions, list(s.tags),
                                 {"vault": s.vault, "path": s.path, "kind": s.kind, "source": s.source,
                                  "note": s.note, "size_hint": s.size_hint, "versions": s.versions,
                                  "via": s.via, "tags": list(s.tags)}))
    return w


WORLDS = {"pentest-v1": pentest_v1}
