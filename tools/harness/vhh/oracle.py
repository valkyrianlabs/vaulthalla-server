"""Independent RBAC reference model: allow | deny | None ("no oracle") for (principal, vault, op, path).

Rules (written from the product's documented RBAC, core/src/rbac/fs/policy/Evaluator.cpp and share/Manager.cpp):

1. Unknown or deactivated principals are denied everything.
2. A principal's own vault role on the vault decides alone (user beats group): its path-scoped overrides first (best
   glob by specificity), then the role's permission bits.
3. Otherwise the principal's groups' roles on the vault decide. Group order is unspecified in the product, so when
   two groups' roles disagree the model answers None (no oracle) rather than guess.
4. Otherwise the admin role's vault globals decide (built-in admin roles carry the same preset in every scope).
5. Overrides select by the permission an action needs (files.download for a read, dirs.list for a list); a denied
   List/Lookup is still allowed on the corridor to an allow override (traversal); a denied file Lookup falls back to
   the Read decision.
6. Share principals ("public:<share id>") get only the link's allowed operations, inside the link's root, while the
   link is active. Creating a public link needs share_public on the root plus every delegated operation.

Where the model is unsure (compound ops, unmodeled admin roles, group-order ties) it says None: unmapped probes are
reported as "no oracle", never as passed.
"""
from __future__ import annotations

import posixpath
from dataclasses import dataclass

from vhh import glob, roles
from vhh.world import World

ACTIONS = ("preview", "list", "write", "read", "touch", "overwrite", "rename", "delete", "move", "copy",
           "share_internal", "share_public", "share_public_validated", "lookup")

_SHARE_SUFFIX = {"share_internal": "internal", "share_public": "public", "share_public_validated": "public_with_val"}
FILE_PERM = {"preview": "preview", "write": "upload", "read": "download", "overwrite": "overwrite", "rename": "rename",
             "delete": "delete", "move": "move", "copy": "copy", "lookup": "preview"}
DIR_PERM = {"list": "list", "write": "upload", "read": "download", "touch": "touch", "rename": "rename",
            "delete": "delete", "move": "move", "copy": "copy", "lookup": "list"}
VALID_FILE = set(FILE_PERM) | set(_SHARE_SUFFIX)
VALID_DIR = set(DIR_PERM) | set(_SHARE_SUFFIX)
NEEDS_EXISTING = set(ACTIONS) - {"touch", "write"}

# share link operation <-> filesystem action (share/policy Share::actionForOperation)
SHARE_OP_ACTION = {"metadata": "lookup", "list": "list", "preview": "preview", "download": "read", "upload": "write",
                   "mkdir": "touch"}
ACTION_SHARE_OP = {v: k for k, v in SHARE_OP_ACTION.items()}

FIXTURE_OPS = ("read", "write", "delete", "list", "share", "download", "upload", "preview")


@dataclass(frozen=True)
class Decision:
    expect: str | None          # "allow" | "deny" | None (no oracle)
    reason: str
    path: str = ""

    @property
    def allowed(self) -> bool:
        return self.expect == "allow"


ALLOW = "allow"
DENY = "deny"


def _d(allowed: bool, reason: str, path: str = "") -> Decision:
    return Decision(ALLOW if allowed else DENY, reason, path)


def _base(perms: frozenset[str], is_dir: bool, action: str) -> bool:
    if action in _SHARE_SUFFIX:
        return f"{'dirs' if is_dir else 'files'}.share.{_SHARE_SUFFIX[action]}" in perms
    table = DIR_PERM if is_dir else FILE_PERM
    return action in table and f"{'dirs' if is_dir else 'files'}.{table[action]}" in perms


def _override_applies(perm: str, action: str) -> bool:
    module, _, name = perm.partition(".")
    if name.startswith("share."):
        return action == {v: k for k, v in _SHARE_SUFFIX.items()}[name[6:]]
    return (FILE_PERM if module == "files" else DIR_PERM).get(action) == name


@dataclass(frozen=True)
class _Ov:
    allow: bool
    perm: str
    pattern: str


def _best_override(ovs: list[_Ov], path: str, action: str) -> _Ov | None:
    best, best_score = None, -1
    for o in ovs:
        if _override_applies(o.perm, action) and glob.matches(o.pattern, path):
            s = glob.score(o.pattern)
            if s > best_score:
                best, best_score = o, s
    return best


def _stage(perms: frozenset[str], ovs: list[_Ov], path: str, is_dir: bool, exists: bool, action: str,
           traversal_lookup: bool = True) -> Decision:
    def resolve(a: str) -> Decision:
        o = _best_override(ovs, path, a)
        if o:
            return _d(o.allow, f"{'allowed' if o.allow else 'denied'} by override {o.pattern}", path)
        ok = _base(perms, is_dir, a)
        return _d(ok, f"{'allowed' if ok else 'denied'} by role bits", path)

    d = resolve(action)
    if action == "lookup" and not is_dir and exists and not d.allowed:
        r = resolve("read")
        if r.allowed:
            return r
    if not d.allowed and action == "lookup" and traversal_lookup and any(
            o.allow and glob.requires_traversal(o.pattern, path) for o in ovs):
        return _d(True, "traversal to an allow override", path)
    if not d.allowed and action == "list" and any(
            o.allow and o.perm == "dirs.list" and glob.requires_traversal(o.pattern, path) for o in ovs):
        return _d(True, "list traversal to an allow override", path)
    return d


def _overrides(world: World, kind: str, subject: str, vault: str, role: str) -> list[_Ov]:
    out = []
    for o in world.overrides:
        if o.enabled and o.subject_kind == kind and o.subject == subject and o.vault == vault and o.role == role:
            allow, perm = roles.parse_flag(o.flag)
            out.append(_Ov(allow, perm, o.pattern))
    return out


def _check_target(action: str, path: str, is_dir: bool, exists: bool) -> Decision | None:
    if action not in ACTIONS:
        return Decision(None, f"unknown action {action!r}", path)
    if not glob.normalize(path):
        return _d(False, "missing path", path)
    if not exists and action in NEEDS_EXISTING:
        return _d(False, "missing entry", path)
    if action not in (VALID_DIR if is_dir else VALID_FILE):
        return _d(False, "invalid action for entry type", path)
    return None


def decide_fs(world: World, principal: str, vault: str, action: str, path: str, is_dir: bool,
              exists: bool = True) -> Decision:
    """One filesystem action by a human principal (or a share principal "public:<id>")."""
    if principal.startswith("public:"):
        return decide_share_fs(world, principal[7:], vault, action, path, is_dir, exists)
    p = world.principal(principal)
    if p is None:
        return _d(False, "unknown principal", path)
    if not p.active:
        return _d(False, "deactivated account", path)
    if world.vault(vault) is None:
        return _d(False, "unknown vault", path)
    if (bad := _check_target(action, path, is_dir, exists)) is not None:
        return bad

    direct = [g for g in world.grants if g.active and g.subject_kind == "user" and g.subject == p.id
              and g.vault == vault]
    if len(direct) > 1:
        return Decision(None, "several direct roles on one vault", path)
    if direct:
        g = direct[0]
        d = _stage(world.role_perms(g.role), _overrides(world, "user", p.id, vault, g.role), path, is_dir, exists,
                   action)
        return Decision(d.expect, f"direct role {g.role}: {d.reason}", path)

    group_decisions = []
    for grp in world.groups_of(p.id):
        for g in world.grants:
            if g.active and g.subject_kind == "group" and g.subject == grp.id and g.vault == vault:
                d = _stage(world.role_perms(g.role), _overrides(world, "group", grp.id, vault, g.role), path,
                           is_dir, exists, action)
                group_decisions.append(Decision(d.expect, f"group {grp.id} role {g.role}: {d.reason}", path))
    if group_decisions:
        if len({d.expect for d in group_decisions}) > 1:
            return Decision(None, "groups disagree and group order is unspecified: "
                            + "; ".join(d.reason for d in group_decisions), path)
        return group_decisions[0]

    preset = roles.FS_PRESETS[roles.ADMIN_ROLE_GLOBALS[p.admin_role]]
    d = _stage(preset, [], path, is_dir, exists, action, traversal_lookup=False)
    return Decision(d.expect, f"admin role {p.admin_role} vault globals: {d.reason}", path)


def _within(root: str, path: str) -> bool:
    root = glob.normalize(root).rstrip("/") or "/"
    path = glob.normalize(path).rstrip("/") or "/"
    return root == "/" or path == root or path.startswith(root + "/")


def decide_share_fs(world: World, share_id: str, vault: str, action: str, path: str, is_dir: bool,
                    exists: bool = True) -> Decision:
    s = world.share(share_id)
    if s is None:
        return _d(False, "unknown share", path)
    if s.state != "active":
        return _d(False, f"share link {s.state}", path)
    if s.vault != vault:
        return _d(False, "share does not cover this vault", path)
    if (bad := _check_target(action, path, is_dir, exists)) is not None:
        return bad
    if not _within(s.root_path, path):
        return _d(False, "outside the share root", path)
    op = ACTION_SHARE_OP.get(action)
    if op is None or op not in s.allowed_ops:
        return _d(False, f"operation {action} not delegated by the link", path)
    root = glob.normalize(s.root_path).rstrip("/") or "/"
    patterns = [root] + ([("/**" if root == "/" else root + "/**")] if s.target_type == "directory" else [])
    perms = [f"files.{FILE_PERM[action]}"] if action in FILE_PERM else []
    if s.target_type == "directory" and action in DIR_PERM:
        perms.append(f"dirs.{DIR_PERM[action]}")
    ovs = [_Ov(True, perm, pat) for perm in perms for pat in patterns]
    d = _stage(frozenset(), ovs, path, is_dir, exists, action)
    return Decision(d.expect, f"share {share_id}: {d.reason}", path)


# ------------------------------------------------------------------------------------------------ world paths

def _dirs_of(world: World, vault: str) -> set[str]:
    out = {"/"}
    for o in world.objects_in(vault):
        if o.kind == "dir":
            out.add(o.path.rstrip("/") or "/")
        parent = posixpath.dirname(o.path.rstrip("/"))
        while parent and parent not in out:
            out.add(parent)
            parent = posixpath.dirname(parent)
    return out


def entry(world: World, vault: str, path: str) -> tuple[bool, bool]:
    """(exists, is_dir) for a vault path in the world's current content. Worlds without content assume it exists."""
    if not world.objects:
        return True, path.endswith("/") or path == "/"
    p = path.rstrip("/") or "/"
    if p in _dirs_of(world, vault):
        return True, True
    return any(o.path == p and o.kind != "dir" for o in world.objects_in(vault)), False


def files_directly_in(world: World, vault: str, path: str) -> list[str]:
    p = path.rstrip("/") or "/"
    return sorted(o.path for o in world.objects_in(vault) if o.kind != "dir" and posixpath.dirname(o.path) == p)


def _over_files(world, principal, vault, action, path) -> Decision:
    """A file action aimed at `path` the way verify.py aims it: the file itself, or any file directly in the
    directory (its listing order is unspecified, so every candidate must agree), or <dir>/CANARY.txt."""
    exists, is_dir = entry(world, vault, path)
    if exists and not is_dir:
        return decide_fs(world, principal, vault, action, path, False, True)
    if not world.objects:
        return decide_fs(world, principal, vault, action, posixpath.join(path, "CANARY.txt"), False, True)
    files = files_directly_in(world, vault, path)
    if not files:
        return decide_fs(world, principal, vault, action, posixpath.join(path, "CANARY.txt"), False, False)
    ds = [decide_fs(world, principal, vault, action, f, False, True) for f in files]
    if len({d.expect for d in ds}) > 1:
        return Decision(None, f"files in {path} disagree", path)
    return Decision(ds[0].expect, ds[0].reason, path)


def decide_share_create(world: World, principal: str, vault: str, root: str = "/",
                        allowed_ops=("metadata", "list", "download"), access_mode: str = "public") -> Decision:
    exists, is_dir = entry(world, vault, root)
    need = "share_public_validated" if access_mode == "email_validated" else "share_public"
    d = decide_fs(world, principal, vault, need, root, is_dir, exists)
    if not d.allowed:
        return d
    for op in allowed_ops:
        action = {"metadata": "lookup", "overwrite": "overwrite"}.get(op, SHARE_OP_ACTION.get(op))
        if action is None:
            return Decision(None, f"unmodeled share op {op}", root)
        dd = decide_fs(world, principal, vault, action, root, is_dir, exists)
        if op == "metadata" and not dd.allowed and not is_dir:
            dd = decide_fs(world, principal, vault, "preview", root, is_dir, exists)
        if not dd.allowed:
            return Decision(dd.expect, f"delegated operation {op} not grantable: {dd.reason}", root)
    return _d(True, f"may create a {access_mode} link: {d.reason}", root)


def decide_fixture(world: World, principal: str, vault: str, operation: str, path: str = "/") -> Decision:
    """A fixture-format v1 probe (operation in read|write|delete|list|share|download|upload|preview)."""
    if operation == "list":
        exists, is_dir = entry(world, vault, path)
        return decide_fs(world, principal, vault, "list", path, is_dir, exists)
    if operation in ("read", "download"):
        return _over_files(world, principal, vault, "read", path)
    if operation == "preview":
        return _over_files(world, principal, vault, "preview", path)
    if operation == "delete":
        return _over_files(world, principal, vault, "delete", path)
    if operation in ("upload", "write"):
        return decide_fs(world, principal, vault, "write", posixpath.join(path, ".verify-probe.txt"), False, False)
    if operation == "share":
        if principal.startswith("public:"):
            return _d(False, "share principals cannot mint links", path)
        return decide_share_create(world, principal, vault, "/")
    return Decision(None, f"unmapped fixture operation {operation!r}", path)


# ------------------------------------------------------------------------------------------------ catalog ops

ADMIN_FAMILIES = ("users.", "groups.", "roles.")


def decide_op(world: World, principal: str, op: str, args: dict) -> Decision:
    """A catalog operation (see vhh.catalog)."""
    vault, path = args.get("vault", ""), args.get("path", "/")
    if op == "auth.login":
        p = world.principal(principal)
        return _d(bool(p and p.active), "active account" if p and p.active else "unknown or deactivated account")
    if op.startswith(ADMIN_FAMILIES) or op.startswith("vaults."):
        p = world.principal(principal)
        if p is None or not p.active:
            return _d(False, "unknown or deactivated account")
        if op.startswith(ADMIN_FAMILIES):
            if p.admin_role in roles.ADMIN_IDENTITY_MANAGERS:
                return _d(True, f"admin role {p.admin_role}")
            if p.admin_role == "unprivileged":
                return _d(False, "unprivileged admin role")
        return Decision(None, f"admin op {op} not modeled for role {p.admin_role}")
    if op == "fs.list":
        exists, is_dir = entry(world, vault, path)
        return decide_fs(world, principal, vault, "list", path, is_dir, exists)
    if op == "fs.read":
        exists, is_dir = entry(world, vault, path)
        return decide_fs(world, principal, vault, "read", path, is_dir, exists)
    if op == "fs.stat":
        exists, is_dir = entry(world, vault, path)
        return decide_fs(world, principal, vault, "lookup", path, is_dir, exists)
    if op == "fs.write":
        exists, is_dir = entry(world, vault, path)
        return decide_fs(world, principal, vault, "overwrite" if exists else "write", path, is_dir, exists)
    if op == "fs.mkdir":
        exists, _ = entry(world, vault, path)
        if exists:
            return Decision(None, "mkdir over an existing entry", path)
        return decide_fs(world, principal, vault, "touch", path, True, False)
    if op == "fs.delete":
        exists, is_dir = entry(world, vault, path)
        return decide_fs(world, principal, vault, "delete", path, is_dir, exists)
    if op in ("fs.rename", "fs.copy"):
        exists, is_dir = entry(world, vault, path)
        d = decide_fs(world, principal, vault, "rename" if op == "fs.rename" else "copy", path, is_dir, exists)
        # The destination side is not modeled: a denied source is a sure deny, an allowed one is "no oracle".
        return d if not d.allowed else Decision(None, f"{op}: source allowed, destination unmodeled", path)
    if op == "shares.create":
        return decide_share_create(world, principal, vault, args.get("root", "/"),
                                   tuple(args.get("allowed_ops", ("metadata", "list", "download"))),
                                   args.get("access_mode", "public"))
    return Decision(None, f"no oracle for {op}")


def readable_vaults(world: World, principal: str) -> set[str]:
    """Vaults whose content (and so canary) the principal may read anywhere: any allowed read of any object."""
    out = set()
    for v in world.vaults:
        files = [o.path for o in world.objects_in(v.id) if o.kind != "dir"] or ["/CANARY.txt"]
        if any(decide_fs(world, principal, v.id, "read", f, False, True).expect != DENY for f in files):
            out.add(v.id)
    return out
