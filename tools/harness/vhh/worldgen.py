"""Seeded random worlds: principals, group trees, vault-role assignments, path-scoped overrides, shares, content.

Every choice is drawn from `seeds.rng(seed, "world", <stream>)`, so a world is a pure function of (seed, profile).
Generated worlds have no hand-written expectations: the oracle is the oracle ("expectations": computed).
"""
from __future__ import annotations

from vhh import roles
from vhh.seeds import fmt_seed, h64, rng
from vhh.world import UID_BASE, Grant, Group, Obj, Override, Principal, Share, Vault, VaultRole, World

PROFILES = {
    "smoke": {"users": (3, 4), "groups": (1, 2), "vaults": (2, 3), "grants": (2, 4), "overrides": (1, 2),
              "shares": (0, 1), "files": (3, 6)},
    "pressure": {"users": (5, 9), "groups": (2, 4), "vaults": (3, 6), "grants": (4, 10), "overrides": (2, 6),
                 "shares": (1, 3), "files": (6, 14)},
}

DIRS = ("/", "/docs", "/restricted", "/a", "/a/b", "/drop")
GRANT_ROLES = ("guest", "reader", "contributor", "editor", "manager", "power_user")
# Share-permission overrides are left out on purpose: the product matches them against every action (a TODO in
# Files/Directories::resolveFromQualifiedName), which the model does not reproduce.
OVERRIDE_FLAGS = ("deny-files-download", "allow-files-download", "deny-files-upload", "allow-files-upload",
                  "deny-files-delete", "allow-files-delete", "deny-dirs-list", "allow-dirs-list", "deny-files-preview")
PATTERNS = ("/restricted/**", "/docs/*", "/a/**", "/a/b/*", "/**/*.txt", "/docs/f?.txt", "/drop/**")
OWNER_ROLE = "vhh-owner"


def generate(seed: int, profile: str = "smoke") -> World:
    cfg = PROFILES[profile]

    def r(stream: str):
        return rng(seed, "world", stream)

    def count(stream: str, key: str) -> int:
        lo, hi = cfg[key]
        return r(stream).randint(lo, hi)

    w = World(name=f"gen-{fmt_seed(seed)}-{profile}", seed=fmt_seed(seed), profile=profile,
              content_seed=f"vhh-world-{fmt_seed(seed)}",
              tags={"user_prefix": "vhh_", "group_prefix": "vhh-", "marker": "[vhh-world]"})
    w.vault_roles = [VaultRole(OWNER_ROLE, "manager", ["allow-files-share-public", "allow-dirs-share-public"],
                               "owner role with public sharing")]

    # principals: one admin, the rest unprivileged, maybe one deactivated
    n = count("users", "users")
    w.principals.append(Principal("u-admin", "admin", admin_role="admin", linux_uid=UID_BASE + 1))
    for i in range(n):
        w.principals.append(Principal(f"u-{i:02d}", f"user{i:02d}", linux_uid=UID_BASE + 2 + i))
    if r("deactivated").random() < 0.5:
        w.principals[-1].active = False
    users = [p.id for p in w.principals if p.admin_role == "unprivileged"]

    # groups (a shallow tree; membership is direct only, parents are informational)
    for i in range(count("groups", "groups")):
        gr = r(f"group:{i}")
        members = sorted(gr.sample(users, gr.randint(1, max(1, len(users) // 2))))
        parent = w.groups[gr.randrange(len(w.groups))].id if w.groups and gr.random() < 0.3 else None
        w.groups.append(Group(f"g-{i:02d}", f"group{i:02d}", members, parent))

    # vaults, each with an explicit owner role (owners get no automatic vault role)
    for i in range(count("vaults", "vaults")):
        vr = r(f"vault:{i}")
        owner = vr.choice(users)
        vid = f"v-{i:02d}"
        w.vaults.append(Vault(vid, f"vault{i:02d}", owner, "1G"))
        w.canaries[vid] = f"VHH-CANARY-{h64(seed, 'canary', vid):016x}"
        w.grants.append(Grant("user", owner, vid, OWNER_ROLE, published=False, note="owner role"))
        for k in range(count(f"files:{i}", "files")):
            fr = r(f"file:{i}:{k}")
            d = fr.choice(DIRS)
            name = f"f{k}.txt" if fr.random() < 0.6 else f"f{k}.bin"
            w.objects.append(Obj(f"o-{i:02d}-{k:02d}", vid, f"{d.rstrip('/')}/{name}", "text"))
        w.objects.append(Obj(f"o-{i:02d}-canary", vid, "/CANARY.txt", "text", tags=["canary"]))

    # grants: users or groups; at most one direct role per (user, vault)
    taken: set[tuple[str, str, str]] = {(g.subject_kind, g.subject, g.vault) for g in w.grants}
    for i in range(count("grants", "grants")):
        gr = r(f"grant:{i}")
        kind = "group" if w.groups and gr.random() < 0.4 else "user"
        subject = gr.choice([g.id for g in w.groups] if kind == "group" else users)
        vault = gr.choice(w.vaults).id
        if (kind, subject, vault) in taken:
            continue
        taken.add((kind, subject, vault))
        w.grants.append(Grant(kind, subject, vault, gr.choice(GRANT_ROLES), active=gr.random() > 0.15))

    # overrides attach to an existing assignment
    assignable = [g for g in w.grants if g.role != OWNER_ROLE]
    for i in range(count("overrides", "overrides") if assignable else 0):
        orr = r(f"override:{i}")
        g = orr.choice(assignable)
        w.overrides.append(Override(g.subject_kind, g.subject, g.vault, g.role, orr.choice(OVERRIDE_FLAGS),
                                    orr.choice(PATTERNS)))

    for i in range(count("shares", "shares")):
        sr = r(f"share:{i}")
        v = sr.choice(w.vaults)
        ops = ["metadata", "list"] + (["download"] if sr.random() < 0.7 else [])
        w.shares.append(Share(f"sl-{i:02d}", v.id, "/", "directory", "download" if "download" in ops else "access",
                              "share_download_only" if "download" in ops else "share_preview_read", ops,
                              sr.choice(("active", "active", "expired", "revoked")), key=f"share{i:02d}"))
    for role in w.vault_roles:
        for f in role.flags:
            roles.parse_flag(f)  # fail fast on a generator typo
    return w
