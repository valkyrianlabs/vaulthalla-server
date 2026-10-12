"""Role templates and permission names, transcribed from the daemon's RBAC sources (data only).

Sources (keep in sync when they change):
- vault filesystem bits: core/include/rbac/permission/vault/fs/{Files,Directories,Share}.hpp
- filesystem presets:    core/include/rbac/permission/vault/Filesystem.hpp
- vault role templates:  core/src/rbac/role/Vault.cpp + core/include/rbac/role/vault/Base.hpp
- admin roles + globals: core/src/rbac/role/Admin.cpp + core/include/rbac/permission/admin/VaultGlobals.hpp

A permission set is a frozenset of names like "files.download", "dirs.list", "files.share.public".
"""
from __future__ import annotations

import re

FILE_PERMS = ("preview", "upload", "download", "overwrite", "rename", "delete", "move", "copy")
DIR_PERMS = ("list", "upload", "download", "touch", "delete", "rename", "move", "copy")
SHARE_PERMS = ("internal", "public", "public_with_val")


def _s(prefix: str, *names: str) -> frozenset[str]:
    return frozenset(f"{prefix}.{n}" for n in names)


_SH_INT = ("share.internal",)
_SH_INT_VAL = ("share.internal", "share.public_with_val")
_SH_ALL = tuple(f"share.{n}" for n in SHARE_PERMS)

_FILES = {
    "none": _s("files"),
    "preview_only": _s("files", "preview"),
    "download_only": _s("files", "preview", "download"),
    "read_only": _s("files", "preview", "download", "copy", *_SH_INT),
    "contributor": _s("files", "preview", "upload", "download", "overwrite", "copy", *_SH_INT),
    "editor": _s("files", "preview", "upload", "download", "overwrite", "rename", "move", "copy", *_SH_INT_VAL),
    "manager": _s("files", "preview", "upload", "download", "overwrite", "rename", "delete", "move", "copy",
                  *_SH_INT_VAL),
    "full": _s("files", *FILE_PERMS, *_SH_ALL),
}
_DIRS = {
    "none": _s("dirs"),
    "list_only": _s("dirs", "list"),
    "download_only": _s("dirs", "list", "download"),
    "read_only": _s("dirs", "list", "download", "copy", *_SH_INT),
    "contributor": _s("dirs", "list", "upload", "download", "touch", "copy", *_SH_INT),
    "editor": _s("dirs", "list", "upload", "download", "touch", "rename", "move", "copy", *_SH_INT_VAL),
    "manager": _s("dirs", "list", "upload", "download", "touch", "delete", "rename", "move", "copy", *_SH_INT_VAL),
    "full": _s("dirs", *DIR_PERMS, *_SH_ALL),
}

# Filesystem presets (Filesystem::None/BrowseOnly/...): files preset + directories preset.
FS_PRESETS = {
    "none": _FILES["none"] | _DIRS["none"],
    "browse_only": _FILES["preview_only"] | _DIRS["list_only"],
    "read_only": _FILES["read_only"] | _DIRS["read_only"],
    "download_only": _FILES["download_only"] | _DIRS["download_only"],
    "contributor": _FILES["contributor"] | _DIRS["contributor"],
    "editor": _FILES["editor"] | _DIRS["editor"],
    "manager": _FILES["manager"] | _DIRS["manager"],
    "full": _FILES["full"] | _DIRS["full"],
}

# Vault role templates (role::Vault::*) -> filesystem preset of their vault::Base.
VAULT_ROLE_TEMPLATES = {
    "implicit_deny": "none",
    "guest": "browse_only",
    "reader": "read_only",
    "contributor": "contributor",
    "editor": "editor",
    "manager": "manager",
    "power_user": "full",
    "full": "full",
    "role_manager": "read_only",
    "sync_operator": "read_only",
}

# Admin roles (role::Admin::*) -> the vault-globals filesystem preset (uniform across self/admin/user scopes for
# every built-in admin role).
ADMIN_ROLE_GLOBALS = {
    "unprivileged": "none",
    "auditor": "read_only",
    "support": "read_only",
    "identity_admin": "manager",
    "security_admin": "manager",
    "platform_operator": "full",
    "vault_admin": "full",
    "admin": "full",
    "super_admin": "full",
    "key_custodian": "read_only",
}
ADMIN_ROLES = tuple(ADMIN_ROLE_GLOBALS)

# Admin roles that may manage identities/roles (users.*, groups.*, roles.*). Other built-in roles are not modeled for
# admin ops: the oracle answers "no oracle" for them instead of guessing.
ADMIN_IDENTITY_MANAGERS = ("admin", "super_admin")

_FLAG = re.compile(r"^(allow|deny)-(files|dirs)-(share-)?([a-z_]+)$")


class FlagError(ValueError):
    pass


def parse_flag(flag: str) -> tuple[bool, str]:
    """'allow-files-share-public' -> (True, 'files.share.public'); 'deny-dirs-list' -> (False, 'dirs.list')."""
    m = _FLAG.match(flag)
    if not m:
        raise FlagError(f"unknown permission flag {flag!r}")
    allow, module, share, name = m.group(1) == "allow", m.group(2), m.group(3), m.group(4)
    valid = SHARE_PERMS if share else (FILE_PERMS if module == "files" else DIR_PERMS)
    if name not in valid:
        raise FlagError(f"unknown permission flag {flag!r}")
    return allow, f"{module}.{'share.' if share else ''}{name}"


def template_perms(name: str) -> frozenset[str]:
    if name not in VAULT_ROLE_TEMPLATES:
        raise KeyError(f"unknown vault role template {name!r}")
    return FS_PRESETS[VAULT_ROLE_TEMPLATES[name]]


def apply_flags(base: frozenset[str], flags) -> frozenset[str]:
    out = set(base)
    for flag in flags:
        allow, perm = parse_flag(flag)
        (out.add if allow else out.discard)(perm)
    return frozenset(out)
