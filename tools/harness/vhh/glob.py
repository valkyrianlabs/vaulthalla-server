"""Path-scoped override globs, written from the documented semantics (core/src/rbac/fs/glob/*):

- patterns are vault-absolute ("/..."); no escapes; only "*" and "**"
- "*"  one or more characters, never "/"
- "?"  exactly one character, never "/"
- "**/" zero or more whole segments; a bare "**" any sequence (including "/" and empty)
- specificity: literal run = 10 + its length, "/" = 1, "?" = 2, wildcards = 0; the highest score wins, ties keep the
  first declared override
"""
from __future__ import annotations

import posixpath
from functools import lru_cache


class GlobError(ValueError):
    pass


@lru_cache(maxsize=4096)
def tokenize(pattern: str) -> tuple[tuple[str, str], ...]:
    if not pattern or not pattern.startswith("/"):
        raise GlobError(f"glob must be vault-absolute: {pattern!r}")
    if "\\" in pattern or "***" in pattern:
        raise GlobError(f"unsupported glob: {pattern!r}")
    out: list[tuple[str, str]] = []
    lit = ""
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c in "/?*":
            if lit:
                out.append(("lit", lit))
                lit = ""
            if c == "*" and pattern[i + 1:i + 2] == "*":
                out.append(("**", "**"))
                i += 1
            else:
                out.append((c, c))
        else:
            lit += c
        i += 1
    if lit:
        out.append(("lit", lit))
    return tuple(out)


def normalize(path: str) -> str:
    if not path.startswith("/"):
        return ""
    trail = path.endswith("/") and path != "/"
    n = posixpath.normpath(path)
    if n.startswith("//"):
        n = "/" + n.lstrip("/")
    return n + "/" if trail and n != "/" else n


def _match(toks, path: str, ti: int, pi: int) -> bool:
    if ti == len(toks):
        return pi == len(path)
    kind, val = toks[ti]
    if kind == "lit":
        return path.startswith(val, pi) and _match(toks, path, ti + 1, pi + len(val))
    if kind == "/":
        return pi < len(path) and path[pi] == "/" and _match(toks, path, ti + 1, pi + 1)
    if kind == "?":
        return pi < len(path) and path[pi] != "/" and _match(toks, path, ti + 1, pi + 1)
    if kind == "*":
        j = pi
        while j < len(path) and path[j] != "/":
            j += 1
            if _match(toks, path, ti + 1, j):
                return True
        return False
    # "**"
    if ti + 1 < len(toks) and toks[ti + 1][0] == "/":
        if _match(toks, path, ti + 2, pi):
            return True
        return any(path[j] == "/" and _match(toks, path, ti + 2, j + 1) for j in range(pi, len(path)))
    return any(_match(toks, path, ti + 1, j) for j in range(pi, len(path) + 1))


def matches(pattern: str, path: str) -> bool:
    p = normalize(path)
    return bool(p) and _match(tokenize(pattern), p, 0, 0)


def score(pattern: str) -> int:
    s = 0
    for kind, val in tokenize(pattern):
        s += {"lit": 10 + len(val), "/": 1, "?": 2}.get(kind, 0)
    return s


def literal_prefix(pattern: str) -> str:
    out = ""
    for kind, val in tokenize(pattern):
        if kind in ("*", "**", "?"):
            break
        out += val
    return out or "/"


def _ancestor_or_self(a: str, p: str) -> bool:
    if a == "/":
        return p.startswith("/")
    return p == a or (p.startswith(a) and p[len(a)] == "/")


def requires_traversal(pattern: str, directory: str) -> bool:
    """True when `directory` lies on the corridor to what the pattern grants (a strict ancestor of its literal
    prefix), so a low-risk List/Lookup there must be allowed for the grant to be reachable."""
    d = normalize(directory)
    if not d or matches(pattern, d):
        return False
    prefix = literal_prefix(pattern)
    if not _ancestor_or_self(d, prefix):
        return False
    if d != prefix:
        return True
    if prefix.endswith("/"):
        return True
    trimmed = prefix.rstrip("/") or "/"
    return d == trimmed or d == (posixpath.dirname(prefix) or "/")
