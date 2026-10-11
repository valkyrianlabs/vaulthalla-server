"""Stable, counter-based seed derivation.

Every random choice is a pure function of (root, stream labels, index), so adding or removing an unrelated op or
session never shifts another's choices. The same function exists on the C++ side (Tier A) so a seed printed by either
tier means the same thing: BLAKE2b-64 over length-prefixed parts.
"""
from __future__ import annotations

import hashlib
import random
import secrets
import struct


def h64(*parts: object) -> int:
    m = hashlib.blake2b(digest_size=8)
    for p in parts:
        b = p if isinstance(p, bytes) else str(p).encode()
        m.update(struct.pack("<I", len(b)))
        m.update(b)
    return int.from_bytes(m.digest(), "little")


def rng(root: int, *labels: object) -> random.Random:
    return random.Random(h64(root, *labels))


def parse_seed(text: str | None) -> int:
    """Accepts decimal or 0x-hex; None/'' draws a fresh random seed (which the caller must print)."""
    if not text:
        return secrets.randbits(64)
    return int(text, 0) & (2**64 - 1)


def fmt_seed(seed: int) -> str:
    return f"0x{seed:016x}"
