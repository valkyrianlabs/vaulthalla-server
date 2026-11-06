#!/usr/bin/env python3
"""Reference implementation and golden vectors for the #329 encryption formats.

Formats (normative text in design/encryption/):
  - VHF1: the framed, chunked AEAD container for file content, manifest segments and manifest roots
    (02-authenticated-file-format.md; manifest kinds in 03-metadata-recovery.md).
  - KEV1: the key envelope that wraps a vault key version to a recipient public key (03-metadata-recovery.md,
    04-sealed-vaults.md).
  - Object ids: Crockford base32 of 16 random bytes, and the OpaqueV1 object keys (01-provider-blind-storage.md).

Usage:
  python3 vh_crypto_vectors.py            # write vectors.json next to this script
  python3 vh_crypto_vectors.py --check    # regenerate in memory, compare with vectors.json byte for byte, then
                                          # run the independent reference reader over every vector
  python3 vh_crypto_vectors.py --out PATH # write somewhere else

Only fixed keys, salts and ephemeral keys are used, so the output is deterministic. The reader below never calls the
writer: --check proves both that the committed file is what this script generates and that a separate decoding
path accepts every positive vector and rejects every negative one with the documented error code.

Dependencies: Python 3.10+, `cryptography` >= 41 (AES-GCM, X25519, P-256). HKDF and HMAC come from the standard
library so the construction is visible here.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCHEMA = "vh-crypto-vectors/1"
HERE = Path(__file__).resolve().parent
DEFAULT_OUT = HERE / "vectors.json"

# --------------------------------------------------------------------------------------------------------------------
# Common helpers
# --------------------------------------------------------------------------------------------------------------------

B32_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"  # Crockford, lower case, no padding


def b32_encode(data: bytes) -> str:
    """Big-endian bit stream, 5 bits per symbol, the last symbol zero-padded on the right."""
    bits = int.from_bytes(data, "big")
    nbits = len(data) * 8
    nsym = (nbits + 4) // 5
    bits <<= nsym * 5 - nbits
    return "".join(B32_ALPHABET[(bits >> (5 * (nsym - 1 - i))) & 31] for i in range(nsym))


class B32Error(ValueError):
    pass


def b32_decode_uid(text: str) -> bytes:
    """Strict decoder for 16-byte ids: exactly 26 lower-case symbols, zero padding bits (one canonical spelling)."""
    if len(text) != 26:
        raise B32Error("bad_length")
    value = 0
    for ch in text:
        idx = B32_ALPHABET.find(ch)
        if idx < 0:
            raise B32Error("bad_symbol")
        value = (value << 5) | idx
    if value & 0b11:
        raise B32Error("non_canonical")
    return (value >> 2).to_bytes(16, "big")


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def pattern(n: int, seed: int) -> bytes:
    """Deterministic test plaintext: byte i = (i * 131 + seed * 17 + 7) mod 256."""
    return bytes((i * 131 + seed * 17 + 7) & 0xFF for i in range(n))


def label_bytes(label: str, n: int) -> bytes:
    """Fixed test material: the first n bytes of SHA-256(label) (repeated SHA-256 chaining when n > 32)."""
    out, block = b"", label.encode()
    while len(out) < n:
        block = sha256(block)
        out += block
    return out[:n]


# --------------------------------------------------------------------------------------------------------------------
# VHF1 (02-authenticated-file-format.md)
# --------------------------------------------------------------------------------------------------------------------

VHF1_MAGIC = bytes([0x89, 0x56, 0x48, 0x46, 0x0D, 0x0A, 0x1A, 0x0A])  # "\x89VHF\r\n\x1a\n"
VHF1_VERSION = 1
VHF1_HEADER_LEN = 120
VHF1_BODY_LEN = 88  # header bytes covered by the header tag
VHF1_SUITE_AES256GCM_HKDF_SHA256 = 0x0001
VHF1_TAG_LEN = 16
VHF1_MIN_CHUNK_LOG2, VHF1_MAX_CHUNK_LOG2, VHF1_WRITER_CHUNK_LOG2 = 10, 22, 16
KIND_FILE, KIND_SEGMENT, KIND_ROOT = 1, 2, 3
INFO_HDR, INFO_ENC = b"vh.f1.hdr", b"vh.f1.enc"


@dataclass(frozen=True)
class Vhf1Params:
    key_version: int
    vault_uid: bytes
    object_uid: bytes
    salt: bytes
    kind: int = KIND_FILE
    chunk_log2: int = VHF1_WRITER_CHUNK_LOG2


def vhf1_header_body(p: Vhf1Params) -> bytes:
    assert len(p.vault_uid) == 16 and len(p.object_uid) == 16 and len(p.salt) == 32
    body = (VHF1_MAGIC
            + struct.pack(">HHHBBI", VHF1_VERSION, VHF1_HEADER_LEN, VHF1_SUITE_AES256GCM_HKDF_SHA256,
                          p.chunk_log2, p.kind, p.key_version)
            + b"\x00\x00\x00\x00"  # reserved
            + p.vault_uid + p.object_uid + p.salt)
    assert len(body) == VHF1_BODY_LEN
    return body


def vhf1_keys(vault_key: bytes, salt: bytes, header_hash: bytes) -> tuple[bytes, bytes, bytes]:
    prk = hkdf_extract(salt, vault_key)
    return prk, hkdf_expand(prk, INFO_HDR + header_hash), hkdf_expand(prk, INFO_ENC + header_hash)


def vhf1_nonce(index: int) -> bytes:
    return b"\x00\x00\x00\x00" + struct.pack(">Q", index)


def vhf1_aad(header_hash: bytes, index: int, final: bool) -> bytes:
    return header_hash + struct.pack(">QB", index, 1 if final else 0)


def vhf1_seal(plaintext: bytes, vault_key: bytes, p: Vhf1Params) -> tuple[bytes, dict]:
    """Writer. Returns the object bytes and the intermediate values the vectors publish."""
    body = vhf1_header_body(p)
    hh = sha256(body)
    prk, k_hdr, k_enc = vhf1_keys(vault_key, p.salt, hh)
    tag = hmac.new(k_hdr, body, hashlib.sha256).digest()
    out = bytearray(body + tag)
    size = 1 << p.chunk_log2
    n = max(1, -(-len(plaintext) // size))
    aead = AESGCM(k_enc)
    chunks = []
    for i in range(n):
        final = i == n - 1
        part = plaintext[i * size:(i + 1) * size]
        sealed = aead.encrypt(vhf1_nonce(i), part, vhf1_aad(hh, i, final))
        out += sealed
        chunks.append({"index": i, "final": final, "plaintext_len": len(part),
                       "nonce_hex": vhf1_nonce(i).hex(), "aad_hex": vhf1_aad(hh, i, final).hex(),
                       "tag_hex": sealed[-VHF1_TAG_LEN:].hex()})
    inter = {"header_body_hex": body.hex(), "header_hash_hex": hh.hex(), "prk_hex": prk.hex(),
             "k_hdr_hex": k_hdr.hex(), "k_enc_hex": k_enc.hex(), "header_tag_hex": tag.hex(),
             "chunk_count": n, "chunks": chunks}
    return bytes(out), inter


# ---- reader (independent of the writer above: it parses, it never builds a header) ----

class VhfError(Exception):
    def __init__(self, code: str, chunk_index: int | None = None):
        super().__init__(code if chunk_index is None else f"{code}@{chunk_index}")
        self.code, self.chunk_index = code, chunk_index

    def as_json(self) -> dict:
        out = {"error": self.code}
        if self.chunk_index is not None:
            out["chunk_index"] = self.chunk_index
        return out


@dataclass(frozen=True)
class Expect:
    kind: int
    vault_uid: bytes
    object_uid: bytes
    keys: dict[int, bytes]  # key_version -> vault key


@dataclass(frozen=True)
class OpenedHeader:
    chunk_size: int
    key_version: int
    header_hash: bytes
    k_enc: bytes
    salt: bytes


def vhf1_open_header(head: bytes, ex: Expect) -> OpenedHeader:
    """Header checks, in the normative order of 02 §3.6."""
    if len(head) < VHF1_HEADER_LEN or head[:8] != VHF1_MAGIC:
        raise VhfError("bad_magic")
    version, header_len, suite, chunk_log2, kind, key_version = struct.unpack(">HHHBBI", head[8:20])
    if version != VHF1_VERSION:
        raise VhfError("unsupported_version")
    if header_len != VHF1_HEADER_LEN:
        raise VhfError("bad_header_length")
    if suite != VHF1_SUITE_AES256GCM_HKDF_SHA256:
        raise VhfError("unsupported_suite")
    if not VHF1_MIN_CHUNK_LOG2 <= chunk_log2 <= VHF1_MAX_CHUNK_LOG2:
        raise VhfError("bad_chunk_size")
    if head[20:24] != b"\x00\x00\x00\x00":
        raise VhfError("reserved_nonzero")
    if kind != ex.kind:
        raise VhfError("kind_mismatch")
    if not hmac.compare_digest(head[24:40], ex.vault_uid):
        raise VhfError("vault_mismatch")
    if not hmac.compare_digest(head[40:56], ex.object_uid):
        raise VhfError("object_mismatch")
    if key_version == 0 or key_version not in ex.keys:
        raise VhfError("key_unavailable")
    body, tag, salt = head[:VHF1_BODY_LEN], head[VHF1_BODY_LEN:VHF1_HEADER_LEN], head[56:88]
    hh = hashlib.sha256(body).digest()
    prk = hmac.new(salt, ex.keys[key_version], hashlib.sha256).digest()

    def expand(info: bytes) -> bytes:  # one block of HKDF-Expand is all 32 bytes need
        return hmac.new(prk, info + hh + b"\x01", hashlib.sha256).digest()

    if not hmac.compare_digest(hmac.new(expand(INFO_HDR), body, hashlib.sha256).digest(), tag):
        raise VhfError("header_auth_failed")
    return OpenedHeader(1 << chunk_log2, key_version, hh, expand(INFO_ENC), salt)


def vhf1_layout(object_size: int, chunk_size: int) -> tuple[int, int]:
    """(chunk_count, plaintext_size) from the object size, or bad_size (02 §3.4)."""
    rest = object_size - VHF1_HEADER_LEN
    if rest < VHF1_TAG_LEN:
        raise VhfError("bad_size")
    q, r = divmod(rest, chunk_size + VHF1_TAG_LEN)
    if r == 0:
        return q, q * chunk_size
    if r == VHF1_TAG_LEN and q == 0:
        return 1, 0
    if r > VHF1_TAG_LEN:
        return q + 1, q * chunk_size + r - VHF1_TAG_LEN
    raise VhfError("bad_size")


def vhf1_chunk_span(i: int, n: int, plaintext_size: int, chunk_size: int) -> tuple[int, int]:
    start = VHF1_HEADER_LEN + i * (chunk_size + VHF1_TAG_LEN)
    plain = chunk_size if i < n - 1 else plaintext_size - i * chunk_size
    return start, start + plain + VHF1_TAG_LEN


def vhf1_open_chunk(h: OpenedHeader, sealed: bytes, i: int, final: bool) -> bytes:
    try:
        return AESGCM(h.k_enc).decrypt(b"\x00" * 4 + i.to_bytes(8, "big"), sealed,
                                       h.header_hash + i.to_bytes(8, "big") + bytes([1 if final else 0]))
    except Exception:
        raise VhfError("chunk_auth_failed", i) from None


def vhf1_open(obj: bytes, ex: Expect, expected_size: int | None = None) -> bytes:
    """Whole-object read: every chunk is authenticated before any plaintext is returned."""
    h = vhf1_open_header(obj[:VHF1_HEADER_LEN], ex)
    if expected_size is not None and expected_size != len(obj):
        raise VhfError("size_mismatch")
    n, psize = vhf1_layout(len(obj), h.chunk_size)
    out = bytearray()
    for i in range(n):
        a, b = vhf1_chunk_span(i, n, psize, h.chunk_size)
        out += vhf1_open_chunk(h, obj[a:b], i, i == n - 1)
    return bytes(out)


def vhf1_range(obj: bytes, ex: Expect, start: int, end: int, expected_size: int | None) -> tuple[bytes, dict]:
    """Authenticated range read of plaintext [start, end): fetch the header (or take it from the manifest), fetch only
    the covering chunks, authenticate each whole chunk, then cut. `obj` stands in for the provider: only the slices
    named in the returned plan are read from it."""
    h = vhf1_open_header(obj[:VHF1_HEADER_LEN], ex)
    if expected_size is None:
        raise VhfError("size_unknown")  # a range reader must know the object size from authenticated metadata
    if expected_size != len(obj):  # in production: the Content-Range total of the ranged GET
        raise VhfError("size_mismatch")
    n, psize = vhf1_layout(expected_size, h.chunk_size)
    if not 0 <= start <= end <= psize:
        raise VhfError("range_out_of_bounds")
    if start == end:
        return b"", {"chunk_first": None, "chunk_last": None, "object_range": None}
    first, last = start // h.chunk_size, (end - 1) // h.chunk_size
    lo = vhf1_chunk_span(first, n, psize, h.chunk_size)[0]
    hi = vhf1_chunk_span(last, n, psize, h.chunk_size)[1]
    window = obj[lo:hi]
    plain = bytearray()
    for i in range(first, last + 1):
        a, b = vhf1_chunk_span(i, n, psize, h.chunk_size)
        plain += vhf1_open_chunk(h, window[a - lo:b - lo], i, i == n - 1)
    cut = start - first * h.chunk_size
    return bytes(plain[cut:cut + (end - start)]), {"chunk_first": first, "chunk_last": last, "object_range": [lo, hi]}


# --------------------------------------------------------------------------------------------------------------------
# KEV1 key envelopes (03-metadata-recovery.md §5)
# --------------------------------------------------------------------------------------------------------------------

KEV1_MAGIC = bytes([0x89, 0x56, 0x48, 0x4B, 0x0D, 0x0A, 0x1A, 0x0A])  # "\x89VHK\r\n\x1a\n"
KEV1_VERSION = 1
KEV1_SUITE_X25519, KEV1_SUITE_P256 = 1, 2
KEV1_PURPOSE_VAULT_KEY = 1  # registry (03 §5.2): 1 = a whole vault key version; 2-255 reserved (e.g. threshold shares)
KEV1_CLASS_CUSTOMER = 0     # registry (03 §5.2): 0 = customer-controlled (recovery recipients, owner devices);
                            # 1-255 reserved for separately authorized recipient classes (custodian, threshold participant)
KEV1_INFO = b"vh.kev1.wrap"
KEV1_EPK_LEN = {KEV1_SUITE_X25519: 32, KEV1_SUITE_P256: 65}


def x25519_pub(sk: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def p256_priv(scalar: bytes) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())


def p256_pub(scalar: bytes) -> bytes:
    return p256_priv(scalar).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def ecdh(suite: int, sk: bytes, peer_pub: bytes) -> bytes:
    """Raw shared secret: X25519 output, or the P-256 x-coordinate. Refuses an all-zero result."""
    try:
        if suite == KEV1_SUITE_X25519:
            shared = X25519PrivateKey.from_private_bytes(sk).exchange(X25519PublicKey.from_public_bytes(peer_pub))
        elif suite == KEV1_SUITE_P256:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub)
            shared = p256_priv(sk).exchange(ec.ECDH(), peer)
        else:
            raise KevError("unsupported_suite")
    except KevError:
        raise
    except Exception:
        raise KevError("bad_ephemeral") from None
    if shared == b"\x00" * len(shared):
        raise KevError("bad_ephemeral")
    return shared


class KevError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code

    def as_json(self) -> dict:
        return {"error": self.code}


def kev1_prefix(suite: int, key_version: int, vault_uid: bytes, recipient_pub: bytes, epk: bytes) -> bytes:
    return (KEV1_MAGIC + struct.pack(">HHBB", KEV1_VERSION, suite, KEV1_PURPOSE_VAULT_KEY, KEV1_CLASS_CUSTOMER)
            + b"\x00\x00"
            + struct.pack(">I", key_version) + vault_uid + sha256(recipient_pub)
            + struct.pack(">H", len(epk)) + epk)


def kev1_wrap(vault_key: bytes, suite: int, key_version: int, vault_uid: bytes, recipient_pub: bytes,
              eph_sk: bytes) -> tuple[bytes, dict]:
    epk = x25519_pub(eph_sk) if suite == KEV1_SUITE_X25519 else p256_pub(eph_sk)
    shared = ecdh(suite, eph_sk, recipient_pub)
    prefix = kev1_prefix(suite, key_version, vault_uid, recipient_pub, epk)
    k_wrap = hkdf_expand(hkdf_extract(epk + recipient_pub, shared), KEV1_INFO + prefix)
    env = prefix + AESGCM(k_wrap).encrypt(b"\x00" * 12, vault_key, prefix)
    return env, {"epk_hex": epk.hex(), "shared_hex": shared.hex(), "prefix_hex": prefix.hex(),
                 "k_wrap_hex": k_wrap.hex()}


def kev1_unwrap(env: bytes, recipient_sk: bytes, suite_expected: int, vault_uid: bytes) -> tuple[int, bytes]:
    """Reader: returns (key_version, vault key)."""
    if len(env) < 70 or env[:8] != KEV1_MAGIC:
        raise KevError("bad_magic")
    version, suite, purpose = struct.unpack(">HHB", env[8:13])
    if version != KEV1_VERSION:
        raise KevError("unsupported_version")
    if suite != suite_expected or suite not in KEV1_EPK_LEN:
        raise KevError("unsupported_suite")
    if purpose != KEV1_PURPOSE_VAULT_KEY:
        raise KevError("bad_purpose")  # a restore skips such envelopes (unknown kind of payload), it doesn't fail
    if env[13] != KEV1_CLASS_CUSTOMER:
        raise KevError("unsupported_recipient_class")  # likewise skipped: never decrypted by a v1 reader
    if env[14:16] != b"\x00\x00":
        raise KevError("reserved_nonzero")
    key_version = struct.unpack(">I", env[16:20])[0]
    if env[20:36] != vault_uid:
        raise KevError("vault_mismatch")
    rpk = x25519_pub(recipient_sk) if suite == KEV1_SUITE_X25519 else p256_pub(recipient_sk)
    if not hmac.compare_digest(env[36:68], hashlib.sha256(rpk).digest()):
        raise KevError("recipient_mismatch")
    epk_len = struct.unpack(">H", env[68:70])[0]
    if epk_len != KEV1_EPK_LEN[suite] or len(env) != 70 + epk_len + 48:
        raise KevError("bad_length")
    prefix, epk = env[:70 + epk_len], env[70:70 + epk_len]
    shared = ecdh(suite, recipient_sk, epk)
    prk = hmac.new(epk + rpk, shared, hashlib.sha256).digest()
    k_wrap = hmac.new(prk, KEV1_INFO + prefix + b"\x01", hashlib.sha256).digest()
    try:
        key = AESGCM(k_wrap).decrypt(b"\x00" * 12, env[70 + epk_len:], prefix)
    except Exception:
        raise KevError("wrap_auth_failed") from None
    if key_version == 0:
        raise KevError("bad_key_version")
    return key_version, key


# --------------------------------------------------------------------------------------------------------------------
# Recovery seed (03 §5.3): 16 bytes, written as 26 base32 symbols plus one check symbol
# --------------------------------------------------------------------------------------------------------------------

def recovery_seed_text(seed: bytes) -> str:
    return b32_encode(seed) + B32_ALPHABET[sha256(seed)[0] >> 3]


def recovery_seed_parse(text: str) -> bytes:
    if len(text) != 27:
        raise B32Error("bad_length")
    seed = b32_decode_uid(text[:26])
    if text[26] != B32_ALPHABET[hashlib.sha256(seed).digest()[0] >> 3]:
        raise B32Error("bad_check")
    return seed


def recovery_keys(seed: bytes) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    prk = hkdf_extract(b"vh.recovery.v1", seed)
    x_sk = hkdf_expand(prk, b"x25519")
    ed_seed = hkdf_expand(prk, b"ed25519")
    ed_pk = Ed25519PrivateKey.from_private_bytes(ed_seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"x25519_sk_hex": x_sk.hex(), "x25519_pk_hex": x25519_pub(x_sk).hex(),
            "recipient_id_hex": sha256(x25519_pub(x_sk)).hex(), "ed25519_seed_hex": ed_seed.hex(),
            "ed25519_pk_hex": ed_pk.hex()}


# --------------------------------------------------------------------------------------------------------------------
# Manifest roots and chain rules (03-metadata-recovery.md §3-§4)
# --------------------------------------------------------------------------------------------------------------------

class ManifestError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code

    def as_json(self) -> dict:
        return {"error": self.code}


def canonical_json(value) -> bytes:
    """Writers may serialize however they like (the AEAD covers bytes, not structures); the vectors use this form so
    the plaintexts are reproducible: UTF-8, sorted keys, no insignificant whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def manifest_accept_root(root: dict, root_object: bytes, known: dict | None, segments: dict[str, bytes]) -> dict:
    """Anti-rollback and consistency rules a reader applies after the root object authenticated.
    known = {"epoch": int, "root_sha256": hex} from the DB or a customer checkpoint, or None (a fresh restore)."""
    if root.get("type") != "vh.manifest.root" or root.get("v") != 1:
        raise ManifestError("bad_root")
    epoch = root["epoch"]
    digest = sha256(root_object).hex()
    if known is not None:
        if epoch < known["epoch"]:
            raise ManifestError("rollback")
        if epoch == known["epoch"] and digest != known["root_sha256"]:
            raise ManifestError("fork")
        if epoch == known["epoch"] + 1 and root.get("prev") != known["root_sha256"]:
            raise ManifestError("fork")
    for seg in root["segments"]:
        blob = segments.get(seg["sid"])
        if blob is None:
            raise ManifestError("segment_missing")
        if sha256(blob).hex() != seg["object_sha256"] or len(blob) != seg["size"]:
            raise ManifestError("segment_mismatch")
    result = {"epoch": epoch, "root_sha256": digest}
    if known is not None and epoch > known["epoch"] + 1:
        # The chain back to known can't be walked here (no retained roots): accepted with a gap warning (§4.1).
        result["warning"] = "gap"
    return result


# --------------------------------------------------------------------------------------------------------------------
# Fixed test material
# --------------------------------------------------------------------------------------------------------------------

VAULT_KEYS = {1: bytes(range(32)), 2: bytes(range(32, 64))}  # key v1 = 00..1f (the key-check vectors' key)
VAULT_UID = bytes.fromhex("5648f1a2b3c4d5e6f708192a3b4c5d6e")
OTHER_VAULT_UID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
FILE_UID = bytes.fromhex("9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d")
OTHER_FILE_UID = bytes.fromhex("1b4e28ba2fa1411a8b0f2c3d4e5f6a7b")


def salt_for(name: str) -> bytes:
    return label_bytes("vh-vector-salt/" + name, 32)


def file_expect(object_uid: bytes = FILE_UID, kind: int = KIND_FILE) -> Expect:
    return Expect(kind=kind, vault_uid=VAULT_UID, object_uid=object_uid, keys=dict(VAULT_KEYS))


HEX_LIMIT = 8192  # objects up to this many bytes are published in full; larger ones by digest


def vhf1_positive(name: str, desc: str, plaintext: bytes, plaintext_note: str | None, *, chunk_log2: int,
                  key_version: int = 1, object_uid: bytes = FILE_UID, kind: int = KIND_FILE):
    p = Vhf1Params(key_version=key_version, vault_uid=VAULT_UID, object_uid=object_uid, salt=salt_for(name),
                   kind=kind, chunk_log2=chunk_log2)
    obj, inter = vhf1_seal(plaintext, VAULT_KEYS[key_version], p)
    if inter["chunk_count"] > 4:
        inter["chunks"] = inter["chunks"][:2] + inter["chunks"][-2:]
        inter["chunks_note"] = "first two and last two chunks shown"
    vec = {"name": name, "description": desc,
           "params": {"chunk_log2": chunk_log2, "kind": kind, "key_version": key_version,
                      "vault_uid_hex": VAULT_UID.hex(), "object_uid_hex": object_uid.hex(),
                      "salt_hex": p.salt.hex()},
           "plaintext_size": len(plaintext), "plaintext_sha256": sha256(plaintext).hex(),
           "object_size": len(obj), "object_sha256": sha256(obj).hex(), "intermediate": inter}
    if len(obj) <= HEX_LIMIT:
        vec["plaintext_hex"] = plaintext.hex()
        vec["object_hex"] = obj.hex()
    else:
        vec["plaintext_generator"] = plaintext_note
    return vec, obj, plaintext


def build() -> dict:
    out: dict = {
        "schema": SCHEMA,
        "generated_by": "design/encryption/vectors/vh_crypto_vectors.py",
        "conventions": {
            "integers": "big-endian",
            "hex": "lower case",
            "keys": {str(v): k.hex() for v, k in VAULT_KEYS.items()},
            "plaintext_generator": "pattern(n, seed): byte i = (i * 131 + seed * 17 + 7) mod 256",
            "salt_derivation": "test salts are SHA-256('vh-vector-salt/' + vector name); production salts are 32 "
                               "bytes from the CSPRNG",
            "errors": "a negative vector names the first check that fails, in the order of 02 §3.6 / 03 §5.3",
        },
    }

    # ---- object ids and keys ----
    ids = [bytes(16), bytes([0xFF] * 16), FILE_UID, VAULT_UID]
    out["object_ids"] = {
        "alphabet": B32_ALPHABET,
        "encode": [{"uid_hex": u.hex(), "b32": b32_encode(u), "content_key": "o/" + b32_encode(u)} for u in ids],
        "decode_negative": [
            {"text": b32_encode(FILE_UID).upper(), "error": "bad_symbol", "why": "upper case is not canonical"},
            {"text": b32_encode(FILE_UID)[:-1] + "i", "error": "bad_symbol", "why": "i, l, o, u are not symbols"},
            {"text": b32_encode(FILE_UID)[:-1], "error": "bad_length", "why": "25 symbols"},
            {"text": b32_encode(FILE_UID)[:-1] + B32_ALPHABET[B32_ALPHABET.index(b32_encode(FILE_UID)[-1]) | 1],
             "error": "non_canonical", "why": "padding bits must be zero"},
        ],
    }

    # ---- VHF1 positives ----
    small = 10  # 1 KiB chunks keep the published objects small; writers use 16
    v_empty = vhf1_positive("empty", "0-byte file: one empty final chunk (tag only)", b"", None, chunk_log2=small)
    v_one = vhf1_positive("one_chunk", "16-byte file, one short final chunk", b"hello vaulthalla", None,
                          chunk_log2=small)
    v_exact1 = vhf1_positive("exact_one_chunk", "exactly one full chunk (1024 bytes): no empty trailing chunk",
                             pattern(1024, 1), None, chunk_log2=small)
    v_exact2 = vhf1_positive("exact_two_chunks", "exactly two full chunks (2048 bytes)", pattern(2048, 2), None,
                             chunk_log2=small)
    v_multi = vhf1_positive("multi_chunk", "3 full chunks and a 100-byte final chunk (3172 bytes)",
                            pattern(3 * 1024 + 100, 3), None, chunk_log2=small)
    v_v2 = vhf1_positive("key_version_2", "one chunk sealed under key version 2", pattern(300, 4), None,
                         chunk_log2=small, key_version=2)
    v_real = vhf1_positive("writer_chunk_size", "writer default 64 KiB chunks: 2 full chunks + 1 byte (131073)",
                           pattern(2 * 65536 + 1, 5), "pattern(131073, 5)", chunk_log2=16)
    positives = [v_empty, v_one, v_exact1, v_exact2, v_multi, v_v2, v_real]
    objects = {v[0]["name"]: v[1] for v in positives}

    # ---- VHF1 range reads (on multi_chunk) ----
    ranges = []
    multi_obj, multi_plain = objects["multi_chunk"], v_multi[2]
    for a, b, desc in [(1000, 2100, "crosses two chunk boundaries"), (1024, 2048, "exactly chunk 1"),
                       (3072, 3172, "exactly the final chunk"), (0, 1, "first byte"), (5, 5, "empty range")]:
        plain, plan = vhf1_range(multi_obj, file_expect(), a, b, len(multi_obj))
        assert plain == multi_plain[a:b]
        ranges.append({"object": "multi_chunk", "description": desc, "start": a, "end": b,
                       "expected_object_size": len(multi_obj), **plan, "plaintext_hex": plain.hex()})

    # ---- VHF1 negatives ----
    def chunk_bounds(name: str, i: int) -> tuple[int, int]:
        h = vhf1_open_header(objects[name][:VHF1_HEADER_LEN], file_expect())
        n, psize = vhf1_layout(len(objects[name]), h.chunk_size)
        return vhf1_chunk_span(i, n, psize, h.chunk_size)

    def flip(data: bytes, at: int) -> bytes:
        b = bytearray(data)
        b[at] ^= 0x01
        return bytes(b)

    m = objects["multi_chunk"]
    c0, c1, c2, c3 = (chunk_bounds("multi_chunk", i) for i in range(4))
    other_file_obj, _ = vhf1_seal(multi_plain, VAULT_KEYS[1], Vhf1Params(1, VAULT_UID, OTHER_FILE_UID,
                                                                         salt_for("multi_chunk")))
    other_vault_hdr, _ = vhf1_seal(b"", VAULT_KEYS[1], Vhf1Params(1, OTHER_VAULT_UID, FILE_UID,
                                                                  salt_for("multi_chunk")))
    swapped_header = other_vault_hdr[:VHF1_HEADER_LEN] + m[VHF1_HEADER_LEN:]
    neg_defs = [
        ("truncated_at_chunk_boundary", "final chunk removed: the new last chunk was sealed with final=0",
         m[:c2[1]], {}, {"error": "chunk_auth_failed", "chunk_index": 2}),
        ("truncated_mid_chunk", "last 10 bytes removed", m[:-10], {}, {"error": "chunk_auth_failed", "chunk_index": 3}),
        ("truncated_to_bad_size", "cut 5 bytes into chunk 3's tag region: no valid layout",
         m[:c3[0] + 5], {}, {"error": "bad_size"}),
        ("header_only", "header with no chunk at all", m[:VHF1_HEADER_LEN], {}, {"error": "bad_size"}),
        ("extended_duplicate_final", "final chunk appended twice: the old final is no longer last",
         m + m[c3[0]:c3[1]], {}, {"error": "chunk_auth_failed", "chunk_index": 3}),
        ("reordered_chunks", "chunks 0 and 1 swapped", m[:c0[0]] + m[c1[0]:c1[1]] + m[c0[0]:c0[1]] + m[c2[0]:],
         {}, {"error": "chunk_auth_failed", "chunk_index": 0}),
        ("tampered_ciphertext", "one bit flipped in chunk 1's ciphertext", flip(m, c1[0] + 7), {},
         {"error": "chunk_auth_failed", "chunk_index": 1}),
        ("tampered_tag", "one bit flipped in chunk 2's tag", flip(m, c2[1] - 1), {},
         {"error": "chunk_auth_failed", "chunk_index": 2}),
        ("tampered_header_key_version", "key_version byte changed (2 is a held key): header tag fails",
         m[:19] + b"\x02" + m[20:], {}, {"error": "header_auth_failed"}),
        ("tampered_header_salt", "one bit flipped in the salt", flip(m, 60), {}, {"error": "header_auth_failed"}),
        ("bad_magic", "first byte changed", flip(m, 0), {}, {"error": "bad_magic"}),
        ("unsupported_version", "format_version 2", m[:8] + b"\x00\x02" + m[10:], {},
         {"error": "unsupported_version"}),
        ("reserved_nonzero", "reserved field set", m[:23] + b"\x01" + m[24:], {}, {"error": "reserved_nonzero"}),
        ("chunk_from_other_file", "chunk 1 replaced by chunk 1 of the same plaintext sealed for another file uid",
         m[:c1[0]] + other_file_obj[c1[0]:c1[1]] + m[c1[1]:], {}, {"error": "chunk_auth_failed", "chunk_index": 1}),
        ("wrong_aad_header_swap",
         "a genuine header of another vault (same key, same salt) on this object's chunks: the chunk AAD "
         "(header hash) no longer matches; the reader expects the other vault",
         swapped_header, {"vault_uid_hex": OTHER_VAULT_UID.hex()}, {"error": "chunk_auth_failed", "chunk_index": 0}),
        ("expected_other_vault", "reader expects another vault uid", m, {"vault_uid_hex": OTHER_VAULT_UID.hex()},
         {"error": "vault_mismatch"}),
        ("expected_other_file", "reader expects another object uid (object stored under the wrong key)", m,
         {"object_uid_hex": OTHER_FILE_UID.hex()}, {"error": "object_mismatch"}),
        ("expected_manifest_kind", "a file object presented where a manifest segment is expected", m,
         {"kind": KIND_SEGMENT}, {"error": "kind_mismatch"}),
        ("key_not_held", "reader holds only key version 2", m, {"keys": [2]}, {"error": "key_unavailable"}),
    ]
    negatives = []
    for name, desc, data, override, expect in neg_defs:
        negatives.append({"name": name, "base": "multi_chunk" if name != "header_only" else "multi_chunk",
                          "description": desc, "expect_override": override, "object_hex": data.hex(),
                          "expect": expect})

    range_negatives = []
    for name, desc, data, a, b, size, expect in [
        ("range_tampered_inside", "chunk 1 tampered, range covers chunk 1", flip(m, c1[0] + 3), 1000, 1100,
         len(m), {"error": "chunk_auth_failed", "chunk_index": 1}),
        ("range_tampered_outside", "chunk 3 tampered, range covers chunks 0-1 only: succeeds (only emitted bytes "
         "are authenticated)", flip(m, c3[0] + 3), 1000, 1100, len(m), {"ok": True}),
        ("range_truncated_object", "final chunk dropped; the authenticated metadata still says the full size",
         m[:c2[1]], 0, 100, len(m), {"error": "size_mismatch"}),
        ("range_without_size", "no authenticated size available", m, 0, 100, None, {"error": "size_unknown"}),
        ("range_past_end", "end beyond the plaintext size", m, 3000, 3173, len(m), {"error": "range_out_of_bounds"}),
    ]:
        entry = {"name": name, "description": desc, "object_hex": data.hex(), "start": a, "end": b,
                 "expected_object_size": size, "expect": expect}
        if expect.get("ok"):
            entry["plaintext_hex"] = multi_plain[a:b].hex()
        range_negatives.append(entry)

    out["vhf1"] = {"positive": [v[0] for v in positives], "range_reads": ranges, "negative": negatives,
                   "range_negative": range_negatives}

    # ---- KEV1 ----
    rcpt_x = label_bytes("vh-vector/recovery-recipient-x25519", 32)
    eph_x = label_bytes("vh-vector/ephemeral-x25519", 32)
    rcpt_p = label_bytes("vh-vector/device-p256", 32)
    eph_p = label_bytes("vh-vector/ephemeral-p256", 32)
    kev = []
    envs = {}
    for name, suite, rsk, esk, kv in [("x25519_v1", KEV1_SUITE_X25519, rcpt_x, eph_x, 1),
                                      ("x25519_v2", KEV1_SUITE_X25519, rcpt_x, label_bytes("vh-vector/eph2", 32), 2),
                                      ("p256_v1", KEV1_SUITE_P256, rcpt_p, eph_p, 1)]:
        rpk = x25519_pub(rsk) if suite == KEV1_SUITE_X25519 else p256_pub(rsk)
        env, inter = kev1_wrap(VAULT_KEYS[kv], suite, kv, VAULT_UID, rpk, esk)
        envs[name] = env
        kev.append({"name": name, "suite": suite, "key_version": kv, "vault_uid_hex": VAULT_UID.hex(),
                    "vault_key_hex": VAULT_KEYS[kv].hex(), "recipient_sk_hex": rsk.hex(), "recipient_pk_hex": rpk.hex(),
                    "recipient_id_hex": sha256(rpk).hex(), "ephemeral_sk_hex": esk.hex(), "intermediate": inter,
                    "envelope_hex": env.hex(),
                    "object_key": ".vaulthalla/key/" + b32_encode(sha256(env)[:16])})
    e = envs["x25519_v1"]
    other_rcpt = label_bytes("vh-vector/someone-else", 32)
    zero_epk = e[:70] + b"\x00" * 32 + e[102:]
    kev_neg = [
        ("wrong_recipient", "unwrapped with another X25519 key", e, other_rcpt, KEV1_SUITE_X25519, VAULT_UID,
         {"error": "recipient_mismatch"}),
        ("tampered_key_version", "key_version changed in the authenticated prefix", e[:19] + b"\x02" + e[20:],
         rcpt_x, KEV1_SUITE_X25519, VAULT_UID, {"error": "wrap_auth_failed"}),
        ("tampered_wrapped_key", "one bit flipped in the wrapped key", e[:-20] + bytes([e[-20] ^ 1]) + e[-19:], rcpt_x,
         KEV1_SUITE_X25519, VAULT_UID, {"error": "wrap_auth_failed"}),
        ("other_vault", "envelope presented for another vault", e, rcpt_x, KEV1_SUITE_X25519, OTHER_VAULT_UID,
         {"error": "vault_mismatch"}),
        ("low_order_ephemeral", "all-zero ephemeral X25519 key", zero_epk, rcpt_x, KEV1_SUITE_X25519, VAULT_UID,
         {"error": "bad_ephemeral"}),
        ("suite_confusion", "X25519 envelope read as a P-256 one", e, rcpt_p, KEV1_SUITE_P256, VAULT_UID,
         {"error": "unsupported_suite"}),
        ("reserved_purpose_threshold_share", "purpose 2 (reserved, e.g. a future threshold share): skipped by v1 readers",
         e[:12] + b"\x02" + e[13:], rcpt_x, KEV1_SUITE_X25519, VAULT_UID, {"error": "bad_purpose"}),
        ("reserved_recipient_class", "recipient class 1 (reserved for separately authorized recipients): skipped by "
         "v1 readers", e[:13] + b"\x01" + e[14:], rcpt_x, KEV1_SUITE_X25519, VAULT_UID,
         {"error": "unsupported_recipient_class"}),
        ("reserved_nonzero", "reserved bytes 14-15 set", e[:15] + b"\x01" + e[16:], rcpt_x, KEV1_SUITE_X25519,
         VAULT_UID, {"error": "reserved_nonzero"}),
    ]
    out["kev1"] = {
        "positive": kev,
        "negative": [{"name": n, "description": d, "envelope_hex": env.hex(), "recipient_sk_hex": sk.hex(),
                      "suite_expected": s, "vault_uid_hex": vu.hex(), "expect": ex}
                     for n, d, env, sk, s, vu, ex in kev_neg],
    }

    # ---- recovery seed -> recipient and signing keys (03 §5.3, 04 §4.1) ----
    seeds = []
    for label in ["vh-vector/recovery-seed-1", "vh-vector/recovery-seed-2"]:
        seed = label_bytes(label, 16)
        d = recovery_keys(seed)
        seeds.append({"seed_hex": seed.hex(), "seed_text": recovery_seed_text(seed), **d})
    out["recovery_seed"] = {
        "derivation": "PRK = HKDF-Extract(salt='vh.recovery.v1', IKM=seed); x25519_sk = HKDF-Expand(PRK, 'x25519', 32); "
                      "ed25519_seed = HKDF-Expand(PRK, 'ed25519', 32); text = b32(seed) ‖ check symbol "
                      "alphabet[SHA-256(seed)[0] >> 3]",
        "positive": seeds,
        "negative": [{"seed_text": seeds[0]["seed_text"][:-1] + B32_ALPHABET[
            (B32_ALPHABET.index(seeds[0]["seed_text"][-1]) + 1) % 32], "error": "bad_check"}],
    }

    # ---- manifest objects and chain ----
    seg_uid = label_bytes("vh-vector/segment-1", 16)
    seg_plain = {"type": "vh.manifest.segment", "v": 1, "vault_uid": b32_encode(VAULT_UID), "range": ["00", "ff"],
                 "entries": [
                     {"uid": b32_encode(bytes.fromhex("11" * 16)), "kind": "dir", "parent": None, "name": "",
                      "mode": 0o755, "mtime": "2026-11-05T12:00:00Z"},
                     {"uid": b32_encode(bytes.fromhex("22" * 16)), "kind": "dir",
                      "parent": b32_encode(bytes.fromhex("11" * 16)), "name": "Reports", "mode": 0o755,
                      "mtime": "2026-11-05T12:00:00Z"},
                     {"uid": b32_encode(FILE_UID), "kind": "file", "parent": b32_encode(bytes.fromhex("22" * 16)),
                      "name": "Q3 board pack.pdf", "mode": 0o644, "mtime": "2026-11-05T12:01:00Z",
                      "size": 3172, "format": 1, "key_version": 1, "generation": salt_for("multi_chunk").hex(),
                      "object": {"etag": "\"" + hashlib.md5(objects["multi_chunk"]).hexdigest() + "\"",
                                 "size": len(objects["multi_chunk"]), "version_id": None},
                      "versions": [], "names": []},
                 ]}
    seg_obj, seg_inter = vhf1_seal(canonical_json(seg_plain), VAULT_KEYS[2],
                                   Vhf1Params(2, VAULT_UID, seg_uid, salt_for("segment-1"), KIND_SEGMENT,
                                              VHF1_WRITER_CHUNK_LOG2))
    seg_ref = {"sid": b32_encode(seg_uid), "range": ["00", "ff"], "count": 3, "object_sha256": sha256(seg_obj).hex(),
               "size": len(seg_obj)}

    def root_doc(epoch: int, prev: str | None) -> dict:
        return {"type": "vh.manifest.root", "v": 1, "vault_uid": b32_encode(VAULT_UID), "layout": "OpaqueV1",
                "epoch": epoch, "prev": prev, "published_at": f"2026-11-05T12:0{epoch}:00Z",
                "producer": {"node_id": "8f14e45f-ceea-467a-9575-0c6d2b6a1b8a", "vault_id": 42,
                             "software": "vaulthalla 1.20.0"},
                "keys": [{"version": 1, "key_check": "72e4c8b7f8ab43b8ed8869a57cef1703", "attestation": None,
                          "created_at": "2026-10-01T00:00:00Z", "retired_at": "2026-11-01T00:00:00Z"},
                         {"version": 2, "key_check": None, "attestation": None,
                          "created_at": "2026-11-01T00:00:00Z", "retired_at": None}],
                "segments": [seg_ref], "snapshots": [], "stats": {"files": 1, "dirs": 2, "bytes": 3172}}

    root_uid = VAULT_UID  # the root's object uid is the vault uid; kind 3 keeps it apart
    r1_plain = root_doc(1, None)
    r1_obj, r1_inter = vhf1_seal(canonical_json(r1_plain), VAULT_KEYS[2],
                                 Vhf1Params(2, VAULT_UID, root_uid, salt_for("root-1"), KIND_ROOT, 16))
    r2_plain = root_doc(2, sha256(r1_obj).hex())
    r2_obj, r2_inter = vhf1_seal(canonical_json(r2_plain), VAULT_KEYS[2],
                                 Vhf1Params(2, VAULT_UID, root_uid, salt_for("root-2"), KIND_ROOT, 16))
    r3_plain = root_doc(3, sha256(r2_obj).hex())
    r3_obj, _ = vhf1_seal(canonical_json(r3_plain), VAULT_KEYS[2],
                          Vhf1Params(2, VAULT_UID, root_uid, salt_for("root-3"), KIND_ROOT, 16))
    r2_fork_plain = dict(r2_plain, published_at="2026-11-05T12:09:00Z")
    r2_fork_obj, _ = vhf1_seal(canonical_json(r2_fork_plain), VAULT_KEYS[2],
                               Vhf1Params(2, VAULT_UID, root_uid, salt_for("root-2-fork"), KIND_ROOT, 16))
    out["manifest"] = {
        "objects": [
            {"name": "segment_1", "object_key": ".vaulthalla/seg/" + seg_ref["sid"], "kind": KIND_SEGMENT,
             "key_version": 2, "object_uid_hex": seg_uid.hex(), "plaintext_utf8": canonical_json(seg_plain).decode(),
             "object_hex": seg_obj.hex(), "header_hash_hex": seg_inter["header_hash_hex"]},
            {"name": "root_epoch_1", "object_key": ".vaulthalla/root", "kind": KIND_ROOT, "key_version": 2,
             "object_uid_hex": root_uid.hex(), "plaintext_utf8": canonical_json(r1_plain).decode(),
             "object_hex": r1_obj.hex(), "object_sha256": sha256(r1_obj).hex()},
            {"name": "root_epoch_2", "object_key": ".vaulthalla/root", "kind": KIND_ROOT, "key_version": 2,
             "object_uid_hex": root_uid.hex(), "plaintext_utf8": canonical_json(r2_plain).decode(),
             "object_hex": r2_obj.hex(), "object_sha256": sha256(r2_obj).hex()},
            {"name": "root_epoch_3", "object_key": ".vaulthalla/root", "kind": KIND_ROOT, "key_version": 2,
             "object_uid_hex": root_uid.hex(), "plaintext_utf8": canonical_json(r3_plain).decode(),
             "object_hex": r3_obj.hex(), "object_sha256": sha256(r3_obj).hex()},
        ],
        "chain": [
            {"name": "fresh_restore_accepts_epoch_2", "root": "root_epoch_2", "known": None,
             "expect": {"epoch": 2, "root_sha256": sha256(r2_obj).hex()}},
            {"name": "advance_1_to_2", "root": "root_epoch_2",
             "known": {"epoch": 1, "root_sha256": sha256(r1_obj).hex()},
             "expect": {"epoch": 2, "root_sha256": sha256(r2_obj).hex()}},
            {"name": "rollback_2_to_1", "root": "root_epoch_1",
             "known": {"epoch": 2, "root_sha256": sha256(r2_obj).hex()}, "expect": {"error": "rollback"}},
            {"name": "fork_same_epoch", "root_hex": r2_fork_obj.hex(), "root_plaintext_utf8":
                canonical_json(r2_fork_plain).decode(),
             "known": {"epoch": 2, "root_sha256": sha256(r2_obj).hex()}, "expect": {"error": "fork"}},
            {"name": "segment_replaced", "root": "root_epoch_2", "known": None,
             "segments_override": {seg_ref["sid"]: flip(seg_obj, 200).hex()}, "expect": {"error": "segment_mismatch"}},
            {"name": "segment_missing", "root": "root_epoch_2", "known": None, "segments_override": {},
             "expect": {"error": "segment_missing"}},
            {"name": "gap_1_to_3", "root": "root_epoch_3",
             "known": {"epoch": 1, "root_sha256": sha256(r1_obj).hex()},
             "expect": {"epoch": 3, "root_sha256": sha256(r3_obj).hex(), "warning": "gap"}},
            {"name": "rollback_3_to_2", "root": "root_epoch_2",
             "known": {"epoch": 3, "root_sha256": sha256(r3_obj).hex()}, "expect": {"error": "rollback"}},
        ],
        "negative": [
            {"name": "segment_as_root", "description": "a segment object read where the root is expected",
             "object_hex": seg_obj.hex(), "expect_kind": KIND_ROOT, "expect_object_uid_hex": root_uid.hex(),
             "expect": {"error": "kind_mismatch"}},
        ],
    }
    return out


# --------------------------------------------------------------------------------------------------------------------
# --check: verify every vector with the reader paths only
# --------------------------------------------------------------------------------------------------------------------

def expect_from(params: dict, override: dict) -> Expect:
    keys = {int(v): bytes.fromhex(k) for v, k in VECTOR_KEYS.items()}
    if "keys" in override:
        keys = {v: keys[v] for v in override["keys"]}
    return Expect(kind=override.get("kind", params.get("kind", KIND_FILE)),
                  vault_uid=bytes.fromhex(override.get("vault_uid_hex", params["vault_uid_hex"])),
                  object_uid=bytes.fromhex(override.get("object_uid_hex", params["object_uid_hex"])), keys=keys)


VECTOR_KEYS: dict[str, str] = {}


def verify(doc: dict) -> list[str]:
    failures: list[str] = []
    VECTOR_KEYS.clear()
    VECTOR_KEYS.update(doc["conventions"]["keys"])

    def check(cond: bool, what: str) -> None:
        if not cond:
            failures.append(what)

    for e in doc["object_ids"]["encode"]:
        check(b32_decode_uid(e["b32"]).hex() == e["uid_hex"], f"object_ids decode {e['b32']}")
    for e in doc["object_ids"]["decode_negative"]:
        try:
            b32_decode_uid(e["text"])
            failures.append(f"object_ids accepted {e['text']}")
        except B32Error as err:
            check(str(err) == e["error"], f"object_ids {e['text']}: {err} != {e['error']}")

    positives = {}
    for v in doc["vhf1"]["positive"]:
        if "object_hex" in v:
            obj = bytes.fromhex(v["object_hex"])
        else:  # large vector: rebuild from the published generator and compare digests
            n, seed = map(int, v["plaintext_generator"].removeprefix("pattern(").removesuffix(")").split(","))
            p = v["params"]
            obj, _ = vhf1_seal(pattern(n, seed), VAULT_KEYS[p["key_version"]],
                               Vhf1Params(p["key_version"], bytes.fromhex(p["vault_uid_hex"]),
                                          bytes.fromhex(p["object_uid_hex"]), bytes.fromhex(p["salt_hex"]),
                                          p["kind"], p["chunk_log2"]))
        positives[v["name"]] = obj
        check(hashlib.sha256(obj).hexdigest() == v["object_sha256"] and len(obj) == v["object_size"],
              f"vhf1 {v['name']}: object digest")
        try:
            plain = vhf1_open(obj, expect_from(v["params"], {}), v["object_size"])
            check(hashlib.sha256(plain).hexdigest() == v["plaintext_sha256"], f"vhf1 {v['name']}: plaintext")
            if "plaintext_hex" in v:
                check(plain.hex() == v["plaintext_hex"], f"vhf1 {v['name']}: plaintext hex")
        except VhfError as err:
            failures.append(f"vhf1 {v['name']}: rejected ({err})")
    params = {v["name"]: v["params"] for v in doc["vhf1"]["positive"]}

    for r in doc["vhf1"]["range_reads"]:
        try:
            plain, plan = vhf1_range(positives[r["object"]], expect_from(params[r["object"]], {}), r["start"],
                                     r["end"], r["expected_object_size"])
            check(plain.hex() == r["plaintext_hex"], f"range {r['description']}: plaintext")
            check(plan["chunk_first"] == r["chunk_first"] and plan["chunk_last"] == r["chunk_last"]
                  and plan["object_range"] == r["object_range"], f"range {r['description']}: plan")
        except VhfError as err:
            failures.append(f"range {r['description']}: rejected ({err})")

    for n in doc["vhf1"]["negative"]:
        try:
            vhf1_open(bytes.fromhex(n["object_hex"]), expect_from(params[n["base"]], n["expect_override"]))
            failures.append(f"vhf1 negative {n['name']}: accepted")
        except VhfError as err:
            check(err.as_json() == n["expect"], f"vhf1 negative {n['name']}: {err.as_json()} != {n['expect']}")

    for n in doc["vhf1"]["range_negative"]:
        try:
            plain, _ = vhf1_range(bytes.fromhex(n["object_hex"]), expect_from(params["multi_chunk"], {}), n["start"],
                                  n["end"], n["expected_object_size"])
            check(n["expect"].get("ok") is True and plain.hex() == n.get("plaintext_hex"),
                  f"range negative {n['name']}: accepted")
        except VhfError as err:
            check(err.as_json() == n["expect"], f"range negative {n['name']}: {err.as_json()} != {n['expect']}")

    for k in doc["kev1"]["positive"]:
        env = bytes.fromhex(k["envelope_hex"])
        try:
            kv, key = kev1_unwrap(env, bytes.fromhex(k["recipient_sk_hex"]), k["suite"], bytes.fromhex(k["vault_uid_hex"]))
            check(kv == k["key_version"] and key.hex() == k["vault_key_hex"], f"kev1 {k['name']}: key")
        except KevError as err:
            failures.append(f"kev1 {k['name']}: rejected ({err})")
        check(k["object_key"] == ".vaulthalla/key/" + b32_encode(hashlib.sha256(env).digest()[:16]),
              f"kev1 {k['name']}: object key")
    for n in doc["kev1"]["negative"]:
        try:
            kev1_unwrap(bytes.fromhex(n["envelope_hex"]), bytes.fromhex(n["recipient_sk_hex"]), n["suite_expected"],
                        bytes.fromhex(n["vault_uid_hex"]))
            failures.append(f"kev1 negative {n['name']}: accepted")
        except KevError as err:
            check(err.as_json() == n["expect"], f"kev1 negative {n['name']}: {err.as_json()} != {n['expect']}")

    for s in doc["recovery_seed"]["positive"]:
        try:
            seed = recovery_seed_parse(s["seed_text"])
            check(seed.hex() == s["seed_hex"], "recovery seed: parse")
            # independent path: derive with the stdlib HMAC directly
            prk = hmac.new(b"vh.recovery.v1", seed, hashlib.sha256).digest()
            x_sk = hmac.new(prk, b"x25519\x01", hashlib.sha256).digest()
            check(x_sk.hex() == s["x25519_sk_hex"], "recovery seed: x25519 sk")
            check(X25519PrivateKey.from_private_bytes(x_sk).public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex() == s["x25519_pk_hex"],
                "recovery seed: x25519 pk")
            check(hmac.new(prk, b"ed25519\x01", hashlib.sha256).digest().hex() == s["ed25519_seed_hex"],
                  "recovery seed: ed25519 seed")
        except B32Error as err:
            failures.append(f"recovery seed rejected ({err})")
    for s in doc["recovery_seed"]["negative"]:
        try:
            recovery_seed_parse(s["seed_text"])
            failures.append("recovery seed negative accepted")
        except B32Error as err:
            check(str(err) == s["error"], f"recovery seed negative: {err}")

    mobjs = {o["name"]: o for o in doc["manifest"]["objects"]}
    decoded = {}
    for o in doc["manifest"]["objects"]:
        ex = Expect(kind=o["kind"], vault_uid=VAULT_UID, object_uid=bytes.fromhex(o["object_uid_hex"]),
                    keys={int(v): bytes.fromhex(k) for v, k in VECTOR_KEYS.items()})
        try:
            plain = vhf1_open(bytes.fromhex(o["object_hex"]), ex)
            check(plain.decode() == o["plaintext_utf8"], f"manifest {o['name']}: plaintext")
            decoded[o["name"]] = json.loads(plain)
        except VhfError as err:
            failures.append(f"manifest {o['name']}: rejected ({err})")
    seg = mobjs["segment_1"]
    seg_sid = seg["object_key"].rsplit("/", 1)[1]
    for c in doc["manifest"]["chain"]:
        if "root_hex" in c:
            root_obj = bytes.fromhex(c["root_hex"])
            ex = Expect(KIND_ROOT, VAULT_UID, VAULT_UID, {int(v): bytes.fromhex(k) for v, k in VECTOR_KEYS.items()})
            root = json.loads(vhf1_open(root_obj, ex))
        else:
            root_obj, root = bytes.fromhex(mobjs[c["root"]]["object_hex"]), decoded[c["root"]]
        segs = {seg_sid: bytes.fromhex(seg["object_hex"])}
        if "segments_override" in c:
            segs = {sid: bytes.fromhex(h) for sid, h in c["segments_override"].items()}
        try:
            got = manifest_accept_root(root, root_obj, c["known"], segs)
            check(got == c["expect"], f"manifest chain {c['name']}: {got} != {c['expect']}")
        except ManifestError as err:
            check(err.as_json() == c["expect"], f"manifest chain {c['name']}: {err.as_json()} != {c['expect']}")
    for n in doc["manifest"]["negative"]:
        ex = Expect(n["expect_kind"], VAULT_UID, bytes.fromhex(n["expect_object_uid_hex"]),
                    {int(v): bytes.fromhex(k) for v, k in VECTOR_KEYS.items()})
        try:
            vhf1_open(bytes.fromhex(n["object_hex"]), ex)
            failures.append(f"manifest negative {n['name']}: accepted")
        except VhfError as err:
            check(err.as_json() == n["expect"], f"manifest negative {n['name']}: {err.as_json()} != {n['expect']}")
    return failures


def render(doc: dict) -> str:
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def count(doc: dict) -> int:
    v, k, m = doc["vhf1"], doc["kev1"], doc["manifest"]
    return (len(doc["object_ids"]["encode"]) + len(doc["object_ids"]["decode_negative"]) + len(v["positive"])
            + len(v["range_reads"]) + len(v["negative"]) + len(v["range_negative"]) + len(k["positive"])
            + len(k["negative"]) + len(m["objects"]) + len(m["chain"]) + len(m["negative"])
            + len(doc["recovery_seed"]["positive"]) + len(doc["recovery_seed"]["negative"]))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="verify vectors.json instead of writing it")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()
    doc = build()
    text = render(doc)
    if not args.check:
        args.out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out} ({count(doc)} vectors)")
        return 0
    if not args.out.exists():
        print(f"FAIL: {args.out} is missing; run without --check to generate it")
        return 1
    committed = args.out.read_text(encoding="utf-8")
    if committed != text:
        print(f"FAIL: {args.out} differs from what this script generates (regenerate it and review the diff)")
        return 1
    failures = verify(json.loads(committed))
    if failures:
        print("FAIL:\n  " + "\n  ".join(failures))
        return 1
    print(f"OK: {count(doc)} vectors match the generator and the reference reader")
    return 0


if __name__ == "__main__":
    sys.exit(main())
