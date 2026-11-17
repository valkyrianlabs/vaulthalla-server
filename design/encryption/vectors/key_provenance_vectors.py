#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Valkyrian Labs LLC
"""Golden vectors for key provenance: the key check, an origin's attestation, and a Mac's origin vault id (spec 03
§6.5; vault/KeyCheck.hpp and vault/KeyAttestation.hpp, implemented by vl-keykit attestation.hpp).

  python3 key_provenance_vectors.py            # write key_provenance.json
  python3 key_provenance_vectors.py --check    # regenerate in memory, compare byte for byte, run the reference

Its own file beside the verbatim copy vectors.json (which it does not change), copied verbatim to vl-keykit's vectors/.
The reference, independent of the C++ (Python's hashlib BLAKE2b and the cryptography package's Ed25519):

  key_check           = hex(BLAKE2b(key = K, digest_size = 16, "vh-key-check-v1" ‖ ASCII-decimal(vault_id) ‖ UInt32BE(v)))
  attestation message = "vh-key-attest-v1" ‖ node_id ‖ UInt64BE(vault_id) ‖ UInt32BE(v) ‖ key_check (16 raw bytes)
  attestation         = Ed25519(seed, message)
  mac_origin_vault_id = 1 + (UInt32BE(vault_uid[0..3]) mod (2^31 - 1))

The server's documented vectors (key 00..1f: vault 42 version 3 -> 72e4c8b7…, vault 1 version 1 -> c7a67cda…; seed
00..1f over node 00000000-0000-4000-8000-000000000001) are reproduced here.
"""

import argparse
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

HERE = Path(__file__).resolve().parent
DEFAULT_OUT = HERE / "key_provenance.json"


def _reference():
    spec = importlib.util.spec_from_file_location("vh_crypto_vectors", HERE / "vh_crypto_vectors.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module   # dataclasses look their module up there
    spec.loader.exec_module(module)
    return module


R = _reference()

KEY_CHECK_DOMAIN = b"vh-key-check-v1"
KEY_ATTEST_DOMAIN = b"vh-key-attest-v1"
MAX_VAULT_ID = 2**31 - 1


def key_check(key: bytes, vault_id: int, version: int) -> str:
    if len(key) != 32:
        raise ValueError("bad_key")
    if not 1 <= vault_id <= 2**64 - 1:
        raise ValueError("bad_vault_id")
    msg = KEY_CHECK_DOMAIN + str(vault_id).encode() + struct.pack(">I", version)
    return hashlib.blake2b(msg, key=key, digest_size=16).hexdigest()


def attestation_message(node_id: str, vault_id: int, version: int, check_hex: str) -> bytes:
    if not node_id:
        raise ValueError("bad_node_id")
    if vault_id == 0:
        raise ValueError("bad_vault_id")
    if len(check_hex) != 32 or check_hex != check_hex.lower():
        raise ValueError("bad_key_check")
    return KEY_ATTEST_DOMAIN + node_id.encode() + struct.pack(">QI", vault_id, version) + bytes.fromhex(check_hex)


def mac_origin_vault_id(uid: bytes) -> int:
    return 1 + struct.unpack(">I", uid[:4])[0] % MAX_VAULT_ID


def sign(seed: bytes, msg: bytes) -> tuple[bytes, bytes]:
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), sk.sign(msg)


def verifies(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except InvalidSignature:
        return False


def build() -> dict:
    seq = bytes(range(32))
    seed = bytes(range(32))
    server_node = "00000000-0000-4000-8000-000000000001"
    mac_node = R.b32_encode(R.label_bytes("vh-vector/mac-installation", 16))
    mac_vault = mac_origin_vault_id(R.VAULT_UID)
    checks = [{"key_hex": seq.hex(), "vault_id": vid, "version": ver, "key_check": key_check(seq, vid, ver)}
              for vid, ver in [(42, 3), (1, 1), (MAX_VAULT_ID, 7), (mac_vault, 1)]]
    attestations = []
    for name, node, vid, ver in [("server", server_node, 42, 3), ("mac", mac_node, mac_vault, 1)]:
        check = key_check(seq, vid, ver)
        msg = attestation_message(node, vid, ver, check)
        pk, sig = sign(seed, msg)
        attestations.append({"name": name, "seed_hex": seed.hex(), "node_id": node, "vault_id": vid, "version": ver,
                             "key_check": check, "message_hex": msg.hex(), "public_key_hex": pk.hex(),
                             "signature_hex": sig.hex()})
    m = attestations[1]
    flipped = bytes([bytes.fromhex(m["signature_hex"])[0] ^ 1]).hex() + m["signature_hex"][2:]
    return {
        "key_check": "lower-case hex of BLAKE2b-128 keyed by the 32 key bytes over 'vh-key-check-v1' ‖ "
                     "ASCII-decimal(vault_id) ‖ UInt32BE(version)",
        "attestation": "Ed25519 (RFC 8032, the 32-byte seed) over 'vh-key-attest-v1' ‖ node_id (UTF-8) ‖ "
                       "UInt64BE(vault_id) ‖ UInt32BE(version) ‖ key_check (16 raw bytes)",
        "mac_origin_vault_id": "1 + (UInt32BE(vault_uid[0..3]) mod (2^31 - 1))",
        "key_checks": checks,
        "attestations": attestations,
        "mac_origin_vault_ids": [{"vault_uid": R.b32_encode(u), "vault_id": mac_origin_vault_id(u)}
                                 for u in [R.VAULT_UID, R.OTHER_VAULT_UID, bytes.fromhex("7fffffff" + "00" * 12),
                                           bytes.fromhex("ffffffff" + "00" * 12), bytes(16)]],
        "negative": [
            {"what": "key_check", "key_hex": seq[:31].hex(), "vault_id": 1, "version": 1, "error": "bad_key"},
            {"what": "key_check", "key_hex": seq.hex(), "vault_id": 0, "version": 1, "error": "bad_vault_id"},
            {"what": "message", "node_id": "", "vault_id": 42, "version": 3, "key_check": checks[0]["key_check"],
             "error": "bad_node_id"},
            {"what": "message", "node_id": server_node, "vault_id": 42, "version": 3,
             "key_check": checks[0]["key_check"].upper(), "error": "bad_key_check"},
            # The Mac's attestation with one bit of the signature flipped, then under another node and version.
            {"what": "verify", "public_key_hex": m["public_key_hex"], "node_id": m["node_id"], "vault_id": m["vault_id"],
             "version": m["version"], "key_check": m["key_check"], "signature_hex": flipped, "error": "bad_signature"},
            {"what": "verify", "public_key_hex": m["public_key_hex"], "node_id": server_node, "vault_id": m["vault_id"],
             "version": 1, "key_check": m["key_check"], "signature_hex": m["signature_hex"], "error": "bad_signature"},
        ],
    }


def verify(doc: dict) -> list[str]:
    failures: list[str] = []

    def check(cond: bool, what: str) -> None:
        if not cond:
            failures.append(what)

    for c in doc["key_checks"]:
        check(key_check(bytes.fromhex(c["key_hex"]), c["vault_id"], c["version"]) == c["key_check"],
              f"key check {c['vault_id']}/{c['version']}")
    for a in doc["attestations"]:
        msg = attestation_message(a["node_id"], a["vault_id"], a["version"], a["key_check"])
        check(msg.hex() == a["message_hex"], f"attestation message {a['name']}")
        check(verifies(bytes.fromhex(a["public_key_hex"]), msg, bytes.fromhex(a["signature_hex"])),
              f"attestation {a['name']} verifies")
    for u in doc["mac_origin_vault_ids"]:
        check(mac_origin_vault_id(R.b32_decode_uid(u["vault_uid"])) == u["vault_id"] and
              1 <= u["vault_id"] <= MAX_VAULT_ID, f"mac origin vault id {u['vault_uid']}")
    for n in doc["negative"]:
        if n["what"] == "verify":
            msg = attestation_message(n["node_id"], n["vault_id"], n["version"], n["key_check"])
            check(not verifies(bytes.fromhex(n["public_key_hex"]), msg, bytes.fromhex(n["signature_hex"])),
                  "a negative attestation verifies")
            continue
        try:
            if n["what"] == "key_check":
                key_check(bytes.fromhex(n["key_hex"]), n["vault_id"], n["version"])
            else:
                attestation_message(n["node_id"], n["vault_id"], n["version"], n["key_check"])
            check(False, f"negative {n['error']} accepted")
        except ValueError as e:
            check(str(e) == n["error"], f"negative {n['error']}: got {e}")
    check(doc["key_checks"][0]["key_check"] == "72e4c8b7f8ab43b8ed8869a57cef1703", "the server's documented key check")
    check(doc["attestations"][0]["public_key_hex"].startswith("03a107bff3ce10be"), "the server's documented public key")
    return failures


def render(doc: dict) -> str:
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def count(doc: dict) -> int:
    return sum(len(doc[k]) for k in ("key_checks", "attestations", "mac_origin_vault_ids", "negative"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="verify key_provenance.json instead of writing it")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()
    doc = build()
    text = render(doc)
    if not args.check:
        args.out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out} ({count(doc)} vectors)")
        return 0
    if not args.out.exists() or args.out.read_text(encoding="utf-8") != text:
        print(f"FAIL: {args.out} differs from what this script generates (regenerate it and review the diff)")
        return 1
    failures = verify(json.loads(text))
    if failures:
        print("FAIL:\n  " + "\n  ".join(failures))
        return 1
    print(f"OK: {count(doc)} key provenance vectors match the generator and the reference")
    return 0


if __name__ == "__main__":
    sys.exit(main())
