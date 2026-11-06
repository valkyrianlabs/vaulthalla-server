#!/usr/bin/env python3
"""The device approval payload vectors (#361; docs/reference/device-approvals.md, MFA design note 6.2).

Writes or checks core/test-assets/device/approval-vectors.json, the vector Vaulthalla Desktop (valkyrianlabs/
vaulthalla-desktop #47/#48) and the daemon (DeviceApprovalVectors in core/tests/unit/test_device_approvals.cpp) both
assert: the canonical bytes an approval key signs,

    "vh-device-approval-v1" 0x00 node_id 0x00 server_spki_sha256[32] approving_device_spki_sha256[32]
    challenge[32] family 0x00 target 0x00 UInt64BE(expires_at)

an ECDSA P-256/SHA-256 signature over them that verifies under the vector's approval key, and negatives that change
one field each (the signature must not verify over their payload).

    tools/dev/device_approval_vectors.py --check   # recompute every payload and verify every signature (CI-safe)
    tools/dev/device_approval_vectors.py --write   # regenerate the file (new signatures unless RFC 6979 is available)

Every key and value here is a published test value: never use it for anything else.
"""

import argparse
import base64
import hashlib
import json
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

REPO = Path(__file__).resolve().parents[2]
VECTORS = REPO / "core" / "test-assets" / "device" / "approval-vectors.json"
DOMAIN = b"vh-device-approval-v1"
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def derived(label: str) -> bytes:
    return hashlib.sha256(b"vh-device-approval-vector/" + label.encode()).digest()


def key_from_label(label: str) -> ec.EllipticCurvePrivateKey:
    scalar = int.from_bytes(derived(label), "big") % (P256_ORDER - 1) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


def spki_der(key) -> bytes:
    public = key.public_key() if hasattr(key, "public_key") else key
    return public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def payload(fields: dict) -> bytes | None:
    node, family, target = fields["node_id"].encode(), fields["family"].encode(), fields["target"].encode()
    if not node or not family or b"\0" in node + family + target:
        return None
    out = DOMAIN + b"\0" + node + b"\0"
    for name in ("server_spki_sha256", "approving_device_spki_sha256", "challenge"):
        value = bytes.fromhex(fields[name])
        assert len(value) == 32, name
        out += value
    return out + family + b"\0" + target + b"\0" + struct.pack(">Q", fields["expires_at"])


def sign(key, message: bytes) -> bytes:
    try:  # RFC 6979 (cryptography >= 44): the same file on every run
        return key.sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    except TypeError:
        return key.sign(message, ec.ECDSA(hashes.SHA256()))


def verifies(spki: bytes, message: bytes, signature: bytes) -> bool:
    public = serialization.load_der_public_key(spki)
    try:
        public.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def build() -> dict:
    approval = key_from_label("approval-key")
    other = key_from_label("another-approval-key")
    server = key_from_label("server-key")
    device = key_from_label("device-key")
    new_device = key_from_label("new-device-key")
    approval_spki = spki_der(approval)
    new_spki_hex = hashlib.sha256(spki_der(new_device)).hexdigest()
    fields = {
        "node_id": "6f1c2d3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f",
        "server_spki_sha256": hashlib.sha256(spki_der(server)).hexdigest(),
        "approving_device_spki_sha256": hashlib.sha256(spki_der(device)).hexdigest(),
        "challenge": derived("challenge").hex(),
        "family": "device.trust",
        # What device.pairing.approve's step_up_required names: request id, the new device's key, and the first 16 hex
        # digits of SHA-256 of the chosen code ("680179" here). Opaque to the device: it signs the refusal's target.
        "target": "device.pairing.approve:0123456789abcdef:" + new_spki_hex + ":" +
                  hashlib.sha256(b"680179").hexdigest()[:16],
        "expires_at": 1798761600,
    }
    message = payload(fields)
    signature = sign(approval, message)

    def changed(name: str, value) -> dict:
        f = dict(fields)
        f[name] = value
        p = payload(f)
        assert p is not None and p != message
        return {"name": "wrong_" + name, "fields": f, "payload_hex": p.hex()}

    flip = lambda h: ("0" if h[0] != "0" else "1") + h[1:]
    negatives = [
        changed("node_id", "6f1c2d3e-4b5a-4c6d-8e7f-9a0b1c2d3e40"),
        changed("server_spki_sha256", flip(fields["server_spki_sha256"])),
        changed("approving_device_spki_sha256", flip(fields["approving_device_spki_sha256"])),
        changed("challenge", flip(fields["challenge"])),
        changed("family", "keys"),
        changed("target", fields["target"][:-1] + ("0" if fields["target"][-1] != "0" else "1")),
        changed("expires_at", fields["expires_at"] + 1),
    ]
    return {
        "description": "Vaulthalla device approval payload vectors (#361). The canonical bytes an approval key signs "
                       "and an ECDSA P-256/SHA-256 signature over them. Shared with vaulthalla-desktop; regenerate "
                       "with tools/dev/device_approval_vectors.py. Test keys only.",
        "format": "\"vh-device-approval-v1\" 0x00 node_id 0x00 server_spki_sha256[32] "
                  "approving_device_spki_sha256[32] challenge[32] family 0x00 target 0x00 UInt64BE(expires_at)",
        "conventions": {
            "hex": "lower case; 32-byte values are SHA-256 digests or the server challenge",
            "base64": "standard alphabet with padding",
            "signature": "DER Ecdsa-Sig-Value (ECDSA P-256 over SHA-256 of the payload)",
            "spki": "SubjectPublicKeyInfo DER, 91 bytes: id-ecPublicKey, prime256v1, uncompressed point",
            "approving_device_spki_sha256": "SHA-256 of the approving device's own mTLS key SPKI (its device id)",
            "server_spki_sha256": "SHA-256 of the SPKI of the certificate the node's device listener presents",
            "node_id": "the node id device.pair.status and device.endpoints report",
        },
        "approval_key": {
            "private_scalar_hex": approval.private_numbers().private_value.to_bytes(32, "big").hex(),
            "spki_der_b64": base64.b64encode(approval_spki).decode(),
            "spki_sha256": hashlib.sha256(approval_spki).hexdigest(),
        },
        "positive": {
            "fields": fields,
            "payload_hex": message.hex(),
            "payload_b64": base64.b64encode(message).decode(),
            "signature_der_b64": base64.b64encode(signature).decode(),
        },
        "negative": negatives,
        "wrong_key": {
            "description": "a signature over the positive payload by another key: never verifies under approval_key",
            "spki_der_b64": base64.b64encode(spki_der(other)).decode(),
            "signature_der_b64": base64.b64encode(sign(other, message)).decode(),
        },
        "no_payload": [
            {"name": "nul_in_target", "fields": {**fields, "target": "a\u0000b"}},
            {"name": "nul_in_node_id", "fields": {**fields, "node_id": "node\u0000id"}},
            {"name": "empty_family", "fields": {**fields, "family": ""}},
            {"name": "empty_node_id", "fields": {**fields, "node_id": ""}},
        ],
    }


def check(doc: dict) -> list[str]:
    problems = []
    spki = base64.b64decode(doc["approval_key"]["spki_der_b64"])
    if len(spki) != 91:
        problems.append("approval key SPKI is not 91 bytes")
    if hashlib.sha256(spki).hexdigest() != doc["approval_key"]["spki_sha256"]:
        problems.append("approval key spki_sha256")
    scalar = int(doc["approval_key"]["private_scalar_hex"], 16)
    if spki_der(ec.derive_private_key(scalar, ec.SECP256R1())) != spki:
        problems.append("private scalar does not match the SPKI")
    pos = doc["positive"]
    message = payload(pos["fields"])
    if message is None or message.hex() != pos["payload_hex"] or base64.b64decode(pos["payload_b64"]) != message:
        problems.append("positive payload")
    signature = base64.b64decode(pos["signature_der_b64"])
    if not verifies(spki, message, signature):
        problems.append("positive signature does not verify")
    for n in doc["negative"]:
        p = payload(n["fields"])
        if p is None or p.hex() != n["payload_hex"] or p == message:
            problems.append("negative payload " + n["name"])
        elif verifies(spki, p, signature):
            problems.append("negative verifies: " + n["name"])
    wrong = doc["wrong_key"]
    if not verifies(base64.b64decode(wrong["spki_der_b64"]), message, base64.b64decode(wrong["signature_der_b64"])):
        problems.append("wrong_key signature does not verify under its own key")
    if verifies(spki, message, base64.b64decode(wrong["signature_der_b64"])):
        problems.append("wrong_key signature verifies under the approval key")
    for n in doc["no_payload"]:
        if payload(n["fields"]) is not None:
            problems.append("no_payload builds one: " + n["name"])
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.write:
        VECTORS.parent.mkdir(parents=True, exist_ok=True)
        VECTORS.write_text(json.dumps(build(), indent=2) + "\n")
    problems = check(json.loads(VECTORS.read_text()))
    for p in problems:
        print("device approval vectors:", p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
