#!/usr/bin/env python3
"""Write the WebAuthn fuzz seed corpora (core/src/auth/webauthn/fuzz/corpus/<target>/) from the W3C vectors.

    python3 -I tools/dev/webauthn_seed_corpus.py core/test-assets/webauthn/w3c-webauthn-l3-vectors.json \
        core/src/auth/webauthn/fuzz/corpus

Seeds per target: cbor_cose gets attestation objects and the COSE keys inside them, authenticator_data every
authenticatorData, client_data every clientDataJSON plus response JSON built from the same vectors. Files are named
by the SHA-1 of their content (libFuzzer's convention), so re-running is idempotent. Inputs libFuzzer finds later
(tools/dev/fuzz-webauthn.sh --merge) and crash reproducers land in the same directories.
"""
import base64
import hashlib
import json
import os
import sys


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def auth_data_of(attestation_object: bytes) -> bytes:
    # The vectors' attestation objects end with "authData" followed by a byte string; read its CBOR header.
    key = b"\x68authData"
    i = attestation_object.index(key) + len(key)
    head = attestation_object[i]
    assert head >> 5 == 2, "authData is a byte string"
    ai = head & 0x1F
    if ai < 24:
        n, i = ai, i + 1
    else:
        width = {24: 1, 25: 2, 26: 4}[ai]
        n, i = int.from_bytes(attestation_object[i + 1:i + 1 + width], "big"), i + 1 + width
    return attestation_object[i:i + n]


def cose_key_of(auth_data: bytes) -> bytes:
    pos = 37 + 16
    length = int.from_bytes(auth_data[pos:pos + 2], "big")
    return auth_data[pos + 2 + length:]  # no extensions in the vectors


def main() -> None:
    vectors = json.load(open(sys.argv[1]))["vectors"]
    out = sys.argv[2]
    seeds = {"cbor_cose": [], "authenticator_data": [], "client_data": []}
    for v in vectors:
        reg, auth = v["registration"], v["authentication"]
        att = bytes.fromhex(reg["attestationObject"])
        ad = auth_data_of(att)
        seeds["cbor_cose"] += [att, cose_key_of(ad)]
        seeds["authenticator_data"] += [ad, bytes.fromhex(auth["authenticatorData"])]
        cd_reg, cd_auth = bytes.fromhex(reg["clientDataJSON"]), bytes.fromhex(auth["clientDataJSON"])
        seeds["client_data"] += [cd_reg, cd_auth]
        cred = bytes.fromhex(reg["credential_id"])
        envelope = {"id": b64u(cred), "rawId": b64u(cred), "type": "public-key", "clientExtensionResults": {}}
        seeds["client_data"].append(json.dumps({**envelope, "response": {
            "clientDataJSON": b64u(cd_reg), "attestationObject": b64u(att), "transports": ["usb"]}}).encode())
        seeds["client_data"].append(json.dumps({**envelope, "response": {
            "clientDataJSON": b64u(cd_auth), "authenticatorData": b64u(bytes.fromhex(auth["authenticatorData"])), "signature": b64u(bytes.fromhex(auth["signature"])),
            "userHandle": None}}).encode())
    for target, items in seeds.items():
        d = os.path.join(out, target)
        os.makedirs(d, exist_ok=True)
        for data in items:
            with open(os.path.join(d, hashlib.sha1(data).hexdigest()), "wb") as f:
                f.write(data)


if __name__ == "__main__":
    main()
