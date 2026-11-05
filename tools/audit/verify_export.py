#!/usr/bin/env python3
"""Verify a Vaulthalla audit export (vh-audit-export-v1) offline, without the daemon or its database.

    vh audit export > audit.ndjson
    python3 tools/audit/verify_export.py audit.ndjson [--public-key HEX]...

Checks, from the file alone:
  * every event's hash covers its fields (layout: core/include/audit/Chain.hpp),
  * each event's prev_hash is the hash of the event before it, with no gaps in seq,
  * every signed head names an exported event whose hash it matches, and (with --public-key, the node's Ed25519
    attestation public keys from `vh vault keys status` / key_attestation_keys) that its signature verifies.

Signature checks need the `cryptography` package; without it they are reported as skipped. Exit status 0 when
everything checks out, 1 otherwise.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys

CHAIN_DOMAIN = b"vh-audit-v1"
HEAD_DOMAIN = b"vh-audit-head-v1"


def _str(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack(">I", len(raw)) + raw


def _opt32(value) -> bytes:
    return b"\x00" if value is None else b"\x01" + struct.pack(">I", value)


def _opt64(value) -> bytes:
    return b"\x00" if value is None else b"\x01" + struct.pack(">Q", value)


def event_hash(e: dict) -> str:
    msg = (CHAIN_DOMAIN + struct.pack(">Q", e["seq"]) + bytes.fromhex(e["prev_hash"]) + struct.pack(">Q", e["occurred_us"])
           + _str(e["level"]) + _str(e["action"]) + _str(e["outcome"]) + _opt32(e["actor_id"]) + _str(e["actor"])
           + _str(e["origin"]) + _opt32(e["vault_id"]) + _opt64(e["entry_id"]) + _str(e["message"]) + _str(e["details"]))
    return hashlib.sha256(msg).hexdigest()


def head_message(h: dict) -> bytes:
    return (HEAD_DOMAIN + _str(h["node_id"]) + struct.pack(">Q", h["seq"]) + bytes.fromhex(h["hash"])
            + struct.pack(">Q", h["signed_us"]))


def verify(lines: list[str], public_keys: list[bytes]) -> tuple[bool, list[str]]:
    report: list[str] = []
    ok = True
    header = None
    events: list[dict] = []
    heads: list[dict] = []
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        obj = json.loads(line)
        kind = obj.get("type")
        if kind == "export":
            header = obj
        elif kind == "event":
            events.append(obj)
        elif kind == "head":
            heads.append(obj)
        else:
            return False, [f"line {n}: unknown record type {kind!r}"]
    if not header or header.get("format") != "vh-audit-export-v1":
        return False, ["not a vh-audit-export-v1 file (no header line)"]

    by_seq: dict[int, str] = {}
    prev = None
    for e in events:
        if prev is not None:
            if e["seq"] != prev["seq"] + 1:
                ok = False
                report.append(f"event {e['seq']}: expected {prev['seq'] + 1} (events are missing or out of order)")
                break
            if e["prev_hash"] != prev["hash"]:
                ok = False
                report.append(f"event {e['seq']}: previous-hash does not match event {prev['seq']}")
                break
        elif header.get("since_us") is None and header.get("anchor") is None and e["prev_hash"] != "00" * 32:
            ok = False
            report.append(f"event {e['seq']}: the export starts mid-chain without an anchor")
            break
        elif header.get("anchor") and header.get("since_us") is None and e["prev_hash"] != header["anchor"]["hash"]:
            ok = False
            report.append(f"event {e['seq']}: does not continue the retention checkpoint")
            break
        if event_hash(e) != e["hash"]:
            ok = False
            report.append(f"event {e['seq']}: its contents do not match its hash (altered)")
            break
        by_seq[e["seq"]] = e["hash"]
        prev = e
    report.append(f"{len(events)} event(s) checked" + (f" ({events[0]['seq']}..{events[-1]['seq']})" if events else ""))

    verifier = None
    if public_keys:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            verifier = [Ed25519PublicKey.from_public_bytes(k) for k in public_keys]
        except ImportError:
            report.append("signatures: skipped (install the 'cryptography' package)")
    for h in heads:
        if h["seq"] not in by_seq:
            if events and h["seq"] > events[-1]["seq"]:
                ok = False
                report.append(f"head at {h['seq']}: names an event missing from the export (removed from the end?)")
            continue
        if by_seq[h["seq"]] != h["hash"]:
            ok = False
            report.append(f"head at {h['seq']}: does not match the chain (history was rewritten)")
            continue
        if verifier is not None:
            msg, sig = head_message(h), bytes.fromhex(h["signature"])
            good = False
            for key in verifier:
                try:
                    key.verify(sig, msg)
                    good = True
                    break
                except Exception:  # noqa: BLE001 - any failure is "not this key"
                    pass
            if not good:
                ok = False
                report.append(f"head at {h['seq']}: signature does not verify with the given key(s)")
    report.append(f"{len(heads)} signed head(s) checked" + ("" if verifier is not None else " (hashes only)"))
    return ok, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("export", help="NDJSON file from `vh audit export` or the console's Export")
    parser.add_argument("--public-key", action="append", default=[], help="node attestation public key, hex (repeatable)")
    args = parser.parse_args(argv)
    with open(args.export, encoding="utf-8") as f:
        lines = f.read().splitlines()
    ok, report = verify(lines, [bytes.fromhex(k) for k in args.public_key])
    print("Audit export verified." if ok else "AUDIT EXPORT FAILED VERIFICATION.")
    for line in report:
        print("  " + line)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
