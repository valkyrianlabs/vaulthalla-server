#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Valkyrian Labs LLC
"""Golden vectors for the manifest root's writer floor (vl-vaultfmt docs/engine.md, "The writer floor"; vaulthalla-server
design/core/vault-format-library.md, decision 7).

  python3 writer_floor_vectors.py            # write writer_floor.json
  python3 writer_floor_vectors.py --check    # regenerate in memory, compare byte for byte, run the reference rules

This library's own file, beside the verbatim copy vectors.json (which it does not change): sealed roots that carry
`writer_floor` (and one that doesn't), sealed with the reference VHF1 sealer of vh_crypto_vectors.py, and the
decision table a writer applies. The rules, as this reference implements them independently of the C++:

  floor(root)          = root["writer_floor"] if present else 0
  a writer of revision R may publish over (or take in) a root  iff  floor(root) <= R
  the floor it writes  = max(floor(base), floor(recorded), needs), where needs <= R (a writer can't need more than it
                         round-trips); the member is omitted when that is 0
"""

import argparse
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_OUT = HERE / "writer_floor.json"


def _reference():
    spec = importlib.util.spec_from_file_location("vh_crypto_vectors", HERE / "vh_crypto_vectors.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module   # dataclasses look their module up there
    spec.loader.exec_module(module)
    return module


R = _reference()


def floor_of(root: dict) -> int:
    return root.get("writer_floor", 0)


def decide(base_floor: int, recorded_floor: int, revision: int, needs: int) -> dict:
    if needs > revision:
        return {"error": "invalid_argument"}
    if max(base_floor, recorded_floor) > revision:
        return {"error": "writer_floor"}
    written = max(base_floor, recorded_floor, needs)
    return {"writer_floor": written} if written else {"writer_floor": None}


def build() -> dict:
    vault = R.VAULT_UID
    seg_uid = R.label_bytes("vh-writer-floor/segment", 16)
    seg_plain = {"type": "vh.manifest.segment", "v": 1, "vault_uid": R.b32_encode(vault), "range": ["00", "ff"],
                 "entries": [{"uid": R.b32_encode(bytes.fromhex("11" * 16)), "kind": "dir", "parent": None,
                              "name": "", "mode": 0o755, "mtime": "2026-11-15T12:00:00Z"}]}
    seg_obj, _ = R.vhf1_seal(R.canonical_json(seg_plain), R.VAULT_KEYS[2],
                             R.Vhf1Params(2, vault, seg_uid, R.salt_for("writer-floor-segment"), R.KIND_SEGMENT,
                                          R.VHF1_WRITER_CHUNK_LOG2))
    seg_ref = {"sid": R.b32_encode(seg_uid), "range": ["00", "ff"], "count": 1, "object_sha256": R.sha256(seg_obj).hex(),
               "size": len(seg_obj)}

    def root(name: str, floor: int | None) -> dict:
        plain = {"type": "vh.manifest.root", "v": 1, "vault_uid": R.b32_encode(vault), "layout": "OpaqueV1",
                 "epoch": 1, "prev": None, "published_at": "2026-11-15T12:00:00Z",
                 "producer": {"node_id": "desktop-writer-floor", "software": "vl-vaultfmt vectors"},
                 "keys": [{"version": 2, "key_check": None, "attestation": None, "created_at": "2026-11-15T12:00:00Z",
                           "retired_at": None}],
                 "segments": [seg_ref], "snapshots": [], "stats": {"files": 0, "dirs": 1, "bytes": 0},
                 "publish": "version_log", "writers": ["desktop-writer-floor"]}
        if floor is not None:
            plain["writer_floor"] = floor
        obj, _ = R.vhf1_seal(R.canonical_json(plain), R.VAULT_KEYS[2],
                             R.Vhf1Params(2, vault, vault, R.salt_for("writer-floor-" + name), R.KIND_ROOT, 16))
        return {"name": name, "key_version": 2, "plaintext_utf8": R.canonical_json(plain).decode(),
                "object_hex": obj.hex(), "object_sha256": R.sha256(obj).hex(), "writer_floor": floor_of(plain)}

    roots = [root("no_floor", None), root("floor_1", 1), root("floor_2", 2)]
    decisions = []
    for base in (0, 1, 2):
        for recorded in (0, 2):
            for revision in (1, 2):
                for needs in (0, 1, 2):
                    decisions.append({"base_floor": base, "recorded_floor": recorded, "revision": revision,
                                      "needs": needs, "expect": decide(base, recorded, revision, needs)})
    return {
        "description": "The manifest root's writer floor (vl-vaultfmt docs/engine.md). Roots are sealed under key "
                       "version 2 of vectors.json's conventions (vault key 2 = bytes 0x20..0x3f), object uid = the "
                       "vectors' vault uid; `segment` is the one segment each root pins.",
        "generated_by": "vectors/writer_floor_vectors.py",
        "vault_uid_hex": vault.hex(),
        "segment": {"object_key": ".vaulthalla/seg/" + seg_ref["sid"], "object_hex": seg_obj.hex()},
        "roots": roots,
        "decisions": decisions,
    }


def verify(doc: dict) -> list[str]:
    failures = []
    for r in doc["roots"]:
        ex = R.Expect(kind=R.KIND_ROOT, vault_uid=bytes.fromhex(doc["vault_uid_hex"]),
                      object_uid=bytes.fromhex(doc["vault_uid_hex"]), keys=dict(R.VAULT_KEYS))
        plain = R.vhf1_open(bytes.fromhex(r["object_hex"]), ex)
        if plain.decode() != r["plaintext_utf8"]:
            failures.append(f"{r['name']}: the object does not open to its plaintext")
        if floor_of(json.loads(plain)) != r["writer_floor"]:
            failures.append(f"{r['name']}: floor")
    for d in doc["decisions"]:
        if decide(d["base_floor"], d["recorded_floor"], d["revision"], d["needs"]) != d["expect"]:
            failures.append(f"decision {d}")
    return failures


def render(doc: dict) -> str:
    return json.dumps(doc, indent=1, ensure_ascii=False) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="verify writer_floor.json instead of writing it")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()
    doc = build()
    text = render(doc)
    if not args.check:
        args.out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out} ({len(doc['roots'])} roots, {len(doc['decisions'])} decisions)")
        return 0
    if not args.out.exists() or args.out.read_text(encoding="utf-8") != text:
        print(f"FAIL: {args.out} differs from what this script generates (regenerate it and review the diff)")
        return 1
    failures = verify(json.loads(text))
    if failures:
        print("FAIL:\n  " + "\n  ".join(failures))
        return 1
    print(f"OK: {len(doc['roots'])} roots and {len(doc['decisions'])} decisions match the generator and the reference")
    return 0


if __name__ == "__main__":
    sys.exit(main())
