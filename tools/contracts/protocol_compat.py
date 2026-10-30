#!/usr/bin/env python3
"""ws protocol compatibility: the surface of each protocol version is frozen, and a breaking change needs a bump.

core/usage declares the ws protocol range (kProtocolVersion, kProtocolMin in core/usage/include/WsProtocol.hpp) and
`vh_usage --json` publishes it with the ws book (`protocol`, `ws`, `models`, `envelope`, `capabilities`). This tool
normalizes that surface (commands with their payload and response fields and model references, models with their
fields, the envelope, the error codes and the capability names; no descriptions, timeouts or other prose) and
compares it with the frozen baseline of the current protocol version, core/usage/protocol/v<kProtocolVersion>.json.

Breaking (fails the check):
  - a command removed (or a variant of it), or its input changed from a payload/token to something else
  - a request field newly required, removed, or retyped (a type, enum value, element type or model it accepted is
    gone)
  - a response field removed or retyped (it may now carry a type, element type or model it didn't)
  - a required response field made optional
  - a response enum value removed
  - a model removed while still referenced
  - an error code removed
  - a capability removed
Additive (allowed): new commands, new optional request fields, new response fields, new enum values, new models,
new capabilities, new error codes.

  protocol_compat.py --check [--usage-json F | --vh-usage BIN]   exit 1 on a breaking change (meson test
                                                                 `protocol_compat`); without a build source it checks
                                                                 the committed web/src/util/generated/wsContract.json
  protocol_compat.py --write [--usage-json F | --vh-usage BIN]   write (or refresh, when the change is additive) the
                                                                 baseline of the current protocol version; only when
                                                                 asked

Standard library only. Policy: docs/reference/ws-protocol.md.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE_DIR = REPO_ROOT / "core" / "usage" / "protocol"
SNAPSHOT_JSON = REPO_ROOT / "web" / "src" / "util" / "generated" / "wsContract.json"
PROTOCOL_HPP = "core/usage/include/WsProtocol.hpp"
WRITE = "python3 tools/contracts/protocol_compat.py --write --vh-usage build/core/vh_usage"

Fields = dict[str, dict[str, Any]]


# ---- normalization ---------------------------------------------------------------------------------------------

def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def norm_field(field: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"types": sorted(set(field["types"])), "required": bool(field.get("required", True))}
    for key in ("enum", "item_enum"):
        if field.get(key):
            out[key] = sorted(set(field[key]))
    for key in ("items", "model"):
        if field.get(key):
            out[key] = field[key]
    if field.get("fields"):
        out["fields"] = norm_fields(field["fields"])
    if field.get("values"):
        out["values"] = norm_field(field["values"])
    if field.get("element"):
        out["element"] = norm_field(field["element"])
    if field.get("one_of"):
        out["one_of"] = sorted((norm_field(a) for a in field["one_of"]), key=canonical)
    return out


def norm_fields(fields: list[dict[str, Any]]) -> Fields:
    return {f["name"]: norm_field(f) for f in fields}


def surface(usage: dict[str, Any]) -> dict[str, Any]:
    """The normalized ws surface of a vh_usage --json document (or of the committed ws snapshot)."""
    missing = [k for k in ("protocol", "ws", "models", "envelope", "capabilities") if k not in usage]
    if missing:
        raise SystemExit("the contract has no " + ", ".join(missing) + " (a build from before protocol negotiation?)")
    commands: dict[str, Any] = {}
    error_codes = {c["code"] for c in usage["envelope"].get("error_codes", [])}
    for c in usage["ws"]:
        commands[c["command"]] = {
            "input": c["input"],
            "payload": norm_fields(c["payload"]),
            "response": norm_fields(c["response"]),
            "response_model": c.get("response_model"),
            "variants": {v["mode"]: {"payload": norm_fields(v["payload"]), "response": norm_fields(v["response"])}
                         for v in c.get("variants", [])},
        }
        # "unauthorized" (the UNAUTHORIZED status) and "error" (ERROR without a code) are refusal kinds, not codes.
        error_codes.update(k for k in c.get("refusal_kinds", c.get("refusal_codes", []))
                           if k not in ("unauthorized", "error"))
        error_codes.update(x["code"] for x in c.get("confirmations", []))
    return {
        "protocol": usage["protocol"]["version"],
        "commands": commands,
        "models": {m["name"]: norm_fields(m["fields"]) for m in usage["models"]},
        "envelope": {frame: norm_fields(usage["envelope"][frame]) for frame in ("request", "response", "error_frame")},
        "error_codes": sorted(error_codes),
        "capabilities": sorted(c["name"] for c in usage["capabilities"]),
    }


# ---- comparison ------------------------------------------------------------------------------------------------

class Diff:
    def __init__(self) -> None:
        self.breaks: list[str] = []
        self.additions: list[str] = []

    def brk(self, where: str, what: str) -> None:
        line = f"{where}: {what}"
        if line not in self.breaks:
            self.breaks.append(line)

    def add(self, where: str, what: str) -> None:
        line = f"{where}: {what}"
        if line not in self.additions:
            self.additions.append(line)


def _signature(field: dict[str, Any]) -> str:
    return canonical([field["types"], field.get("model", ""), field.get("items", "")])


def compare_field(base: dict[str, Any], cur: dict[str, Any], side: str, where: str, d: Diff) -> None:
    """`side` is "request" (what clients send: the server must keep accepting it) or "response" (what clients read:
    the server must not send what they don't expect)."""
    request = side == "request"
    if request and cur["required"] and not base["required"]:
        d.brk(where, "request field newly required")
    if not request and base["required"] and not cur["required"]:
        d.brk(where, "required response field made optional")

    lost = sorted(set(base["types"]) - set(cur["types"]))
    gained = sorted(set(cur["types"]) - set(base["types"]))
    if request and lost:
        d.brk(where, f"request field retyped: no longer accepts {', '.join(lost)}")
    if not request and gained:
        d.brk(where, f"response field retyped: may now be {', '.join(gained)}")
    if (request and gained) or (not request and lost):
        d.add(where, f"types now {', '.join(cur['types'])}")

    for key, label in (("items", "element type"), ("model", "model")):
        if base.get(key, "") != cur.get(key, ""):
            d.brk(where, f"{side} field retyped: {label} {base.get(key) or '(none)'} -> {cur.get(key) or '(none)'}")

    for key, label in (("enum", "enum value"), ("item_enum", "element enum value")):
        b, c = base.get(key), cur.get(key)
        if b and c:
            removed = sorted(set(b) - set(c))
            if removed:
                d.brk(where, f"{side} {label} removed: {', '.join(removed)}")
            added = sorted(set(c) - set(b))
            if added:
                d.add(where, f"new {label}: {', '.join(added)}")
        elif c and not b and request:
            d.brk(where, f"request field retyped: now restricted to {', '.join(c)}")
        elif b and not c:
            d.add(where, f"{label}s no longer restricted")

    if base.get("fields") or cur.get("fields"):
        compare_fields(base.get("fields", {}), cur.get("fields", {}), side, where, d)
    for key, suffix in (("values", ".*"), ("element", "[]")):
        if base.get(key) and cur.get(key):
            compare_field(base[key], cur[key], side, where + suffix, d)
        elif base.get(key) or cur.get(key):
            d.brk(where, f"{side} field retyped: {key} shape {'removed' if base.get(key) else 'added'}")

    if base.get("one_of") or cur.get("one_of"):
        b_alts = {_signature(a): a for a in base.get("one_of", [])}
        c_alts = {_signature(a): a for a in cur.get("one_of", [])}
        for sig, alt in b_alts.items():
            if sig in c_alts:
                compare_field(alt, c_alts[sig], side, f"{where}|{'/'.join(alt['types'])}", d)
            elif request:
                d.brk(where, f"request field retyped: no longer accepts the {'/'.join(alt['types'])} alternative")
        for sig, alt in c_alts.items():
            if sig not in b_alts:
                if request:
                    d.add(where, f"accepts a new {'/'.join(alt['types'])} alternative")
                else:
                    d.brk(where, f"response field retyped: may now be the {'/'.join(alt['types'])} alternative")


def compare_fields(base: Fields, cur: Fields, side: str, where: str, d: Diff) -> None:
    for name, b in base.items():
        path = f"{where}.{name}"
        if name not in cur:
            d.brk(path, f"{side} field removed")
        else:
            compare_field(b, cur[name], side, path, d)
    for name, c in cur.items():
        if name in base:
            continue
        path = f"{where}.{name}"
        if side == "request" and c["required"]:
            d.brk(path, "new request field is required")
        else:
            d.add(path, f"new {'optional ' if side == 'request' else ''}{side} field")


def _walk_models(fields: Fields, out: set[str]) -> None:
    for f in fields.values():
        _walk_field(f, out)


def _walk_field(f: dict[str, Any], out: set[str]) -> None:
    if f.get("model"):
        out.add(f["model"])
    _walk_models(f.get("fields", {}), out)
    for key in ("values", "element"):
        if f.get(key):
            _walk_field(f[key], out)
    for alt in f.get("one_of", []):
        _walk_field(alt, out)


def model_contexts(s: dict[str, Any]) -> dict[str, set[str]]:
    """model name -> the sides ("request", "response") it is read on, transitively through other models."""
    direct: dict[str, set[str]] = {"request": set(), "response": set()}
    for c in s["commands"].values():
        shapes = [("request", c["payload"]), ("response", c["response"])]
        for v in c["variants"].values():
            shapes += [("request", v["payload"]), ("response", v["response"])]
        for side, fields in shapes:
            _walk_models(fields, direct[side])
        if c["response_model"]:
            direct["response"].add(c["response_model"])
    _walk_models(s["envelope"]["request"], direct["request"])
    _walk_models(s["envelope"]["response"], direct["response"])
    _walk_models(s["envelope"]["error_frame"], direct["response"])

    out: dict[str, set[str]] = {}
    for side, roots in direct.items():
        pending = list(roots)
        while pending:
            name = pending.pop()
            if side in out.setdefault(name, set()):
                continue
            out[name].add(side)
            nested: set[str] = set()
            _walk_models(s["models"].get(name, {}), nested)
            pending.extend(nested)
    return out


def referenced_models(s: dict[str, Any]) -> set[str]:
    return set(model_contexts(s))


def compare(base: dict[str, Any], cur: dict[str, Any]) -> Diff:
    d = Diff()
    for name, b in base["commands"].items():
        c = cur["commands"].get(name)
        if c is None:
            d.brk(name, "command removed")
            continue
        if b["input"] != c["input"] and b["input"] != "none":
            d.brk(name, f"request retyped: input {b['input']} -> {c['input']}")
        compare_fields(b["payload"], c["payload"], "request", f"{name} payload", d)
        compare_fields(b["response"], c["response"], "response", f"{name} response", d)
        if b["response_model"] and b["response_model"] != c["response_model"]:
            d.brk(name, f"response retyped: model {b['response_model']} -> {c['response_model'] or '(none)'}")
        for mode, bv in b["variants"].items():
            cv = c["variants"].get(mode)
            if cv is None:
                d.brk(name, f"{mode} variant removed")
                continue
            compare_fields(bv["payload"], cv["payload"], "request", f"{name} ({mode}) payload", d)
            compare_fields(bv["response"], cv["response"], "response", f"{name} ({mode}) response", d)
        for mode in sorted(set(c["variants"]) - set(b["variants"])):
            d.add(name, f"new {mode} variant")
    for name in sorted(set(cur["commands"]) - set(base["commands"])):
        d.add(name, "new command")

    contexts = model_contexts(base)
    still_referenced = referenced_models(cur)
    for name, fields in base["models"].items():
        if name not in cur["models"]:
            if name in still_referenced:
                d.brk(f"model {name}", "model removed while still referenced")
            continue
        for side in sorted(contexts.get(name, {"response"})):
            compare_fields(fields, cur["models"][name], side, f"model {name}", d)
    for name in sorted(set(cur["models"]) - set(base["models"])):
        d.add(f"model {name}", "new model")

    for frame, side in (("request", "request"), ("response", "response"), ("error_frame", "response")):
        compare_fields(base["envelope"][frame], cur["envelope"][frame], side, f"envelope {frame}", d)

    for code in sorted(set(base["error_codes"]) - set(cur["error_codes"])):
        d.brk(f"error code {code}", "error code removed")
    for code in sorted(set(cur["error_codes"]) - set(base["error_codes"])):
        d.add(f"error code {code}", "new error code")
    for cap in sorted(set(base["capabilities"]) - set(cur["capabilities"])):
        d.brk(f"capability {cap}", "capability removed (capabilities are never removed while the protocol lasts)")
    for cap in sorted(set(cur["capabilities"]) - set(base["capabilities"])):
        d.add(f"capability {cap}", "new capability")
    return d


# ---- baselines -------------------------------------------------------------------------------------------------

def baseline_path(version: int) -> Path:
    return BASELINE_DIR / f"v{version}.json"


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def baseline_text(s: dict[str, Any]) -> str:
    doc = {"$comment": f"Frozen ws surface of protocol {s['protocol']}. Generated by "
                       "tools/contracts/protocol_compat.py --write; never edit by hand.", **s}
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def load_baseline(version: int) -> dict[str, Any] | None:
    path = baseline_path(version)
    if not path.exists():
        return None
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc.pop("$comment", None)
    return doc


def bump_advice(version: int) -> str:
    return (f"to ship this, bump kProtocolVersion to {version + 1} in {PROTOCOL_HPP}, add its baseline "
            f"({WRITE}), and decide kProtocolMin: keep {version} only if every handler you changed still answers "
            f"protocol-{version} sessions (Session::protocolVersion()) in the old shape; otherwise raise it. "
            f"Keep v{version}.json. Otherwise make the change additive (docs/reference/ws-protocol.md).")


def check(usage: dict[str, Any]) -> tuple[list[str], list[str]]:
    """(problems, notes) for the current contract against the baseline of its protocol version."""
    cur = surface(usage)
    version, minimum = usage["protocol"]["version"], usage["protocol"]["min"]
    problems: list[str] = []
    if not 1 <= minimum <= version:
        problems.append(f"protocol min {minimum} is not within 1..{version}")
    for v in range(minimum, version):
        if not baseline_path(v).exists():
            problems.append(f"protocol {v} is still served (kProtocolMin = {minimum}) but its baseline "
                            f"{rel(baseline_path(v))} is gone")
    base = load_baseline(version)
    if base is None:
        problems.append(f"no baseline for protocol {version}: {rel(baseline_path(version))}; "
                        f"freeze it with {WRITE}")
        return problems, []
    if base.get("protocol") != version:
        problems.append(f"{rel(baseline_path(version))} is the baseline of protocol "
                        f"{base.get('protocol')}, not {version}")
    d = compare(base, cur)
    if d.breaks:
        problems.append(f"{len(d.breaks)} breaking change(s) against protocol {version}:\n"
                        + "\n".join("     " + b for b in d.breaks) + "\n   " + bump_advice(version))
    notes = d.additions
    return problems, notes


# ---- sources and main ------------------------------------------------------------------------------------------

def load_usage(args: argparse.Namespace) -> dict[str, Any]:
    if args.usage_json:
        return json.loads(Path(args.usage_json).read_text(encoding="utf-8"))
    if args.vh_usage:
        result = subprocess.run([args.vh_usage, "--json"], check=True, capture_output=True, text=True, timeout=60)
        return json.loads(result.stdout)
    return json.loads(SNAPSHOT_JSON.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="exit 1 on a breaking change")
    mode.add_argument("--write", action="store_true", help="write or refresh the current version's baseline")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--usage-json", help="vh_usage --json output (build/core/usage.json)")
    source.add_argument("--vh-usage", help="the vh_usage binary (build/core/vh_usage)")
    args = parser.parse_args(argv)

    usage = load_usage(args)
    if args.write:
        cur = surface(usage)
        version = cur["protocol"]
        base = load_baseline(version)
        if base is not None:
            d = compare(base, cur)
            if d.breaks:
                print(f"refusing to overwrite {rel(baseline_path(version))}: the change is breaking:",
                      file=sys.stderr)
                for b in d.breaks:
                    print("  - " + b, file=sys.stderr)
                print(bump_advice(version), file=sys.stderr)
                return 1
        BASELINE_DIR.mkdir(parents=True, exist_ok=True)
        baseline_path(version).write_text(baseline_text(cur), encoding="utf-8")
        print(f"wrote {rel(baseline_path(version))} ({len(cur['commands'])} commands, "
              f"{len(cur['models'])} models, {len(cur['capabilities'])} capabilities)")
        return 0

    problems, notes = check(usage)
    if problems:
        print("ws protocol compatibility:", file=sys.stderr)
        for p in problems:
            print(" - " + p, file=sys.stderr)
        return 1
    version = usage["protocol"]["version"]
    print(f"ws protocol {version}: compatible with its baseline"
          + (f" ({len(notes)} additive change(s); freeze them with --write when they ship)" if notes else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
