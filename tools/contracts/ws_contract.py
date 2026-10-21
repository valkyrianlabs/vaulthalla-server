#!/usr/bin/env python3
"""Server-owned ws contract for the web console: generate it, and fail when it drifts.

The ws command book lives in core/usage (core/usage/src/contract/ws/*.cpp) and is published by
`vh_usage --json` (build/core/usage.json). This tool turns its `ws` section into

  web/src/util/generated/wsContract.json   the ws book and the models it names, with their hashes (reviewable; what
                                           the TS is generated from, and what other clients vendor)
  web/src/util/generated/wsContract.ts     TypeScript: per-command payload/response types (`WsContract`), the model
                                           shapes (`WsModels`), command names, client timeouts, contract version and
                                           hashes

`web/src/util/wsContractCheck.ts` type-checks the hand-written `WebSocketCommandMap` against `WsContract`, so a
server-side change breaks `pnpm typecheck` until the files are regenerated and the map follows.

  ws_contract.py --write --vh-usage build/core/vh_usage     regenerate both files from a build
  ws_contract.py --write --usage-json build/core/usage.json
  ws_contract.py --check [--usage-json F | --vh-usage BIN]  exit 1 on drift (meson test `ws_contract_drift`)

Without a build source, --check only verifies the committed files against each other (hash, generated TS).
Standard library only.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATED_DIR = REPO_ROOT / "web" / "src" / "util" / "generated"
CONTRACT_JSON = GENERATED_DIR / "wsContract.json"
CONTRACT_TS = GENERATED_DIR / "wsContract.ts"
REGENERATE = "python3 tools/contracts/ws_contract.py --write --vh-usage build/core/vh_usage"
LINE_LIMIT = 110


# ---- canonical form and hashes (must match core/usage/src/contract/Export.cpp) ---------------------------------

def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


SNAPSHOT_KEYS = ("contract_version", "ws_hash", "ws", "models_hash", "models")


def ws_snapshot(usage: dict[str, Any]) -> dict[str, Any]:
    """The part of vh_usage --json the web console (and any other ws client) depends on."""
    snapshot = {key: usage[key] for key in SNAPSHOT_KEYS}
    for section in ("ws", "models"):
        computed = sha256_hex(canonical(usage[section]))
        if computed != usage[f"{section}_hash"]:
            raise SystemExit(f"usage contract {section}_hash {usage[f'{section}_hash']} does not match its {section} "
                             f"section ({computed})")
    return snapshot


def snapshot_text(snapshot: dict[str, Any]) -> str:
    return json.dumps(snapshot, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


# ---- TypeScript generation -------------------------------------------------------------------------------------

def ts_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def ts_key(name: str) -> str:
    return name if name.replace("_", "a").isalnum() and not name[0].isdigit() else ts_string(name)


def literal_union(values: list[str]) -> str:
    return " | ".join(ts_string(v) for v in values)


# The model names the snapshot being rendered declares. A name it doesn't declare renders as `object` (the C++ and
# Python contract tests fail on such a name, so committed output never has one; it keeps a half-built book typable).
DECLARED_MODELS: set[str] = set()


def ts_model(name: str) -> str:
    return f"WsModels[{ts_string(name)}]" if name in DECLARED_MODELS else "object"


def ts_field_type(field: dict[str, Any], indent: int) -> str:
    parts: list[str] = []
    if field.get("one_of"):
        # A spelled-out union: each alternative renders on its own; null stays on the field itself.
        for alternative in field["one_of"]:
            parts.append(ts_field_type({**alternative, "name": field.get("name", "")}, indent))
        if "null" in field["types"]:
            parts.append("null")
        return " | ".join(dict.fromkeys(parts))
    for t in field["types"]:
        if t == "string":
            parts.append(literal_union(field["enum"]) if field.get("enum") else "string")
        elif t in ("integer", "number"):
            parts.append("number")
        elif t == "boolean":
            parts.append("boolean")
        elif t == "null":
            parts.append("null")
        elif t == "object":
            if field.get("partial") and (field.get("model") or field.get("fields")):
                shape = ts_model(field["model"]) if field.get("model") else ts_object(field["fields"], indent)
                parts.append(f"WsPartial<{shape}>")
            elif field.get("model"):
                parts.append(ts_model(field["model"]))
            elif field.get("fields"):
                parts.append(ts_object(field["fields"], indent))
            elif field.get("values"):
                parts.append(f"Record<string, {ts_field_type(field['values'], indent)}>")
            else:
                parts.append("object")
        elif t == "array":
            items = field.get("items", "")
            if field.get("element"):
                element = f"({ts_field_type(field['element'], indent)})"
            elif items == "string":
                element = f"({literal_union(field['item_enum'])})" if field.get("item_enum") else "string"
            elif items == "object":
                if field.get("model"):
                    element = ts_model(field["model"])
                else:
                    element = ts_object(field["fields"], indent) if field.get("fields") else "object"
            elif items in ("integer", "number"):
                element = "number"
            elif items == "boolean":
                element = "boolean"
            else:
                element = "unknown"
            parts.append(f"{element}[]")
        else:
            raise SystemExit(f"unknown JSON type {t!r} on field {field['name']!r}")
    # A field typed ["integer", "array"] with string items renders as `number | string[]`.
    seen: list[str] = []
    for p in parts:
        if p not in seen:
            seen.append(p)
    return " | ".join(seen)


def ts_object(fields: list[dict[str, Any]], indent: int) -> str:
    if not fields:
        return "Record<string, never>"
    members = [f"{ts_key(f['name'])}{'' if f['required'] else '?'}: {ts_field_type(f, indent + 2)}" for f in fields]
    one_line = "{ " + "; ".join(members) + " }"
    if len(one_line) + indent <= LINE_LIMIT and "\n" not in one_line:
        return one_line
    pad = " " * (indent + 2)
    return "{\n" + "".join(f"{pad}{m}\n" for m in members) + " " * indent + "}"


def ts_payload(command: dict[str, Any], fields: list[dict[str, Any]], indent: int) -> str:
    if command["input"] != "payload":
        return "null"
    return ts_object(fields, indent)


def ts_union(shapes: list[str]) -> str:
    unique: list[str] = []
    for s in shapes:
        if s not in unique:
            unique.append(s)
    return " | ".join(unique)


def doc_comment(text: str, indent: int) -> str:
    pad = " " * indent
    words = text.split()
    lines: list[str] = []
    line = ""
    for w in words:
        if len(pad) + 3 + len(line) + 1 + len(w) > LINE_LIMIT and line:
            lines.append(line)
            line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        lines.append(line)
    return f"{pad}/**\n" + "".join(f"{pad} * {l.replace('*/', '* /')}\n" for l in lines) + f"{pad} */\n"


def generate_ts(snapshot: dict[str, Any]) -> str:
    commands = snapshot["ws"]
    DECLARED_MODELS.clear()
    DECLARED_MODELS.update(m["name"] for m in snapshot.get("models", []))
    out: list[str] = [
        "// Generated by tools/contracts/ws_contract.py from the ws command book in core/usage",
        "// (core/usage/src/contract/ws/*.cpp, published by `vh_usage --json`). Do not edit: change the book, rebuild,",
        f"// then run: {REGENERATE}",
        "// web/src/util/wsContractCheck.ts checks WebSocketCommandMap against these types.",
        "",
        f"export const WS_CONTRACT_VERSION = {snapshot['contract_version']}",
        "",
        "// What the daemon's meta.contract.get answers as ws_hash when it was built from the same book.",
        f"export const WS_CONTRACT_HASH = {ts_string(snapshot['ws_hash'])}",
        "",
        "// What meta.contract.get answers as models_hash when the daemon's model shapes are these.",
        f"export const WS_MODELS_HASH = {ts_string(snapshot['models_hash'])}",
        "",
        "// A merge patch (payload members marked `partial`): any subset of the members, at any depth.",
        "export type WsPartial<T> = { [K in keyof T]?: T[K] extends readonly unknown[] ? T[K] : T[K] extends object "
        "? WsPartial<T[K]> : T[K] }",
        "",
        "// The server models the book names (core/usage/src/contract/models), checked against their serializers.",
        "export interface WsModels {",
    ]
    for m in snapshot["models"]:
        out.append(doc_comment(m["description"], 2).rstrip("\n"))
        out.append(f"  {ts_string(m['name'])}: {ts_object(m['fields'], 2)}")
    out += ["}", "", "export interface WsContract {"]
    for c in commands:
        out.append(doc_comment(c["description"], 2).rstrip("\n"))
        payload = ts_union([ts_payload(c, c["payload"], 4)] + [ts_payload(c, v["payload"], 4) for v in c["variants"]])
        response = ts_union([ts_object(c["response"], 4)] + [ts_object(v["response"], 4) for v in c["variants"]])
        out.append(f"  {ts_string(c['command'])}: {{")
        out.append(f"    payload: {payload}")
        out.append(f"    response: {response}")
        out.append("  }")
    out.append("}")
    out.append("")
    out.append("export type WsContractCommand = keyof WsContract")
    out.append("")
    out.append("export const WS_CONTRACT_COMMANDS: readonly WsContractCommand[] = [")
    out.extend(f"  {ts_string(c['command'])}," for c in commands)
    out.append("]")
    out.append("")
    out.append("// The NeedsConfirmation refusals per command: data.code, and the payload member (dotted path) a resend sets to")
    out.append("// accept it (null: no resend accepts it; the description says what to do instead).")
    out.append("export const WS_CONTRACT_CONFIRMATIONS: Readonly<")
    out.append("  Partial<Record<WsContractCommand, readonly { code: string; accept_field: string | null }[]>>")
    out.append("> = {")
    for c in commands:
        if c.get("confirmations"):
            items = ", ".join("{ code: %s, accept_field: %s }" % (ts_string(x["code"]),
                              ts_string(x["accept_field"]) if x["accept_field"] else "null")
                              for x in c["confirmations"])
            line = f"  {ts_string(c['command'])}: [{items}],"
            if len(line) <= LINE_LIMIT:
                out.append(line)
            else:
                out.append(f"  {ts_string(c['command'])}: [")
                for x in c["confirmations"]:
                    out.append("    { code: %s, accept_field: %s }," % (ts_string(x["code"]),
                               ts_string(x["accept_field"]) if x["accept_field"] else "null"))
                out.append("  ],")
    out.append("}")
    out.append("")
    out.append("// Client timeouts the server declares per command (a timeout means \"no answer yet\", never \"failed\").")
    out.append("export const WS_CONTRACT_TIMEOUTS: Readonly<Record<WsContractCommand, number>> = {")
    out.extend(f"  {ts_string(c['command'])}: {c['client_timeout_ms']}," for c in commands)
    out.append("}")
    out.append("")
    return "\n".join(out)


# ---- sources ---------------------------------------------------------------------------------------------------

def load_usage(args: argparse.Namespace) -> dict[str, Any] | None:
    if args.usage_json:
        return json.loads(Path(args.usage_json).read_text(encoding="utf-8"))
    if args.vh_usage:
        result = subprocess.run([args.vh_usage, "--json"], check=True, capture_output=True, text=True, timeout=60)
        return json.loads(result.stdout)
    return None


def unified(expected: str, actual: str, name: str, limit: int = 60) -> str:
    diff = list(difflib.unified_diff(actual.splitlines(), expected.splitlines(), f"{name} (committed)",
                                     f"{name} (generated)", lineterm="", n=1))
    if len(diff) > limit:
        diff = diff[:limit] + [f"... ({len(diff) - limit} more diff lines)"]
    return "\n".join(diff)


def drift(usage: dict[str, Any] | None) -> list[str]:
    """Problems between the build's contract (when given), the committed snapshot and the committed TS."""
    problems: list[str] = []
    if not CONTRACT_JSON.exists() or not CONTRACT_TS.exists():
        return [f"missing {CONTRACT_JSON.relative_to(REPO_ROOT)} or {CONTRACT_TS.relative_to(REPO_ROOT)}"]
    committed_json = CONTRACT_JSON.read_text(encoding="utf-8")
    committed = json.loads(committed_json)

    for section in ("ws", "models"):
        if section not in committed or sha256_hex(canonical(committed[section])) != committed.get(f"{section}_hash"):
            problems.append(f"{CONTRACT_JSON.relative_to(REPO_ROOT)} was edited by hand: its {section}_hash does not "
                            f"match its {section} section")

    if usage is not None:
        expected_json = snapshot_text(ws_snapshot(usage))
        if expected_json != committed_json:
            problems.append("the ws command book in core/usage changed but web/src/util/generated was not regenerated:\n"
                            + unified(expected_json, committed_json, CONTRACT_JSON.name))
        source = ws_snapshot(usage)
    else:
        source = committed

    expected_ts = generate_ts(source)
    committed_ts = CONTRACT_TS.read_text(encoding="utf-8")
    if expected_ts != committed_ts:
        problems.append(f"{CONTRACT_TS.relative_to(REPO_ROOT)} is not what the contract generates:\n"
                        + unified(expected_ts, committed_ts, CONTRACT_TS.name))
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="regenerate the committed files")
    mode.add_argument("--check", action="store_true", help="exit 1 when the committed files drift")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--usage-json", help="vh_usage --json output (build/core/usage.json)")
    source.add_argument("--vh-usage", help="the vh_usage binary (build/core/vh_usage)")
    args = parser.parse_args(argv)

    usage = load_usage(args)
    if args.write:
        if usage is None:
            parser.error("--write needs --usage-json or --vh-usage")
        snapshot = ws_snapshot(usage)
        GENERATED_DIR.mkdir(parents=True, exist_ok=True)
        CONTRACT_JSON.write_text(snapshot_text(snapshot), encoding="utf-8")
        CONTRACT_TS.write_text(generate_ts(snapshot), encoding="utf-8")
        print(f"wrote {CONTRACT_JSON.relative_to(REPO_ROOT)} and {CONTRACT_TS.relative_to(REPO_ROOT)} "
              f"({len(snapshot['ws'])} commands, ws_hash {snapshot['ws_hash'][:12]})")
        return 0

    problems = drift(usage)
    if problems:
        print("ws contract drift:", file=sys.stderr)
        for p in problems:
            print(" - " + p, file=sys.stderr)
        print(f"fix: rebuild, then {REGENERATE}; then make web/src/util/webSocketCommands.ts follow "
              "(pnpm --dir web typecheck names the commands that disagree)", file=sys.stderr)
        return 1
    print("ws contract: committed files match" + (" the build's usage module" if usage is not None else " each other"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
