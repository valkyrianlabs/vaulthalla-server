#!/usr/bin/env python3
"""Reconcile the Vaulthalla GitHub Project board to .github/project/schema.yml.

Every command is a dry run unless --apply is given. Mutating the production board
(schema `project`) additionally needs --production.

  snapshot      dump board fields, views, workflows and items as JSON (backup before changes)
  apply         reconcile fields, options and views; --labels also reconciles repo labels;
                --delete-retired deletes retire_fields once their guards pass
  migrate       move items off retired options (schema retire_options) and seed empty
                Hazards/Proof from area:* labels; --issue-writes adds the retired options'
                labels to issues (public repo writes)
  lint          check open items against the Ready gate and flag stale claims (read-only)
  seed-sandbox  copy items and their field values from --from into a private sandbox
                project and strip its built-in workflows (rehearsal only)
  transfer      rebuild a board in another owner's project from a `snapshot` file: issues and
                pull requests (node ids survive repository transfers), drafts, field values,
                issue types and item order; idempotent, so a partial run can be repeated

Needs gh authenticated with the `project` scope (plus repo for labels).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import subprocess
import sys
import time

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA = ROOT / ".github/project/schema.yml"

DATA_TYPES = {"single_select": "SINGLE_SELECT", "multi_select": "MULTI_SELECT",
              "text": "TEXT", "date": "DATE", "number": "NUMBER"}
LAYOUTS = {"table": "TABLE_LAYOUT", "board": "BOARD_LAYOUT", "roadmap": "ROADMAP_LAYOUT"}
AUTONOMY_ORDER = ["Autonomous", "Checkpointed", "Assist only", "Human only"]
STALE_CLAIM_DAYS = 7


# ---------------------------------------------------------------- GitHub access

class GitHub:
    def __init__(self, apply: bool):
        self.apply = apply
        self.writes = 0

    def query(self, q: str, **variables):
        body = json.dumps({"query": q, "variables": variables})
        for attempt in range(6):
            proc = subprocess.run(["gh", "api", "graphql", "--input", "-"], input=body,
                                  capture_output=True, text=True)
            if proc.returncode == 0:
                return json.loads(proc.stdout)["data"]
            err = proc.stderr.strip() or proc.stdout.strip()
            # Bulk writes (transfer) trip GitHub's secondary rate limit; it clears within a minute or two.
            if "secondary rate limit" not in err.lower() or attempt == 5:
                raise SystemExit(f"graphql error: {err}")
            time.sleep(30 * (attempt + 1))

    def mutate(self, desc: str, q: str, **variables):
        print(("  WRITE " if self.apply else "  would ") + desc)
        self.writes += 1
        return self.query(q, **variables) if self.apply else None

    def run(self, desc: str, argv: list[str]):
        print(("  WRITE " if self.apply else "  would ") + desc)
        self.writes += 1
        if self.apply:
            subprocess.run(argv, check=True, capture_output=True, text=True)


BOARD_Q = """
query($owner:String!, $number:Int!) { organization(login:$owner) { projectV2(number:$number) {
  id number title public
  fields(first:100) { nodes { __typename
    ... on ProjectV2Field { id name dataType }
    ... on ProjectV2IterationField { id name dataType configuration {
      iterations { id title } completedIterations { id title } } }
    ... on ProjectV2SingleSelectField { id name dataType options { id name color description } }
    ... on ProjectV2MultiSelectField { id name dataType multiSelectOptions { id name color description } } } }
  views(first:50) { nodes { id number name layout filter
    fields(first:50) { nodes { ... on ProjectV2FieldCommon { id name } } } } }
  workflows(first:50) { nodes { id name enabled } }
} } }"""

ITEMS_Q = """
query($id:ID!, $after:String) { node(id:$id) { ... on ProjectV2 {
  items(first:100, after:$after) { pageInfo { hasNextPage endCursor } nodes { id
    fieldValues(first:50) { nodes { __typename
      ... on ProjectV2ItemFieldSingleSelectValue { name field { ... on ProjectV2FieldCommon { name } } }
      ... on ProjectV2ItemFieldMultiSelectValue { options { name } field { ... on ProjectV2FieldCommon { name } } }
      ... on ProjectV2ItemFieldTextValue { text field { ... on ProjectV2FieldCommon { name } } }
      ... on ProjectV2ItemFieldDateValue { date field { ... on ProjectV2FieldCommon { name } } }
      ... on ProjectV2ItemFieldNumberValue { number field { ... on ProjectV2FieldCommon { name } } }
      ... on ProjectV2ItemFieldIterationValue { title field { ... on ProjectV2FieldCommon { name } } } } }
    content { __typename
      ... on Issue { id number title state body issueType { name } labels(first:50) { nodes { name } }
                     repository { nameWithOwner }
                     subIssues { totalCount } blockedBy(first:20) { nodes { state } } }
      ... on PullRequest { id number title state repository { nameWithOwner } }
      ... on DraftIssue { id title body } } } } } } }"""


def load_board(gh: GitHub, owner: str, number: int) -> dict:
    p = gh.query(BOARD_Q, owner=owner, number=number)["organization"]["projectV2"]
    if p is None:
        raise SystemExit(f"project {owner}#{number} not found")
    fields = {}
    for f in p["fields"]["nodes"]:
        opts = f.get("options") or f.get("multiSelectOptions")
        fields[f["name"]] = {"id": f["id"], "dataType": f["dataType"], "options": opts}
        if f.get("configuration"):
            cfg = f["configuration"]
            fields[f["name"]]["iterations"] = {i["title"]: i["id"]
                                               for i in cfg["iterations"] + cfg["completedIterations"]}
    views = {v["name"]: {"id": v["id"], "layout": v["layout"], "filter": v["filter"] or "",
                         "fields": [x["name"] for x in v["fields"]["nodes"] if x]}
             for v in p["views"]["nodes"]}
    return {"id": p["id"], "number": p["number"], "title": p["title"], "public": p["public"],
            "fields": fields, "views": views, "workflows": p["workflows"]["nodes"]}


def load_items(gh: GitHub, project_id: str) -> list[dict]:
    items, after = [], None
    while True:
        page = gh.query(ITEMS_Q, id=project_id, after=after)["node"]["items"]
        items += [normalize_item(n) for n in page["nodes"]]
        if not page["pageInfo"]["hasNextPage"]:
            return items
        after = page["pageInfo"]["endCursor"]


def normalize_item(n: dict) -> dict:
    values = {}
    for v in n["fieldValues"]["nodes"]:
        if not v or not v.get("field"):
            continue
        name = v["field"]["name"]
        kind = v["__typename"]
        if kind.endswith("SingleSelectValue"):
            values[name] = v["name"]
        elif kind.endswith("MultiSelectValue"):
            values[name] = [o["name"] for o in v["options"]]
        elif kind.endswith("TextValue"):
            values[name] = v["text"]
        elif kind.endswith("DateValue"):
            values[name] = v["date"]
        elif kind.endswith("NumberValue"):
            values[name] = v["number"]
        elif kind.endswith("IterationValue"):
            values[name] = v["title"]
    c = n["content"] or {"__typename": "Unknown"}
    return {
        "id": n["id"], "kind": c["__typename"], "content_id": c.get("id"),
        "repo": (c.get("repository") or {}).get("nameWithOwner"),
        "number": c.get("number"), "title": c.get("title", ""),
        "open": c.get("state", "OPEN") == "OPEN", "body": c.get("body") or "",
        "issue_type": (c.get("issueType") or {}).get("name"),
        "labels": sorted(x["name"] for x in (c.get("labels") or {}).get("nodes", [])),
        "sub_issues": (c.get("subIssues") or {}).get("totalCount", 0),
        "open_blockers": sum(1 for b in (c.get("blockedBy") or {}).get("nodes", []) if b["state"] == "OPEN"),
        "values": values,
    }


def ref(item: dict) -> str:
    return f"#{item['number']}" if item["number"] else f"draft '{item['title'][:40]}'"


# ---------------------------------------------------------------- pure planning

def option_usage(items: list[dict]) -> dict[tuple[str, str], int]:
    usage: dict[tuple[str, str], int] = {}
    for it in items:
        for field, val in it["values"].items():
            for v in (val if isinstance(val, list) else [val]):
                if isinstance(v, str):
                    usage[(field, v)] = usage.get((field, v), 0) + 1
    return usage


def find_field(board: dict, spec: dict) -> tuple[str, dict] | tuple[None, None]:
    for name in [spec["name"], *spec.get("renamed_from", [])]:
        if name in board["fields"]:
            return name, board["fields"][name]
    return None, None


def plan_options(spec: dict, existing: list[dict] | None, usage: dict, field_name: str | None):
    """Desired option list for a select field. Keeps ids of matched options so values survive.

    Retired options stay while in use; unknown options are never dropped (warned instead).
    Returns (options, warnings).
    """
    existing = existing or []
    by_name = {o["name"]: o for o in existing}
    retired = spec.get("retire_options", {})
    out, kept, warnings = [], set(), []
    for opt in spec["options"]:
        entry = {"name": opt["name"], "color": opt["color"], "description": opt.get("description", "")}
        for n in [opt["name"], *opt.get("renamed_from", [])]:
            if n in by_name and by_name[n]["id"] not in kept:
                entry["id"] = by_name[n]["id"]
                kept.add(entry["id"])
                break
        out.append(entry)
    for o in existing:
        if o["id"] in kept:
            continue
        used = usage.get((field_name, o["name"]), 0)
        if o["name"] in retired and not used:
            continue
        reason = (f"retired option '{o['name']}' still on {used} item(s); run migrate"
                  if o["name"] in retired else f"option '{o['name']}' is not in the schema; kept")
        warnings.append(f"{spec['name']}: {reason}")
        out.append({"id": o["id"], "name": o["name"], "color": o["color"], "description": o["description"] or ""})
    return out, warnings


def options_differ(desired: list[dict], existing: list[dict] | None) -> bool:
    key = lambda o: (o.get("id"), o["name"], o["color"], o.get("description") or "")
    return [key(o) for o in desired] != [key(o) for o in (existing or [])]


def expand_filter(flt: str, schema: dict) -> str:
    for domain in {a["domain"] for a in schema["areas"].values()}:
        token = "{areas:%s}" % domain
        if token in flt:
            names = ",".join(f'"area:{k}"' for k, a in schema["areas"].items() if a["domain"] == domain)
            flt = flt.replace(token, f"label:{names}")
    return flt


def item_areas(item: dict, schema: dict) -> list[str]:
    return [l[len("area:"):] for l in item["labels"] if l.startswith("area:") and l[len("area:"):] in schema["areas"]]


def seeded_hazards_proof(areas: list[str], schema: dict) -> tuple[list[str], list[str]]:
    proof_specs = {o["name"]: o for o in field_spec(schema, "Proof")["options"]}
    proof = list(dict.fromkeys(p for a in areas for p in schema["areas"][a]["proof"]))
    hazards = list(dict.fromkeys([h for a in areas for h in schema["areas"][a]["hazards"]] +
                                 [h for p in proof for h in proof_specs[p].get("implies_hazards", [])]))
    order = [o["name"] for o in field_spec(schema, "Hazards")["options"]]
    porder = list(proof_specs)
    return (sorted(hazards, key=order.index) or ["none"]), sorted(proof, key=porder.index)


def autonomy_cap(hazards: list[str], schema: dict) -> str:
    caps = {o["name"]: o.get("max_autonomy") for o in field_spec(schema, "Hazards")["options"]}
    worst = 0
    for h in hazards:
        if caps.get(h):
            worst = max(worst, AUTONOMY_ORDER.index(caps[h]))
    return AUTONOMY_ORDER[worst]


def plan_item_migration(item: dict, schema: dict) -> dict:
    """What migrate would change for one issue. Pure; seeded fields are only set where empty.

    Moves the item off retired select options (schema retire_options), adding their labels, and
    on open items seeds empty Hazards/Proof from the issue's area:* labels.
    """
    plan = {"set": {}, "labels": [], "notes": []}
    for spec in schema["fields"]:
        cur = item["values"].get(spec["name"])
        r = spec.get("retire_options", {}).get(cur) if isinstance(cur, str) else None
        if r:
            plan["set"][spec["name"]] = r["to"]
            plan["labels"] += r.get("labels", [])
            if r.get("note"):
                plan["notes"].append(f"{spec['name']} {cur} -> {r['to']}: {r['note']}")
    areas = item_areas(item, schema)
    if item["open"] and areas:
        hazards, proof = seeded_hazards_proof(areas, schema)
        if not item["values"].get("Hazards"):
            plan["set"]["Hazards"] = hazards
        if not item["values"].get("Proof") and proof:
            plan["set"]["Proof"] = proof
    plan["labels"] = [l for l in dict.fromkeys(plan["labels"]) if l not in item["labels"]]
    return plan


def lint_item(item: dict, schema: dict, today: dt.date) -> list[str]:
    gate, v, problems = schema["ready_gate"], item["values"], []
    status = v.get("Status")
    if status == "Ready":
        if gate.get("require_issue_type") and not item["issue_type"]:
            problems.append("no issue type")
        if gate.get("require_area_label") and not any(l.startswith("area:") for l in item["labels"]):
            problems.append("no area:* label")
        problems += [f"{f} unset" for f in gate["require_fields"] if not v.get(f)]
        if v.get("Size") in gate.get("forbid_sizes", []):
            problems.append(f"Size {v['Size']} must be split before Ready")
        if v.get("Size") in gate.get("require_sub_issues_for_sizes", []) and not item["sub_issues"]:
            problems.append(f"Size {v['Size']} without sub-issues")
        problems += [f"has {l}" for l in item["labels"] if l in gate.get("forbid_labels", [])]
        if gate.get("forbid_open_blockers") and item["open_blockers"]:
            problems.append(f"{item['open_blockers']} open blocker(s)")
        wanted = gate.get("require_body_heading_any") or []
        if wanted and not has_heading(item["body"], wanted):
            problems.append(f"no {' / '.join(wanted)} section")
        cap = autonomy_cap(v.get("Hazards") or [], schema)
        if v.get("Autonomy") and AUTONOMY_ORDER.index(v["Autonomy"]) < AUTONOMY_ORDER.index(cap):
            problems.append(f"Autonomy {v['Autonomy']} exceeds hazard cap {cap}")
    if "none" in (v.get("Hazards") or []) and len(v["Hazards"]) > 1:
        problems.append("Hazards has 'none' plus other hazards")
    if status == "Claimed":
        touched = v.get("Last touched")
        if not v.get("Agent") and not touched:
            problems.append("Claimed without Agent or Last touched")
        elif touched and (today - dt.date.fromisoformat(touched)).days > STALE_CLAIM_DAYS:
            problems.append(f"stale claim (last touched {touched})")
    return problems


def has_heading(body: str, prefixes: list[str]) -> bool:
    headings = [m.group(1).strip().lower() for m in re.finditer(r"^#{1,6}\s+(.+)$", body, re.M)]
    return any(h.startswith(p.lower()) for h in headings for p in prefixes)


def field_spec(schema: dict, name: str) -> dict:
    return next(f for f in schema["fields"] if f["name"] == name)


# ---------------------------------------------------------------- commands

def guard_mutation(args, schema: dict, number: int):
    if args.apply and number == schema["project"] and not args.production:
        raise SystemExit(f"refusing to mutate production project #{number} without --production")


def cmd_snapshot(gh, schema, args):
    board = load_board(gh, args.owner, args.project)
    board["items"] = load_items(gh, board["id"])
    json.dump(board, sys.stdout, indent=1)
    print()


def cmd_apply(gh, schema, args):
    guard_mutation(args, schema, args.project)
    board = load_board(gh, args.owner, args.project)
    items = load_items(gh, board["id"])
    usage = option_usage(items)
    print(f"[apply] {board['title']} (#{board['number']}, {len(items)} items)"
          f"{'' if gh.apply else ' -- dry run'}")
    warnings = []

    print("fields:")
    for spec in schema["fields"]:
        current_name, cur = find_field(board, spec)
        dtype = DATA_TYPES[spec["type"]]
        select_key = {"single_select": "singleSelectOptions", "multi_select": "multiSelectOptions"}.get(spec["type"])
        if cur is None:
            variables = {"input": {"projectId": board["id"], "dataType": dtype, "name": spec["name"]}}
            if select_key:
                opts, _ = plan_options(spec, None, usage, None)
                variables["input"][select_key] = opts
            gh.mutate(f"create field {spec['name']} ({dtype})",
                      "mutation($input:CreateProjectV2FieldInput!){createProjectV2Field(input:$input){clientMutationId}}",
                      **variables)
            continue
        if cur["dataType"] != dtype:
            warnings.append(f"{current_name}: is {cur['dataType']}, schema wants {dtype}; not converted")
            continue
        update = {}
        if current_name != spec["name"]:
            update["name"] = spec["name"]
        if select_key:
            opts, w = plan_options(spec, cur["options"], usage, current_name)
            warnings += w
            if options_differ(opts, cur["options"]):
                update[select_key] = opts
        if update:
            what = ", ".join(f"rename {current_name} -> {spec['name']}" if k == "name" else "options" for k in update)
            gh.mutate(f"update field {current_name}: {what}",
                      "mutation($input:UpdateProjectV2FieldInput!){updateProjectV2Field(input:$input){clientMutationId}}",
                      input={"fieldId": cur["id"], **update})

    if gh.apply:
        board = load_board(gh, args.owner, args.project)

    print("views:")
    for spec in schema["views"]:
        flt = expand_filter(spec["filter"], schema)
        missing = [f for f in spec["fields"] if f not in board["fields"]]
        if missing:
            warnings.append(f"view {spec['name']}: unknown fields {missing}" +
                            ("" if gh.apply else " (expected in a dry run if apply would create them)"))
            continue
        field_ids = [board["fields"][f]["id"] for f in spec["fields"]]
        layout = LAYOUTS[spec["layout"]]
        cur = board["views"].get(spec["name"])
        if cur is None:
            res = gh.mutate(f"create view {spec['name']} ({spec['layout']})",
                            "mutation($input:CreateProjectV2ViewInput!){createProjectV2View(input:$input){projectV2View{id}}}",
                            input={"projectId": board["id"], "name": spec["name"], "layout": layout,
                                   "configuration": {"visibleFieldIds": field_ids}})
            view_id = res["createProjectV2View"]["projectV2View"]["id"] if res else None
            if flt:
                gh.mutate(f"set view {spec['name']} filter: {flt}",
                          "mutation($input:UpdateProjectV2ViewInput!){updateProjectV2View(input:$input){clientMutationId}}",
                          input={"viewId": view_id, "filter": flt})
        else:
            update = {}
            if cur["layout"] != layout:
                update["layout"] = layout
            if cur["filter"] != flt:
                update["filter"] = flt
            if set(cur["fields"]) != set(spec["fields"]):  # GitHub imposes its own column order
                update["configuration"] = {"visibleFieldIds": field_ids}
            if update:
                gh.mutate(f"update view {spec['name']}: {', '.join(update)}"
                          + (f" (filter: {flt})" if "filter" in update else ""),
                          "mutation($input:UpdateProjectV2ViewInput!){updateProjectV2View(input:$input){clientMutationId}}",
                          input={"viewId": cur["id"], **update})
    for name in board["views"]:
        if name not in {v["name"] for v in schema["views"]}:
            warnings.append(f"view {name}: not in schema; left alone")

    if args.labels:
        print("labels:")
        existing = {l["name"]: l for l in json.loads(subprocess.run(
            ["gh", "label", "list", "-R", schema["repo"], "--limit", "500", "--json", "name,color,description"],
            check=True, capture_output=True, text=True).stdout)}
        wanted = {f"area:{k}": {"color": schema["label_color"], "description": a["description"][:100]}
                  for k, a in schema["areas"].items()}
        wanted.update(schema.get("labels", {}))
        for name, spec in wanted.items():
            cur = existing.get(name)
            if cur and cur["color"].lower() == spec["color"].lower() and cur["description"] == spec["description"]:
                continue
            gh.run(f"{'update' if cur else 'create'} label {name}",
                   ["gh", "label", "create", name, "-R", schema["repo"], "--color", spec["color"],
                    "--description", spec["description"], "--force"])

    if args.delete_retired:
        print("retired fields:")
        for name, spec in schema.get("retire_fields", {}).items():
            cur = board["fields"].get(name)
            if not cur:
                continue
            if spec.get("guard") == "area_label":
                valued = [i for i in items if i["open"] and i["values"].get(name)]
                warnings += [f"{name}: {ref(i)} is a draft (no labels); its {name} value is lost on delete"
                             for i in valued if i["kind"] == "DraftIssue"]
                blocking = [ref(i) for i in valued if i["kind"] == "Issue"
                            and not any(l.startswith("area:") for l in i["labels"])]
                if blocking:
                    warnings.append(f"{name}: not deleted; open items without area:* label: {', '.join(blocking)}")
                    continue
            gh.mutate(f"delete field {name} ({spec['reason']})",
                      "mutation($id:ID!){deleteProjectV2Field(input:{fieldId:$id}){clientMutationId}}", id=cur["id"])

    have_types = {n["name"] for n in gh.query(
        "query($o:String!){organization(login:$o){issueTypes(first:50){nodes{name}}}}",
        o=args.owner)["organization"]["issueTypes"]["nodes"]}
    for t in schema["issue_types"]:
        if t not in have_types:
            warnings.append(f"issue type {t} missing in org {args.owner} (create it in org settings)")

    print("set by hand in the web UI (no API):")
    for spec in schema["views"]:
        for k, v in (spec.get("ui") or {}).items():
            print(f"  - {spec['name']}: {k.replace('_', ' ')} = {v}")
    report(warnings, gh)


def cmd_migrate(gh, schema, args):
    guard_mutation(args, schema, args.project)
    board = load_board(gh, args.owner, args.project)
    absent = [f["name"] for f in schema["fields"] if f["name"] not in board["fields"]]
    if absent:
        raise SystemExit(f"run apply first; missing fields: {absent}")
    items = load_items(gh, board["id"])
    print(f"[migrate] {board['title']} (#{board['number']}, {len(items)} items)"
          f"{'' if gh.apply else ' -- dry run'}{'' if args.issue_writes else ', no issue writes'}")
    notes = []
    for item in items:
        if item["kind"] != "Issue":
            notes.append(f"{ref(item)}: {item['kind']} skipped")
            continue
        plan = plan_item_migration(item, schema)
        if not (plan["set"] or plan["labels"] or plan["notes"]):
            continue
        print(f"{ref(item)} {item['title'][:70]}")
        for fname, val in plan["set"].items():
            f = board["fields"][fname]
            by_name = {o["name"]: o["id"] for o in f["options"]}
            value = ({"multiSelectOptionIds": [by_name[v] for v in val]} if isinstance(val, list)
                     else {"singleSelectOptionId": by_name[val]})
            gh.mutate(f"{fname} = {val}",
                      "mutation($p:ID!,$i:ID!,$f:ID!,$v:ProjectV2FieldValue!){updateProjectV2ItemFieldValue("
                      "input:{projectId:$p,itemId:$i,fieldId:$f,value:$v}){clientMutationId}}",
                      p=board["id"], i=item["id"], f=f["id"], v=value)
        if plan["labels"]:
            desc = f"add labels {', '.join(plan['labels'])}"
            if args.issue_writes:
                gh.run(desc, ["gh", "issue", "edit", str(item["number"]), "-R", schema["repo"],
                              "--add-label", ",".join(plan["labels"])])
            else:
                print(f"  skip  {desc} (needs --issue-writes)")
        notes += [f"{ref(item)}: {n}" for n in plan["notes"]]
    report(notes, gh)


def cmd_lint(gh, schema, args):
    board = load_board(gh, args.owner, args.project)
    items = load_items(gh, board["id"])
    today = dt.date.today()
    failures = 0
    for item in items:
        if not item["open"] or item["kind"] == "DraftIssue":
            continue
        problems = lint_item(item, schema, today)
        if problems:
            failures += 1
            print(f"{ref(item)} [{item['values'].get('Status', '-')}] {item['title'][:60]}")
            for p in problems:
                print(f"  - {p}")
    print(f"{failures} item(s) with problems")
    return 1 if failures else 0


def cmd_seed_sandbox(gh, schema, args):
    if args.project == schema["project"]:
        raise SystemExit("seed-sandbox never targets the production project")
    src = load_board(gh, args.owner, args.source)
    dst = load_board(gh, args.owner, args.project)
    if dst["public"]:
        raise SystemExit(f"sandbox #{dst['number']} is public; make it private first")
    print(f"[seed-sandbox] #{src['number']} -> #{dst['number']} {dst['title']}{'' if gh.apply else ' -- dry run'}")
    for wf in dst["workflows"]:
        gh.mutate(f"delete sandbox workflow '{wf['name']}'",
                  "mutation($id:ID!){deleteProjectV2Workflow(input:{workflowId:$id}){clientMutationId}}", id=wf["id"])
    have = {i["content_id"] for i in load_items(gh, dst["id"])}
    for item in load_items(gh, src["id"]):
        if item["kind"] not in ("Issue", "PullRequest") or item["content_id"] in have:
            continue
        if not (item["open"] or args.all):
            continue
        res = gh.mutate(f"add {ref(item)}",
                        "mutation($p:ID!,$c:ID!){addProjectV2ItemById(input:{projectId:$p,contentId:$c}){item{id}}}",
                        p=dst["id"], c=item["content_id"])
        new_id = res["addProjectV2ItemById"]["item"]["id"] if res else None
        copy_values(gh, dst, new_id, item)
    report([], gh)


def field_value(f: dict, val) -> dict | None:
    """The ProjectV2FieldValue for `val` (option/iteration names, text, date, number) in field `f`, or None."""
    if f["options"]:
        by_name = {o["name"]: o["id"] for o in f["options"]}
        vals = val if isinstance(val, list) else [val]
        if any(v not in by_name for v in vals):
            return None
        return ({"multiSelectOptionIds": [by_name[v] for v in vals]} if f["dataType"] == "MULTI_SELECT"
                else {"singleSelectOptionId": by_name[vals[0]]})
    if f["dataType"] == "ITERATION":
        return {"iterationId": f["iterations"][val]} if val in f.get("iterations", {}) else None
    if f["dataType"] in ("TEXT", "DATE", "NUMBER"):
        return {f["dataType"].lower(): val}
    return None


def copy_values(gh, dst: dict, item_id: str | None, item: dict) -> list[str]:
    """Set `item`'s field values on `item_id` in board `dst`, matched by field and option name.

    Returns the values that have no counterpart on `dst`. Value writes are not counted as writes.
    """
    missing = []
    for fname, val in item["values"].items():
        if fname == "Title":
            continue
        f = dst["fields"].get(fname)
        value = field_value(f, val) if f else None
        if value is None:
            missing.append(f"{ref(item)}: {fname}={val!r}")
            continue
        if gh.apply:
            gh.query("mutation($p:ID!,$i:ID!,$f:ID!,$v:ProjectV2FieldValue!){updateProjectV2ItemFieldValue("
                     "input:{projectId:$p,itemId:$i,fieldId:$f,value:$v}){clientMutationId}}",
                     p=dst["id"], i=item_id, f=f["id"], v=value)
    return missing


def cmd_transfer(gh, schema, args):
    snap = json.loads(args.snapshot.read_text())
    dst = load_board(gh, args.owner, args.project)
    if args.owner == schema["owner"]:
        guard_mutation(args, schema, dst["number"])
    if dst["id"] == snap["id"]:
        raise SystemExit("transfer needs a different target project than the snapshot's")
    print(f"[transfer] snapshot '{snap['title']}' ({len(snap['items'])} items) -> {args.owner}#{dst['number']} "
          f"{dst['title']}{'' if gh.apply else ' -- dry run'}")
    types = {t["name"]: t["id"] for t in gh.query(
        "query($o:String!){organization(login:$o){issueTypes(first:50){nodes{id name}}}}",
        o=args.owner)["organization"]["issueTypes"]["nodes"]}
    have = {}
    for i in load_items(gh, dst["id"]):
        have[i["content_id"] if i["kind"] != "DraftIssue" else ("draft", i["title"])] = i
    notes, prev = [], None
    for item in snap["items"]:
        if item["kind"] in ("Issue", "PullRequest"):
            key = item["content_id"]
        elif item["kind"] == "DraftIssue":
            key = ("draft", item["title"])
        else:
            notes.append(f"skipped {item['kind']} item '{item['title'][:40]}' (content not readable)")
            continue
        current = have.get(key)
        if current:
            item_id = current["id"]
        elif item["kind"] == "DraftIssue":
            res = gh.mutate(f"add {ref(item)}",
                            "mutation($p:ID!,$t:String!,$b:String){addProjectV2DraftIssue("
                            "input:{projectId:$p,title:$t,body:$b}){projectItem{id}}}",
                            p=dst["id"], t=item["title"], b=item["body"])
            item_id = res["addProjectV2DraftIssue"]["projectItem"]["id"] if res else None
        else:
            res = gh.mutate(f"add {ref(item)}",
                            "mutation($p:ID!,$c:ID!){addProjectV2ItemById(input:{projectId:$p,contentId:$c}){item{id}}}",
                            p=dst["id"], c=item["content_id"])
            item_id = res["addProjectV2ItemById"]["item"]["id"] if res else None
        # Values already on the target win only when they match; the snapshot is the source of truth.
        stale = {k: v for k, v in item["values"].items() if not current or current["values"].get(k) != v}
        notes += copy_values(gh, dst, item_id, {**item, "values": stale})
        if item["kind"] == "Issue" and item["issue_type"] and (not current or current["issue_type"] != item["issue_type"]):
            if item["issue_type"] not in types:
                notes.append(f"{ref(item)}: issue type {item['issue_type']} missing in org {args.owner}")
            else:
                gh.mutate(f"type {ref(item)} {item['issue_type']}",
                          "mutation($i:ID!,$t:ID!){updateIssue(input:{id:$i,issueTypeId:$t}){clientMutationId}}",
                          i=item["content_id"], t=types[item["issue_type"]])
        if gh.apply and item_id:
            gh.query("mutation($p:ID!,$i:ID!,$a:ID){updateProjectV2ItemPosition("
                     "input:{projectId:$p,itemId:$i,afterId:$a}){clientMutationId}}",
                     p=dst["id"], i=item_id, a=prev)
        prev = item_id
    report(notes, gh)


def report(notes: list[str], gh: GitHub):
    if notes:
        print("notes:")
        for n in notes:
            print(f"  ! {n}")
    print(f"{gh.writes} write(s) {'applied' if gh.apply else 'planned (dry run; pass --apply)'}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["snapshot", "apply", "migrate", "lint", "seed-sandbox", "transfer"])
    ap.add_argument("--schema", type=pathlib.Path, default=SCHEMA)
    ap.add_argument("--owner")
    ap.add_argument("--project", type=int, help="project number (default: schema project)")
    ap.add_argument("--apply", action="store_true", help="execute writes (default: dry run)")
    ap.add_argument("--production", action="store_true", help="allow writes to the schema's production project")
    ap.add_argument("--labels", action="store_true", help="apply: reconcile repo labels too")
    ap.add_argument("--delete-retired", action="store_true", help="apply: delete retire_fields")
    ap.add_argument("--issue-writes", action="store_true", help="migrate: add labels to issues")
    ap.add_argument("--source", type=int, help="seed-sandbox: project to copy items from")
    ap.add_argument("--all", action="store_true", help="seed-sandbox: include closed items")
    ap.add_argument("--snapshot", type=pathlib.Path, help="transfer: snapshot JSON to rebuild from")
    args = ap.parse_args(argv)
    schema = yaml.safe_load(args.schema.read_text())
    args.owner = args.owner or schema["owner"]
    args.project = args.project or schema["project"]
    if args.command == "seed-sandbox" and not args.source:
        ap.error("seed-sandbox needs --source")
    if args.command == "transfer" and not args.snapshot:
        ap.error("transfer needs --snapshot")
    gh = GitHub(apply=args.apply)
    cmd = {"snapshot": cmd_snapshot, "apply": cmd_apply, "migrate": cmd_migrate,
           "lint": cmd_lint, "seed-sandbox": cmd_seed_sandbox, "transfer": cmd_transfer}[args.command]
    return cmd(gh, schema, args) or 0


if __name__ == "__main__":
    sys.exit(main())
