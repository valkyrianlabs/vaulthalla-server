from __future__ import annotations

import datetime as dt
import unittest

import yaml

from tools.project import board

SCHEMA = yaml.safe_load(board.SCHEMA.read_text())


def item(number=1, open=True, values=None, labels=(), issue_type="Bug", body="## Acceptance\n- x",
         sub_issues=0, open_blockers=0):
    return {"id": f"I{number}", "kind": "Issue", "content_id": f"C{number}", "number": number,
            "title": f"issue {number}", "open": open, "body": body, "issue_type": issue_type,
            "labels": list(labels), "sub_issues": sub_issues, "open_blockers": open_blockers,
            "values": values or {}}


def opt(id, name, color="GRAY", description=""):
    return {"id": id, "name": name, "color": color, "description": description}


class SchemaConsistency(unittest.TestCase):
    def test_area_hazards_and_proof_are_real_options(self):
        hazards = {o["name"] for o in board.field_spec(SCHEMA, "Hazards")["options"]}
        proof = {o["name"] for o in board.field_spec(SCHEMA, "Proof")["options"]}
        for key, area in SCHEMA["areas"].items():
            self.assertLessEqual(set(area["hazards"]), hazards, key)
            self.assertLessEqual(set(area["proof"]), proof, key)
            self.assertTrue(area["proof"], f"{key} has no proof")

    def test_area_context_docs_exist(self):
        for key, area in SCHEMA["areas"].items():
            for doc in area["context"]:
                self.assertTrue((board.ROOT / doc).exists(), f"{key}: {doc}")

    def test_hazard_caps_and_implications_are_valid(self):
        hazards = {o["name"] for o in board.field_spec(SCHEMA, "Hazards")["options"]}
        for o in board.field_spec(SCHEMA, "Hazards")["options"]:
            if o.get("max_autonomy"):
                self.assertIn(o["max_autonomy"], board.AUTONOMY_ORDER)
        for o in board.field_spec(SCHEMA, "Proof")["options"]:
            self.assertLessEqual(set(o.get("implies_hazards", [])), hazards)

    def test_retire_targets_exist(self):
        for f in SCHEMA["fields"]:
            names = {o["name"] for o in f.get("options", [])}
            for old, r in f.get("retire_options", {}).items():
                self.assertIn(r["to"], names, f"{f['name']}.{old}")

    def test_view_fields_are_known(self):
        builtin = {"Title", "Assignees", "Status", "Labels", "Linked pull requests", "Sub-issues progress",
                   "Iteration", "Target date", "Start date", "Milestone", "Repository", "Reviewers"}
        custom = {f["name"] for f in SCHEMA["fields"]}
        for v in SCHEMA["views"]:
            self.assertLessEqual(set(v["fields"]), builtin | custom, v["name"])
            self.assertIn(v["layout"], board.LAYOUTS)


class PlanOptions(unittest.TestCase):
    spec = {"name": "Status", "options": [
        {"name": "Inbox", "color": "PINK"},
        {"name": "Claimed", "renamed_from": ["In progress"], "color": "YELLOW"},
        {"name": "Triaged", "color": "ORANGE"}],
        "retire_options": {"Blocked": {"to": "Triaged"}}}

    def test_rename_keeps_option_id(self):
        out, _ = board.plan_options(self.spec, [opt("a", "Inbox"), opt("b", "In progress")], {}, "Status")
        self.assertEqual([(o.get("id"), o["name"]) for o in out],
                         [("a", "Inbox"), ("b", "Claimed"), (None, "Triaged")])

    def test_retired_option_kept_while_in_use_dropped_after(self):
        existing = [opt("a", "Inbox"), opt("c", "Blocked")]
        out, warnings = board.plan_options(self.spec, existing, {("Status", "Blocked"): 1}, "Status")
        self.assertIn("c", [o.get("id") for o in out])
        self.assertTrue(any("run migrate" in w for w in warnings))
        out, warnings = board.plan_options(self.spec, existing, {}, "Status")
        self.assertNotIn("c", [o.get("id") for o in out])
        self.assertEqual(warnings, [])

    def test_unknown_option_is_never_dropped(self):
        out, warnings = board.plan_options(self.spec, [opt("z", "Mystery")], {}, "Status")
        self.assertIn("z", [o.get("id") for o in out])
        self.assertTrue(any("not in the schema" in w for w in warnings))

    def test_matching_options_are_not_rewritten(self):
        existing = [opt("a", "Inbox", "PINK"), opt("b", "Claimed", "YELLOW"), opt("t", "Triaged", "ORANGE")]
        out, _ = board.plan_options(self.spec, existing, {}, "Status")
        self.assertFalse(board.options_differ(out, existing))


class Filters(unittest.TestCase):
    def test_area_domain_token_expands_to_label_or(self):
        flt = board.expand_filter("{areas:web}", SCHEMA)
        self.assertEqual(flt, 'label:"area:web-ui"')
        core = board.expand_filter("{areas:core}", SCHEMA)
        self.assertIn('"area:fuse"', core)
        self.assertNotIn('"area:web-ui"', core)


class Migration(unittest.TestCase):
    def plan(self, **kw):
        return board.plan_item_migration(item(**kw), SCHEMA)

    def test_area_labels_seed_hazards_and_proof(self):
        p = self.plan(labels=["area:fuse", "bug"])
        # integration (make itest) is isolated now: FUSE work no longer implies a destructive local proof.
        self.assertEqual(p["set"]["Hazards"], ["fuse-blocking"])
        self.assertEqual(p["set"]["Proof"], ["core", "integration"])
        self.assertEqual(p["labels"], [])

    def test_area_without_hazards_seeds_none(self):
        self.assertEqual(self.plan(labels=["area:cli"])["set"]["Hazards"], ["none"])

    def test_retired_options_move_with_labels(self):
        p = self.plan(values={"Status": "Needs Repro", "Size": "Epic"})
        self.assertEqual(p["set"], {"Status": "Triaged", "Size": "XL"})
        self.assertEqual(p["labels"], ["needs:repro"])
        self.assertIn("Size Epic -> XL: split into sub-issues", p["notes"])

    def test_no_area_label_means_nothing_seeded(self):
        self.assertEqual(self.plan(labels=["bug", "area:unknown"])["set"], {})

    def test_never_overwrites_triaged_values_or_existing_labels(self):
        p = self.plan(labels=["area:cli", "needs:repro"],
                      values={"Status": "Needs Repro", "Hazards": ["migration"], "Proof": ["core"]})
        self.assertEqual(p["set"], {"Status": "Triaged"})
        self.assertEqual(p["labels"], [])

    def test_multi_select_values_are_not_retire_lookups(self):
        self.assertEqual(self.plan(values={"Hazards": ["none"], "Proof": ["core"]})["set"], {})

    def test_closed_items_only_leave_retired_options(self):
        self.assertEqual(self.plan(open=False, labels=["area:fuse"], values={"Size": "Epic"})["set"], {"Size": "XL"})


class Lint(unittest.TestCase):
    today = dt.date(2026, 10, 9)
    ready = {"Status": "Ready", "Priority": "P2", "Size": "S", "Clarity": "Known fix",
             "Autonomy": "Autonomous", "Hazards": ["none"], "Proof": ["core"]}

    def lint(self, **kw):
        return board.lint_item(item(**kw), SCHEMA, self.today)

    def test_complete_ready_item_passes(self):
        self.assertEqual(self.lint(values=self.ready, labels=["area:cli"]), [])

    def test_ready_gate_failures(self):
        problems = self.lint(values={**self.ready, "Size": "L", "Autonomy": "Autonomous",
                                     "Hazards": ["release-publish"]},
                             labels=["needs:repro"], issue_type=None, body="no headings", open_blockers=1)
        for expected in ("no issue type", "no area:* label", "Size L without sub-issues", "has needs:repro",
                         "1 open blocker(s)", "no Acceptance / Done when section",
                         "Autonomy Autonomous exceeds hazard cap Checkpointed"):
            self.assertIn(expected, problems)

    def test_none_hazard_must_stand_alone(self):
        self.assertIn("Hazards has 'none' plus other hazards",
                      self.lint(values={"Status": "Inbox", "Hazards": ["none", "migration"]}))

    def test_stale_claim(self):
        self.assertEqual(self.lint(values={"Status": "Claimed", "Agent": "a", "Last touched": "2026-10-05"}), [])
        self.assertIn("stale claim (last touched 2026-09-20)",
                      self.lint(values={"Status": "Claimed", "Agent": "a", "Last touched": "2026-09-20"}))

    def test_heading_match_is_prefix_on_markdown_headings(self):
        self.assertTrue(board.has_heading("x\n### Done when\n- y", ["Acceptance", "Done when"]))
        self.assertFalse(board.has_heading("acceptance is mentioned in prose", ["Acceptance"]))


if __name__ == "__main__":
    unittest.main()
