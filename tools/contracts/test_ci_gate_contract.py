"""Contract: push CI on main skips only trees CI already tested, and fails open (#185).

`.github/scripts/ci_gate.py` decides; these tests drive its decision logic against a fake GitHub API, and check the
workflow wiring and the release.toml commit messages it relies on.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("ci_gate", REPO_ROOT / ".github/scripts/ci_gate.py")
ci_gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ci_gate)

RUNS = "actions/workflows/build_and_test.yml/runs?head_sha="


class FakeGitHub:
    """Commits with trees and parents, merged PRs, workflow runs with their build job conclusion, and tags."""

    def __init__(self) -> None:
        self.commits: dict[str, dict] = {}
        self.pulls: dict[str, list[dict]] = {}
        self.runs: dict[str, list[tuple[str, str]]] = {}  # sha -> [(event, build job conclusion)]
        self.tags: dict[str, str] = {}
        self.diffs: dict[tuple[str, str], list[dict]] = {}  # (base, head) -> compare API files

    def bump(self, base: str, head: str, old: str = "1.2.2", new: str = "1.2.3", extra: list[dict] = ()) -> None:
        """A `vlr cut` diff: VERSION, meson.build and web/package.json change only their version lines."""
        self.diffs[(base, head)] = [
            {"filename": "VERSION", "status": "modified", "patch": f"@@ -1 +1 @@\n-{old}\n+{new}"},
            {"filename": "meson.build", "status": "modified",
             "patch": f"@@ -1,3 +1,3 @@\n project('vaulthalla', 'cpp',\n-  version: '{old}',\n+  version: '{new}',"},
            {"filename": "web/package.json", "status": "modified",
             "patch": f'@@ -2,3 +2,3 @@\n   "name": "web",\n-  "version": "{old}",\n+  "version": "{new}",'},
            *extra,
        ]

    def commit(self, sha: str, tree: str, *parents: str) -> None:
        self.commits[sha] = {"tree": {"sha": tree}, "parents": [{"sha": p} for p in parents]}

    def run(self, sha: str, event: str, build: str = "success") -> None:
        self.runs.setdefault(sha, []).append((event, build))

    def __call__(self, path: str):
        if path.startswith("git/commits/"):
            return self.commits.get(path.removeprefix("git/commits/"))
        if path.startswith("commits/") and path.endswith("/pulls"):
            return self.pulls.get(path.split("/")[1], [])
        if path.startswith(RUNS):
            query = dict(part.split("=", 1) for part in path.split("?", 1)[1].split("&"))
            sha, event = query["head_sha"], query.get("event")
            runs = [
                {"id": f"{sha}:{i}"}
                for i, (run_event, _) in enumerate(self.runs.get(sha, []))
                if event is None or run_event == event
            ]
            return {"workflow_runs": runs}
        if path.startswith("actions/runs/"):
            sha, index = path.split("/")[2].split(":")
            conclusion = self.runs[sha][int(index)][1]
            return {"jobs": [{"name": "build", "conclusion": conclusion}, {"name": "gate", "conclusion": "success"}]}
        if path.startswith("compare/"):
            base, head = path.removeprefix("compare/").split("...")
            return {"files": self.diffs.get((base, head), [])}
        if path.startswith("git/ref/tags/"):
            tag = path.removeprefix("git/ref/tags/")
            if tag not in self.tags:
                return None
            return {"object": {"type": "tag", "sha": f"tagobj-{tag}"}}
        if path.startswith("git/tags/tagobj-"):
            return {"object": {"type": "commit", "sha": self.tags[path.removeprefix("git/tags/tagobj-")]}}
        raise AssertionError(f"unexpected API call {path}")


def push(head: str, message: str, commits: int = 1, **extra) -> dict:
    return {"after": head, "head_commit": {"id": head, "message": message}, "commits": [{}] * commits, **extra}


class CiGateDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gh = FakeGitHub()
        gh = self.gh
        gh.commit("main0", "T0")
        gh.commit("prhead", "T1", "main0")
        gh.commit("merge", "T1", "main0", "prhead")  # an up-to-date PR: the merge lands the PR head's tree
        gh.pulls["merge"] = [{"number": 7, "merged_at": "2026-10-10T00:00:00Z", "base": {"ref": "main"},
                              "head": {"sha": "prhead"}}]
        gh.run("prhead", "pull_request")

    def decide(self, event: dict, name: str = "push") -> tuple[bool, str]:
        return ci_gate.decide(name, event, self.gh, ci_gate.version_files())

    def cut(self, parent: str = "merge", **bump) -> None:
        self.gh.commit("cut", "T3", parent)
        self.gh.tags["v1.2.3"] = "cut"
        self.gh.bump(parent, "cut", **bump)

    def test_pull_requests_always_build(self) -> None:
        self.assertEqual(self.decide({}, "pull_request")[0], True)

    def test_merge_of_a_tested_up_to_date_pr_skips(self) -> None:
        run, reason = self.decide(push("merge", "Merge pull request #7 from vaulthalla/x", commits=3))
        self.assertFalse(run)
        self.assertIn("PR #7", reason)

    def test_merge_whose_tree_ci_never_tested_builds(self) -> None:
        self.gh.commit("merge", "T2", "main0", "prhead")  # main moved and the branch wasn't updated
        self.assertTrue(self.decide(push("merge", "Merge pull request #7", commits=3))[0])

    def test_merge_of_a_pr_whose_build_failed_or_never_ran_builds(self) -> None:
        self.gh.runs["prhead"] = [("pull_request", "failure")]
        self.assertTrue(self.decide(push("merge", "Merge pull request #7", commits=3))[0])
        self.gh.runs["prhead"] = []
        self.assertTrue(self.decide(push("merge", "Merge pull request #7", commits=3))[0])

    def test_direct_push_builds(self) -> None:
        self.gh.commit("direct", "T9", "main0")
        self.assertTrue(self.decide(push("direct", "fix: something"))[0])

    def test_force_push_and_deletion_build(self) -> None:
        self.assertTrue(self.decide(push("merge", "Merge pull request #7", forced=True))[0])
        self.assertTrue(self.decide(push("merge", "Merge pull request #7", deleted=True))[0])

    def test_release_cut_on_a_tested_parent_skips(self) -> None:
        self.cut()
        run, reason = self.decide(push("cut", "chore(release): v1.2.3"))
        self.assertFalse(run)
        self.assertIn("only a version bump", reason)

    def test_release_commit_carrying_real_changes_builds(self) -> None:
        # `vlr cut` (no --push), `git commit --amend` with code, `vlr cut X.Y.Z --push`: the resume path pushes the
        # amended commit under the release subject, tagged. Only its content gives it away.
        code = {"filename": "core/src/main.cpp", "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+b"}
        self.cut(extra=[code])
        run, reason = self.decide(push("cut", "chore(release): v1.2.3"))
        self.assertTrue(run)
        self.assertIn("core/src/main.cpp", reason)

    def test_version_file_edits_beyond_the_version_line_build(self) -> None:
        self.cut()
        meson = self.gh.diffs[("merge", "cut")][1]
        meson["patch"] += "\n-  default_options: ['warning_level=3'],\n+  default_options: ['warning_level=1'],"
        self.assertTrue(self.decide(push("cut", "chore(release): v1.2.3"))[0])
        self.gh.bump("merge", "cut", new="1.2.4")  # bumped to a version other than the tag's
        self.assertTrue(self.decide(push("cut", "chore(release): v1.2.3"))[0])
        self.gh.diffs[("merge", "cut")] = []  # compare API gave nothing back
        self.assertTrue(self.decide(push("cut", "chore(release): v1.2.3"))[0])

    def test_version_files_come_from_release_toml(self) -> None:
        self.assertEqual(ci_gate.version_files(), {"VERSION", "meson.build", "web/package.json"})

    def test_release_cut_needs_its_tag_one_commit_and_a_tested_parent(self) -> None:
        self.gh.commit("cut", "T3", "merge")
        self.gh.bump("merge", "cut")
        self.assertTrue(self.decide(push("cut", "chore(release): v1.2.3"))[0], "no tag")
        self.gh.tags["v1.2.3"] = "elsewhere"
        self.assertTrue(self.decide(push("cut", "chore(release): v1.2.3"))[0], "tag on another commit")
        self.gh.tags["v1.2.3"] = "cut"
        self.assertTrue(self.decide(push("cut", "chore(release): v1.2.3", commits=2))[0], "untested commit along")
        self.gh.commit("direct", "T9", "main0")
        self.gh.commit("cut", "T3", "direct")
        self.gh.bump("direct", "cut")
        self.assertTrue(self.decide(push("cut", "chore(release): v1.2.3"))[0], "parent never passed CI")
        self.gh.run("direct", "push")
        self.assertFalse(self.decide(push("cut", "chore(release): v1.2.3"))[0], "parent passed push CI")

    def test_a_gated_skip_is_not_a_passing_build(self) -> None:
        self.gh.commit("direct", "T9", "main0")
        self.gh.run("direct", "push", build="skipped")
        self.cut(parent="direct")
        self.assertTrue(self.decide(push("cut", "chore(release): v1.2.3"))[0])

    def test_finalize_record_is_not_treated_as_a_cut(self) -> None:
        self.gh.commit("record", "T4", "merge")
        self.gh.tags["v1.2.3"] = "record"
        self.assertTrue(self.decide(push("record", "chore(release): record v1.2.3 [skip ci]"))[0])

    def test_api_errors_fail_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            event_path = Path(tmp, "event.json")
            event_path.write_text(json.dumps(push("merge", "Merge pull request #7")))
            output = Path(tmp, "output")
            env = {"GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_PATH": str(event_path), "GITHUB_OUTPUT": str(output),
                   "GITHUB_REPOSITORY": "vaulthalla/server", "GH_TOKEN": "x"}

            def broken(*_args, **_kwargs):
                raise OSError("network down")

            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(ci_gate, "github_api",
                                                                                 lambda *a: broken), \
                    mock.patch("sys.stdout", io.StringIO()):
                self.assertEqual(ci_gate.main(), 0)
            self.assertEqual(output.read_text(), "run=true\n")


class CiGateWiringTests(unittest.TestCase):
    ci = (REPO_ROOT / ".github/workflows/build_and_test.yml").read_text(encoding="utf-8")
    release = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    def test_gate_runs_only_on_pushes_off_the_vps(self) -> None:
        gate = self.ci.split("\n  gate:\n", 1)[1].split("\n  build:\n", 1)[0]
        self.assertIn("if: github.event_name == 'push'", gate)
        self.assertIn("runs-on: ubuntu-latest", gate)
        self.assertIn("python3 .github/scripts/ci_gate.py", gate)
        for permission in ("contents: read", "actions: read", "pull-requests: read"):
            self.assertIn(permission, gate)
        self.assertNotIn("write", gate)

    def test_build_jobs_fail_open_when_the_gate_is_skipped_or_fails(self) -> None:
        # PR events skip the gate; an errored gate has no output. Both must still build: only an explicit `false`
        # skips, and `!cancelled()` keeps a skipped/failed dependency from skipping the build.
        condition = "if: ${{ !cancelled() && needs.gate.outputs.run != 'false' }}"
        for job in ("build", "tooling"):
            block = self.ci.split(f"\n  {job}:\n", 1)[1].split("\n  tooling:\n", 1)[0]
            with self.subTest(job=job):
                self.assertIn("needs: gate", block)
                self.assertIn(condition, block)

    def test_finalize_skips_ci_but_the_tagged_cut_commit_never_does(self) -> None:
        release = tomllib.loads((REPO_ROOT / "release.toml").read_text(encoding="utf-8"))["release"]
        self.assertIn("[skip ci]", release["finalize_commit_message"])
        self.assertIn("{version}", release["finalize_commit_message"])
        # A skip marker on the tagged commit would skip release.yml's tag push too; the gate matches this subject.
        cut = release.get("cut_commit_message", "chore(release): v{version}")
        self.assertEqual(cut, "chore(release): v{version}")
        self.assertRegex(cut.format(version="1.2.3"), ci_gate.CUT_SUBJECT)

    def test_release_builds_the_web_app_once(self) -> None:
        web_verify = self.release.split("\n  web-verify:\n", 1)[1].split("\n  docs-validate:\n", 1)[0]
        self.assertNotIn("build_web", web_verify)
        self.assertIn("./.github/actions/test_web", web_verify)
        # build_web used to sync the licensed icons for this job; without them the typecheck fails (v1.11.0's
        # first release run). Every job that typechecks must sync them first.
        self.assertLess(web_verify.index("./.github/actions/sync_web_icons"), web_verify.index("./.github/actions/test_web"))
        artifacts = self.release.split("\n  release-artifacts:\n", 1)[1].split("\n  publish-debian:\n", 1)[0]
        self.assertLess(artifacts.index("vlr build-deb"), artifacts.index("pnpm --dir web budgets"))


if __name__ == "__main__":
    unittest.main()
