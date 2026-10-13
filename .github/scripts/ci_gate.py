#!/usr/bin/env python3
"""Decide whether a push to main needs the full CI build (#185).

A push to main skips the build when the exact tree it lands was already built and tested:

- a merged pull request whose head has the same tree as the pushed commit (the branch was up to date with main, so
  the PR run tested exactly these files) and a pull_request run of this workflow whose `build` job succeeded on it;
- a `vlr cut` release commit (`chore(release): vX.Y.Z`, the only commit in the push, tagged vX.Y.Z) on top of a
  covered parent, whose diff is purely the version bump: only release.toml's version files change, and every changed
  line is the old version replaced by the new one. release.yml builds the tagged commit. `vlr cut` resumes by
  pushing whatever commit is at HEAD, so a release commit amended with real changes keeps the subject; the content
  check sends it through the full build.

`vlr finalize` commits carry `[skip ci]` (release.toml `finalize_commit_message`), so GitHub never starts this
workflow for them. Direct pushes and anything the gate can't prove run the full build. Any error also runs it: the
gate can only save work, never skip a check it couldn't verify.

Writes `run=true|false` to $GITHUB_OUTPUT and the reason to the job summary. Standard library only.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

# The workflow and job whose pull_request run must have tested the tree: Linux CI by default; macos.yml passes its own.
WORKFLOW = os.environ.get("CI_GATE_WORKFLOW", "build_and_test.yml")
BUILD_JOB = os.environ.get("CI_GATE_JOB", "build")
CUT_SUBJECT = re.compile(r"^chore\(release\): v(\d+\.\d+\.\d+)$")
REPO_ROOT = Path(__file__).resolve().parents[2]

Api = Callable[[str], Any]


def github_api(repository: str, token: str, base: str = "https://api.github.com") -> Api:
    def get(path: str) -> Any:
        request = urllib.request.Request(
            f"{base}/repos/{repository}/{path}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise

    return get


def tree_of(api: Api, sha: str) -> str | None:
    commit = api(f"git/commits/{sha}")
    return commit["tree"]["sha"] if commit else None


def build_passed(api: Api, sha: str, event: str | None = None) -> bool:
    """A run of this workflow on `sha` whose build job really ran and succeeded (a gated skip doesn't count)."""
    query = f"actions/workflows/{WORKFLOW}/runs?head_sha={sha}&status=success&per_page=20"
    if event:
        query += f"&event={event}"
    runs = (api(query) or {}).get("workflow_runs", [])
    for run in runs:
        jobs = (api(f"actions/runs/{run['id']}/jobs?per_page=50") or {}).get("jobs", [])
        if any(job["name"] == BUILD_JOB and job["conclusion"] == "success" for job in jobs):
            return True
    return False


def tested_pull_request(api: Api, sha: str) -> int | None:
    """The merged PR whose tested head has exactly the tree of `sha`, if any."""
    tree = tree_of(api, sha)
    for pr in api(f"commits/{sha}/pulls") or []:
        if not pr.get("merged_at") or pr["base"]["ref"] != "main":
            continue
        head = pr["head"]["sha"]
        if tree is not None and tree_of(api, head) == tree and build_passed(api, head, event="pull_request"):
            return pr["number"]
    return None


def covered(api: Api, sha: str) -> str | None:
    """Why `sha`'s tree is known to build and pass the suite, or None."""
    if build_passed(api, sha):
        return f"{sha[:12]} passed CI"
    pr = tested_pull_request(api, sha)
    if pr is not None:
        return f"{sha[:12]} has the tree PR #{pr} passed CI with"
    return None


def tag_target(api: Api, tag: str) -> str | None:
    ref = api(f"git/ref/tags/{tag}")
    if not ref:
        return None
    target = ref["object"]
    if target["type"] == "tag":  # annotated (vlr cut tags are)
        target = (api(f"git/tags/{target['sha']}") or {}).get("object", {})
    return target.get("sha")


def version_files(root: Path = REPO_ROOT) -> set[str]:
    """The files `vlr version` manages: release.toml's canonical file and its targets."""
    config = tomllib.loads((root / "release.toml").read_text(encoding="utf-8"))["version"]
    canonical = config["canonical"]
    return {canonical if isinstance(canonical, str) else canonical["path"], *(t["path"] for t in config.get("targets", []))}


def _changed_lines(patch: str) -> tuple[list[str], list[str]]:
    removed = [line[1:] for line in patch.splitlines() if line.startswith("-") and not line.startswith("---")]
    added = [line[1:] for line in patch.splitlines() if line.startswith("+") and not line.startswith("+++")]
    return removed, added


def version_bump_problem(api: Api, parent: str, head: str, version: str, managed: set[str]) -> str | None:
    """None when parent..head is purely a version bump to `version`; otherwise what else it changes."""
    files = (api(f"compare/{parent}...{head}") or {}).get("files")
    if not files:
        return "the compare API returned no files"
    old_versions = set()
    for changed in files:
        name = changed["filename"]
        if name not in managed or changed.get("status") != "modified":
            return f"it changes {name}"
        if "patch" not in changed:
            return f"no diff for {name}"
        removed, added = _changed_lines(changed["patch"])
        if not removed or len(removed) != len(added):
            return f"{name} changes more than its version lines"
        for before, after in zip(removed, added):
            old = re.search(r"\d+\.\d+\.\d+", before)
            if not old or before.replace(old.group(0), version) != after or old.group(0) == version:
                return f"{name} changes more than its version: {after.strip()!r}"
            old_versions.add(old.group(0))
    if len(old_versions) != 1:
        return f"inconsistent old versions {sorted(old_versions)}"
    return None


def decide(event_name: str, event: dict[str, Any], api: Api, managed: set[str] | None = None) -> tuple[bool, str]:
    """(run, reason) for one workflow event."""
    if event_name != "push":
        return True, f"{event_name}: always built"
    if event.get("deleted") or event.get("forced"):
        return True, "deleted or force push"
    head = event.get("after") or ""
    head_commit = event.get("head_commit") or {}
    commits = event.get("commits") or []
    if not head or not head_commit:
        return True, "no head commit in the event"

    subject = (head_commit.get("message") or "").splitlines()[0] if head_commit.get("message") else ""
    cut = CUT_SUBJECT.match(subject)
    if cut and len(commits) == 1:
        tag = f"v{cut.group(1)}"
        commit = api(f"git/commits/{head}") or {}
        parents = [p["sha"] for p in commit.get("parents", [])]
        if len(parents) == 1 and tag_target(api, tag) == head:
            problem = version_bump_problem(api, parents[0], head, cut.group(1),
                                           version_files() if managed is None else managed)
            if problem:
                return True, f"release commit {tag} is more than a version bump: {problem}"
            why = covered(api, parents[0])
            if why:
                return False, f"release cut {tag} is only a version bump (release.yml builds it); its parent {why}"
            return True, f"release cut {tag}, but its parent {parents[0][:12]} has no passing CI"

    pr = tested_pull_request(api, head)
    if pr is not None:
        return False, f"merge of PR #{pr}: the same tree passed CI on the pull request"
    return True, "direct push (or a merge whose exact tree CI hasn't tested)"


def main() -> int:
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    try:
        with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as handle:
            event = json.load(handle)
        api = github_api(
            os.environ["GITHUB_REPOSITORY"],
            os.environ["GH_TOKEN"],
            os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        )
        run, reason = decide(event_name, event, api)
    except Exception as exc:  # fail open: an unverifiable push gets the full build
        print(f"::warning::CI gate could not decide ({exc}); running the full build")
        run, reason = True, f"gate error: {exc}"

    print(f"run={str(run).lower()}: {reason}")
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"run={str(run).lower()}\n")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(f"**CI gate:** {'build' if run else 'skip'}: {reason}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
