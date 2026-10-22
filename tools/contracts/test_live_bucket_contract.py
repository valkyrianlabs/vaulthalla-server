"""Contract: tests never create, delete or reconfigure a provider bucket, and live tests stay in the one shared bucket.

Agents running the old live suites (VH_LIVE_UPSTREAM=1 with account-admin credentials) left buckets behind in the
maintainer's Cloudflare account. Since then (.claude/context/testing.md, "Live provider tests"):

  - the only live credential is the shared test bucket's: VAULTHALLA_TEST_R2_* (and VAULTHALLA_TEST_S3_* for one AWS
    test bucket); account-admin / provisioning credentials appear nowhere in test or tooling code;
  - a real admin or events adapter (AwsAdmin, R2Admin, AwsEvents, R2Events) is constructed in test code only by the
    live helper (core/tests/helpers/live_bucket.hpp, which wraps it in GuardedAdmin) or in a file that replaces the
    network with curl::http::setTransportForTesting;
  - the helper's GuardedAdmin refuses bucket creation, deletion, lifecycle, versioning, account listings and probes
    without forwarding them, and the helper builds clients only for the configured bucket;
  - a file that uses the helper reaches the provider only through it: no credentials, controllers or factories of its
    own, no bucket administration calls (the listed guard self-tests aside, which assert the refusal);
  - tooling (tools/, bin/, Makefile, .github/) has no bucket provisioning commands;
  - bin/tests/run_unit.sh hands through exactly the shared-bucket variables.

The runtime half of the guard is the LiveBucketGuard suite (core/tests/unit/test_live_bucket.cpp) and the fixture
itself (violations fail the test even when swallowed; TearDown fails a key left outside vh-test-runs/).

Run by module: python3 -m unittest tools.contracts.test_live_bucket_contract
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS = REPO_ROOT / "core" / "tests"
HELPER = TESTS / "helpers" / "live_bucket.hpp"
LIVE_TESTS = TESTS / "unit" / "test_live_bucket.cpp"
RUN_UNIT = REPO_ROOT / "bin" / "tests" / "run_unit.sh"
THIS = Path(__file__).resolve()

CODE_SUFFIXES = {".cpp", ".hpp", ".h", ".py", ".sh", ".bash", ".yml", ".yaml", ".mk", ".mjs", ".js", ".ts", ".toml"}
SKIP_DIRS = {"node_modules", ".git", "build", ".next", "test-results", "__pycache__"}

# Bucket-provisioning credentials and their gate. None of these may come back into test or tooling code.
PROVISIONING_ENV = re.compile(r"\b(VH_LIVE_UPSTREAM|VH_AWS_ADMIN_\w*|VH_R2_ADMIN_\w*|VH_CF_API_TOKEN)\b")

REAL_ADAPTER = re.compile(r"\b(AwsAdmin|R2Admin|AwsEvents|R2Events)\s*[(>{]")

# What a file using the live helper may not do itself (it goes through live().controller() / live().admin()).
LIVE_FILE_FORBIDDEN: dict[str, re.Pattern[str]] = {
    "createBucket": re.compile(r"\bcreateBucket\s*\("),
    "deleteBucket": re.compile(r"\bdeleteBucket\s*\("),
    "putLifecycle": re.compile(r"\bputLifecycle\s*\("),
    "putVersioning": re.compile(r"\bputVersioning\s*\("),
    "events": re.compile(r"\b(ensureChannel|subscribe|unsubscribe|removeChannel)\s*\("),
    "listBuckets": re.compile(r"\b(listBuckets|probe)\s*\("),
    "factory": re.compile(r"\bsetFactoryForTesting\s*\("),
    "getenv": re.compile(r"\bgetenv\s*\("),
    "api_key": re.compile(r"\bAPIKey\s*>\s*\(|\bAPIKey\s*\(|\bAPIKey\s+\w+\s*[({]"),
    "controller": re.compile(r"\bController\s*>\s*\(|\bController\s+\w+\s*[({]"),
    "bucket_literal": re.compile(r"\"(?:s3://|vaulthalla-test)"),
}

# (file, rule) -> exact count, with the reason. A new occurrence fails until someone looks at it.
LIVE_FILE_EXCEPTIONS: dict[tuple[str, str], tuple[int, str]] = {
    ("core/tests/unit/test_live_bucket.cpp", "createBucket"): (
        4, "RecordingAdmin's override + LiveBucketGuard asserting the guard refuses CreateBucket"),
    ("core/tests/unit/test_live_bucket.cpp", "deleteBucket"): (2, "override + refusal asserted"),
    ("core/tests/unit/test_live_bucket.cpp", "putLifecycle"): (2, "override + refusal asserted"),
    ("core/tests/unit/test_live_bucket.cpp", "putVersioning"): (2, "override + refusal asserted"),
    ("core/tests/unit/test_live_bucket.cpp", "listBuckets"): (4, "overrides + refusals asserted"),
    ("core/tests/unit/test_live_bucket.cpp", "bucket_literal"): (
        2, "other bucket names the guard self-tests assert are refused"),
    ("core/tests/unit/test_live_bucket.cpp", "api_key"): (
        2, "the factory self-test: a fake R2 key (never used for a request) and a copy with another access key"),
}

# Provider bucket administration from shell / Python tooling.
TOOLING_FORBIDDEN = re.compile(
    r"create-bucket|delete-bucket|put-bucket-[a-z-]+|\bs3\s+(?:mb|rb)\b|\bmc\s+(?:mb|rb)\b|\brclone\s+(?:mkdir|purge|rmdir)\b"
    r"|--bucket-mode|\bupstream\b[\"', ]+\s*(?:cleanup|lifecycle|protect)\b"
)

SHARED_BUCKET_VARS = {
    f"VAULTHALLA_TEST_{p}_{v}"
    for p in ("R2", "S3")
    for v in ("ACCESS_KEY", "SECRET_ACCESS_KEY", "ENDPOINT", "REGION", "BUCKET")
}


def code_files(*roots: Path):
    for root in roots:
        if root.is_file():
            yield root
            continue
        for path in root.rglob("*"):
            if any(part in SKIP_DIRS for part in path.parts) or not path.is_file() or path.resolve() == THIS:
                continue
            if path.suffix in CODE_SUFFIXES or path.name == "Makefile":
                yield path


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def rel(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


class LiveBucketContract(unittest.TestCase):
    def test_no_provisioning_credentials_in_tests_or_tooling(self):
        roots = [TESTS, REPO_ROOT / "tools", REPO_ROOT / "bin", REPO_ROOT / ".github", REPO_ROOT / "Makefile"]
        offenders = []
        for path in code_files(*roots):
            for m in PROVISIONING_ENV.finditer(path.read_text(errors="ignore")):
                offenders.append(f"{rel(path)}: {m.group(1)}")
        self.assertEqual(offenders, [], "bucket-provisioning credentials are gone from tests; use the shared bucket")

    def test_real_adapters_only_in_the_helper_or_offline(self):
        offenders = []
        for path in code_files(TESTS):
            text = strip_comments(path.read_text(errors="ignore"))
            if not REAL_ADAPTER.search(text) or path == HELPER:
                continue
            if "setTransportForTesting(" not in text:
                offenders.append(rel(path))
        self.assertEqual(offenders, [], "a real provider adapter outside live_bucket.hpp and without the transport seam")

    def test_the_guard_never_forwards_bucket_administration(self):
        text = strip_comments(HELPER.read_text())
        self.assertIn('kRunsRoot = "vh-test-runs/"', text)
        body = text.split("class GuardedAdmin final", 1)[1].split("\n};", 1)[0]
        for method in ("createBucket", "deleteBucket", "putLifecycle", "putVersioning", "listBuckets", "probe"):
            self.assertNotRegex(body, rf"in_->\s*{method}\s*\(", f"GuardedAdmin forwards {method}")
            decl = re.search(rf"\b{method}\s*\([^)]*\)[^{{]*\{{([^}}]*)\}}", body)
            self.assertIsNotNone(decl, f"GuardedAdmin must override {method}")
            self.assertIn("violate(", decl.group(1), f"GuardedAdmin::{method} must refuse")
        self.assertRegex(body, r"requireDeletable\(o\.key\)", "deleteObjects checks every key")
        for m in re.finditer(r"\bController\s*>\s*\(([^;]*)\)|\bController\s+\w+\s*\(([^;]*)\)", text):
            args = m.group(1) or m.group(2)
            self.assertRegex(args, r"\bt_?\.bucket\b", f"a controller for something but the configured bucket: {args}")
        for m in re.finditer(r"make_unique<GuardedAdmin>\(([^;]*)\)", text):
            self.assertRegex(m.group(1), r"\bt_?\.bucket\b")

    def test_live_test_files_reach_the_provider_only_through_the_helper(self):
        users = [p for p in code_files(TESTS) if p != HELPER and "live_bucket.hpp" in p.read_text(errors="ignore")]
        self.assertIn(LIVE_TESTS, users)
        self.assertIn(TESTS / "unit" / "test_S3Provider.cpp", users)
        problems = []
        seen = set()
        for path in users:
            text = strip_comments(path.read_text(errors="ignore"))
            text = re.sub(r"#include[^\n]*", "", text)
            for name, pattern in LIVE_FILE_FORBIDDEN.items():
                count = len(pattern.findall(text))
                expected, _ = LIVE_FILE_EXCEPTIONS.get((rel(path), name), (0, ""))
                seen.add((rel(path), name))
                if count != expected:
                    problems.append(f"{rel(path)}: {name} x{count} (allowed {expected})")
        self.assertEqual(problems, [])
        self.assertEqual(set(LIVE_FILE_EXCEPTIONS) - seen, set(), "stale exception entries")

    def test_guard_self_tests_exist(self):
        text = LIVE_TESTS.read_text()
        for name in ("RefusesBucketProvisioningConfigurationAndAccountListings", "OnlyTheConfiguredBucket",
                     "DeletesOnlyUnderItsPrefixAndNeverOutsideTheRunsRoot",
                     "FactoryHandsOutOnlyTheGuardedClientForTheTestCredential"):
            self.assertIn(f"TEST_F(LiveBucketGuard, {name})", text)

    def test_tooling_never_provisions_buckets(self):
        roots = [REPO_ROOT / "tools", REPO_ROOT / "bin", REPO_ROOT / ".github", REPO_ROOT / "Makefile"]
        offenders = []
        for path in code_files(*roots):
            for m in TOOLING_FORBIDDEN.finditer(path.read_text(errors="ignore")):
                offenders.append(f"{rel(path)}: {m.group(0)}")
        self.assertEqual(offenders, [], "provider bucket administration in tooling")

    def test_run_unit_hands_through_only_the_shared_bucket(self):
        text = RUN_UNIT.read_text()
        block = re.search(r"LIVE_ENV_VARS=\(([^)]*)\)", text)
        self.assertIsNotNone(block)
        self.assertEqual(set(block.group(1).split()), SHARED_BUCKET_VARS)


if __name__ == "__main__":
    unittest.main()
