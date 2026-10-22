"""Contract: provider bucket administration in tests goes only through the guarded live helper.

Live tests once created buckets freely and left them behind in the maintainer's Cloudflare account. The rules now
(.claude/context/testing.md, "Live provider tests"):

  1. every bucket a test creates is named vh-test-<host>-<pid>-<start>, and the helper refuses to create, delete,
     empty or reconfigure any other bucket;
  2. every bucket a test creates is emptied and deleted after the run, also when tests fail, and checked gone; an
     orphan sweep removes only old buckets of that pattern.

This contract keeps that structure in place:

  - the old shared-bucket credentials (VAULTHALLA_TEST_*) appear nowhere but published history, and neither do the
    retired provisioning gates (VH_LIVE_UPSTREAM, VH_R2_EVENTS_*) or AWS admin credentials;
  - the R2 admin credential and the opt-in switch are read only by the helper (and handed through by run_unit.sh);
    nothing a default run uses (meson test, verify.sh, Makefile, CI) sets VH_LIVE_TESTS;
  - real admin/events adapters are constructed in test code only by the helper, or behind the HTTP transport seam;
  - every bucket- and queue-scoped method of GuardedAdmin / GuardedEvents checks the name before forwarding, the
    pattern rejects real and near-miss names, and the cleanup guard (sweep, global environment, empty + delete +
    gone check) is wired;
  - files using the helper reach the provider only through it (no credentials, controllers, factories or bucket
    deletes of their own);
  - tooling has no bucket provisioning commands.

The runtime half is LiveBucketGuard.* in core/tests/unit/test_live_r2.cpp (no credentials needed, runs in CI).

Run by module: python3 -m unittest tools.contracts.test_live_bucket_contract
"""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS = REPO_ROOT / "core" / "tests"
HELPER = TESTS / "helpers" / "live_bucket.hpp"
LIVE_TESTS = TESTS / "unit" / "test_live_r2.cpp"
RUN_UNIT = REPO_ROOT / "bin" / "tests" / "run_unit.sh"
THIS = Path(__file__).resolve()

CODE_SUFFIXES = {".cpp", ".hpp", ".h", ".py", ".sh", ".bash", ".yml", ".yaml", ".mk", ".mjs", ".js", ".ts", ".tsx",
                 ".toml", ".example", ".build", ".in", ".json"}
SKIP_DIRS = {"node_modules", ".git", ".next", "test-results", "__pycache__", "vendor"}

# Published history that can't be rewritten (vl-release owns it) and dated result logs: (path, exact count).
OLD_VARS_HISTORY = {
    "debian/changelog": None,                          # any count: published releases
    "RELEASE_NOTES.md": None,
    ".claude/context/phase2-results.md": 1,            # Phase 2 results as recorded
    "docs/dev/s3-gateway-implementation-notes.md": 5,  # the dated validation log
}

RETIRED = re.compile(r"\b(VH_LIVE_UPSTREAM|VH_R2_EVENTS_\w*|VH_AWS_ADMIN_\w*)\b")
LIVE_CREDENTIALS = re.compile(r"\b(VH_R2_ADMIN_\w+|VH_CF_API_TOKEN|VH_LIVE_TESTS)\b")
LIVE_CREDENTIAL_READERS = {
    "core/tests/helpers/live_bucket.hpp", "core/tests/unit/test_live_r2.cpp", "bin/tests/run_unit.sh",
    "tools/lab/providers.env.example", "tools/lab/test_providers.sh",
    # The remote gateway smoke hands the key to the daemon under test as its upstream API key; its bucket is created
    # and deleted by vh_live_bucket (the helper), never by the script itself.
    "tools/smoke/s3_gateway_scoped_budget_smoke.sh", "tools/e2e/load_env.sh",
}
FIXED_TEST_BUCKETS = ["vh-test-gateway-smoke"]
TOOL = TESTS / "helpers" / "live_bucket_tool.cpp"

REAL_ADAPTER = re.compile(r"\b(AwsAdmin|R2Admin|AwsEvents|R2Events)\s*[(>{]")

GUARDED_ADMIN_METHODS = ("headBucket", "createBucket", "deleteBucket", "inspect", "putLifecycle", "versioning",
                         "putVersioning", "listObjects", "listObjectVersions", "deleteObjects", "objectsUnder",
                         "uploadsUnder")
GUARDED_EVENTS_METHODS = ("ensureChannel", "subscribe", "unsubscribe", "rules", "removeChannel", "poll", "ack",
                          "retry", "backlog")

# What a file using the helper may not do itself.
LIVE_FILE_FORBIDDEN: dict[str, re.Pattern[str]] = {
    "deleteBucket": re.compile(r"\bdeleteBucket\s*\("),
    "createBucket": re.compile(r"\bcreateBucket\s*\("),
    "factory": re.compile(r"\bsetFactoryForTesting\s*\("),
    "getenv": re.compile(r"\bgetenv\s*\("),
    "api_key": re.compile(r"\bAPIKey\s*>\s*\(|\bAPIKey\s*\(|\bAPIKey\s+\w+\s*[({]"),
    "controller": re.compile(r"\bController\s*>\s*\(|\bController\s+\w+\s*[({]"),
}
# (file, rule) -> (exact count, reason). A new occurrence fails until someone looks at it.
LIVE_FILE_EXCEPTIONS: dict[tuple[str, str], tuple[int, str]] = {
    ("core/tests/unit/test_live_r2.cpp", "deleteBucket"): (
        3, "RecordingAdmin's override; the guard self-tests (refused names, a forwarded vh-test-* name)"),
    ("core/tests/unit/test_live_r2.cpp", "createBucket"): (
        6, "RecordingAdmin's override; guard self-tests; the 409 collision check on the run's existing bucket"),
    ("core/tests/helpers/live_bucket_tool.cpp", "createBucket"): (
        1, "vh_live_bucket creates a fixed tooling bucket after isFixedTestBucket() accepted the name"),
}

TOOLING_FORBIDDEN = re.compile(
    r"create-bucket|delete-bucket|put-bucket-[a-z-]+|\bs3\s+(?:mb|rb)\b|\bmc\s+(?:mb|rb)\b|\brclone\s+(?:mkdir|purge|rmdir)\b"
    r"|--bucket-mode|\bupstream\b[\"', ]+\s*(?:cleanup|lifecycle|protect)\b"
)

LIVE_ENV_VARS = {"VH_LIVE_TESTS", "VH_R2_ADMIN_ACCESS_KEY", "VH_R2_ADMIN_SECRET_KEY", "VH_R2_ADMIN_ENDPOINT",
                 "VH_R2_ADMIN_REGION", "VH_CF_API_TOKEN"}

NOT_TEST_BUCKETS = ["vh-test", "vh-test-", "vaulthalla", "vaulthalla-database-backups", "portfolio",
                    "docs-valkyrian-labs", "vh-test-foo", "vh-test-host-1-170000000", "VH-TEST-host-1-1700000000",
                    "vh-test-host-1-1700000000x", "xvh-test-host-1-1700000000", "vh-test-runs"]


def repo_files() -> list[Path]:
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, check=True).stdout
        return [REPO_ROOT / p for p in out.decode().split("\0") if p]
    except (OSError, subprocess.CalledProcessError):   # a copy without .git
        return [p for p in REPO_ROOT.rglob("*")
                if p.is_file() and not any(part in SKIP_DIRS or part.startswith("build") for part in
                                           p.relative_to(REPO_ROOT).parts)]


def code_files(*roots: Path):
    for root in roots:
        if root.is_file():
            yield root
            continue
        for path in root.rglob("*"):
            if any(part in SKIP_DIRS for part in path.parts) or not path.is_file() or path.resolve() == THIS:
                continue
            if path.suffix in CODE_SUFFIXES or path.name in {"Makefile", "meson.build"}:
                yield path


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def rel(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def method_body(cls: str, method: str) -> str:
    """The body of `method` in class `cls` of the helper (braces matched)."""
    text = strip_comments(HELPER.read_text())
    start = text.index(f"class {cls} final")
    m = re.compile(rf"\b{method}\s*\([^;{{]*?\)\s*(?:const\s*)?(?:override\s*)?\{{").search(text, start)
    if not m:
        raise AssertionError(f"{cls}::{method} not found")
    depth, i = 1, m.end()
    while depth:
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        i += 1
    return text[m.end():i - 1]


class LiveBucketContract(unittest.TestCase):
    def test_old_test_credentials_are_gone(self):
        offenders = []
        for path in repo_files():
            if path.resolve() == THIS or not path.is_file():
                continue
            try:
                count = path.read_text(errors="ignore").count("VAULTHALLA_TEST_")
            except OSError:
                continue
            if not count:
                continue
            name = rel(path)
            if name in OLD_VARS_HISTORY and OLD_VARS_HISTORY[name] in (None, count):
                continue
            offenders.append(f"{name}: {count}")
        self.assertEqual(offenders, [], "VAULTHALLA_TEST_* were revoked; live tests use VH_R2_ADMIN_* via the helper")

    def test_retired_gates_and_aws_admin_are_gone_from_code(self):
        roots = [REPO_ROOT / "core", REPO_ROOT / "tools", REPO_ROOT / "bin", REPO_ROOT / ".github",
                 REPO_ROOT / "Makefile", REPO_ROOT / "deploy", REPO_ROOT / "web" / "src"]
        offenders = [f"{rel(p)}: {m.group(1)}" for p in code_files(*roots)
                     for m in RETIRED.finditer(p.read_text(errors="ignore"))]
        self.assertEqual(offenders, [])

    def test_only_the_helper_reads_the_live_credential(self):
        roots = [REPO_ROOT / "core", REPO_ROOT / "tools", REPO_ROOT / "bin", REPO_ROOT / ".github",
                 REPO_ROOT / "Makefile", REPO_ROOT / "deploy", REPO_ROOT / "web" / "src"]
        offenders = sorted({rel(p) for p in code_files(*roots)
                            if LIVE_CREDENTIALS.search(p.read_text(errors="ignore"))} - LIVE_CREDENTIAL_READERS)
        self.assertEqual(offenders, [])

    def test_default_runs_never_opt_in(self):
        for path in (REPO_ROOT / "core" / "meson.build", REPO_ROOT / "tools" / "dev" / "verify.sh",
                     REPO_ROOT / "Makefile"):
            self.assertNotIn("VH_LIVE_TESTS", path.read_text(), rel(path))
        for path in code_files(REPO_ROOT / ".github"):
            self.assertNotIn("VH_LIVE_TESTS", path.read_text(errors="ignore"), rel(path))
        text = strip_comments(HELPER.read_text())
        self.assertIn('env("VH_LIVE_TESTS") == "1"', text)
        self.assertIn("if (!optedIn()) GTEST_SKIP()", text)

    def test_real_adapters_only_in_the_helper_or_offline(self):
        offenders = []
        for path in code_files(TESTS):
            text = strip_comments(path.read_text(errors="ignore"))
            if path != HELPER and REAL_ADAPTER.search(text) and "setTransportForTesting(" not in text:
                offenders.append(rel(path))
        self.assertEqual(offenders, [], "a real provider adapter outside live_bucket.hpp and without the transport seam")

    def test_every_bucket_and_queue_call_is_name_checked(self):
        for method in GUARDED_ADMIN_METHODS:
            body = method_body("GuardedAdmin", method)
            self.assertIn("requireTestBucket(", body, f"GuardedAdmin::{method}")
            first_forward = min([body.find(s) for s in ("in_->", "api_->", "api_ ") if s in body] or [len(body)])
            self.assertLess(body.index("requireTestBucket("), first_forward, f"GuardedAdmin::{method} checks first")
        for method in ("remove", "removeUntilGone"):
            body = method_body("QueueAdmin", method)
            self.assertIn("requireTestQueue(", body, f"QueueAdmin::{method}")
            first = min(i for i in (body.find("list()"), body.find("remove(n)"), body.find("api(")) if i >= 0)
            self.assertLess(body.index("requireTestQueue("), first, f"QueueAdmin::{method} checks first")
        for method in GUARDED_EVENTS_METHODS:
            body = method_body("GuardedEvents", method)
            self.assertIn("requireTestBucket(", body, f"GuardedEvents::{method}")
            self.assertLess(body.index("requireTestBucket("), body.index("in_->"), f"GuardedEvents::{method} checks first")

    def test_the_name_pattern_admits_only_generated_test_buckets(self):
        text = HELPER.read_text()
        m = re.search(r'kRunBucketPattern = R"\((.*?)\)";', text)
        self.assertIsNotNone(m)
        pattern = re.compile(m.group(1))
        self.assertTrue(m.group(1).startswith("^vh-test-"))
        self.assertTrue(pattern.match("vh-test-coopersmacstudio-49338-1792686773"))
        for name in NOT_TEST_BUCKETS:
            self.assertIsNone(pattern.match(name), name)
        self.assertIn('kBucketPrefix = "vh-test-"', text)
        fixed = re.search(r"static const std::vector<std::string> names\{([^}]*)\};", text)
        self.assertIsNotNone(fixed, "fixedTestBuckets()")
        self.assertEqual(re.findall(r'"([^"]*)"', fixed.group(1)), FIXED_TEST_BUCKETS, "the fixed allow-list is exact")
        for name in FIXED_TEST_BUCKETS:
            self.assertTrue(name.startswith("vh-test-") and pattern.match(name) is None)

    def test_the_tool_manages_only_the_fixed_buckets(self):
        text = strip_comments(TOOL.read_text())
        self.assertLess(text.index("isFixedTestBucket(name)"), text.index("guardedAdmin("), "name refused before a client exists")
        self.assertNotIn("isRunBucketName", text)
        self.assertIn("emptyAndDeleteBucket(", text)
        smoke = (REPO_ROOT / "tools/smoke/s3_gateway_scoped_budget_smoke.sh").read_text()
        self.assertIn('UPSTREAM_BUCKET="vh-test-gateway-smoke"', smoke)
        self.assertIn('"$LIVE_BUCKET_BIN" delete "$UPSTREAM_BUCKET"', smoke)
        self.assertIn("trap finish EXIT", smoke)
        self.assertNotRegex(smoke, r"S3_GATEWAY_SMOKE_(UPSTREAM_\w+|API_KEY)\b", "no upstream env overrides")

    def test_the_cleanup_guard_is_wired(self):
        text = strip_comments(HELPER.read_text())
        # The only bucket deletion outside GuardedAdmin's own override: empty, delete, then HeadBucket must say gone.
        outside = text.split("class GuardedAdmin final", 1)[0] + text.split("class GuardedEvents final", 1)[1]
        deletes = re.findall(r"\bdeleteBucket\s*\(", outside)
        self.assertEqual(len(deletes), 1)
        body = text.split("inline void emptyAndDeleteBucket(", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("emptyUnder(", body)
        self.assertIn("deleteBucket(", body)
        self.assertIn("still exists after DeleteBucket", body)
        ensure = text.split("const std::string& ensure()", 1)[1].split("\n    }\n", 1)[0]
        self.assertLess(ensure.index("sweep()"), ensure.index("createBucket("), "sweep before creating")
        self.assertIn("isOrphan(", text.split("static std::vector<std::string> orphans(", 1)[1])
        self.assertIn("RunBucket::get().finish()", text.split("class RunBucketEnvironment", 1)[1])
        self.assertRegex(LIVE_TESTS.read_text(), r"AddGlobalTestEnvironment\(new live::RunBucketEnvironment\)")
        teardown = text.split("void TearDown() override {", 2)[2] if text.count("void TearDown() override {") > 1 else ""
        self.assertIn("emptyUnder(", teardown, "each test's prefix is emptied in TearDown")

    def test_live_test_files_reach_the_provider_only_through_the_helper(self):
        users = [p for p in code_files(TESTS) if p != HELPER and "live_bucket.hpp" in p.read_text(errors="ignore")]
        self.assertIn(LIVE_TESTS, users)
        problems, seen = [], set()
        for path in users:
            text = re.sub(r"#include[^\n]*", "", strip_comments(path.read_text(errors="ignore")))
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
        for name in ("RefusesEveryBucketThatIsNotATestBucket", "EventsTouchOnlyTestBucketsAndTestQueues",
                     "NamesAndTheOrphanSweep", "TheFactoryHandsOutGuardedClientsForTheLiveCredentialOnly"):
            self.assertIn(f"TEST_F(LiveBucketGuard, {name})", text)

    def test_tooling_never_provisions_buckets(self):
        roots = [REPO_ROOT / "tools", REPO_ROOT / "bin", REPO_ROOT / ".github", REPO_ROOT / "Makefile"]
        offenders = [f"{rel(p)}: {m.group(0)}" for p in code_files(*roots)
                     for m in TOOLING_FORBIDDEN.finditer(p.read_text(errors="ignore"))]
        self.assertEqual(offenders, [], "provider bucket administration in tooling")

    def test_run_unit_hands_through_only_the_live_switch_and_credential(self):
        block = re.search(r"LIVE_ENV_VARS=\(([^)]*)\)", RUN_UNIT.read_text())
        self.assertIsNotNone(block)
        self.assertEqual(set(block.group(1).split()), LIVE_ENV_VARS)
        self.assertIn('[[ "${VH_LIVE_TESTS:-}" == 1 ]] || return 0', RUN_UNIT.read_text())


if __name__ == "__main__":
    unittest.main()
