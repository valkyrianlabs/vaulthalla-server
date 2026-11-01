"""Every FUSE op the daemon registers answers its request, even when it throws (#263).

An exception escaping a lowlevel op (a DB pool timeout, an unknown inode) used to leave the kernel request unanswered,
hanging the caller. core/src/fuse/Bridge.cpp registers each op through fuse::task::Guard (core/include/fuse/task/
Request.hpp), which answers what escapes. A new op registered bare would bring the hang back; this keeps every
registration guarded and every Bridge op registered. Behavior is proven by core/tests/unit/test_fuse_reply_guard.cpp.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BRIDGE = REPO / "core" / "src" / "fuse" / "Bridge.cpp"
BRIDGE_HPP = REPO / "core" / "include" / "fuse" / "Bridge.hpp"
REQUEST_HPP = REPO / "core" / "include" / "fuse" / "task" / "Request.hpp"
SERVICE = REPO / "core" / "src" / "fuse" / "Service.cpp"

# Ops whose only possible reply is fuse_reply_none.
NO_REPLY = {"forget", "forget_multi"}


def operations_body() -> str:
    text = BRIDGE.read_text()
    m = re.search(r"fuse_lowlevel_ops getOperations\(\) \{(.*?)\n\}", text, re.S)
    assert m, "getOperations() not found in Bridge.cpp"
    return m.group(1)


class FuseReplyGuardContract(unittest.TestCase):
    def test_every_registered_op_goes_through_the_guard(self) -> None:
        registrations = re.findall(r"ops\.(\w+)\s*=\s*([^;]+);", operations_body())
        self.assertGreaterEqual(len(registrations), 20)
        for field, value in registrations:
            wrapper = "guardedForget" if field in NO_REPLY else "guarded"
            self.assertEqual(value.strip(), f"task::{wrapper}<&{field}>",
                             f"ops.{field} must be registered as task::{wrapper}<&{field}> (#263)")

    def test_every_bridge_op_is_registered(self) -> None:
        declared = set(re.findall(r"void (\w+)\(fuse_req_t req", BRIDGE_HPP.read_text()))
        registered = {field for field, _ in re.findall(r"ops\.(\w+)\s*=\s*([^;]+);", operations_body())}
        self.assertEqual(declared - registered, set(), "Bridge ops declared but not registered")

    def test_the_guard_answers_and_the_mount_uses_the_guarded_table(self) -> None:
        request = REQUEST_HPP.read_text()
        self.assertIn("fuse_reply_err(req, errnum);", request)
        self.assertIn("fuse_reply_none(req);", request)
        self.assertRegex(request, r"catch \(const db::PoolAcquireTimeout&\) \{\s*return EAGAIN;")
        self.assertIn("fuse_lowlevel_ops ops = getOperations();", SERVICE.read_text(),
                      "the mount must register the guarded table from getOperations()")

    def test_resolver_failures_report_denials_as_expected(self) -> None:
        # A refusal by the permission model (no Vaulthalla user for the uid, or RBAC) is expected, not a FUSE fault:
        # system processes stat every mount. Resolver failures go through replyResolveError, which tells them apart.
        text = BRIDGE.read_text()
        self.assertNotRegex(text, r"replyError\(req, timer, \w+\.errnum\)")
        self.assertGreaterEqual(text.count("replyResolveError(req, timer, "), 15)
        self.assertRegex(text, r"Status::MissingUser && resolved\.status != resolver::Status::AccessDenied")


if __name__ == "__main__":
    unittest.main()
