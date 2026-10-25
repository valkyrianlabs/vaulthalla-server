"""Contract: HTTP uploads commit in bounded memory, and PUT /upload/content streams (#258).

The /upload/session commit used to read each staged file whole into memory (fs::ops::readFileToVector, up to the
8 GiB file limit) before sealing it. Both upload lanes now hand the staged file to Filesystem::createFile as
source_path (a streaming seal), and the conditional lane's body never goes through the session's buffered-request
path (capped at a few MiB). Its staging file is flushed through platform::durable::sync before the commit. These are
regressions a unit test only catches for the sizes it tries, so they are pinned here.

Run by module: python3 -m unittest tools.contracts.test_upload_content_contract
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
HTTP = REPO_ROOT / "core" / "src" / "protocols" / "http"
COORDINATOR = HTTP / "upload" / "Coordinator.cpp"
CONTENT = HTTP / "upload" / "Content.cpp"
SESSION = HTTP / "Session.cpp"
ROUTER = HTTP / "Router.cpp"


def _code(path: Path) -> str:
    """The source without // and /* */ comments."""
    return re.sub(r"//[^\n]*|/\*.*?\*/", "", path.read_text(encoding="utf-8"), flags=re.S)


def _body(code: str, signature: str) -> str:
    """The brace-balanced body of the first function whose definition starts with `signature`."""
    start = code.index(signature)
    open_brace = code.index("{", start)
    depth = 0
    for i in range(open_brace, len(code)):
        depth += {"{": 1, "}": -1}.get(code[i], 0)
        if depth == 0:
            return code[open_brace:i + 1]
    raise AssertionError(f"unbalanced body after {signature!r}")


class UploadContentContractTests(unittest.TestCase):
    def test_upload_commits_never_buffer_the_whole_file(self) -> None:
        for path in (COORDINATOR, CONTENT):
            self.assertNotIn("readFileToVector", _code(path), f"{path.name} buffers a staged file whole")
        commit = _body(_code(COORDINATOR), "std::shared_ptr<vh::fs::model::File> commitCompletedUploadFile(")
        self.assertIn("source_path", commit, "the session commit must seal from the staged file")

    def test_the_conditional_lane_seals_from_staging_through_the_cas_path(self) -> None:
        commit = _body(_code(CONTENT), "model::preview::Response Upload::commit(")
        self.assertIn("vh::platform::durable::sync(", commit, "flush the staging file through the durability seam")
        self.assertIn("Filesystem::createFile(", commit)
        self.assertIn("source_path", commit)
        self.assertIn("expected_source_id", commit, "a replacement is a compare-and-swap on the matched generation")

    def test_the_session_streams_the_conditional_lane(self) -> None:
        serve = _body(_code(SESSION), "bool Session::serve(")
        streamed = serve.find("upload::content::isRequest")
        buffered = serve.find("handle_buffered_request")
        self.assertGreaterEqual(streamed, 0, "Session::serve must route PUT /upload/content to the streaming handler")
        self.assertLess(streamed, buffered, "PUT /upload/content must never reach the buffered-request path")
        handler = _body(_code(SESSION), "bool Session::handle_streaming_content(")
        self.assertNotIn("std::string body", handler, "the body goes to the staging file, not a string")

    def test_the_router_routes_the_lane_before_upload_sessions(self) -> None:
        route = _body(_code(ROUTER), "Response Router::route(")
        content = route.find('"/upload/content"')
        sessions = route.find('starts_with("/upload")')
        self.assertGreaterEqual(content, 0)
        self.assertLess(content, sessions)


if __name__ == "__main__":
    unittest.main()
