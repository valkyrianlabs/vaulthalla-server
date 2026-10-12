"""Repository paths and the reused pentest modules (tools/lab/pentest), imported rather than duplicated."""
from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[3]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# client.py needs `websockets` (in requirements.txt); fixture.py and content.py are stdlib only.
pentest = SimpleNamespace(
    fixture=importlib.import_module("tools.lab.pentest.fixture"),
    content=importlib.import_module("tools.lab.pentest.content"),
)


def pentest_publish():
    return importlib.import_module("tools.lab.pentest.publish")


def pentest_client():
    return importlib.import_module("tools.lab.pentest.client")
