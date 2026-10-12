"""Append-only JSONL trace: a header line, then one line per op attempt / verdict / event, then a summary.

Every line passes through the central Redactor twice (structured, then the serialized text), so a secret registered
with the broker or held under a sensitive key cannot reach the file. Reading is strict: a corrupt line is an error
with its line number, never silently skipped.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from vhh.model import Op, Result, Verdict
from vhh.redact import Redactor

TRACE_VERSION = 1


class TraceError(ValueError):
    pass


class TraceWriter:
    def __init__(self, path: str | os.PathLike, redactor: Redactor, header: dict):
        self.path = Path(path)
        self.redactor = redactor
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # exclusive create: a trace is never overwritten or appended to by a second run
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self._f = os.fdopen(fd, "w", encoding="utf-8")
        self.lines = 0
        self._write({"kind": "header", "trace_version": TRACE_VERSION, "started_at": time.time(), **header})

    def _write(self, rec: dict) -> None:
        text = json.dumps(self.redactor.redact(rec), sort_keys=True, separators=(",", ":"), default=str)
        text = self.redactor.redact_text(text)
        with self._lock:
            self._f.write(text + "\n")
            self._f.flush()
            self.lines += 1

    def op(self, op: Op, result: Result) -> None:
        self._write({"kind": "op", "op": op.to_json(), "result": result.to_json()})

    def verdict(self, v: Verdict) -> None:
        self._write({"kind": "verdict", **v.to_json()})

    def event(self, name: str, **data) -> None:
        self._write({"kind": "event", "event": name, "t": time.time(), **data})

    def summary(self, summary: dict) -> None:
        self._write({"kind": "summary", **summary})

    def close(self) -> None:
        with self._lock:
            if not self._f.closed:
                self._f.flush()
                os.fsync(self._f.fileno())
                self._f.close()


class Trace:
    def __init__(self, header: dict, records: list[dict]):
        self.header = header
        self.records = records

    @property
    def ops(self) -> list[tuple[Op, Result]]:
        out = []
        for r in self.records:
            if r["kind"] == "op":
                out.append((Op(**r["op"]), Result(**r["result"])))
        return out

    @property
    def verdicts(self) -> list[Verdict]:
        return [Verdict(**{k: v for k, v in r.items() if k != "kind"}) for r in self.records if r["kind"] == "verdict"]

    @property
    def summary(self) -> dict | None:
        return next((r for r in reversed(self.records) if r["kind"] == "summary"), None)


def read_trace(path: str | os.PathLike) -> Trace:
    header, records = None, []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                raise TraceError(f"{path}:{n}: empty line")
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                raise TraceError(f"{path}:{n}: corrupt trace line ({e.msg})") from e
            if not isinstance(rec, dict) or "kind" not in rec:
                raise TraceError(f"{path}:{n}: not a trace record")
            if n == 1:
                if rec["kind"] != "header" or rec.get("trace_version") != TRACE_VERSION:
                    raise TraceError(f"{path}:1: missing or unsupported trace header")
                header = rec
                continue
            if rec["kind"] not in ("op", "verdict", "event", "summary"):
                raise TraceError(f"{path}:{n}: unknown record kind {rec['kind']!r}")
            if rec["kind"] == "op":
                try:
                    Op(**rec["op"])
                    Result(**rec["result"])
                except (KeyError, TypeError) as e:
                    raise TraceError(f"{path}:{n}: malformed op record ({e})") from e
            records.append(rec)
    if header is None:
        raise TraceError(f"{path}: empty trace")
    return Trace(header, records)
