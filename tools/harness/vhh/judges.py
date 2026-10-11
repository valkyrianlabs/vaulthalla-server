"""Judges: turn (op, result, states in flight) into verdicts. Only failures become Verdicts; passes are counted.

- oracle     allow/deny vs the reference model in any state during the op (plus a revocation grace window)
- parity     the same read-only probe on different surfaces in the same state must agree
- canary     bytes a principal received must not hold canaries of vaults it may not read
- integrity  bytes read/written must hash to the deterministic content for some version in flight
- liveness   timeouts, crashes, disconnects and deadline overruns
- invariants hooks run at quiesce points

Classification: product (the daemon misbehaved), oracle (the model is unsure or wrong), harness (our own defect),
unknown (either product or model; a human looks). A hand-written expectation that agrees with the model upgrades an
oracle mismatch to "product".
"""
from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable

from vhh import content, oracle
from vhh.model import REFUSALS, UNHEALTHY, Op, Result, Verdict
from vhh.state import Snapshot
from vhh.world import World

PROBE_OPS = {"fs.list", "fs.read", "fs.stat"}


@dataclass
class Observation:
    op: Op
    result: Result
    states: list[Snapshot]        # every state the op may have observed while in flight (oldest first)
    deadline_s: float
    grace: list[Snapshot] = field(default_factory=list)   # recently superseded states (revocation grace window)

    @property
    def worlds(self) -> list[World]:
        return [s.world for s in self.states]

    @property
    def lenient(self) -> list[Snapshot]:
        return self.grace + self.states


def answer(result: Result) -> str | None:
    if result.outcome == "ok":
        return oracle.ALLOW
    if result.outcome in REFUSALS:
        return oracle.DENY
    return None


@dataclass
class Judges:
    counts: Counter = field(default_factory=Counter)
    _parity: dict = field(default_factory=dict)
    _readable: dict = field(default_factory=dict)
    invariants: list[Callable[[World], list[Verdict]]] = field(default_factory=list)

    def judge(self, ob: Observation) -> list[Verdict]:
        out: list[Verdict] = []
        for fn in (self.liveness, self.oracle, self.parity, self.canary, self.integrity):
            out += fn(ob)
        return out

    # ------------------------------------------------------------------ liveness
    def liveness(self, ob: Observation) -> list[Verdict]:
        r = ob.result
        self.counts["liveness.checked"] += 1
        fault = r.data.get("fault") if isinstance(r.data, dict) else None
        if r.outcome in UNHEALTHY:
            kind = {"timeout": "wedge"}.get(r.outcome, r.outcome)
            return [Verdict("liveness", False, ob.op.seq, f"{ob.op.op} by {ob.op.principal} on {ob.op.surface}: "
                            f"{kind}: {r.detail}", f"done within {ob.deadline_s}s", r.outcome, fault or "unknown")]
        if r.t1_ns and r.t0_ns and (r.t1_ns - r.t0_ns) / 1e9 > ob.deadline_s:
            return [Verdict("liveness", False, ob.op.seq, f"{ob.op.op} overran its {ob.deadline_s}s deadline",
                            ob.deadline_s, (r.t1_ns - r.t0_ns) / 1e9, "product")]
        if r.outcome == "error" and fault != "harness":
            # An error the surface could not classify (EIO, an untyped failure) is never an acceptable answer: an
            # allowed op should succeed and a refused one should refuse cleanly. Harness faults are failed by the
            # engine itself, so they are not double-counted here.
            return [Verdict("error", False, ob.op.seq, f"{ob.op.op} by {ob.op.principal} on {ob.op.surface}: "
                            f"unexplained error: {r.detail}", "ok or a typed refusal", r.outcome, fault or "unknown")]
        return []

    # ------------------------------------------------------------------ oracle
    def oracle(self, ob: Observation) -> list[Verdict]:
        got = answer(ob.result)
        if got is None:
            return []
        decisions = [oracle.decide_op(s.world, ob.op.principal, ob.op.op, ob.op.args) for s in ob.lenient]
        if any(d.expect is None for d in decisions):
            self.counts["oracle.no_oracle"] += 1
            return []
        self.counts["oracle.checked"] += 1
        if any(d.expect == got for d in decisions):
            return []
        d = decisions[-1]
        classification = "unknown"
        hand = self._hand_expectation(ob.states[-1].world, ob.op)
        if hand is not None:
            classification = "product" if hand == d.expect else "oracle"
        return [Verdict("oracle", False, ob.op.seq,
                        f"{ob.op.principal} {ob.op.op} {ob.op.args.get('vault', '')}:{ob.op.args.get('path', '')} on "
                        f"{ob.op.surface}: model says {d.expect} ({d.reason}), daemon said {got} "
                        f"({ob.result.outcome})", d.expect, got, classification)]

    @staticmethod
    def _hand_expectation(w: World, op: Op) -> str | None:
        fixture_op = {"fs.list": "list", "fs.read": "read", "fs.write": "write", "fs.delete": "delete",
                      "shares.create": "share"}.get(op.op)
        for e in w.expectations:
            if (e.principal, e.resource, e.operation, e.path) == (op.principal, op.args.get("vault"), fixture_op,
                                                                  op.args.get("path", "/")):
                return e.expect
        return None

    # ------------------------------------------------------------------ parity
    def parity(self, ob: Observation) -> list[Verdict]:
        got = answer(ob.result)
        if ob.op.op not in PROBE_OPS or got is None or len(ob.states) != 1:
            return []
        key = (ob.states[0].version, ob.op.principal, ob.op.op, ob.op.args.get("vault"), ob.op.args.get("path"))
        seen = self._parity.setdefault(key, {})
        seen.setdefault(ob.op.surface, (got, ob.op.seq))
        self.counts["parity.checked"] += 1
        others = {s: v for s, v in seen.items() if v[0] != got}
        if not others:
            return []
        s, (other, seq) = next(iter(others.items()))
        return [Verdict("parity", False, ob.op.seq,
                        f"{ob.op.principal} {ob.op.op} {key[3]}:{key[4]}: {ob.op.surface} said {got}, {s} said "
                        f"{other} (seq {seq}) in the same state", other, got, "product")]

    # ------------------------------------------------------------------ canary
    def _readable_by(self, s: Snapshot, principal: str) -> set[str]:
        k = (s.version, principal)
        if k not in self._readable:
            self._readable[k] = oracle.readable_vaults(s.world, principal)
        return self._readable[k]

    def canary(self, ob: Observation) -> list[Verdict]:
        body = ob.result.body
        if not body:
            return []
        self.counts["canary.scanned"] += 1
        found = content.canaries_in(ob.states[-1].world, body)
        if not found:
            return []
        allowed = set().union(*(self._readable_by(s, ob.op.principal) for s in ob.lenient))
        leaked = sorted(found - allowed)
        if not leaked:
            return []
        # never put the canary value in a verdict: name the vault only
        return [Verdict("canary", False, ob.op.seq,
                        f"canary trip: {ob.op.principal} received content of {', '.join(leaked)} via {ob.op.op} on "
                        f"{ob.op.surface} ({ob.op.args.get('vault', '')}:{ob.op.args.get('path', '')})",
                        "no foreign canary", leaked, "product")]

    # ------------------------------------------------------------------ integrity
    def integrity(self, ob: Observation) -> list[Verdict]:
        r, op = ob.result, ob.op
        if r.outcome != "ok" or op.op not in ("fs.read", "fs.write"):
            return []
        actual = r.bytes_sha256 or (hashlib.sha256(r.body).hexdigest() if r.body is not None else None)
        if actual is None:
            return []
        vault, path = op.args.get("vault"), op.args.get("path")
        if op.op == "fs.write":
            w = ob.states[-1].world
            version = int(op.args.get("version", 1))
            want = hashlib.sha256(content.formula(w, vault, path, version,
                                                  content.formula_size(w, vault, path, version))).hexdigest()
            self.counts["integrity.checked"] += 1
            if actual != want:
                return [Verdict("integrity", False, op.seq, f"{op.op} {vault}:{path} v{version}: written bytes do not "
                                "match the content formula", want, actual, "harness")]
            return []
        candidates = set()
        for w in ob.worlds:
            for o in w.objects_in(vault):
                if o.path == path and o.kind != "dir":
                    candidates.add(content.object_sha256(w, o))
        if not candidates:
            return []
        self.counts["integrity.checked"] += 1
        if actual in candidates:
            return []
        return [Verdict("integrity", False, op.seq, f"{op.principal} read {vault}:{path} on {op.surface}: bytes match "
                        "no version written while the read was in flight", sorted(candidates), actual, "product")]

    # ------------------------------------------------------------------ invariants
    def quiesce(self, w: World) -> list[Verdict]:
        out = []
        for fn in self.invariants:
            try:
                out += fn(w)
            except Exception as e:  # noqa: BLE001 - a broken hook is a harness failure, not a pass
                out.append(Verdict("harness", False, None, f"invariant hook {getattr(fn, '__name__', fn)} raised: "
                                   f"{e!r}", classification="harness"))
        self.counts["invariants.checked"] += len(self.invariants)
        return out
