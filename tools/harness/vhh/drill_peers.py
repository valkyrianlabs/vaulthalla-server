"""The server link drill (design/peers/link.md): two real daemons pair, keep one link, reconnect, rotate and unlink.

    sudo tools/harness/vhh.sh drill peers --build build [--keep] [--out report.json]

Two independent private instances (own database, swtpm, state, device listener on a private loopback port), driven
through the real `vh` as their super admin. First with peers.experimental off: every `vh peer` command refuses.
Then on (config.yaml appended, both restarted):

  1. trust on first use: B opens a window (`vh peer pair`), A dials it (`vh peer link`) and shows a code; B is offered
     three codes, a wrong pick denies the request; then the right one links both sides, and the link comes up;
  2. the link survives B restarting (killed), then A restarting: it is dialled again and comes back by itself;
  3. A unlinks: B is told and revokes its side too; neither dials or accepts the other again;
  4. the brokered path (expect_spki): A refuses a listener whose key is not the expected one, B refuses a request whose
     key is not the expected one, and with both keys given the link is made, compared by a person (from `vh`);
  5. A rotates its identity: B is told first (signed by the old key), keeps the link and pins the new key once it sees
     it; then A's emergency rotation (--revoke-peers) drops the link, and B can't reach A under its old pins.

Nothing secret is printed or kept: the drill's directory holds only its report.
"""
from __future__ import annotations

import json
import os
import pwd
import secrets
import shutil
import time
from pathlib import Path

from vhh.drill import DrillError, Node, Report
from vhh.instance import Instance

PEERS_ON = "peers: {experimental: true}\n"


def _json(node: Node, *args: str) -> tuple[int, dict, str]:
    cp = node.vh(*args, "--json", check=False)
    text = (cp.stdout or "") + (cp.stderr or "")
    try:
        start = cp.stdout.index("{")
        return cp.returncode, json.loads(cp.stdout[start:]), text
    except (ValueError, json.JSONDecodeError):
        return cp.returncode, {}, text


def _identity(node: Node) -> tuple[str, int]:
    """This node's device listener key and port (`vh device remote status`)."""
    code, j, text = _json(node, "device", "remote", "status")
    if code != 0 or not j.get("server_spki_sha256"):
        raise DrillError(f"device remote status failed: {text[-300:]}")
    port = j.get("port") or 0
    if not port and j.get("address"):
        port = int(str(j["address"]).rsplit(":", 1)[-1])
    return j["server_spki_sha256"], int(port)


def _peers(node: Node, everything: bool = False) -> list[dict]:
    args = ("peer", "list", "--all") if everything else ("peer", "list")
    code, j, text = _json(node, *args)
    if code != 0:
        raise DrillError(f"peer list failed: {text[-300:]}")
    return j.get("peers", [])


def _live(node: Node, node_id: str) -> dict | None:
    for p in _peers(node):
        if p.get("node_id") == node_id and not p.get("revoked"):
            return p
    return None


def _wait(what: str, predicate, timeout: float = 90, every: float = 1.0):
    end = time.monotonic() + timeout
    last = None
    while time.monotonic() < end:
        last = predicate()
        if last:
            return last
        time.sleep(every)
    raise DrillError(f"timed out waiting for {what} (last: {json.dumps(last)[:300] if last is not None else None})")


def _connected(node: Node, node_id: str):
    p = _live(node, node_id)
    return p if p and p.get("health", {}).get("connected") else None


def _window(b: Node) -> dict:
    code, j, text = _json(b, "peer", "pair")
    if code != 0 or "node_id" not in j:
        raise DrillError(f"peer pair failed: {text[-300:]}")
    return j


def _link(a: Node, address: str, fingerprint: str | None = None) -> tuple[int, dict, str]:
    args = ["peer", "link", address] + (["--fingerprint", fingerprint] if fingerprint else [])
    return _json(a, *args)


def _pending(b: Node) -> list[dict]:
    code, j, text = _json(b, "peer", "pending")
    if code != 0:
        raise DrillError(f"peer pending failed: {text[-300:]}")
    return j.get("requests", [])


def run(build: Path, *, keep: bool = False, out: Path | None = None) -> tuple[bool, dict]:
    report = Report()
    run_id = time.strftime("%Y%m%dT%H%M%S") + "_" + secrets.token_hex(3)
    admin = os.environ.get("SUDO_USER") or "coop"
    private = Path(f"/tmp/vhh_peers_{run_id}")
    private.mkdir(mode=0o700)
    pw = pwd.getpwnam(admin)
    os.chown(private, pw.pw_uid, pw.pw_gid)
    out = Path(out) if out else private / "report.json"
    summary: dict = {"run_id": run_id, "report": str(out)}
    nodes: list[Node] = []
    try:
        def node(tag: str) -> Node:
            inst = Instance(build, run_id=f"peers{tag}_{run_id}", own_tpm=True, device_server=True)
            inst.start()
            n = Node(inst, admin, private)
            nodes.append(n)
            return n

        def enable(n: Node) -> None:
            with open(n.inst.run_dir / "config.yaml", "a") as f:
                f.write(PEERS_ON)
            n.close()
            n.inst.restart(kill=False)

        # ------------------------------------------------------------------ 0. the switch
        print("vhh drill peers: two daemons; the switch is off", flush=True)
        a, b = node("a"), node("b")
        for who, n, args in (("B", b, ("peer", "pair")), ("A", a, ("peer", "list")),
                             ("A", a, ("peer", "link", "127.0.0.1:1"))):
            cp = n.vh(*args, check=False)
            report.check(f"0: {who}: `vh {' '.join(args)}` refuses while peers.experimental is off",
                         cp.returncode != 0 and "experimental" in (cp.stdout + cp.stderr),
                         (cp.stdout + cp.stderr)[-300:])
        enable(a)
        enable(b)
        spki_a, port_a = _identity(a)
        spki_b, port_b = _identity(b)
        addr_b = f"127.0.0.1:{port_b}"
        summary["keys"] = {"a": spki_a[:16], "b": spki_b[:16]}

        # ------------------------------------------------------------------ 1. trust on first use
        print("vhh drill peers: 1. pair by number matching (trust on first use)", flush=True)
        win = _window(b)
        node_b = win["node_id"]
        report.check("1: B's window names its key and a loopback endpoint on its device port",
                     win.get("spki_sha256") == spki_b and any(c.get("port") == port_b for c in win.get("candidates", [])),
                     json.dumps(win)[:400])
        code, att, text = _link(a, addr_b)
        report.check("1: A dials B and shows a code", code == 0 and att.get("state") == "awaiting_approval"
                     and len(att.get("code") or "") == 6 and (att.get("peer") or {}).get("spki_sha256") == spki_b,
                     text[-400:])
        reqs = _wait("B's pending request", lambda: _pending(b))
        req = reqs[0]
        report.check("1: B is offered three codes, one of them A's", len(req.get("code_choices", [])) == 3
                     and att.get("code") in req["code_choices"] and req.get("spki_sha256") == spki_a,
                     json.dumps(req)[:400])
        wrong = next(c for c in req["code_choices"] if c != att.get("code"))
        cp = b.vh("peer", "approve", req["request_id"], "--code", wrong, check=False)
        report.check("1: a wrong pick denies the request", cp.returncode != 0, (cp.stdout + cp.stderr)[-300:])
        time.sleep(4)  # A's attempt polls peer.pair.status every 2 s and ends on the denial
        report.check("1: neither side is linked after the wrong code", not _live(a, node_b) and not _peers(b))
        # Again, with the right code.
        _window(b)
        code, att, text = _link(a, addr_b)
        if not report.check("1: A asks again", code == 0 and att.get("code"), text[-300:]):
            raise DrillError("the second link attempt failed to start")
        req = _wait("B's pending request", lambda: _pending(b))[0]
        cp = b.vh("peer", "approve", req["request_id"], "--code", att["code"], check=False)
        report.check("1: B approves with the code A shows", cp.returncode == 0, (cp.stdout + cp.stderr)[-300:])
        node_a = req["node_id"]
        pa = _wait("the link up on A", lambda: _connected(a, node_b))
        pb = _wait("the link up on B", lambda: _connected(b, node_a))
        report.check("1: A pins B's key, B pins A's; compared by a person on both",
                     pa["spki_sha256"] == spki_b and pb["spki_sha256"] == spki_a and pa["compared_by"] == "person"
                     and pb["compared_by"] == "person", json.dumps({"a": pa, "b": pb})[:600])
        report.check("1: one connection, the same one on both ends (the tie-break)",
                     pa["health"]["dialed_by"] != pb["health"]["dialed_by"],
                     json.dumps({"a": pa["health"], "b": pb["health"]}))
        report.check("1: each side learned where the other listens (peer.endpoints)",
                     any(e.get("port") == port_b for e in pa.get("endpoints", []))
                     and any(e.get("port") == port_a for e in _wait("B's endpoints for A", lambda: (
                         lambda p: p if p and p.get("endpoints") else None)(_live(b, node_a)), timeout=30)["endpoints"]),
                     json.dumps({"a": pa.get("endpoints"), "b": _live(b, node_a).get("endpoints")})[:500])
        report.check("1: the peer's version is reported", pa["health"].get("peer_version") and
                     pa["health"].get("protocol_compatible") is True, json.dumps(pa["health"]))

        # ------------------------------------------------------------------ 2. restarts
        print("vhh drill peers: 2. B restarts, then A restarts: the link comes back", flush=True)
        since = pa["health"]["since"]
        b.close()
        b.inst.restart(kill=True)
        pa2 = _wait("the link back on A after B restarted", lambda: (lambda p: p if p and p["health"]["since"] != since
                                                                     else None)(_connected(a, node_b)), timeout=180)
        _wait("the link back on B", lambda: _connected(b, node_a), timeout=60)
        report.check("2: after B was killed and restarted, the link came back by itself", bool(pa2))
        a.close()
        a.inst.restart(kill=True)
        _wait("the link back on A after A restarted", lambda: _connected(a, node_b), timeout=180)
        pb3 = _wait("the link back on B after A restarted", lambda: _connected(b, node_a), timeout=60)
        report.check("2: after A was killed and restarted, the link came back by itself", bool(pb3))

        # ------------------------------------------------------------------ 3. unlink
        print("vhh drill peers: 3. A unlinks; B is told", flush=True)
        cp = a.vh("peer", "unlink", node_b, check=False)
        report.check("3: A unlinks B", cp.returncode == 0, (cp.stdout + cp.stderr)[-300:])
        _wait("B's side revoked by the notice", lambda: not _live(b, node_a) or None, timeout=30)
        gone_a = [p for p in _peers(a, everything=True) if p["node_id"] == node_b]
        report.check("3: both rows are kept, revoked (for the audit trail)",
                     gone_a and all(p["revoked"] for p in gone_a)
                     and all(p["revoked"] for p in _peers(b, everything=True) if p["node_id"] == node_a))
        time.sleep(5)
        report.check("3: nothing reconnects", not _live(a, node_b) and not _live(b, node_a))

        # ------------------------------------------------------------------ 4. expect_spki
        print("vhh drill peers: 4. the brokered path: both keys given", flush=True)
        _window(b)
        code, att, text = _link(a, addr_b, fingerprint="0" * 64)
        report.check("4: A refuses a listener whose key is not the expected one",
                     code != 0 and "not the expected" in text, text[-300:])
        code, att, text = _link(a, addr_b, fingerprint=spki_b)
        req = _wait("B's pending request", lambda: _pending(b))[0]
        cp = b.vh("peer", "approve", req["request_id"], "--code", att.get("code") or "", "--fingerprint", "1" * 64,
                  check=False)
        report.check("4: B refuses a request whose key is not the expected one, whatever the code",
                     cp.returncode != 0 and "another server key" in (cp.stdout + cp.stderr),
                     (cp.stdout + cp.stderr)[-300:])
        _window(b)
        code, att, text = _link(a, addr_b, fingerprint=spki_b)
        req = _wait("B's pending request", lambda: _pending(b))[0]
        cp = b.vh("peer", "approve", req["request_id"], "--code", att.get("code") or "", "--fingerprint", spki_a,
                  check=False)
        report.check("4: with both keys given the link is made", cp.returncode == 0, (cp.stdout + cp.stderr)[-300:])
        pa = _wait("the link up on A", lambda: _connected(a, node_b))
        pb = _wait("the link up on B", lambda: _connected(b, node_a))
        # compared_by records who compared, from the caller's channel: both calls came from `vh` (a person), so both
        # rows read person although both keys were pinned (Desktop's brokered link, over device sessions, reads desktop).
        report.check("4: pinned at the terminal, compared by a person on both sides (the channel, not the pin)",
                     pa["compared_by"] == "person" and pb["compared_by"] == "person",
                     json.dumps({"a": pa["compared_by"], "b": pb["compared_by"]}))

        # ------------------------------------------------------------------ 5. rotation
        print("vhh drill peers: 5. A rotates its identity; then the emergency rotation", flush=True)
        code, rot, text = _json(a, "secret", "device-identity", "rotate", "--yes")
        report.check("5: A rotates: B was told first and keeps the link", code == 0 and rot.get("peers_kept") == 1
                     and rot.get("peers_revoked") == 0, text[-400:])
        new_a = rot.get("spki_sha256", "")
        pb = _wait("B pinning A's new key", lambda: (lambda p: p if p and p["spki_sha256"] == new_a
                                                     and p["health"]["connected"] else None)(_live(b, node_a)),
                   timeout=120)
        report.check("5: B pins A's new key once it sees it in use; the old one is gone",
                     pb["spki_sha256"] == new_a and pb.get("next_spki_sha256") is None, json.dumps(pb)[:400])
        code, rot, text = _json(a, "secret", "device-identity", "rotate", "--yes", "--revoke-peers")
        report.check("5: the emergency rotation drops every link without telling anyone",
                     code == 0 and rot.get("peers_revoked") == 1 and rot.get("revoke_peers") is True, text[-400:])
        time.sleep(8)
        report.check("5: A has no live link, and B can't reach A under its old pins",
                     not _live(a, node_b) and not _connected(b, node_a), json.dumps(_live(b, node_a))[:400])
    except (DrillError, KeyboardInterrupt) as e:
        report.check("drill completed", False, str(e) or type(e).__name__)
    finally:
        for n in nodes:
            n.close()
            try:
                found = n.inst.sanitizer_reports()
                report.check(f"{n.inst.run_id}: no sanitizer report", not found, "; ".join(found)[:600])
                n.inst.stop()
            except Exception as e:  # noqa: BLE001
                report.check("instance stopped", False, str(e))
        summary["checks"] = report.checks
        summary["ok"] = report.ok
        out.write_text(json.dumps(summary, indent=2))
        if not keep:
            for f in private.iterdir():
                if f != out:
                    if f.is_dir():
                        shutil.rmtree(f, ignore_errors=True)
                    else:
                        f.unlink()
    return report.ok, summary

