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

Between 1 and 2, the sealed lane (design/peers/mirror.md "Contents"): A writes a file through its mount into a vault
it holds and is made that vault's core with B as its linked server (a mirror_vault row written by hand: no command
makes a vault mirrored yet); B fetches the file's sealed bytes with the real client over the real link, broken off and
resumed by range (a test-only request file, VH_TEST_FAULT_DIR/peer-object-fetch.json), and gets them byte for byte as
A's disk holds them; a generation that is not current and a vault B is not the linked server of are refused. B cannot
hold the vault itself yet (key delivery and vault creation are the next piece): receiving into a vault is proven in
process (MirrorContentsDbTest).

Then 7, starting a mirror: A offers a vault (`vh mirror add`), B accepts (`vh mirror accept`), the keys go over the link
and are proven on B against A's attestation key pinned at pairing, B creates the vault with A's vault uid and root uid
(empty: the tree is piece B's) owned by A's account as a remote account, A's grant follows a `vh peer policy set`, key
rotation is refused on A, B's own cancel of a completed mirror is refused, A's cancel removes B's copy; a second offer
B declines is reported declined on A.

Nothing secret is printed or kept: the drill's directory holds only its report.
"""
from __future__ import annotations

import hashlib
import json
import os
import pwd
import secrets
import shutil
import subprocess
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


def _sql(node: Node, query: str) -> str:
    cp = subprocess.run(["runuser", "-u", "postgres", "--", "psql", "-d", node.inst.db_name, "-tAc", query],
                        capture_output=True, text=True, timeout=60)
    if cp.returncode != 0:
        raise DrillError(f"psql on {node.inst.db_name} failed: {cp.stderr.strip()[:300]}")
    return cp.stdout.strip()


def _b32(uuid_text: str) -> str:
    """A uid's text form (vl-keykit: lower-case Crockford base32, 26 symbols, MSB first, zero padding)."""
    alphabet, n = "0123456789abcdefghjkmnpqrstvwxyz", int(uuid_text.replace("-", ""), 16) << 2
    return "".join(alphabet[(n >> (5 * i)) & 31] for i in reversed(range(26)))


def _fetch(b: Node, faults: Path, ask: dict, timeout: float = 120) -> dict:
    """B's daemon runs one sealed-lane fetch with the real client (test instances only) and reports it."""
    result = faults / "peer-object-fetch.result.json"
    for f in (result, faults / "peer-object-fetch.bin"):
        f.unlink(missing_ok=True)
    tmp = faults / "peer-object-fetch.json.tmp"
    tmp.write_text(json.dumps(ask))
    tmp.rename(faults / "peer-object-fetch.json")
    _wait("B's sealed-lane fetch", result.exists, timeout=timeout, every=0.5)
    return json.loads(result.read_text())


def _sealed_lane(a: Node, b: Node, faults_b: Path, node_a: str, node_b: str, report: Report) -> None:
    a.vh("vault", "create", "sealed", "--local")
    vid = int(_sql(a, "SELECT id FROM vault WHERE name = 'sealed' AND deleted_at IS NULL"))
    _wait("A's mount showing the vault", lambda: (a.inst.mount / "sealed").is_dir(), timeout=60)
    a.sh("head -c 700001 /dev/urandom > MNT/sealed/blob.bin && head -c 1000 /dev/urandom > MNT/sealed/other.bin")
    row = _wait("the sealed file's row", lambda: _sql(a, (
        "SELECT v.uid, f.object_uid, f.encryption_iv, f.content_hash, f.size_bytes FROM files f "
        "JOIN fs_entry e ON e.id = f.fs_entry_id JOIN vault v ON v.id = e.vault_id "
        f"WHERE v.id = {vid} AND e.name = 'blob.bin' AND f.size_bytes = 700001 AND length(f.encryption_iv) = 44")),
        timeout=60)
    vault_uid, object_uid, generation, content_hash, _size = row.split("|")
    # A is the vault's core, B its linked server: by hand (no command makes a vault mirrored yet).
    peer_b = _sql(a, f"SELECT id FROM peer WHERE node_id = '{node_b}' AND revoked_at IS NULL")
    _sql(a, f"INSERT INTO mirror_vault (vault_id, peer_id, role) VALUES ({vid}, {peer_b}, 'core')")
    sealed_on_a = None
    for f in a.inst.backing.rglob("*"):
        if f.is_file() and f.stat().st_size == 120 + 700001 + 16 * ((700001 + 65535) // 65536):
            data = f.read_bytes()
            if hashlib.blake2b(data, digest_size=32).hexdigest() == content_hash:
                sealed_on_a = data
                break
    report.check("6: A's backing file is the generation its row names (BLAKE2b over the sealed bytes)",
                 sealed_on_a is not None)
    ask = {"peer_node": node_a, "vault_uid": _b32(vault_uid), "object_uid": _b32(object_uid),
           "generation": generation, "interrupt_at": 300000}
    got = _fetch(b, faults_b, ask)
    attempts = got.get("attempts", [])
    fetched = (faults_b / "peer-object-fetch.bin").read_bytes() if got.get("ok") else b""
    report.check("6: B fetched the sealed bytes over the real link, broken off at 300,000 bytes and resumed by range",
                 got.get("ok") and len(attempts) == 2 and attempts[0]["status"] == "cancelled"
                 and attempts[1]["status"] == "complete" and attempts[1]["offset"] == 300000
                 and attempts[1]["http_status"] == 206, json.dumps(got)[:800])
    report.check("6: byte for byte what A's disk holds (and what A's log names)",
                 sealed_on_a is not None and fetched == sealed_on_a
                 and hashlib.blake2b(fetched, digest_size=32).hexdigest() == content_hash,
                 f"{len(fetched)} bytes fetched")
    stale = _fetch(b, faults_b, {**ask, "generation": "A" * 43 + "=", "interrupt_at": 0})
    first = (stale.get("attempts") or [{}])[0]
    report.check("6: a generation that is not current is refused (410 generation_not_current)",
                 first.get("status") == "refused" and first.get("http_status") == 410
                 and first.get("code") == "generation_not_current", json.dumps(stale)[:400])
    a.vh("vault", "create", "unmirrored", "--local")
    other_uid = _sql(a, "SELECT uid FROM vault WHERE name = 'unmirrored' AND deleted_at IS NULL")
    foreign = _fetch(b, faults_b, {**ask, "vault_uid": _b32(other_uid), "interrupt_at": 0})
    first = (foreign.get("attempts") or [{}])[0]
    report.check("6: a vault B is not the linked server of is not there for B (404)",
                 first.get("status") == "refused" and first.get("http_status") == 404, json.dumps(foreign)[:400])
    _sql(a, f"DELETE FROM mirror_vault WHERE vault_id = {vid}")


def _mirror_info(node: Node, vault_id: int) -> dict:
    code, j, text = _json(node, "mirror", "info", str(vault_id))
    return j.get("vault", {}) if code == 0 else {}


def _start_mirror(a: Node, b: Node, node_a: str, node_b: str, report: Report) -> None:
    """7: starting a mirror (design/peers/mirror.md "Starting a mirror"): A offers a vault, B accepts, the keys go over
    the link and are proven against A's attestation key B pinned at pairing, B creates the vault (same uid, empty)
    with A's grant; rotation and B's own cancel are refused; A's cancel removes B's copy. A declined offer too."""
    a.vh("vault", "create", "mirrored", "--local")
    vid = int(_sql(a, "SELECT id FROM vault WHERE name = 'mirrored' AND deleted_at IS NULL"))
    _wait("A's mount showing the vault", lambda: (a.inst.mount / "mirrored").is_dir(), timeout=60)
    a.sh("head -c 4096 /dev/urandom > MNT/mirrored/one.bin")
    _wait("the file's row", lambda: _sql(a, (
        "SELECT 1 FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
        f"WHERE e.vault_id = {vid} AND e.name = 'one.bin' AND length(f.encryption_iv) = 44")), timeout=60)
    vault_uid = _sql(a, f"SELECT uid FROM vault WHERE id = {vid}")
    root_uid = _sql(a, "SELECT d.uid FROM fs_entry e JOIN directories d ON d.fs_entry_id = e.id "
                       f"WHERE e.vault_id = {vid} AND e.path = '/'")

    code, offer, text = _json(a, "mirror", "add", str(vid), "--to", node_b)
    report.check("7: A offers the vault to B (mirror.add)", code == 0 and offer.get("state") == "offered", text[-400:])
    pending = _wait("B's pending offer", lambda: [o for o in (_json(b, "mirror", "pending")[1].get("offers") or [])
                                                  if o.get("name") == "mirrored"], timeout=60)
    first = pending[0]
    report.check("7: B holds the offer, waiting for a super admin (uid, size, owner, no history)",
                 first.get("state") == "pending" and first.get("vault_uid") == _b32(vault_uid)
                 and first.get("history") is False and first.get("owner", {}).get("node") == node_a,
                 json.dumps(first)[:500])
    cp = b.vh("mirror", "accept", str(first["id"]), check=False)
    report.check("7: B accepts", cp.returncode == 0, (cp.stdout + cp.stderr)[-300:])
    started = _wait("the start to complete on A", lambda: (lambda m: m if m.get("role") == "core"
                                                           and (m.get("start") or {}).get("state") == "started"
                                                           else None)(_mirror_info(a, vid)), timeout=90)
    report.check("7: A is the vault's core, the start complete", bool(started), json.dumps(started)[:400])
    bvid = int(_wait("B's vault with A's vault uid", lambda: _sql(b, f"SELECT id FROM vault WHERE uid = '{vault_uid}'"),
                     timeout=30))
    mb = _mirror_info(b, bvid)
    report.check("7: B holds the vault as A's mirror: the same uid and root uid, no entries yet",
                 mb.get("role") == "mirror" and (mb.get("peer") or {}).get("node_id") == node_a
                 and _sql(b, "SELECT d.uid FROM fs_entry e JOIN directories d ON d.fs_entry_id = e.id "
                             f"WHERE e.vault_id = {bvid} AND e.path = '/'") == root_uid
                 and _sql(b, f"SELECT count(*) FROM fs_entry WHERE vault_id = {bvid}") == "1",
                 json.dumps(mb)[:500])
    keys_a = _sql(a, f"SELECT version FROM vault_keys WHERE vault_id = {vid}")
    report.check("7: B's keys are A's versions, each proven against A's pinned attestation key (origin: peer)",
                 _sql(b, f"SELECT version FROM vault_keys WHERE vault_id = {bvid}") == keys_a
                 and _sql(b, f"SELECT count(*) FROM vault_key_origin WHERE vault_id = {bvid} AND anchor = 'peer' "
                             f"AND origin_node_id = '{node_a}' AND origin_vault_id = {vid}") != "0",
                 f"A {keys_a}")
    report.check("7: the owner is A's account, a remote account on B",
                 _sql(b, f"SELECT u.remote::text || ':' || u.home_node FROM vault v JOIN users u ON u.id = v.owner_id "
                         f"WHERE v.id = {bvid}") == f"true:{node_a}")
    report.check("7: no grant yet (A's link grants nothing): nobody on B has access", mb.get("grant") is None,
                 json.dumps(mb.get("grant")))
    a.vh("peer", "policy", "set", node_b, "reader")
    g = _wait("A's grant on B", lambda: (_mirror_info(b, bvid).get("grant") or {}).get("role_name") == "reader"
              or None, timeout=30)
    report.check("7: A's grant follows the change (peer policy set reader)", bool(g))

    cp = a.vh("vault", "keys", "rotate", str(vid), check=False)
    report.check("7: key rotation on the mirrored vault is refused on A", "vault_mirrored" in (cp.stdout + cp.stderr),
                 (cp.stdout + cp.stderr)[-300:])
    cp = b.vh("mirror", "cancel", str(bvid), check=False)
    report.check("7: B can't remove a completed mirror (mirror_detach_required)",
                 cp.returncode != 0 and "mirror_detach_required" in (cp.stdout + cp.stderr),
                 (cp.stdout + cp.stderr)[-300:])
    cp = a.vh("mirror", "cancel", str(vid), check=False)
    report.check("7: A cancels the mirror", cp.returncode == 0, (cp.stdout + cp.stderr)[-300:])
    _wait("B's copy removed", lambda: _sql(b, f"SELECT count(*) FROM vault WHERE uid = '{vault_uid}'") == "0" or None,
          timeout=60)
    report.check("7: B's copy, its keys and its mirror row are gone; A has no core row",
                 _sql(b, f"SELECT count(*) FROM vault_keys WHERE vault_id = {bvid}") == "0"
                 and _sql(b, f"SELECT count(*) FROM mirror_vault WHERE vault_id = {bvid}") == "0"
                 and _sql(a, f"SELECT count(*) FROM mirror_vault WHERE vault_id = {vid}") == "0")
    a.vh("peer", "policy", "set", node_b, "none")

    # A declined offer: A learns it.
    a.vh("vault", "create", "declined", "--local")
    did = int(_sql(a, "SELECT id FROM vault WHERE name = 'declined' AND deleted_at IS NULL"))
    code, offer, text = _json(a, "mirror", "add", str(did), "--to", node_b)
    pending = _wait("B's second offer", lambda: [o for o in (_json(b, "mirror", "pending")[1].get("offers") or [])
                                                 if o.get("name") == "declined"], timeout=60)
    b.vh("mirror", "decline", str(pending[0]["id"]))
    dec = _wait("A told of the decline", lambda: (lambda m: m if (m.get("start") or {}).get("state") == "declined"
                                                  else None)(_mirror_info(a, did)), timeout=60)
    report.check("7: B declines an offer and A is told", bool(dec), json.dumps(dec)[:300])


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
        faults = {t: private / f"faults_{t}" for t in ("a", "b")}
        for d in faults.values():
            d.mkdir(mode=0o700)

        def node(tag: str) -> Node:
            inst = Instance(build, run_id=f"peers{tag}_{run_id}", own_tpm=True, device_server=True,
                            extra_env={"VH_TEST_FAULT_DIR": str(faults[tag])})
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

        # ------------------------------------------------------------------ 6. the sealed lane
        print("vhh drill peers: 6. the sealed lane: B fetches a file's sealed bytes from A, resumed", flush=True)
        _sealed_lane(a, b, faults["b"], node_a, node_b, report)

        # ------------------------------------------------------------------ 7. starting a mirror
        print("vhh drill peers: 7. starting a mirror: offer, accept, keys proven, the vault on B, grant, cancel", flush=True)
        _start_mirror(a, b, node_a, node_b, report)

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

