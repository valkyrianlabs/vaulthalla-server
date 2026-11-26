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

Then 7, a whole mirror (design/peers/mirror.md, waves 1 to 3), with no row written by hand:
  a. A's vault holds nested folders, files (an empty one, one of 3 MiB), a symlink and a trashed file;
  b. `vh mirror add` on A, `vh mirror accept` on B, the keys proven on B against A's pinned attestation key, B's vault
     with A's vault uid and root uid owned by A's account (a remote account), A's grant (reader) with the begin; the
     first copy is held back here (test instances only: VH_TEST_FAULT_DIR/mirror-copy-hold) to see the vault empty;
  c. B's first copy: copy_finished and live, its tree A's entry for entry (vh_mirror_tree's uids and hashes, names,
     sizes, content hashes, the symlink's target, the trash), equal digests, A recorded B's acknowledgement;
  d. contents: with background fetching held (VH_TEST_FAULT_DIR/mirror-contents-hold) every file is expected and none
     fetched; one opened through B's mount is fetched ahead and decrypts to A's plaintext; released, the rest arrive
     by themselves and decrypt to A's plaintext;
  e. changes on A through its mount, batch by batch (create, overwrite, rename, a move between folders, a swap of two
     names as three renames, delete to the trash, delete without it): after each B is at A's position with equal
     digests and the same tree, acknowledged on A; what A deleted is gone on B, a trashed file has nothing pending;
  f. access on B: its super admin reads within the grant, is refused a write, and is refused after A's `vh peer policy
     set none`;
  g. B killed while A changes the vault: it comes back, catches up from its position (equal digests, live), and its
     change journal shows each change once.
8, ending a mirror (owner's rule, 2026-11-26): rotation refused on A; B's own cancel of a live mirror refused; A's
cancel without --remove-copy leaves B an orphaned copy that B's super admin removes; --remove-copy with B's keep
setting on leaves it, with it off removes it; an unfinished copy (held back) is removed although A did not ask; an
offer B declines is reported declined on A.

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


def _mv(node: Node, vid: int) -> dict:
    """The vault's mirror_vault row on `node` (both sides), or {}."""
    row = _sql(node, "SELECT role || '|' || state || '|' || term || '|' || last_seq || '|' || "
                     "COALESCE(acked_term::text, '') || '|' || COALESCE(acked_seq::text, '') || '|' || "
                     "encode(digest, 'hex') || '|' || digest_entries || '|' || copy_finished::text || '|' || "
                     f"COALESCE(stop_reason, '') FROM mirror_vault WHERE vault_id = {vid}")
    if not row:
        return {}
    f = row.split("|")
    return {"role": f[0], "state": f[1], "term": int(f[2]), "seq": int(f[3]),
            "acked": (int(f[4]), int(f[5])) if f[4] else None, "digest": f[6], "entries": int(f[7]),
            "copy_finished": f[8] == "true", "stop_reason": f[9]}


def _tree(node: Node, vid: int) -> str:
    """Every entry of the vault as the log describes it: uid and hash of the replicated state (vh_mirror_tree, the
    digest's terms), then names, sizes and content hashes, then the trash."""
    hashes = _sql(node, "SELECT string_agg(entry_uid::text || ':' || encode(entry_hash, 'hex'), ',' ORDER BY entry_uid) "
                        f"FROM vh_mirror_tree({vid})")
    named = _sql(node, (
        "SELECT string_agg(x, ',' ORDER BY x) FROM ("
        "  SELECT COALESCE(f.object_uid::text, d.uid::text, s.uid::text) || ' ' || e.name || ' ' || "
        "    COALESCE(f.size_bytes::text, '-') || ' ' || COALESCE(f.content_hash, '-') || ' ' || COALESCE(s.target, '-') "
        "    AS x FROM fs_entry e LEFT JOIN files f ON f.fs_entry_id = e.id LEFT JOIN directories d ON "
        "    d.fs_entry_id = e.id LEFT JOIN symlinks s ON s.fs_entry_id = e.id "
        f"   WHERE e.vault_id = {vid} AND e.path <> '/' "
        "  UNION ALL SELECT 'trash ' || object_uid::text || ' ' || size_bytes || ' ' || path FROM files_trashed "
        f"   WHERE vault_id = {vid} AND deleted_at IS NULL) t"))
    return hashes + "\n" + named


def _synced(a: Node, va: int, b: Node, vb: int):
    """A numbered everything, B applied through A's position, A recorded B's acknowledgement there, the digests agree
    and both trees are the same entry for entry. The two rows, or None."""
    if _sql(a, f"SELECT count(*) FROM vault_replication_log WHERE vault_id = {va} AND seq IS NULL") != "0":
        return None
    ma, mb = _mv(a, va), _mv(b, vb)
    if not ma or not mb or not mb["copy_finished"] or mb["state"] != "live":
        return None
    at = (ma["term"], ma["seq"])
    if (mb["term"], mb["seq"]) != at or ma["acked"] != at:
        return None
    if ma["digest"] != mb["digest"] or ma["entries"] != mb["entries"]:
        return None
    if _tree(a, va) != _tree(b, vb):
        return None
    return {"a": ma, "b": mb}


def _diag(a: Node, va: int, b: Node, vb: int) -> dict:
    """What the two sides hold, for a failure's report: both rows, what A has not numbered, and the trees' differences."""
    ta, tb = _tree(a, va), _tree(b, vb)
    ha, hb = set(ta.split("\n")[0].split(",")), set(tb.split("\n")[0].split(","))
    na, nb = set(ta.split("\n")[1].split(",")), set(tb.split("\n")[1].split(","))
    return {"a": _mv(a, va), "b": _mv(b, vb),
            "b_stop": _sql(b, f"SELECT COALESCE(stop_detail::text, '') FROM mirror_vault WHERE vault_id = {vb}")[:600],
            "a_unnumbered": _sql(a, f"SELECT count(*) FROM vault_replication_log WHERE vault_id = {va} AND seq IS NULL"),
            "hash_only_a": sorted(ha - hb)[:6], "hash_only_b": sorted(hb - ha)[:6],
            "named_only_a": sorted(na - nb)[:6], "named_only_b": sorted(nb - na)[:6]}


def _wait_synced(a: Node, va: int, b: Node, vb: int, what: str, timeout: float = 120):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        got = _synced(a, va, b, vb)
        if got:
            return got
        time.sleep(1)
    raise DrillError(f"timed out waiting for {what}: {json.dumps(_diag(a, va, b, vb))[:2500]}")


def _plain(node: Node, rel: str) -> str:
    """SHA-256 of a file's plaintext, read through the node's mount as its super admin."""
    return node.sh(f"sha256sum 'MNT/{rel}' | cut -d' ' -f1", timeout=120).stdout.strip()


def _whole_mirror(a: Node, b: Node, faults_b: Path, node_a: str, node_b: str, report: Report) -> None:
    """7: a whole mirror between two real daemons over the real link, nothing written by hand: A's vault with real
    content is offered, accepted, its keys proven and installed on B, the first copy made and checked entry for entry
    with equal digests, the contents fetched in the background (one ahead of the queue when opened), every kind of
    change followed, access within the grant, and catching up after B was down."""
    contents_hold = faults_b / "mirror-contents-hold"
    copy_hold = faults_b / "mirror-copy-hold"

    # ---- 7a. A vault with real content before mirroring
    a.vh("vault", "create", "whole", "--local")
    va = int(_sql(a, "SELECT id FROM vault WHERE name = 'whole' AND deleted_at IS NULL"))
    _wait("A's mount showing the vault", lambda: (a.inst.mount / "whole").is_dir(), timeout=60)
    a.sh("mkdir -p MNT/whole/docs/deep/inner MNT/whole/other"
         " && printf 'a small text\\n' > MNT/whole/docs/a.txt"
         " && head -c 3145728 /dev/urandom > MNT/whole/docs/deep/big.bin"
         " && : > MNT/whole/docs/empty.txt"
         " && head -c 70000 /dev/urandom > MNT/whole/docs/deep/inner/mid.bin"
         " && printf 'top\\n' > MNT/whole/top.txt"
         " && printf 'x\\n' > MNT/whole/other/x.txt && printf 'y\\n' > MNT/whole/other/y.txt"
         " && printf 'unread\\n' > MNT/whole/other/unread.txt"
         " && printf 'to be trashed\\n' > MNT/whole/trash_me.txt"
         " && ln -s docs/a.txt MNT/whole/link.txt")
    _wait("A's files sealed", lambda: _sql(a, (
        "SELECT count(*) FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
        f"WHERE e.vault_id = {va} AND (length(f.encryption_iv) = 44 OR f.size_bytes = 0)")) == "9" or None, timeout=60)
    a.sh("rm MNT/whole/trash_me.txt")
    _wait("A's trashed file", lambda: _sql(a, f"SELECT count(*) FROM files_trashed WHERE vault_id = {va} "
                                              "AND deleted_at IS NULL") == "1" or None, timeout=30)
    report.check("7a: A's vault holds folders, files (an empty one, one of 3 MiB), a symlink and a trashed file",
                 _sql(a, f"SELECT count(*) FROM symlinks s JOIN fs_entry e ON e.id = s.fs_entry_id WHERE e.vault_id = {va}")
                 == "1")
    vault_uid = _sql(a, f"SELECT uid FROM vault WHERE id = {va}")
    root_uid = _sql(a, "SELECT d.uid FROM fs_entry e JOIN directories d ON d.fs_entry_id = e.id "
                       f"WHERE e.vault_id = {va} AND e.path = '/'")
    a.vh("peer", "policy", "set", node_b, "reader")

    # ---- 7b. Offer, accept, keys, begin (the first copy held back to look at the vault as the start leaves it)
    copy_hold.write_text("drill")
    contents_hold.write_text("drill")
    code, offer, text = _json(a, "mirror", "add", str(va), "--to", node_b)
    report.check("7b: A offers the vault to B (mirror.add)", code == 0 and offer.get("state") == "offered", text[-400:])
    pending = _wait("B's pending offer", lambda: [o for o in (_json(b, "mirror", "pending")[1].get("offers") or [])
                                                  if o.get("name") == "whole"], timeout=60)
    first = pending[0]
    report.check("7b: B holds the offer, waiting for a super admin (uid, size, owner, no history)",
                 first.get("state") == "pending" and first.get("vault_uid") == _b32(vault_uid)
                 and first.get("history") is False and first.get("owner", {}).get("node") == node_a,
                 json.dumps(first)[:500])
    cp = b.vh("mirror", "accept", str(first["id"]), check=False)
    report.check("7b: B accepts", cp.returncode == 0, (cp.stdout + cp.stderr)[-300:])
    started = _wait("the start to complete on A", lambda: (lambda m: m if m.get("role") == "core"
                                                           and (m.get("start") or {}).get("state") == "started"
                                                           else None)(_mirror_info(a, va)), timeout=90)
    report.check("7b: A is the vault's core, the start complete", bool(started), json.dumps(started)[:400])
    vb = int(_wait("B's vault with A's vault uid", lambda: _sql(b, f"SELECT id FROM vault WHERE uid = '{vault_uid}'"),
                   timeout=30))
    mb = _mirror_info(b, vb)
    report.check("7b: B holds the vault as A's mirror: same uid and root uid, no entries before the first copy",
                 mb.get("role") == "mirror" and (mb.get("peer") or {}).get("node_id") == node_a
                 and _sql(b, "SELECT d.uid FROM fs_entry e JOIN directories d ON d.fs_entry_id = e.id "
                             f"WHERE e.vault_id = {vb} AND e.path = '/'") == root_uid
                 and _sql(b, f"SELECT count(*) FROM fs_entry WHERE vault_id = {vb}") == "1"
                 and not _mv(b, vb)["copy_finished"], json.dumps(mb)[:500])
    keys_a = _sql(a, f"SELECT version FROM vault_keys WHERE vault_id = {va}")
    report.check("7b: B's keys are A's versions, each proven against A's pinned attestation key (origin: peer)",
                 _sql(b, f"SELECT version FROM vault_keys WHERE vault_id = {vb}") == keys_a
                 and _sql(b, f"SELECT count(*) FROM vault_key_origin WHERE vault_id = {vb} AND anchor = 'peer' "
                             f"AND origin_node_id = '{node_a}' AND origin_vault_id = {va}") != "0", f"A {keys_a}")
    report.check("7b: the owner is A's account, a remote account on B",
                 _sql(b, f"SELECT u.remote::text || ':' || u.home_node FROM vault v JOIN users u ON u.id = v.owner_id "
                         f"WHERE v.id = {vb}") == f"true:{node_a}")
    g = _wait("A's grant on B", lambda: (_mirror_info(b, vb).get("grant") or {}).get("role_name") == "reader"
              or None, timeout=30)
    report.check("7b: B records A's grant (reader) with the begin", bool(g))

    # ---- 7c. The first copy: B's tree is A's entry for entry, the digests agree, A recorded B's acknowledgement
    copy_hold.unlink()
    done = _wait_synced(a, va, b, vb, "B's first copy, applied and acknowledged", timeout=180)
    report.check("7c: B's first copy finished (copy_finished, live), its tree A's entry for entry (uids, names, sizes, "
                 "content hashes, the symlink, the trash), equal digests, A recorded B's acknowledgement",
                 bool(done), json.dumps(done)[:500])

    # ---- 7d. Contents: one opened on B goes ahead of the (held) queue; then the queue drains by itself
    files_with_bytes = int(_sql(a, "SELECT count(*) FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                                   f"WHERE e.vault_id = {va}"))  # the empty one too: it arrives as zero bytes
    pend = lambda: int(_sql(b, f"SELECT count(*) FROM mirror_content_pending WHERE vault_id = {vb}"))
    held = pend()
    report.check("7d: every file with bytes is expected on B, none fetched while the background is held",
                 held == files_with_bytes, f"{held} pending of {files_with_bytes}: " + _sql(
                     b, "SELECT string_agg(p.object_uid::text || ' ' || p.size_bytes || ' ' || p.state || ' ' || "
                        "COALESCE(e.path, '(no live file)'), '; ') FROM mirror_content_pending p LEFT JOIN files f ON "
                        "f.object_uid = p.object_uid LEFT JOIN fs_entry e ON e.id = f.fs_entry_id "
                        f"WHERE p.vault_id = {vb}"))
    big_a = _plain(a, "whole/docs/deep/big.bin")
    big_b = _plain(b, "whole/docs/deep/big.bin")
    report.check("7d: a file opened on B is fetched ahead of the queue and decrypts to A's plaintext",
                 big_a == big_b and pend() == held - 1, f"{big_a[:16]} / {big_b[:16]}, {pend()} still pending")
    contents_hold.unlink()
    _wait("B's queue drained in the background", lambda: pend() == 0 or None, timeout=180)
    same = all(_plain(a, f"whole/{f}") == _plain(b, f"whole/{f}")
               for f in ("docs/a.txt", "docs/deep/inner/mid.bin", "top.txt", "other/x.txt"))
    report.check("7d: the rest arrived without anyone opening them, and decrypt to A's plaintext", same)

    # ---- 7e. Changes on A after the first copy, batch by batch
    def batch(label: str, line: str) -> None:
        a.sh(line)
        ok = _wait_synced(a, va, b, vb, f"B following: {label}")
        report.check(f"7e: {label}: B follows, equal digests, acknowledged on A", bool(ok), json.dumps(ok)[:300])

    batch("create", "printf 'new\\n' > MNT/whole/docs/new.txt && mkdir MNT/whole/docs/fresh")
    batch("overwrite", "printf 'overwritten\\n' > MNT/whole/top.txt")
    report.check("7e: the overwritten file reads A's new bytes on B",
                 _wait("B's new bytes", lambda: pend() == 0 or None, timeout=60) is not None
                 and _plain(b, "whole/top.txt") == _plain(a, "whole/top.txt"))
    batch("rename", "mv MNT/whole/docs/new.txt MNT/whole/docs/renamed.txt")
    batch("move between folders", "mv MNT/whole/docs/a.txt MNT/whole/other/a.txt")
    batch("swap two names (three renames through the mount)",
          "mv MNT/whole/other/x.txt MNT/whole/other/tmp && mv MNT/whole/other/y.txt MNT/whole/other/x.txt"
          " && mv MNT/whole/other/tmp MNT/whole/other/y.txt")
    batch("delete to the trash", "rm MNT/whole/docs/renamed.txt")
    report.check("7e: the trashed file's pending row is gone on B (a trashed file's bytes are never fetched)",
                 _sql(b, f"SELECT count(*) FROM mirror_content_pending p JOIN files_trashed t ON "
                         f"t.object_uid = p.object_uid AND t.vault_id = p.vault_id WHERE p.vault_id = {vb}") == "0")
    link_uid = _sql(b, f"SELECT s.uid FROM symlinks s JOIN fs_entry e ON e.id = s.fs_entry_id WHERE e.vault_id = {vb}")
    batch("delete without the trash (a symlink, an empty folder)", "rm MNT/whole/link.txt && rmdir MNT/whole/docs/fresh")
    report.check("7e: what A deleted is gone on B",
                 _sql(b, f"SELECT count(*) FROM symlinks WHERE uid = '{link_uid}'") == "0"
                 and _sql(b, f"SELECT count(*) FROM fs_entry WHERE vault_id = {vb} AND name = 'fresh'") == "0")
    # Restore and purge have no person's command on a local vault (the trash is purged by a bucket vault's pass; a
    # restore is the manifest applier's): MirrorFollowDbTest applies both from a real core's log.

    # ---- 7f. Access on B: exactly the grant
    report.check("7f: B's super admin reads within the grant (reader)", _plain(b, "whole/other/y.txt") ==
                 _plain(a, "whole/other/y.txt"))
    cp = subprocess.run(["runuser", "-u", b.admin, "--", "timeout", "30", "sh", "-c",
                         f"printf no > '{b.inst.mount}/whole/other/written_on_b.txt'"], capture_output=True, text=True)
    report.check("7f: and is refused what the grant does not allow (a write)",
                 cp.returncode != 0 and _sql(b, f"SELECT count(*) FROM fs_entry WHERE vault_id = {vb} "
                                                "AND name = 'written_on_b.txt'") == "0", (cp.stdout + cp.stderr)[-200:])
    a.vh("peer", "policy", "set", node_b, "none")
    _wait("B's grant cleared", lambda: _mirror_info(b, vb).get("grant") is None or None, timeout=30)
    cp = subprocess.run(["runuser", "-u", b.admin, "--", "timeout", "30", "cat",
                         f"{b.inst.mount}/whole/other/unread.txt"], capture_output=True, text=True)
    report.check("7f: after A's `peer policy set none`, B's super admin is refused", cp.returncode != 0,
                 (cp.stdout + cp.stderr)[-200:])
    a.vh("peer", "policy", "set", node_b, "reader")

    # ---- 7g. B is down while A changes; it catches up from where it was, nothing applied twice
    before = _mv(b, vb)
    _down_and_back(a, b, node_a, node_b, lambda: a.sh("printf 'while B was down\\n' > MNT/whole/docs/offline.txt"
                                                      " && mv MNT/whole/other/y.txt MNT/whole/docs/y.txt"))
    ok = _wait_synced(a, va, b, vb, "B catching up after it came back", timeout=180)
    report.check("7g: B came back, caught up from its position, equal digests, acknowledged, still live",
                 bool(ok) and ok["b"]["seq"] > before["seq"], json.dumps({"before": before, "after": ok})[:500])
    report.check("7g: nothing applied twice: B's change journal has one create of the file written while it was down",
                 _sql(b, f"SELECT count(*) FROM fs_change_log WHERE vault_id = {vb} AND kind = 'create' "
                         "AND name = 'offline.txt'") == "1")


def _down_and_back(a: Node, b: Node, node_a: str, node_b: str, change) -> None:
    """B stops (killed), A changes the vault while it is down, B starts again and the link comes back."""
    b.close()
    b.inst.proc.kill()
    b.inst.proc.wait(timeout=30)
    _wait("A sees the link down", lambda: not _connected(a, node_b) or None, timeout=120)
    change()
    b.inst.restart(kill=True)
    _wait("the link back on A", lambda: _connected(a, node_b), timeout=180)
    _wait("the link back on B", lambda: _connected(b, node_a), timeout=60)


def _ending_rule(a: Node, b: Node, faults_b: Path, node_a: str, node_b: str, report: Report) -> None:
    """8: ending a mirror (owner, 2026-11-26): the core chooses, the mirror keeps or removes by the rule, an orphaned
    copy is removed by the mirror's super admin; rotation is refused; a declined offer is told."""
    copy_hold = faults_b / "mirror-copy-hold"

    def mirrored(name: str, finish: bool = True) -> tuple[int, int, str]:
        a.vh("vault", "create", name, "--local")
        v = int(_sql(a, f"SELECT id FROM vault WHERE name = '{name}' AND deleted_at IS NULL"))
        _wait(f"A's mount showing {name}", lambda: (a.inst.mount / name).is_dir(), timeout=60)
        a.sh(f"printf 'content of {name}\\n' > MNT/{name}/f.txt")
        _wait(f"{name}'s file sealed", lambda: _sql(a, (
            "SELECT 1 FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
            f"WHERE e.vault_id = {v} AND length(f.encryption_iv) = 44")), timeout=60)
        uid = _sql(a, f"SELECT uid FROM vault WHERE id = {v}")
        _json(a, "mirror", "add", str(v), "--to", node_b)
        offer = _wait(f"B's offer of {name}", lambda: [o for o in (_json(b, "mirror", "pending")[1].get("offers") or [])
                                                      if o.get("name") == name], timeout=60)[0]
        b.vh("mirror", "accept", str(offer["id"]))
        _wait(f"{name} started", lambda: (_mirror_info(a, v).get("start") or {}).get("state") == "started" or None,
              timeout=90)
        bv = int(_wait(f"B's {name}", lambda: _sql(b, f"SELECT id FROM vault WHERE uid = '{uid}'"), timeout=30))
        if finish:
            _wait_synced(a, v, b, bv, f"B's first copy of {name}", timeout=180)
        return v, bv, uid

    def told(v: int):
        return _wait("A told what B did", lambda: (_mirror_info(a, v).get("start") or {}).get("copy") or None, timeout=60)

    v1, bv1, uid1 = mirrored("ending")
    cp = a.vh("vault", "keys", "rotate", str(v1), check=False)
    report.check("8: key rotation on the mirrored vault is refused on A", "vault_mirrored" in (cp.stdout + cp.stderr),
                 (cp.stdout + cp.stderr)[-300:])
    cp = b.vh("mirror", "cancel", str(bv1), check=False)
    report.check("8: B can't remove a live mirror (mirror_detach_required)",
                 cp.returncode != 0 and "mirror_detach_required" in (cp.stdout + cp.stderr), (cp.stdout + cp.stderr)[-300:])
    a.vh("mirror", "cancel", str(v1))
    _wait("B's copy orphaned", lambda: _mirror_info(b, bv1).get("role") == "orphaned" or None, timeout=60)
    report.check("8: A ends a finished mirror without --remove-copy: B keeps an orphaned copy (its keys, the last "
                 "grant), A records it kept and has no core row",
                 told(v1) == "kept" and _sql(b, f"SELECT count(*) FROM vault_keys WHERE vault_id = {bv1}") == "1"
                 and (_mirror_info(b, bv1).get("grant") or {}).get("role_name") == "reader"
                 and _sql(a, f"SELECT count(*) FROM mirror_vault WHERE vault_id = {v1}") == "0")
    cp = b.vh("mirror", "cancel", str(bv1), check=False)
    report.check("8: B's super admin removes the orphaned copy",
                 cp.returncode == 0 and _sql(b, f"SELECT count(*) FROM vault WHERE uid = '{uid1}'") == "0"
                 and _sql(b, f"SELECT count(*) FROM vault_keys WHERE vault_id = {bv1}") == "0", (cp.stdout + cp.stderr)[-300:])

    v2, bv2, uid2 = mirrored("kept")
    b.vh("mirror", "keep-removed", node_a, "on")
    a.vh("mirror", "cancel", str(v2), "--remove-copy")
    _wait("B's kept copy orphaned", lambda: _mirror_info(b, bv2).get("role") == "orphaned" or None, timeout=60)
    report.check("8: with B's keep setting on, A's --remove-copy leaves B's finished copy (orphaned, kept)",
                 told(v2) == "kept" and _sql(b, f"SELECT count(*) FROM vault WHERE uid = '{uid2}'") == "1")
    b.vh("mirror", "cancel", str(bv2))
    b.vh("mirror", "keep-removed", node_a, "off")

    v3, bv3, uid3 = mirrored("removed")
    a.vh("mirror", "cancel", str(v3), "--remove-copy")
    _wait("B's copy removed", lambda: _sql(b, f"SELECT count(*) FROM vault WHERE uid = '{uid3}'") == "0" or None, timeout=60)
    report.check("8: with the setting off, A's --remove-copy removes B's finished copy, its keys and its row",
                 told(v3) == "removed" and _sql(b, f"SELECT count(*) FROM vault_keys WHERE vault_id = {bv3}") == "0"
                 and _sql(b, f"SELECT count(*) FROM mirror_vault WHERE vault_id = {bv3}") == "0")

    # An unfinished copy (the first copy held back on B): removed whatever is asked.
    copy_hold.write_text("drill")
    try:
        v4, bv4, uid4 = mirrored("unfinished", finish=False)
        unfinished = not _mv(b, bv4)["copy_finished"]
        a.vh("mirror", "cancel", str(v4))
        _wait("B's unfinished copy removed", lambda: _sql(b, f"SELECT count(*) FROM vault WHERE uid = '{uid4}'") == "0"
              or None, timeout=60)
        report.check("8: an unfinished copy is removed although A did not ask (nothing complete was held)",
                     unfinished and told(v4) == "removed")
    finally:
        copy_hold.unlink(missing_ok=True)

    a.vh("vault", "create", "declined", "--local")
    did = int(_sql(a, "SELECT id FROM vault WHERE name = 'declined' AND deleted_at IS NULL"))
    _json(a, "mirror", "add", str(did), "--to", node_b)
    pending = _wait("B's offer to decline", lambda: [o for o in (_json(b, "mirror", "pending")[1].get("offers") or [])
                                                     if o.get("name") == "declined"], timeout=60)
    b.vh("mirror", "decline", str(pending[0]["id"]))
    dec = _wait("A told of the decline", lambda: (lambda m: m if (m.get("start") or {}).get("state") == "declined"
                                                  else None)(_mirror_info(a, did)), timeout=60)
    report.check("8: B declines an offer and A is told", bool(dec), json.dumps(dec)[:300])


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

        # ------------------------------------------------------------------ 7. a whole mirror
        print("vhh drill peers: 7. a whole mirror: offer, keys, first copy, contents, changes, access, catching up",
              flush=True)
        _whole_mirror(a, b, faults["b"], node_a, node_b, report)

        # ------------------------------------------------------------------ 8. ending a mirror
        print("vhh drill peers: 8. ending a mirror: kept, removed, the keep setting, unfinished, declined", flush=True)
        _ending_rule(a, b, faults["b"], node_a, node_b, report)

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

