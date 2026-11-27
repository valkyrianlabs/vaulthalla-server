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
  h. strict mode on B (wave 4): with a grant that allows every file operation (power_user) and A stopped (the link
     down), every write through B's mount (create, overwrite, mkdir, rename, delete, chmod, touch) is refused with EROFS
     and `vh fs put` with exit code 69 and the reason (mirror_link_down), B's vault is unchanged; once A is back its
     writes arrive, and B's super admin reads within the grant;
  i. changes made on B while the link is up (wave 4 piece B): folders, a rename, a move and a delete through B's mount
     appear on A under the uids B chose and come back confirmed (equal digests, nothing pending on B);
  j. a file written through B's mount, one put with `vh fs put` and an overwrite arrive on A with B's bytes, confirmed,
     with nothing fetched back and no sealed copy left;
  k. a change A refuses (B's role narrowed on A while the change waited): held on B with the reason, its sealed bytes
     kept, B's entry back at A's state;
  l. a folder named on both sides: A's keeps the name, B's becomes its conflict copy with what B put in it;
  m. A stopped while a file is open for writing on B: a new write is refused, the open file is sealed and kept as
     pending, and arrives on A with its bytes once A is back;
  n. B restarted with three changes pending (held back by VH_TEST_FAULT_DIR/mirror-submit-hold, test instances only):
     they survive and are submitted and executed in order;
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
            "b_stop": _sql(b, f"SELECT COALESCE(stop_detail::text, '') FROM mirror_vault WHERE vault_id = {vb}")[:6000],
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
    raise DrillError(f"timed out waiting for {what}: {json.dumps(_diag(a, va, b, vb))[:9000]}")


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
    listing = subprocess.run(["runuser", "-u", b.admin, "--", "timeout", "30", "ls", "-1", str(b.inst.mount)],
                             capture_output=True, text=True)
    root = subprocess.run(["runuser", "-u", b.admin, "--", "timeout", "30", "stat", f"{b.inst.mount}/whole"],
                          capture_output=True, text=True)
    report.check("7f: and the mount shows B's super admin no such vault (no root shortcut for a copy: wave 4)",
                 "whole" not in listing.stdout.split() and root.returncode != 0,
                 f"ls: {listing.stdout[-200:]} stat: {(root.stdout + root.stderr)[-200:]}")
    a.vh("peer", "policy", "set", node_b, "reader")

    # ---- 7h. Strict mode on B (wave 4): a copy of A's vault is read-only on B whenever its link is down, whatever A
    # grants it. With a grant that allows every file operation (power_user), RBAC would let B's super admin write; with
    # A stopped the gate refuses every write with its reason. (With the link up B's writes are pending changes: 7i on.)
    a.vh("peer", "policy", "set", node_b, "power_user")
    _wait("B's grant (power_user)",
          lambda: (_mirror_info(b, vb).get("grant") or {}).get("role_name") == "power_user" or None, timeout=30)
    entries_b = _sql(b, f"SELECT count(*) FROM fs_entry WHERE vault_id = {vb}")
    top_b = _plain(b, "whole/top.txt")
    _stop(a, b, node_a)
    for label, line in (("a new file", "printf no > MNT/whole/other/gate.txt"),
                        ("an overwrite", "printf no > MNT/whole/top.txt"),
                        ("a folder", "mkdir MNT/whole/gate_dir"),
                        ("a rename", "mv MNT/whole/top.txt MNT/whole/top2.txt"),
                        ("a delete", "rm MNT/whole/other/unread.txt"),
                        ("a chmod", "chmod 600 MNT/whole/top.txt"),
                        ("a touch", "touch -d 2001-01-01 MNT/whole/top.txt")):
        cp = subprocess.run(["runuser", "-u", b.admin, "--", "timeout", "30", "sh", "-c",
                             line.replace("MNT", str(b.inst.mount))], capture_output=True, text=True)
        report.check(f"7h: with the link down, B's mount refuses {label} with EROFS (Read-only file system)",
                     cp.returncode != 0 and "Read-only file system" in (cp.stdout + cp.stderr),
                     (cp.stdout + cp.stderr)[-200:])
    for args in (("fs", "put", str(vb), "-", "/other/gate_cli.txt"),
                 ("fs", "put", str(vb), "-", "/top.txt", "--overwrite")):
        cp = _put(b, args, "from the cli\n")
        report.check(f"7h: with the link down, `vh {' '.join(args)}` on B is refused with the read-only exit code (69) "
                     "and the reason", cp.returncode == 69 and "mirror_link_down" in (cp.stdout + cp.stderr),
                     f"exit {cp.returncode}: {(cp.stdout + cp.stderr)[-300:]}")
    report.check("7h: nothing changed on B: its entries, and the overwritten file's bytes",
                 _sql(b, f"SELECT count(*) FROM fs_entry WHERE vault_id = {vb}") == entries_b
                 and _plain(b, "whole/top.txt") == top_b
                 and _sql(b, f"SELECT count(*) FROM mirror_pending WHERE vault_id = {vb}") == "0")
    _start(a, b, node_a, node_b)
    a.sh("printf 'written on A after the link came back\\n' > MNT/whole/other/from_a.txt")
    ok = _wait_synced(a, va, b, vb, "A's write arriving on B once the link is back")
    report.check("7h: A's writes arrive on B (equal digests, acknowledged)", bool(ok), json.dumps(ok)[:300])
    report.check("7h: B's super admin reads within the grant", _wait(
        "A's new file readable on B", lambda: _plain(b, "whole/other/from_a.txt") == _plain(a, "whole/other/from_a.txt")
        or None, timeout=60) is not None)

    _changes_on_the_mirror(a, va, b, vb, faults_b, node_a, node_b, report)
    _scrub_and_resync(a, va, b, vb, faults_b, report)
    _planned_switch(a, va, b, vb, node_a, node_b, report)

    a.vh("peer", "policy", "set", node_b, "reader")
    _wait("B's grant (reader) again", lambda: (_mirror_info(b, vb).get("grant") or {}).get("role_name") == "reader"
          or None, timeout=30)

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


def _put(node: Node, args: tuple, text: str) -> subprocess.CompletedProcess:
    """`vh fs put ... -` on `node` with `text` on stdin (its own exit code, not checked)."""
    env = [f"VAULTHALLA_CLI_SOCKET={node.inst.socket_path}", "VAULTHALLA_NONINTERACTIVE=1", "PATH=/usr/bin:/bin"]
    return subprocess.run(["runuser", "-u", node.admin, "--", "env", "-i", *env, node.cli, *args], input=text,
                          capture_output=True, text=True, timeout=60, cwd=str(node.private))


def _http_upload(node: Node, vault_id: int, path: str, data: bytes) -> dict:
    """The console's HTTP upload lane on `node` (staged as `.upload-http-*.part` next to the target, through the mount on
    Linux, then committed): as a web account of this node made for the drill (role unprivileged, power_user on the vault), its
    generated password kept in memory only. Returns {path: error or None}."""
    import asyncio
    import re
    import vhh._repo  # noqa: F401 - tools.lab importable
    from tools.lab.pentest.client import Target as NetTarget, Ws, ok as ws_ok, upload_files

    name = "drill_web"
    password = getattr(node, "_drill_web_password", None)
    if password is None:
        env = [f"VAULTHALLA_CLI_SOCKET={node.inst.socket_path}", "VAULTHALLA_NONINTERACTIVE=1", "PATH=/usr/bin:/bin"]
        cp = subprocess.run(["runuser", "-u", node.admin, "--", "env", "-i", *env, node.cli, "user", "create", name,
                             "--role", "unprivileged", "--email", f"{name}@drill.invalid"],
                            capture_output=True, text=True, timeout=60, cwd=str(node.private))
        m = re.search(r"^Password:\s*(\S+)\s*$", cp.stdout, re.M)
        if cp.returncode != 0 or not m:
            raise DrillError(f"user create {name} failed (exit {cp.returncode}; output withheld: it may hold a secret)")
        password = m.group(1)
        node._drill_web_password = password
    vault, owner = _sql(node, f"SELECT v.name || '|' || u.name FROM vault v JOIN users u ON u.id = v.owner_id "
                              f"WHERE v.id = {vault_id}").split("|", 1)
    node.vh("vault", "role", "assign", vault, "power_user", "-u", name, "--owner", owner, check=False)
    target = NetTarget(hostname="127.0.0.1", connect_ip="127.0.0.1", ws_port=node.inst.target.ws_port,
                       http_port=node.inst.target.http_port)

    async def go() -> dict:
        async with Ws(target) as ws:
            res = await ws.sign_in(name, password)
            if not ws_ok(res):
                return {path: f"sign-in: {res.get('status')} {res.get('error')}"}
            return upload_files(target, ws.cookie_header(), vault_id, [(path, data)])

    return asyncio.run(go())


def _stop(a: Node, b: Node, node_a: str) -> None:
    """A stops (killed): B's link to its core is down."""
    a.close()
    a.inst.proc.kill()
    a.inst.proc.wait(timeout=30)
    _wait("B sees the link down", lambda: not _connected(b, node_a) or None, timeout=120)


def _start(a: Node, b: Node, node_a: str, node_b: str) -> None:
    a.inst.restart(kill=True)
    _wait("the link back on A", lambda: _connected(a, node_b), timeout=180)
    _wait("the link back on B", lambda: _connected(b, node_a), timeout=60)


def _pending_rows(b: Node, vb: int) -> int:
    return int(_sql(b, f"SELECT count(*) FROM mirror_pending WHERE vault_id = {vb}"))


def _changes_on_the_mirror(a: Node, va: int, b: Node, vb: int, faults_b: Path, node_a: str, node_b: str,
                           report: Report) -> None:
    """7i to 7o (wave 4 piece B): a change made on B, A's mirror, while the link is up: applied on B at once, submitted
    to A, executed there as B's person, and confirmed when it comes back in A's log (nothing pending on B, equal
    digests); a refusal kept as a held change, a clash as a conflict copy, a file open when the link drops kept, pending
    changes surviving B's restart in order. `vh` has no mkdir, rename, move or delete: those go through B's mount."""
    hold = faults_b / "mirror-submit-hold"

    def settled(what: str, timeout: float = 120):
        ok = _wait_synced(a, va, b, vb, what, timeout=timeout)
        ok = ok and _wait(f"{what}: nothing pending on B", lambda: _pending_rows(b, vb) == 0 or None, timeout=60)
        return _wait_synced(a, va, b, vb, what, timeout=timeout) if ok else None

    def on_a(rel: str) -> bool:
        return (a.inst.mount / "whole" / rel).exists()

    # ---- 7i. Folders and names through B's mount
    b.sh("mkdir MNT/whole/from_b && mkdir MNT/whole/from_b/inner")
    ok = settled("B's folders on A")
    report.check("7i: folders made through B's mount appear on A and come back confirmed (equal digests, nothing "
                 "pending on B)", bool(ok) and on_a("from_b/inner"), json.dumps(ok)[:300])
    uid_b = _sql(b, "SELECT d.uid FROM fs_entry e JOIN directories d ON d.fs_entry_id = e.id "
                    f"WHERE e.vault_id = {vb} AND e.path = '/from_b'")
    report.check("7i: A holds them under the uids B chose",
                 _sql(a, f"SELECT count(*) FROM directories WHERE uid = '{uid_b}'") == "1")
    b.sh("mv MNT/whole/from_b/inner MNT/whole/from_b/renamed")
    ok = settled("B's rename on A")
    report.check("7i: a rename on B appears on A, confirmed", bool(ok) and on_a("from_b/renamed"), json.dumps(ok)[:300])
    b.sh("mv MNT/whole/from_b/renamed MNT/whole/docs/renamed_from_b")
    ok = settled("B's move on A")
    report.check("7i: a move on B appears on A, confirmed", bool(ok) and on_a("docs/renamed_from_b"),
                 json.dumps(ok)[:300])
    b.sh("rmdir MNT/whole/docs/renamed_from_b")
    ok = settled("B's delete on A")
    report.check("7i: a delete on B is a delete on A, confirmed", bool(ok) and not on_a("docs/renamed_from_b"),
                 json.dumps(ok)[:300])

    # ---- 7j. Contents: a file written through B's mount, one put with `vh fs put`, an overwrite of A's file
    b.sh("head -c 200000 /dev/urandom > MNT/whole/from_b/written.bin")
    cp = _put(b, ("fs", "put", str(vb), "-", "/from_b/put.txt"), "put on B with vh fs put\n")
    report.check("7j: `vh fs put` on B stores the file", cp.returncode == 0, (cp.stdout + cp.stderr)[-300:])
    b.sh("printf 'top, overwritten on B\\n' > MNT/whole/top.txt")
    ok = settled("B's files on A")
    same = ok and all(_plain(a, f"whole/{f}") == _plain(b, f"whole/{f}")
                      for f in ("from_b/written.bin", "from_b/put.txt", "top.txt"))
    report.check("7j: the files written on B (mount, vh fs put, an overwrite) arrive on A with B's bytes and come back "
                 "confirmed", bool(same), json.dumps(ok)[:300])
    report.check("7j: B fetched nothing for its own files (the same generation is on its disk) and keeps no sealed copy",
                 _sql(b, f"SELECT count(*) FROM mirror_content_pending WHERE vault_id = {vb}") == "0"
                 and not any((b.inst.backing / ".vh-mirror-pending" / str(vb)).glob("*"))
                 if (b.inst.backing / ".vh-mirror-pending").exists() else True)

    # ---- 7j. An HTTP upload's staging file (.upload-http-*.part, staged next to the target through the mount on Linux)
    # is never content, in either direction. On A: the console's HTTP lane (a web account of A's). On B: the same staging
    # file through B's mount (create, write, seal, remove: the lane's own steps there) around the commit's write (`vh fs
    # put`), since on a mirrored vault only B's super admins have access and the drill's super admin has no web password
    # (it is bound to its Linux account): B's staging file is B's scratch, never submitted, and the write is one change.
    staging_b = "from_b/.upload-http-drill0b-f0.part"
    b.sh(f"head -c 150000 /dev/urandom > MNT/whole/{staging_b}")
    staged_rows = _pending_rows(b, vb)
    cp = _put(b, ("fs", "put", str(vb), "-", "/from_b/uploaded_on_b.txt"), "committed from B's staging\n")
    b.sh(f"rm MNT/whole/{staging_b}")
    report.check("7j: B's staging file through the mount is scratch (nothing pending for it); its commit is stored",
                 staged_rows == 0 and cp.returncode == 0, f"pending {staged_rows}; {(cp.stdout + cp.stderr)[-200:]}")
    body_a = os.urandom(120_000)
    errors = _http_upload(a, va, "/docs/uploaded_on_a.bin", body_a)
    report.check("7j: an HTTP upload on A stores the file", errors == {"/docs/uploaded_on_a.bin": None}, json.dumps(errors))
    ok = settled("the uploads on both sides")
    on_b = b.inst.mount / "whole" / "docs" / "uploaded_on_a.bin"

    def arrived_on_b():
        # Settled means equal digests; the bytes come on the sealed lane after (an open meanwhile may answer ENODATA).
        try:
            return on_b.read_bytes() == body_a or None
        except OSError:
            return None

    arrived = _wait("A's upload's bytes on B", arrived_on_b, timeout=60)
    report.check("7j: both arrive and come back confirmed",
                 bool(ok) and _plain(a, "whole/from_b/uploaded_on_b.txt") == _plain(b, "whole/from_b/uploaded_on_b.txt")
                 and bool(arrived), json.dumps(ok)[:300])
    report.check("7j: B's upload was exactly one change submitted to A (its write), no staging file among them",
                 _sql(a, f"SELECT count(*) FROM mirror_submission WHERE vault_id = {va} "
                         "AND payload -> 'args' ->> 'name' = 'uploaded_on_b.txt'") == "1"
                 and _sql(a, f"SELECT count(*) FROM mirror_submission WHERE vault_id = {va} "
                             "AND payload::text LIKE '%.upload-http-%'") == "0")
    report.check("7j: no staging file in A's replication log, on B, or held on B",
                 _sql(a, f"SELECT count(*) FROM vault_replication_log WHERE vault_id = {va} "
                         "AND (name LIKE '.upload-http-%' OR state::text LIKE '%.upload-http-%')") == "0"
                 and _sql(b, f"SELECT count(*) FROM fs_entry WHERE vault_id = {vb} AND name LIKE '.upload-http-%'") == "0"
                 and _sql(b, f"SELECT count(*) FROM mirror_held WHERE vault_id = {vb} "
                             "AND args::text LIKE '%.upload-http-%'") == "0")

    # ---- 7k. A refusal: a change submitted after A narrowed what B may do is kept on B as a held change
    hold.write_text("drill")
    b.sh("printf 'refused on A\\n' > MNT/whole/from_b/refused.txt")
    _wait("B's write pending", lambda: _pending_rows(b, vb) >= 1 or None, timeout=30)
    a.vh("peer", "policy", "set", node_b, "reader")
    _wait("B's grant (reader)", lambda: (_mirror_info(b, vb).get("grant") or {}).get("role_name") == "reader"
          or None, timeout=30)
    hold.unlink()
    ok = settled("B back at A's state after the refusal")
    held = [h for h in (_json(b, "mirror", "held")[1].get("held") or [])
            if h.get("op") == "write" and h.get("state") == "open"]
    report.check("7k: A refuses it (B's role on the vault): B keeps it as a held change with the reason, its entry back at "
                 "A's state (the file gone on B), equal digests",
                 bool(ok) and bool(held) and all(h.get("reason_code") == "denied" for h in held)
                 and not (b.inst.mount / "whole" / "from_b" / "refused.txt").exists(), json.dumps(held)[:400])
    report.check("7k: nothing is lost: the held change keeps the person's sealed bytes",
                 any((b.inst.backing / ".vh-mirror-held" / str(vb) / str(h["id"])).is_file() for h in held),
                 json.dumps(held)[:400])
    a.vh("peer", "policy", "set", node_b, "power_user")
    _wait("B's grant (power_user) again",
          lambda: (_mirror_info(b, vb).get("grant") or {}).get("role_name") == "power_user" or None, timeout=30)

    # ---- 7l. A name clash: the same name made on both sides; B's becomes its conflict copy
    hold.write_text("drill")
    b.sh("mkdir MNT/whole/clash && printf 'mine\\n' > MNT/whole/clash/mine.txt")
    a.sh("mkdir MNT/whole/clash")
    hold.unlink()
    ok = settled("the clash settled")
    names = _sql(b, f"SELECT string_agg(name, ',' ORDER BY name) FROM fs_entry WHERE vault_id = {vb} "
                    "AND parent_id = (SELECT id FROM fs_entry WHERE vault_id = " + str(vb) + " AND path = '/') "
                    "AND name LIKE 'clash%'")
    report.check("7l: a folder named on both sides: A's keeps the name, B's is its conflict copy with what B put in it, "
                 "on both servers, equal digests",
                 bool(ok) and names.startswith("clash,clash (conflict ") and on_a(names.split(",")[1] + "/mine.txt"),
                 names)

    # ---- 7m. The link drops while a file is open for writing on B: it is kept, and arrives once the link is back
    script = ("import os, sys, time\n"
              "f = open(sys.argv[1], 'w')\n"
              "f.write('written before the link dropped\\n')\n"
              "f.flush()\n"
              "while not os.path.exists(sys.argv[2]):\n"
              "    time.sleep(0.2)\n"
              "f.close()\n")
    release = b.private / "close-the-file"
    release.unlink(missing_ok=True)
    writer = subprocess.Popen(["runuser", "-u", b.admin, "--", "python3", "-c", script,
                               str(b.inst.mount / "whole" / "from_b" / "open.txt"), str(release)],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    _wait("the file open on B", lambda: (b.inst.mount / "whole" / "from_b" / "open.txt").exists() or None, timeout=30)
    _stop(a, b, node_a)
    cp = subprocess.run(["runuser", "-u", b.admin, "--", "timeout", "30", "sh", "-c",
                         f"printf no > '{b.inst.mount}/whole/from_b/new_while_down.txt'"], capture_output=True, text=True)
    report.check("7m: with the link down a new write on B is refused (EROFS)",
                 cp.returncode != 0 and "Read-only file system" in (cp.stdout + cp.stderr), (cp.stdout + cp.stderr)[-200:])
    release.write_text("now")
    out, _ = writer.communicate(timeout=60)
    release.unlink(missing_ok=True)
    report.check("7m: the file open for writing when the link dropped is sealed and kept as pending on B",
                 writer.returncode == 0 and _pending_rows(b, vb) >= 1, f"exit {writer.returncode}: {out[-200:]}")
    _start(a, b, node_a, node_b)
    ok = settled("the kept file arriving on A")
    report.check("7m: once the link is back it arrives on A with its bytes, confirmed",
                 bool(ok) and _plain(a, "whole/from_b/open.txt") == _plain(b, "whole/from_b/open.txt"),
                 json.dumps(ok)[:300])

    # ---- 7n. B restarts with pending changes: they survive and go in order
    hold.write_text("drill")
    b.sh("mkdir MNT/whole/order && mkdir MNT/whole/order/second && printf 'third\\n' > MNT/whole/order/second/third.txt")
    _wait("B's three changes pending", lambda: _pending_rows(b, vb) >= 3 or None, timeout=30)
    b.close()
    b.inst.restart(kill=True)
    _wait("the link back on B", lambda: _connected(b, node_a), timeout=180)
    report.check("7n: B's pending changes survived its restart", _pending_rows(b, vb) >= 3)
    hold.unlink()
    ok = settled("B's pending changes after its restart")
    report.check("7n: then they are submitted in order and confirmed (the folder before what is in it)",
                 bool(ok) and on_a("order/second/third.txt"), json.dumps(ok)[:300])
    report.check("7n: A executed them in the order B made them",
                 _sql(a, f"SELECT string_agg(payload ->> 'op', ',' ORDER BY seq) FROM mirror_submission WHERE vault_id = {va} "
                         "AND payload -> 'args' ->> 'name' IN ('order', 'second', 'third.txt')").startswith("mkdir,mkdir,write"))


def _scrub_and_resync(a: Node, va: int, b: Node, vb: int, faults_b: Path, report: Report) -> None:
    """7o (wave 5 piece B): a difference planted in B's tables behind the triggers' backs is caught by the scrub (held
    to every pass with the test-only mirror-scrub-now file) and stops B's copy as diverged; `vh mirror resync` starts it
    over from A's tree, reusing every file whose bytes B holds, and the digests agree again."""
    ok = _wait_synced(a, va, b, vb, "settled before the planted difference", timeout=120)
    report.check("7o: settled before the planted difference", bool(ok), json.dumps(ok)[:300])
    _sql(b, "BEGIN; SELECT set_config('vh.mirror_apply', 'on', true); "
            f"UPDATE fs_entry SET mode = (COALESCE(mode, 420) # 1) WHERE vault_id = {vb} AND path = '/top.txt'; COMMIT;")
    scrub_now = faults_b / "mirror-scrub-now"
    scrub_now.write_text("drill")
    stopped = _wait("the scrub on B", lambda: _sql(b, f"SELECT stop_reason FROM mirror_vault WHERE vault_id = {vb}")
                    == "mirror_scrub_mismatch" or None, timeout=60)
    scrub_now.unlink(missing_ok=True)
    report.check("7o: the scrub catches the planted difference and stops B's copy as diverged",
                 bool(stopped) and _mv(b, vb).get("state") == "diverged", json.dumps(_mv(b, vb))[:300])
    cp = b.vh("mirror", "resync", str(vb), check=False)
    report.check("7o: `vh mirror resync` starts B's copy over", cp.returncode == 0, (cp.stdout + cp.stderr)[-300:])
    copied = _wait("B's copy done again", lambda: _sql(b, f"SELECT copy_finished FROM mirror_vault WHERE vault_id = {vb}")
                   == "t" or None, timeout=120)
    report.check("7o: B fetched nothing for the files it holds (the same generations)",
                 bool(copied) and _sql(b, f"SELECT count(*) FROM mirror_content_pending WHERE vault_id = {vb}") == "0")
    ok = _wait_synced(a, va, b, vb, "B resynced", timeout=180)
    report.check("7o: after the resync both digests agree, B is live again, its resync recorded",
                 bool(ok) and _sql(b, f"SELECT resync_count FROM mirror_vault WHERE vault_id = {vb}") == "1",
                 json.dumps(ok)[:300])


def _planned_switch(a: Node, va: int, b: Node, vb: int, node_a: str, node_b: str, report: Report) -> None:
    """7p (wave 5 piece B): a planned switch A to B asked on A, with writes on both sides before and after (B's as the
    new core, A's as its mirror, submitted and confirmed), then the roles swapped back, asked on A as the mirror."""
    def contents_here(node: Node, vid: int) -> bool:
        """Every file's contents on the mirror `node` (a switch needs them): what is still expected is opened through the
        mount, which fetches it ahead of the background queue (that may be backed off after the link-down steps)."""
        q = ("FROM mirror_content_pending p JOIN files f ON f.object_uid = p.object_uid "
             f"JOIN fs_entry e ON e.id = f.fs_entry_id AND e.vault_id = p.vault_id WHERE p.vault_id = {vid}")
        for path in filter(None, _sql(node, f"SELECT string_agg(e.path, '|') {q}").split("|")):
            node.sh(f"cat 'MNT/whole{path}' > /dev/null", timeout=120)
        return bool(_wait(f"every file's contents on the mirror (vault {vid})",
                          lambda: _sql(node, f"SELECT count(*) {q}") == "0" or None, timeout=60))

    # B's policy for A: the role A holds on the vault once B is its core (the old core's ceiling there).
    b.vh("peer", "policy", "set", node_a, "power_user")
    a.sh("printf 'written on A before the switch\\n' > MNT/whole/docs/before_switch_a.txt")
    b.sh("printf 'written on B before the switch\\n' > MNT/whole/docs/before_switch_b.txt")
    ok = _wait_synced(a, va, b, vb, "both writes settled before the switch", timeout=180)
    ok = ok and _wait("nothing pending on B", lambda: _pending_rows(b, vb) == 0 or None, timeout=60)
    ok = ok and _wait_synced(a, va, b, vb, "settled before the switch", timeout=120)
    report.check("7p: settled before the switch (a write on each side), every file's contents on B",
                 bool(ok) and contents_here(b, vb), json.dumps(ok)[:300])
    term = _mv(a, va)["term"]

    cp = a.vh("mirror", "switch", str(va), check=False)
    printed = cp.stdout + cp.stderr
    report.check("7p: `vh mirror switch` on A switches: A is the mirror, B the core, both in the next term",
                 cp.returncode == 0 and "switched" in printed and _mv(a, va).get("role") == "mirror"
                 and _mv(b, vb).get("role") == "core" and _mv(a, va).get("term") == term + 1
                 and _mv(b, vb).get("term") == term + 1,
                 json.dumps({"out": printed[-400:], "a": _mv(a, va), "b": _mv(b, vb)})[:600])
    report.check("7p: it prints the role A keeps on its new core (B's policy for A: power_user, read-write)",
                 "role 'power_user'" in printed and "(read-write)" in printed, printed[-400:])
    report.check("7p: both servers recorded it (mirror_switch switched) and audited it",
                 _sql(a, f"SELECT phase FROM mirror_switch WHERE vault_id = {va} ORDER BY id DESC LIMIT 1") == "switched"
                 and _sql(b, f"SELECT phase FROM mirror_switch WHERE vault_id = {vb} ORDER BY id DESC LIMIT 1")
                 == "switched"
                 and int(_sql(a, f"SELECT count(*) FROM audit_event WHERE action = 'mirror.switch' AND vault_id = {va}"))
                 >= 2)
    granted = _wait("A's grant from its new core", lambda: (
        (_mirror_info(a, va).get("grant") or {}).get("role_name") == "power_user" and _mv(a, va).get("state") == "live")
        or None, timeout=60)
    report.check("7p: A is a live mirror holding B's grant for it (B's policy: power_user)", bool(granted),
                 json.dumps({"a": _mv(a, va), "info": _mirror_info(a, va)})[:500])
    report.check("7p: A's super admin still reads the vault on A, within that role",
                 _plain(a, "whole/docs/before_switch_b.txt") == _plain(b, "whole/docs/before_switch_b.txt") != "")

    b.sh("printf 'written on B, the core now\\n' > MNT/whole/docs/after_switch_b.txt")
    a.sh("printf 'written on A, the mirror now\\n' > MNT/whole/docs/after_switch_a.txt")
    ok = _wait_synced(b, vb, a, va, "writes after the switch settled (B the core)", timeout=180)
    ok = ok and _wait("nothing pending on A", lambda: _pending_rows(a, va) == 0 or None, timeout=60)
    ok = ok and _wait_synced(b, vb, a, va, "settled after the switch", timeout=120)
    report.check("7p: after the switch B logs from (term + 1, 1) and A follows it; A's own write went to B and came "
                 "back confirmed; equal digests",
                 bool(ok) and _sql(b, f"SELECT min(seq) FROM vault_replication_log WHERE vault_id = {vb} "
                                      f"AND term = {term + 1}") in ("1", "")
                 and (b.inst.mount / "whole" / "docs" / "after_switch_a.txt").exists(),
                 json.dumps(ok)[:300])
    report.check("7p: the files written before and after the switch read the same on both servers",
                 all(_plain(a, f"whole/docs/{n}") == _plain(b, f"whole/docs/{n}") for n in (
                     "before_switch_a.txt", "before_switch_b.txt", "after_switch_a.txt", "after_switch_b.txt")))

    report.check("7p: every file's contents on A, the mirror, before the switch back", contents_here(a, va))
    code, out = a.vh_json("mirror", "switch", str(va), check=False)
    report.check("7p: the switch back, asked on A as the mirror: A is the core again, two terms on",
                 code == 0 and out.get("outcome") == "switched" and _mv(a, va).get("role") == "core"
                 and _mv(b, vb).get("role") == "mirror" and _mv(a, va).get("term") == term + 2,
                 json.dumps({"out": out, "a": _mv(a, va), "b": _mv(b, vb)})[:600])
    a.sh("printf 'written on A, the core again\\n' > MNT/whole/docs/after_switch_back.txt")
    ok = _wait_synced(a, va, b, vb, "settled after the switch back", timeout=180)
    report.check("7p: after the switch back B follows A again, equal digests", bool(ok), json.dumps(ok)[:300])
    b.vh("peer", "policy", "set", node_a, "none")


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

