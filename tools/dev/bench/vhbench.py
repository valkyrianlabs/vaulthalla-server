#!/usr/bin/env python3
"""Identity + preview cost benchmark against a live dev install (stdlib only).

Measures what a FUSE operation and a preview grid cost the daemon: PostgreSQL transactions and per-table scans
(pg_stat_database / pg_stat_user_tables), daemon CPU and syscalls (/proc), and wall latency. Runs against the
local install on the dev VM; never point it at vh-storage.

  sudo -n true  # needs passwordless sudo (postgres stats, `sudo -u vhbench`, derived-cache purge)
  python3 tools/dev/bench/vhbench.py seed  --state DIR      # one-time: users/group/roles + fixtures through FUSE
  python3 tools/dev/bench/vhbench.py run   --state DIR --label baseline > baseline.json
  python3 tools/dev/bench/vhbench.py compare baseline.json candidate.json

`seed` creates (idempotently) a Linux account `vhbench` mapped to the non-admin Vaulthalla user `bench_user`, the group
`bench_staff` (bench_user + 30 fillers, `reader` on vault 1), a direct `contributor` role with a deny override on
/bench/private/**, and fixtures under /bench in vault 1 (100 grid images incl. corrupt ones, multi-page PDFs).
Generated credentials go to DIR/bench_user.password (0600) and are never printed.

When pg_stat_statements is loaded (shared_preload_libraries) and the extension exists in the daemon's database, every
scenario also records per-statement counts, execution time and buffer blocks (`sql`, `per_op.statements`,
`per_op.sql_ms`); the stats are reset before each scenario, so run nothing else against that database meanwhile.
Background services (stats snapshots, janitor, retention) are filtered out. Compare runs taken with an equally warm
fs cache: the first listing of a directory after a daemon restart falls back to the database once.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import http.client
import json
import os
import random
import re
import socket
import statistics
import struct
import subprocess
import sys
import time
import urllib.parse
import uuid
from pathlib import Path

MOUNT = Path("/mnt/vaulthalla")
VAULT_DIR = "admin-default-vault"
VAULT_ID = 1
WS = ("127.0.0.1", 36969)
HTTP = ("127.0.0.1", 36970)
TABLES = ["users", "groups", "group_members", "admin_role_assignments", "user_global_vault_policy",
          "vault_role_assignments", "vault_permission_overrides", "admin_role", "vault_role", "cache_index",
          "refresh_tokens"]
GRID = "/bench/grid"
PDFS = "/bench/pdf"
FILLERS = 30


def sh(*args: str, check: bool = True, timeout: int = 120, input: bytes | None = None) -> str:
    res = subprocess.run(list(args), capture_output=True, timeout=timeout, input=input)
    if check and res.returncode != 0:
        raise RuntimeError(f"{args[0:3]}... exit {res.returncode}: {res.stderr.decode(errors='replace')[:400]}")
    return res.stdout.decode(errors="replace")


def psql(sql: str) -> str:
    return sh("sudo", "-n", "-u", "postgres", "psql", "-X", "-At", "-F", "|", "-c", sql, "vaulthalla")


# ---------------------------------------------------------------- measurement

def daemon_pid() -> int:
    return int(sh("systemctl", "show", "-p", "MainPID", "--value", "vaulthalla.service").strip())


def proc_sample(pid: int) -> dict:
    stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    ticks = os.sysconf("SC_CLK_TCK")
    io = dict(line.split(": ") for line in sh("sudo", "-n", "cat", f"/proc/{pid}/io").splitlines())
    status = Path(f"/proc/{pid}/status").read_text()
    rss = int(re.search(r"VmRSS:\s+(\d+)", status).group(1))
    return {"cpu_s": (int(stat[11]) + int(stat[12])) / ticks, "syscr": int(io["syscr"]), "syscw": int(io["syscw"]),
            "read_bytes": int(io["read_bytes"]), "write_bytes": int(io["write_bytes"]), "rss_kb": rss}


def pg_sample() -> dict:
    # Daemon backends flush their stats at most once a second while busy and after ~10 s idle.
    out = {}
    row = psql("SELECT xact_commit, xact_rollback, tup_returned, tup_fetched FROM pg_stat_database "
               "WHERE datname = 'vaulthalla'").split("|")
    out["xact"] = int(row[0]) + int(row[1])
    out["tup_returned"], out["tup_fetched"] = int(row[2]), int(row[3])
    names = ",".join(f"'{t}'" for t in TABLES)
    for line in psql(f"SELECT relname, coalesce(seq_scan,0) + coalesce(idx_scan,0), n_tup_ins + n_tup_upd + n_tup_del "
                     f"FROM pg_stat_user_tables WHERE relname IN ({names})").splitlines():
        rel, scans, writes = line.split("|")
        out[f"scan.{rel}"] = int(scans)
        out[f"write.{rel}"] = int(writes)
    return out


FLUSH_WAIT = 11.5


def pgss_available() -> bool:
    try:
        return psql("SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'").strip() == "1"
    except RuntimeError:
        return False


def pgss_reset() -> None:
    psql("SELECT pg_stat_statements_reset()")


def pgss_sample(limit: int = 15) -> dict:
    """Statements the daemon ran since the last reset (the profiler's own queries excluded)."""
    rows = psql(
        "SELECT calls, round(total_exec_time::numeric, 3), rows, shared_blks_hit + shared_blks_read, "
        "regexp_replace(left(query, 160), '\\s+', ' ', 'g') FROM pg_stat_statements s "
        "JOIN pg_database d ON d.oid = s.dbid WHERE d.datname = 'vaulthalla' "
        "AND query NOT ILIKE '%pg_stat_statements%' AND query NOT ILIKE '%pg_stat_database%' "
        "AND query NOT ILIKE '%pg_stat_user_tables%' AND query NOT ILIKE '%pg_stat_force_next_flush%' "
        # Background services that run on their own clock (stats snapshots, janitor, retention), not the workload.
        "AND query !~* '(stats_(metric|fuse|cache|threadpool|snapshot)|vault_deletion|files_trashed|pending_operations|"
        "active_share_uploads|pg_stat_activity|''operation'' AS source|FROM ONLY \"public\".\"vault\" x)' "
        "ORDER BY calls DESC").splitlines()
    out = {"statements": 0, "exec_ms": 0.0, "blocks": 0, "top": []}
    for line in rows:
        calls, ms, nrows, blocks, query = line.split("|", 4)
        out["statements"] += int(calls)
        out["exec_ms"] += float(ms)
        out["blocks"] += int(blocks)
        if len(out["top"]) < limit:
            out["top"].append({"calls": int(calls), "ms": float(ms), "rows": int(nrows), "blocks": int(blocks),
                               "query": query})
    out["exec_ms"] = round(out["exec_ms"], 3)
    return out


class Probe:
    """Deltas of PG + daemon counters around a block, corrected for the idle background rate."""

    idle_rate: dict | None = None
    profile: bool = False

    @classmethod
    def calibrate(cls, seconds: float = 20.0) -> None:
        time.sleep(FLUSH_WAIT)
        a, t0 = pg_sample(), time.monotonic()
        time.sleep(seconds)
        b = pg_sample()
        dt = time.monotonic() - t0
        cls.idle_rate = {k: (b[k] - a[k]) / dt for k in a}

    def __enter__(self):
        time.sleep(FLUSH_WAIT)
        self.pid = daemon_pid()
        if Probe.profile:
            pgss_reset()
        self.pg0, self.p0, self.t0 = pg_sample(), proc_sample(self.pid), time.monotonic()
        return self

    def __exit__(self, *exc):
        self.wall = time.monotonic() - self.t0
        self.p1 = proc_sample(self.pid)
        self.sql = pgss_sample() if Probe.profile else None
        time.sleep(FLUSH_WAIT)
        self.pg1 = pg_sample()
        span = time.monotonic() - self.t0
        self.pg = {}
        for k in self.pg0:
            idle = (self.idle_rate or {}).get(k, 0.0) * span
            self.pg[k] = max(0, round(self.pg1[k] - self.pg0[k] - idle))
        self.proc = {k: self.p1[k] - self.p0[k] for k in ("cpu_s", "syscr", "syscw", "read_bytes", "write_bytes")}
        self.proc["rss_kb_after"] = self.p1["rss_kb"]
        return False

    def result(self, ops: int, **extra) -> dict:
        r = {"ops": ops, "wall_s": round(self.wall, 4), "pg": self.pg, "proc": self.proc}
        r["per_op"] = {"xact": round(self.pg["xact"] / ops, 3), "cpu_ms": round(1000 * self.proc["cpu_s"] / ops, 3),
                       "syscalls": round((self.proc["syscr"] + self.proc["syscw"]) / ops, 2)}
        if self.sql is not None:
            r["sql"] = self.sql
            r["per_op"]["statements"] = round(self.sql["statements"] / ops, 3)
            r["per_op"]["sql_ms"] = round(self.sql["exec_ms"] / ops, 4)
        r.update(extra)
        return r


def pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    return s[min(len(s) - 1, int(round(p / 100 * (len(s) - 1))))]


def lat(values: list[float]) -> dict:
    return {"n": len(values), "p50_ms": round(1000 * pct(values, 50), 3), "p95_ms": round(1000 * pct(values, 95), 3),
            "mean_ms": round(1000 * statistics.fmean(values), 3) if values else 0.0}


# ---------------------------------------------------------------- minimal websocket client

class Ws:
    def __init__(self, path: str = "/ws"):
        self.sock = socket.create_connection(WS, timeout=30)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((f"GET {path} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                           f"User-Agent: vhbench/1\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("ws handshake closed")
            head += chunk
        header, self.buf = head.split(b"\r\n\r\n", 1)
        lines = header.decode(errors="replace").split("\r\n")
        if " 101 " not in lines[0]:
            raise RuntimeError(f"ws handshake failed: {lines[0]}")
        self.cookies = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            if name.lower() == "set-cookie":
                cname, _, rest = value.strip().partition("=")
                self.cookies[cname] = rest.split(";", 1)[0]
        self.token = ""

    def _send(self, payload: bytes) -> None:
        mask = os.urandom(4)
        n = len(payload)
        head = bytearray([0x81])
        if n < 126:
            head.append(0x80 | n)
        elif n < 65536:
            head += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            head += bytes([0x80 | 127]) + struct.pack(">Q", n)
        self.sock.sendall(bytes(head) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def _read(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("ws closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _recv(self) -> bytes:
        message = b""
        while True:
            b0, b1 = self._read(2)
            n = b1 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._read(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._read(8))[0]
            data = self._read(n)
            op = b0 & 0x0F
            if op == 0x9:  # ping
                continue
            if op == 0x8:
                raise RuntimeError("ws closed by server")
            message += data
            if b0 & 0x80:
                return message

    def call(self, command: str, payload: dict | None = None) -> dict:
        rid = str(uuid.uuid4())
        self._send(json.dumps({"command": command, "payload": payload or {}, "requestId": rid,
                               "token": self.token}).encode())
        while True:
            msg = json.loads(self._recv())
            if msg.get("token"):
                self.token = msg["token"]
            if msg.get("requestId") == rid:
                return msg

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def login(name: str, password: str) -> tuple[Ws, str]:
    ws = Ws()
    msg = ws.call("auth.login", {"name": name, "password": password})
    if str(msg.get("status", "")).lower() not in ("ok", "success"):
        raise RuntimeError(f"login failed for {name}: {msg.get('error')}")
    cookie = "; ".join(f"{k}={v}" for k, v in ws.cookies.items())
    return ws, cookie


# ---------------------------------------------------------------- HTTP

class Http:
    def __init__(self, cookie: str):
        self.cookie = cookie
        self.conn = http.client.HTTPConnection(*HTTP, timeout=120)

    def req(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
        h = {"Cookie": self.cookie, "Host": "localhost"}
        h.update(headers or {})
        for attempt in range(2):
            try:
                self.conn.request(method, path, body=body, headers=h)
                resp = self.conn.getresponse()
                data = resp.read()
                return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
            except (http.client.HTTPException, ConnectionError, OSError):
                self.conn.close()
                self.conn = http.client.HTTPConnection(*HTTP, timeout=120)
                if attempt:
                    raise
        raise AssertionError

    def preview_url(self, path: str, size: int, page: int = 0) -> str:
        q = {"vault_id": VAULT_ID, "path": path, "size": size}
        if page:
            q["page"] = page
        return "/preview?" + urllib.parse.urlencode(q)

    def batch(self, paths: list[str], size: int = 128):
        body = json.dumps({"size": size, "vault_id": VAULT_ID,
                           "items": [{"key": p, "path": p, "vault_id": VAULT_ID} for p in paths]}).encode()
        return self.req("POST", "/preview/batch", body, {"Content-Type": "application/json"})


# ---------------------------------------------------------------- fixtures

def make_pdf(pages: int, label: str) -> bytes:
    objs = ["<< /Type /Catalog /Pages 2 0 R >>", None, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    kids = []
    for i in range(pages):
        text = f"BT /F1 28 Tf 72 720 Td ({label} page {i + 1}) Tj ET\n" + "".join(
            f"BT /F1 10 Tf 72 {690 - 12 * j} Td (line {j} of page {i + 1} lorem ipsum dolor sit amet) Tj ET\n"
            for j in range(50))
        objs.append(f"<< /Length {len(text)} >>\nstream\n{text}endstream")
        content_id = len(objs)
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {content_id} 0 R "
                    f"/Resources << /Font << /F1 3 0 R >> >> >>")
        kids.append(f"{len(objs)} 0 R")
    objs[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {pages} >>"
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n{body}\nendobj\n".encode()
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def ffmpeg_image(dest: Path, w: int, h: int, seed: int) -> None:
    pattern = ["testsrc2", "mandelbrot", "smptehdbars", "rgbtestsrc"][seed % 4]
    sh("ffmpeg", "-loglevel", "error", "-y", "-f", "lavfi", "-i", f"{pattern}=size={w}x{h}",
       "-vf", f"noise=alls={10 + seed % 20}:allf=t,hue=h={seed * 37 % 360}", "-frames:v", "1",
       *(["-q:v", "3"] if dest.suffix == ".jpg" else []), str(dest), timeout=300)


def build_fixtures(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    manifest = {"grid": [], "corrupt": [], "pdf": []}
    for i in range(100):
        corrupt = i % 25 == 24  # 4 corrupt
        ext = ".png" if i % 4 == 3 else ".jpg"
        name = f"img_{i:03d}{ext}"
        dest = out / name
        if not dest.exists():
            if corrupt:
                good = out / f"_tmp{ext}"
                ffmpeg_image(good, 1600, 1200, i)
                data = good.read_bytes()
                dest.write_bytes(data[: len(data) // 3] + os.urandom(2048))  # truncated + garbage
                good.unlink()
            elif ext == ".jpg":
                ffmpeg_image(dest, 4000, 3000, i)
            else:
                ffmpeg_image(dest, 1920, 1080, i)
        manifest["grid"].append(f"{GRID}/{name}")
        if corrupt:
            manifest["corrupt"].append(f"{GRID}/{name}")
    for i in range(5):
        name = f"doc_{i}.pdf"
        dest = out / name
        if not dest.exists():
            dest.write_bytes(make_pdf(12 + i * 4, f"bench doc {i}"))
        manifest["pdf"].append(f"{PDFS}/{name}")
    return manifest


def vh(*args: str, check: bool = True) -> str:
    return sh("vh", *args, check=check, timeout=120)


def seed(state: Path) -> None:
    state.mkdir(parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    if not sh("getent", "passwd", "vhbench", check=False).strip():
        sh("sudo", "-n", "useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "vhbench")
    uid = int(sh("id", "-u", "vhbench").strip())

    pw_file = state / "bench_user.password"
    if not psql("SELECT 1 FROM users WHERE name = 'bench_user'").strip():
        out = vh("user", "create", "bench_user", "--role", "unprivileged", "--linux-uid", str(uid))
        m = re.search(r"^Password:\s*(\S+)\s*$", out, re.M)
        if not m:
            raise RuntimeError("could not find the generated password in `vh user create` output")
        pw_file.write_text(m.group(1))
        os.chmod(pw_file, 0o600)
    for i in range(FILLERS):
        name = f"bench_filler_{i:02d}"
        if not psql(f"SELECT 1 FROM users WHERE name = '{name}'").strip():
            vh("user", "create", name, "--role", "unprivileged")
    if not psql("SELECT 1 FROM groups WHERE name = 'bench_staff'").strip():
        vh("group", "create", "bench_staff", "--desc", "vhbench")
    members = set(psql("SELECT u.name FROM group_members gm JOIN groups g ON g.id = gm.group_id "
                       "JOIN users u ON u.id = gm.user_id WHERE g.name = 'bench_staff'").split())
    for name in ["bench_user"] + [f"bench_filler_{i:02d}" for i in range(FILLERS)]:
        if name not in members:
            vh("group", "user", "add", "bench_staff", name)
    assigned = psql("SELECT vra.subject_type || ':' || vr.name FROM vault_role_assignments vra "
                    "JOIN vault_role vr ON vr.id = vra.role_id WHERE vra.vault_id = 1 AND ("
                    "(vra.subject_type = 'user' AND vra.subject_id = (SELECT id FROM users WHERE name='bench_user')) OR "
                    "(vra.subject_type = 'group' AND vra.subject_id = (SELECT id FROM groups WHERE name='bench_staff')))")
    if "group:reader" not in assigned:
        vh("vault", "role", "assign", str(VAULT_ID), "reader", "--group", "bench_staff")
    if "user:contributor" not in assigned:
        vh("vault", "role", "assign", str(VAULT_ID), "contributor", "-u", "bench_user")
        vh("vault", "role", "override", "add", str(VAULT_ID), "contributor", "-u", "bench_user",
           "--deny-files-download", "--pattern", "/bench/private/**")

    fixtures = state / "fixtures"
    manifest = build_fixtures(fixtures)
    root = MOUNT / VAULT_DIR
    for rel in ("bench", "bench/grid", "bench/pdf", "bench/private", "bench/deep/a/b/c"):
        (root / rel).mkdir(parents=True, exist_ok=True)
    (root / "bench/deep/a/b/c/leaf.txt").write_text("leaf\n")
    for path in manifest["grid"] + manifest["pdf"]:
        dest = root / path.lstrip("/")
        if not dest.exists():
            dest.write_bytes((fixtures / Path(path).name).read_bytes())
    (state / "manifest.json").write_text(json.dumps(manifest, indent=1))
    print(json.dumps({"seeded": True, "uid": uid, "grid": len(manifest["grid"]), "pdf": len(manifest["pdf"])}))


# ---------------------------------------------------------------- scenarios

def fuse_scenarios(results: dict) -> None:
    deep = MOUNT / VAULT_DIR / "bench/deep/a/b/c/leaf.txt"
    grid = MOUNT / VAULT_DIR / "bench/grid"
    as_bench = ["sudo", "-n", "-u", "vhbench"]

    def loop_stat(prefix: list[str], n: int) -> str:
        return " ".join(prefix) + f" sh -c 'i=0; while [ $i -lt {n} ]; do stat -c %s {deep} >/dev/null; i=$((i+1)); done'"

    for who, prefix in (("admin", []), ("bench_user", as_bench)):
        n = 200
        with Probe() as p:
            subprocess.run(loop_stat(prefix, n), shell=True, check=True, timeout=300)
        results[f"fuse.stat_deep.{who}"] = p.result(n, note="stat of a 6-component path (lookup x6 + getattr)")

        n = 20
        with Probe() as p:
            for _ in range(n):
                subprocess.run(prefix + ["ls", "-l", str(grid)], check=True, capture_output=True, timeout=120)
        results[f"fuse.ls_grid.{who}"] = p.result(n, note="ls -l of a 100-entry directory")

        n = 10
        target = grid / "img_000.jpg"
        with Probe() as p:
            for _ in range(n):
                subprocess.run(prefix + ["cat", str(target)], check=True, capture_output=True, timeout=120)
        size = target.stat().st_size
        results[f"fuse.cat_4mb.{who}"] = p.result(n, note=f"read a {size} byte file")


def seal_scenarios(results: dict) -> None:
    """FUSE writes: each create or overwrite is sealed on close (encrypt, row update, journal; #259)."""
    stamp = time.strftime("%H%M%S")
    as_bench = ["sudo", "-n", "-u", "vhbench"]

    def loop_write(prefix: list[str], folder: Path, n: int, fill: str) -> str:
        return " ".join(prefix) + (f" sh -c 'i=0; while [ $i -lt {n} ]; do printf \"%4096s\" \"{fill}$i\" > {folder}/f$i.txt; "
                                   "i=$((i+1)); done'")

    for who, prefix in (("admin", []), ("bench_user", as_bench)):
        folder = MOUNT / VAULT_DIR / f"bench/seal_{who}_{stamp}"
        subprocess.run(prefix + ["mkdir", str(folder)], check=True, timeout=60)
        n = 200
        with Probe() as p:
            subprocess.run(loop_write(prefix, folder, n, "new"), shell=True, check=True, timeout=600)
        results[f"fuse.seal_create.{who}"] = p.result(n, note="create + write 4 KiB + close (sealed) per file")
        with Probe() as p:
            subprocess.run(loop_write(prefix, folder, n, "again"), shell=True, check=True, timeout=600)
        results[f"fuse.seal_overwrite.{who}"] = p.result(n, note="overwrite 4 KiB + close (sealed) per file")
        subprocess.run(["rm", "-rf", str(folder)], check=True, timeout=600)  # as admin: bench_user may not delete


def preview_scenarios(state: Path, results: dict, manifest: dict) -> None:
    password = (state / "bench_user.password").read_text().strip()
    ws, cookie = login("bench_user", password)
    ws.close()
    grid = manifest["grid"]
    good = [p for p in grid if p not in manifest["corrupt"]]

    # Warm the grid first (a candidate with a new generator version starts with no valid thumbnails): poll until every
    # good image is ready, as a browser would.
    http = Http(cookie)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        _, _, body = http.batch(grid)
        if sum(1 for i in json.loads(body)["items"] if i["status"] == "ready") >= len(good):
            break
        time.sleep(0.5)

    # Warm grid: the batch (readiness) and the thumbnails it points at.
    status, _, body = http.batch(grid)
    first = json.loads(body) if status == 200 else {}
    results["preview.batch_statuses"] = {s: sum(1 for i in first.get("items", []) if i["status"] == s)
                                         for s in ("ready", "queued", "missing", "unsupported", "error", "failed")}
    rounds = 5
    batch_lat, img_lat, sizes = [], [], []
    with Probe() as p:
        for _ in range(rounds):
            t = time.monotonic()
            status, _, body = http.batch(grid)
            batch_lat.append(time.monotonic() - t)
            items = json.loads(body)["items"]
            for item in items:
                if item.get("url"):
                    t = time.monotonic()
                    s, _, data = http.req("GET", item["url"])
                    img_lat.append(time.monotonic() - t)
                    sizes.append(len(data))
    results["preview.grid_warm"] = p.result(rounds, batch=lat(batch_lat), image=lat(img_lat),
                                            thumb_bytes_mean=round(statistics.fmean(sizes)) if sizes else 0,
                                            note="per op = one grid view: batch(100) + GET of every ready thumbnail")

    # Revalidation (browser cache, max-age=0): conditional GETs.
    etags = {}
    for path in good[:50]:
        s, h, _ = http.req("GET", http.preview_url(path, 128))
        if s == 200:
            etags[path] = h.get("etag")
    reval = []
    with Probe() as p:
        for path, etag in etags.items():
            t = time.monotonic()
            http.req("GET", http.preview_url(path, 128), headers={"If-None-Match": etag})
            reval.append(time.monotonic() - t)
    results["preview.revalidate_304"] = p.result(max(1, len(etags)), image=lat(reval))

    # Image viewer (1024): first open of each image, then again.
    viewer = good[:20]
    for phase in ("cold", "warm"):
        latv = []
        with Probe() as p:
            for path in viewer:
                t = time.monotonic()
                http.req("GET", http.preview_url(path, 1024))
                latv.append(time.monotonic() - t)
        results[f"preview.viewer_1024.{phase}"] = p.result(len(viewer), image=lat(latv))

    # PDF pages at 1536: first view, then again.
    for phase in ("cold", "warm"):
        latp = []
        n = 0
        with Probe() as p:
            for doc in manifest["pdf"]:
                for page in range(4):
                    t = time.monotonic()
                    http.req("GET", http.preview_url(doc, 1536, page))
                    latp.append(time.monotonic() - t)
                    n += 1
        results[f"preview.pdf_pages_1536.{phase}"] = p.result(n, image=lat(latp))

    # Concurrency: 8 clients each loading the warm grid twice.
    def client(_):
        h = Http(cookie)
        out = []
        for _ in range(2):
            _, _, body = h.batch(grid)
            for item in json.loads(body)["items"]:
                if item.get("url"):
                    t = time.monotonic()
                    h.req("GET", item["url"])
                    out.append(time.monotonic() - t)
        return out

    with Probe() as p:
        t = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            lats = [x for chunk in pool.map(client, range(8)) for x in chunk]
        elapsed = time.monotonic() - t
    results["preview.grid_warm_concurrent8"] = p.result(16, image=lat(lats), elapsed_s=round(elapsed, 3))

    # Known-bad sources: what the batch reports, and what polling them costs.
    polls = 6
    with Probe() as p:
        for _ in range(polls):
            _, _, body = http.batch(manifest["corrupt"])
    statuses = [i["status"] for i in json.loads(body)["items"]]
    results["preview.corrupt_poll"] = p.result(polls, statuses=statuses,
                                               note="one op = batch of the 4 corrupt images (what the grid repolls)")

    # Cold grid: drop the derived artifacts of the grid, then poll the batch until every good image is ready.
    purge_grid_artifacts()
    polls = 0
    with Probe() as p:
        t = time.monotonic()
        ready = 0
        while time.monotonic() - t < 300:
            polls += 1
            _, _, body = http.batch(grid)
            items = json.loads(body)["items"]
            ready = sum(1 for i in items if i["status"] == "ready")
            if ready >= len(good):
                break
            time.sleep(0.25)
        to_ready = time.monotonic() - t
    results["preview.grid_cold"] = p.result(1, seconds_to_ready=round(to_ready, 3), polls=polls, ready=ready,
                                            note="derived cache purged for the grid; batch polled every 250 ms")


def purge_grid_artifacts() -> None:
    root = sh("sudo", "-n", "find", "/var/lib/vaulthalla/.cache", "-maxdepth", "2", "-type", "d", "-name",
              "derived").split()
    ids = psql("SELECT DISTINCT c.file_id FROM cache_index c JOIN fs_entry e ON e.id = c.file_id "
               "WHERE c.type = 'derived' AND e.path LIKE '/bench/%'").split()
    if not ids:
        return
    psql(f"DELETE FROM cache_index WHERE type = 'derived' AND file_id IN ({','.join(ids)})")
    for r in root:
        for i in ids:
            sh("sudo", "-n", "rm", "-rf", f"{r}/{i}", check=False)


def import_scenario(state: Path, results: dict, manifest: dict) -> None:
    """Bulk FUSE import of the grid into a fresh folder, until its thumbnails exist (eager or on first view)."""
    fixtures = state / "fixtures"
    stamp = time.strftime("%H%M%S")
    folder = f"/bench/import_{stamp}"
    dest = MOUNT / VAULT_DIR / folder.lstrip("/")
    dest.mkdir(parents=True)
    names = [Path(p).name for p in manifest["grid"]]
    password = (state / "bench_user.password").read_text().strip()
    ws, cookie = login("bench_user", password)
    ws.close()
    http = Http(cookie)
    with Probe() as p:
        t = time.monotonic()
        for name in names:
            (dest / name).write_bytes((fixtures / name).read_bytes())
        copied = time.monotonic() - t
        paths = [f"{folder}/{n}" for n in names]
        good = len(names) - len(manifest["corrupt"])
        polls = 0
        while time.monotonic() - t < 600:
            polls += 1
            _, _, body = http.batch(paths)
            ready = sum(1 for i in json.loads(body)["items"] if i["status"] == "ready")
            if ready >= good:
                break
            time.sleep(0.5)
        total = time.monotonic() - t
    results["preview.import_100"] = p.result(len(names), copy_s=round(copied, 3), seconds_to_ready=round(total, 3),
                                             polls=polls, note="FUSE copy of 100 images + time until grid-ready")
    artifacts = psql("SELECT count(*), coalesce(sum(size),0) FROM cache_index c JOIN fs_entry e ON e.id = c.file_id "
                     f"WHERE c.type = 'derived' AND e.path LIKE '{folder}/%'").split("|")
    results["preview.import_100"]["artifacts"] = {"rows": int(artifacts[0]), "bytes": int(artifacts[1])}


def run(state: Path, label: str, only: set[str]) -> None:
    manifest = json.loads((state / "manifest.json").read_text())
    results: dict = {"label": label, "version": sh("dpkg-query", "-W", "-f", "${Version}", "vaulthalla").strip(),
                     "at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    Probe.profile = pgss_available()
    results["pg_stat_statements"] = Probe.profile
    Probe.calibrate()
    results["idle_rate_per_s"] = {k: round(v, 3) for k, v in (Probe.idle_rate or {}).items() if v}
    if not only or "fuse" in only:
        fuse_scenarios(results)
    if not only or "seal" in only:
        seal_scenarios(results)
    if not only or "preview" in only:
        preview_scenarios(state, results, manifest)
    if not only or "import" in only:
        import_scenario(state, results, manifest)
    print(json.dumps(results, indent=1))


def compare(a_path: str, b_path: str) -> None:
    a, b = json.loads(Path(a_path).read_text()), json.loads(Path(b_path).read_text())
    rows = []
    for key in a:
        if not isinstance(a[key], dict) or "per_op" not in a[key] or key not in b:
            continue
        ra, rb = a[key], b[key]
        def g(r, *path):
            for p in path:
                r = r.get(p, {}) if isinstance(r, dict) else {}
            return r if isinstance(r, (int, float)) else None
        for metric in (("per_op", "xact"), ("per_op", "statements"), ("per_op", "sql_ms"), ("per_op", "cpu_ms"),
                       ("per_op", "syscalls"), ("wall_s",),
                       ("image", "p50_ms"), ("image", "p95_ms"), ("batch", "p50_ms"), ("seconds_to_ready",)):
            va, vb = g(ra, *metric), g(rb, *metric)
            if va is None or vb is None:
                continue
            change = "" if not va else f"{(vb - va) / va * 100:+.0f}%"
            rows.append((key, ".".join(metric), va, vb, change))
    w = max(len(r[0]) for r in rows) if rows else 10
    print(f"{'scenario':<{w}}  {'metric':<16} {a['label']:>12} {b['label']:>12} {'change':>8}")
    for r in rows:
        print(f"{r[0]:<{w}}  {r[1]:<16} {r[2]:>12} {r[3]:>12} {r[4]:>8}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seed")
    s.add_argument("--state", required=True, type=Path)
    r = sub.add_parser("run")
    r.add_argument("--state", required=True, type=Path)
    r.add_argument("--label", required=True)
    r.add_argument("--only", default="", help="comma list of fuse,seal,preview,import")
    c = sub.add_parser("compare")
    c.add_argument("a")
    c.add_argument("b")
    args = ap.parse_args()
    if args.cmd == "seed":
        seed(args.state)
    elif args.cmd == "run":
        run(args.state, args.label, {x for x in args.only.split(",") if x})
    else:
        compare(args.a, args.b)
    return 0


if __name__ == "__main__":
    sys.exit(main())
