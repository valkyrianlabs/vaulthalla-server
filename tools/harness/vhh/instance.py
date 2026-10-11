"""Launch and supervise a private daemon instance (VH_TEST_MODE=1) for one engine run.

The instance owns everything it touches: a per-run PostgreSQL database owned by the harness role, a run directory
under /tmp/vhh_<run>/ (backing, mount, logs, runtime, config, CLI socket) and two free loopback ports. The daemon
refuses to start unless all of that is private (core/include/runtime/TestInstance.hpp); this module never points it
anywhere else. It survives the daemon crashing or wedging: deadlines, evidence capture, and abort of this run's own
FUSE connection only.

Runs as root (FUSE allow_other, the TPM, actors switching to test uids). The harness DB role's settings are read from
a root-only file and only ever passed to the daemon's environment; they are registered with the redactor and never
written to a trace, report or log.
"""
from __future__ import annotations

import grp
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

DB_ENV_FILE = Path("/var/lib/vaulthalla-harness/db.env")
RUN_ROOT = Path("/tmp")
RUN_PREFIX = "vhh_"
DB_PREFIX = "vh_harness_"
TARGET_KIND = "vhh-private-local"


class InstanceError(RuntimeError):
    pass


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _read_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        raise InstanceError(f"{path} is missing: run tools/harness/bootstrap.sh first")
    out: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    missing = [k for k in ("VH_TEST_DB_USER", "VH_TEST_DB_PASS", "VH_TEST_DB_HOST", "VH_TEST_DB_PORT") if not out.get(k)]
    if missing:
        raise InstanceError(f"{path} lacks {', '.join(missing)}")
    return out


def mount_entry(mount: Path) -> dict | None:
    """The /proc/self/mountinfo entry for `mount`, read without touching the mount itself."""
    target = str(mount)
    with open("/proc/self/mountinfo") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) > 9 and parts[4] == target:
                sep = parts.index("-")
                major, minor = parts[2].split(":")
                return {"major": int(major), "minor": int(minor), "fstype": parts[sep + 1]}
    return None


def run(cmd: list[str], timeout: float = 30, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)


@dataclass
class Target:
    """target.json: what the engine launched. Destructive commands only accept a target that validates."""
    kind: str
    run_id: str
    nonce: str
    pid: int
    server: str
    db_name: str
    run_dir: str
    mount: str
    backing: str
    cli_socket: str
    ws_port: int
    http_port: int
    artifacts: str
    build_dir: str
    started_at: float
    admin_uid: int
    extra: dict = field(default_factory=dict)

    def ws_url(self) -> str:
        return f"ws://127.0.0.1:{self.ws_port}/ws"

    def http_base(self) -> str:
        return f"http://127.0.0.1:{self.http_port}"

    @staticmethod
    def load(path: Path) -> "Target":
        data = json.loads(Path(path).read_text())
        return Target(**data)


def validate_target(t: Target) -> str | None:
    """Why `t` is not a live private instance this engine launched, or None. Fails closed on any doubt."""
    if t.kind != TARGET_KIND:
        return f"unknown target kind {t.kind!r}"
    if not t.db_name.startswith(DB_PREFIX):
        return f"database {t.db_name!r} is not a harness database"
    for p in (t.run_dir, t.mount, t.backing, t.cli_socket):
        if not os.path.normpath(p).startswith(str(RUN_ROOT / RUN_PREFIX)):
            return f"{p} is not under {RUN_ROOT / RUN_PREFIX}*"
    try:
        exe = os.readlink(f"/proc/{t.pid}/exe")
    except OSError:
        return f"pid {t.pid} is not running"
    if os.path.realpath(exe) != os.path.realpath(t.server):
        return f"pid {t.pid} is {exe}, not {t.server}"
    try:
        environ = Path(f"/proc/{t.pid}/environ").read_bytes().split(b"\0")
    except OSError as e:
        return f"cannot read pid {t.pid} environment: {e}"
    if b"VH_TEST_MODE=1" not in environ or f"VH_TEST_DB_NAME={t.db_name}".encode() not in environ:
        return f"pid {t.pid} is not the test instance for {t.db_name}"
    return None


class Instance:
    """One private daemon. Use as a context manager, or call start()/stop()."""

    def __init__(self, build_dir: Path, run_id: str | None = None, artifacts: Path | None = None,
                 redactor=None, extra_env: dict[str, str] | None = None, start_timeout: float = 90):
        if os.geteuid() != 0:
            raise InstanceError("the engine launches the daemon as root (FUSE allow_other, TPM, actor uids): use sudo")
        self.build_dir = Path(build_dir).resolve()
        self.server = self.build_dir / "core" / "vaulthalla-server"
        self.cli = self.build_dir / "core" / "vaulthalla-cli"
        if not self.server.exists():
            raise InstanceError(f"{self.server} not found (build first: meson compile -C {build_dir})")
        self.run_id = run_id or time.strftime("%Y%m%dT%H%M%S") + "_" + secrets.token_hex(3)
        if not self.run_id.replace("_", "").isalnum():
            raise InstanceError(f"run id {self.run_id!r} must be alphanumeric/underscore")
        self.run_dir = RUN_ROOT / f"{RUN_PREFIX}{self.run_id}"
        self.artifacts = Path(artifacts) if artifacts else self.run_dir / "artifacts"
        self.db_name = f"{DB_PREFIX}{self.run_id}".lower()
        self.redactor = redactor
        self.extra_env = extra_env or {}
        self.start_timeout = start_timeout
        self.proc: subprocess.Popen | None = None
        self.target: Target | None = None
        self._db_created = False
        self._log = None

    # ------------------------------------------------------------------ paths
    @property
    def mount(self) -> Path: return self.run_dir / "mnt"
    @property
    def backing(self) -> Path: return self.run_dir / "backing"
    @property
    def socket_path(self) -> Path: return self.run_dir / "cli.sock"
    @property
    def log_path(self) -> Path: return self.artifacts / "daemon.log"

    # ------------------------------------------------------------------ lifecycle
    def __enter__(self) -> "Instance":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def start(self) -> Target:
        if self.run_dir.exists():
            raise InstanceError(f"{self.run_dir} already exists")
        for d in (self.run_dir, self.run_dir / "run", self.run_dir / "log", self.artifacts):
            d.mkdir(parents=True, mode=0o755, exist_ok=True)
        admin_uid = int(os.environ.get("SUDO_UID") or 1000) or 1000
        (self.run_dir / "run" / "superadmin_uid").write_text(f"{admin_uid}\n")

        ws_port, http_port = _free_port(), _free_port()
        while http_port == ws_port:
            http_port = _free_port()
        (self.run_dir / "config.yaml").write_text(
            "websocket_server: {enabled: true, host: 127.0.0.1, port: %d, max_connections: 4096}\n"
            "http_preview_server: {enabled: true, host: 127.0.0.1, port: %d, max_connections: 1024}\n"
            "s3_gateway: {enabled: false, host: 127.0.0.1, port: %d}\n"
            "email: {enabled: false}\n"
            "operator_emails: {enabled: false}\n"
            "dev: {enabled: false, init_r2_test_vault: false}\n" % (ws_port, http_port, _free_port()))

        db = _read_env_file(DB_ENV_FILE)
        if self.redactor is not None:
            self.redactor.register_secret(db["VH_TEST_DB_PASS"])
        cp = run(["runuser", "-u", "postgres", "--", "createdb", "-O", db["VH_TEST_DB_USER"], self.db_name])
        if cp.returncode != 0:
            raise InstanceError(f"createdb {self.db_name} failed: {cp.stderr.strip()[:300]}")
        self._db_created = True

        env = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(self.run_dir),
            "TMPDIR": str(self.run_dir),
            "VH_TEST_MODE": "1",
            "VH_TEST_DB_NAME": self.db_name,
            "VH_TEST_BACKING_PATH": str(self.backing),
            "VH_TEST_MOUNT_PATH": str(self.mount),
            "VH_TEST_LOG_PATH": str(self.run_dir / "log"),
            "VH_PATH_TO_SUPERADMIN_UID": str(self.run_dir / "run"),
            "VH_PATH_TO_CONFIG": str(self.run_dir / "config.yaml"),
            "VH_TEST_CLI_SOCKET": str(self.socket_path),
            "ASAN_OPTIONS": f"detect_leaks=0:abort_on_error=1:log_path={self.artifacts}/asan",
            "UBSAN_OPTIONS": f"print_stacktrace=1:log_path={self.artifacts}/ubsan",
            "TSAN_OPTIONS": f"log_path={self.artifacts}/tsan:second_deadlock_stack=1",
            **{k: db[k] for k in ("VH_TEST_DB_USER", "VH_TEST_DB_PASS", "VH_TEST_DB_HOST", "VH_TEST_DB_PORT")},
            **self.extra_env,
        }
        self._log = open(self.log_path, "ab", buffering=0)
        cmd = [str(self.server)]
        if self.extra_env.get("VHH_SETARCH") == "1":   # TSan on this kernel needs ASLR off
            cmd = ["setarch", "-R"] + cmd
        self.proc = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=self._log,
                                     stderr=subprocess.STDOUT, start_new_session=True, cwd=str(self.run_dir))
        self._wait_ready(ws_port, http_port)

        self.target = Target(kind=TARGET_KIND, run_id=self.run_id, nonce=secrets.token_hex(8), pid=self.proc.pid,
                             server=str(self.server), db_name=self.db_name, run_dir=str(self.run_dir),
                             mount=str(self.mount), backing=str(self.backing), cli_socket=str(self.socket_path),
                             ws_port=ws_port, http_port=http_port, artifacts=str(self.artifacts),
                             build_dir=str(self.build_dir), started_at=time.time(), admin_uid=admin_uid,
                             extra={"server_cli": str(self.cli)})
        (self.artifacts / "target.json").write_text(json.dumps(asdict(self.target), indent=2))
        why = validate_target(self.target)
        if why:
            self.stop()
            raise InstanceError(f"launched instance failed validation: {why}")
        return self.target

    def _wait_ready(self, ws_port: int, http_port: int) -> None:
        deadline = time.monotonic() + self.start_timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise InstanceError(f"daemon exited with {self.proc.returncode} during startup; "
                                    f"log tail:\n{self.log_tail(30)}")
            if (self.socket_path.exists() and mount_entry(self.mount)
                    and _port_open(ws_port) and _port_open(http_port)):
                # The packaged daemon's socket belongs to the 'vaulthalla' group (it runs as that user); give this
                # run's private socket the same group so CLI actor accounts are gated exactly as in production.
                os.chown(self.socket_path, -1, grp.getgrnam("vaulthalla").gr_gid)
                return
            time.sleep(0.2)
        self.capture_evidence("startup-timeout")
        raise InstanceError(f"daemon not ready within {self.start_timeout}s; log tail:\n{self.log_tail(30)}")

    # ------------------------------------------------------------------ health
    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def health(self) -> dict:
        if not self.alive():
            return {"alive": False, "returncode": None if self.proc is None else self.proc.returncode}
        pid = self.proc.pid
        out: dict = {"alive": True, "pid": pid}
        try:
            status = Path(f"/proc/{pid}/status").read_text()
            for line in status.splitlines():
                if line.startswith(("VmRSS:", "Threads:")):
                    k, v = line.split(":", 1)
                    out[k.lower()] = v.strip()
            out["fds"] = len(os.listdir(f"/proc/{pid}/fd"))
        except OSError:
            pass
        out["fuse"] = self.fuse_connection()
        return out

    def fuse_connection(self) -> dict | None:
        m = mount_entry(self.mount)
        if not m:
            return None
        conn = Path("/sys/fs/fuse/connections") / str(m["minor"])
        info = {"id": m["minor"]}
        try:
            info["waiting"] = int((conn / "waiting").read_text().strip())
        except OSError:
            pass
        return info

    def abort_fuse(self) -> bool:
        """Abort this run's FUSE connection (and only it). Unblocks anything stuck on the mount."""
        m = mount_entry(self.mount)
        if not m or m["fstype"] != "fuse.vaulthalla-fuse":
            return False
        abort = Path("/sys/fs/fuse/connections") / str(m["minor"]) / "abort"
        try:
            abort.write_text("1")
            return True
        except OSError:
            return False

    def log_tail(self, n: int = 50) -> str:
        try:
            data = self.log_path.read_bytes()[-20000:].decode("utf-8", "replace")
        except OSError:
            return ""
        text = "\n".join(data.splitlines()[-n:])
        return self.redactor.redact_text(text) if self.redactor is not None else text

    def capture_evidence(self, reason: str) -> Path:
        """Thread states, fusectl counters, DB activity and the log tail, without blocking on the mount."""
        d = self.artifacts / "evidence" / f"{time.strftime('%H%M%S')}_{reason}"
        d.mkdir(parents=True, exist_ok=True)
        (d / "health.json").write_text(json.dumps(self.health(), indent=2, default=str))
        if self.alive():
            pid = self.proc.pid
            lines = []
            for tid in sorted(os.listdir(f"/proc/{pid}/task"), key=int):
                t = Path(f"/proc/{pid}/task/{tid}")
                row = [tid]
                for name in ("comm", "wchan"):
                    try:
                        row.append((t / name).read_text().strip())
                    except OSError:
                        row.append("?")
                try:
                    row.append((t / "stack").read_text().strip().replace("\n", " | "))
                except OSError:
                    row.append("")
                lines.append("\t".join(row))
            (d / "threads.tsv").write_text("\n".join(lines) + "\n")
        try:
            cp = run(["runuser", "-u", "postgres", "--", "psql", "-XAtc",
                      "select pid,state,wait_event_type,wait_event,now()-query_start,left(query,200) "
                      f"from pg_stat_activity where datname='{self.db_name}'"], timeout=10)
            (d / "pg_stat_activity.txt").write_text(cp.stdout)
        except (subprocess.TimeoutExpired, OSError):
            pass
        (d / "daemon.log.tail").write_text(self.log_tail(400))
        return d

    # ------------------------------------------------------------------ shutdown
    def stop(self, grace: float = 15) -> dict:
        """Stop the daemon (by its own pid), make sure the mount is gone, drop the run database. Idempotent."""
        report: dict = {"run_id": self.run_id}
        if self.proc is not None and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=grace)
                report["stop"] = "clean"
            except subprocess.TimeoutExpired:
                report["stop"] = "forced"
                report["evidence"] = str(self.capture_evidence("stop-timeout"))
                self.abort_fuse()
                self.proc.kill()
                try:
                    self.proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    report["stop"] = "unkillable"
        if self.proc is not None:
            report["returncode"] = self.proc.returncode
        if mount_entry(self.mount):
            self.abort_fuse()
            run(["fusermount3", "-uz", str(self.mount)], timeout=10)
            report["mount_cleanup"] = "lazy-unmounted" if not mount_entry(self.mount) else "STILL MOUNTED"
        if self._db_created:
            cp = run(["runuser", "-u", "postgres", "--", "dropdb", "--force", "--if-exists", self.db_name], timeout=60)
            report["db_dropped"] = cp.returncode == 0
            self._db_created = cp.returncode != 0
        if self._log:
            self._log.close()
            self._log = None
        # The run dir holds sealed test keys and backing data; artifacts are kept, the rest goes.
        if not mount_entry(self.mount):
            for name in ("backing", "mnt", "run", "cli.sock"):
                p = self.run_dir / name
                if p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)
                elif p.exists():
                    p.unlink()
        return report


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False
