#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
import filecmp
import hashlib
import ipaddress
import os
import pwd
import re
import secrets
import shutil
import socket
import string
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

DB_NAME = "vaulthalla"
DB_USER = "vaulthalla"
SERVICE_UNIT = "vaulthalla.service"
PENDING_DB_PASSWORD_FILE = Path("/run/vaulthalla/db_password")
STATE_DIR = Path("/var/lib/vaulthalla")
# TPMKeyProvider("psql") seals the DB password to <backing path>/.sealed_psql.blob/psql.{priv,pub}.
SEALED_DB_SECRET_DIR = STATE_DIR / ".sealed_psql.blob"
DB_BOOTSTRAP_OPTOUT_MARKER = STATE_DIR / "db_bootstrap_disabled"
NGINX_OPTOUT_MARKER = STATE_DIR / "nginx_config_disabled"
# The generated initial web password of the built-in super admin ('admin'), written once by the daemon on a fresh
# install (core auth/Bootstrap.hpp). Whether that password is still in use is auth_bootstrap_state in the DB.
INITIAL_PASSWORD_FILE = STATE_DIR / "super_admin_initial_password"
PGCONNECT_TIMEOUT_SECONDS = 10
DEFAULT_COMMAND_TIMEOUT_SECONDS = 120
SERVICE_HEALTH_TIMEOUT_SECONDS = 30
SERVICE_HEALTH_STABLE_SECONDS = 5

DEFAULT_CONFIG_PATH = Path("/etc/vaulthalla/config.yaml")
DEFAULT_SCHEMA_DIR = Path("/usr/share/vaulthalla/psql")
DEFAULT_NGINX_TEMPLATE = Path("/usr/share/vaulthalla/nginx/vaulthalla")

NGINX_SITE_AVAILABLE = Path("/etc/nginx/sites-available/vaulthalla")
NGINX_SITE_ENABLED = Path("/etc/nginx/sites-enabled/vaulthalla")
NGINX_MANAGED_MARKER = Path("/var/lib/vaulthalla/nginx_site_managed")
NGINX_DEFAULT_SITE_AVAILABLE = Path("/etc/nginx/sites-available/default")
NGINX_DEFAULT_SITE_ENABLED = Path("/etc/nginx/sites-enabled/default")
NGINX_DEFAULT_DISABLED_MARKER = Path("/var/lib/vaulthalla/nginx_default_site_disabled")
NGINX_RENEWAL_DEPLOY_HOOK = Path("/etc/letsencrypt/renewal-hooks/deploy/vaulthalla-nginx-reload.sh")
LETSENCRYPT_LIVE_DIR = Path("/etc/letsencrypt/live")
CERTBOT_RENEWAL_WINDOW_SECONDS = 30 * 24 * 60 * 60

# HTTPS by default (#324): without a public certificate, nginx serves the console with a locally generated
# certificate (self-signed, ECDSA P-256, 825 days: the longest lifetime Apple platforms accept for a trusted
# server certificate). Regenerated when it nears expiry or the host's names/addresses change.
LOCAL_TLS_DIR = Path("/etc/vaulthalla/tls")
LOCAL_TLS_CERT = LOCAL_TLS_DIR / "local.crt"
LOCAL_TLS_KEY = LOCAL_TLS_DIR / "local.key"
LOCAL_TLS_DAYS = 825
LOCAL_TLS_RENEW_DAYS = 30

WEB_UPSTREAM_HOST = "127.0.0.1"
WEB_UPSTREAM_PORT = 36968


class LifecycleError(RuntimeError):
    pass


@dataclass
class CertificateState:
    exists: bool
    domains: set[str]
    renewal_due: bool


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def run_capture(
    args: list[str],
    input_text: str | None = None,
    timeout: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    # Every external call is bounded; secrets travel via input_text (stdin), never argv.
    try:
        return subprocess.run(args, capture_output=True, text=True, check=False, input=input_text, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise LifecycleError(f"command timed out after {timeout:.0f}s: {' '.join(args[:6])}") from exc


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def trim(value: str) -> str:
    return value.strip()


def combined_output(result: subprocess.CompletedProcess[str]) -> str:
    out = (result.stdout or "") + (result.stderr or "")
    return trim(out)


def format_failure(step: str, result: subprocess.CompletedProcess[str]) -> str:
    msg = f"{step} (exit {result.returncode})"
    output = combined_output(result)
    if output:
        msg += f": {output}"
    return msg


def config_path() -> Path:
    override = os.environ.get("VAULTHALLA_CONFIG_PATH")
    return Path(override) if override else DEFAULT_CONFIG_PATH


def fallback_deploy_root() -> Path:
    return Path(__file__).resolve().parents[1]


def schema_dir() -> Path:
    if DEFAULT_SCHEMA_DIR.is_dir():
        return DEFAULT_SCHEMA_DIR
    fallback = fallback_deploy_root() / "psql"
    return fallback


def nginx_template_path() -> Path:
    if DEFAULT_NGINX_TEMPLATE.is_file():
        return DEFAULT_NGINX_TEMPLATE
    return fallback_deploy_root() / "nginx" / "vaulthalla.conf"


def ensure_privileged_or_reexec() -> None:
    if os.geteuid() == 0:
        return
    if command_exists("sudo"):
        probe = run_capture(["sudo", "-n", "true"])
        if probe.returncode == 0:
            os.execvp("sudo", ["sudo", "-n", sys.executable, __file__, *sys.argv[1:]])
    raise LifecycleError("requires root privileges (or non-interactive sudo access)")


def parse_scalar(raw: str) -> Any:
    text = trim(raw)
    if text == "":
        return ""
    if text.startswith("'") and text.endswith("'") and len(text) >= 2:
        return text[1:-1].replace("''", "'")
    if text.startswith('"') and text.endswith('"') and len(text) >= 2:
        return text[1:-1]
    if text in ("true", "false"):
        return text == "true"
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    return text


def parse_config_projection_from_text(text: str) -> dict[str, dict[str, Any]]:
    projection: dict[str, dict[str, Any]] = {
        "websocket_server": {"enabled": True, "host": "127.0.0.1", "port": 33369},
        "http_preview_server": {"enabled": True, "host": "127.0.0.1", "port": 33370},
        "s3_gateway": {"enabled": False, "host": "127.0.0.1", "port": 39000},
        "database": {"host": "localhost", "port": 5432, "name": DB_NAME, "user": DB_USER, "pool_size": 10},
    }
    section: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not raw_line.startswith((" ", "\t")):
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*):\s*$", line)
            section = m.group(1) if m else None
            continue
        if section not in projection:
            continue
        m = re.match(r"^\s{2}([A-Za-z_][A-Za-z0-9_-]*):\s*(.*?)\s*$", line)
        if not m:
            continue
        key = m.group(1)
        projection[section][key] = parse_scalar(m.group(2))
    return projection


def load_config_projection(path: Path) -> dict[str, dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LifecycleError(f"failed loading config '{path}': {exc}") from exc
    return parse_config_projection_from_text(text)


def yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    if re.fullmatch(r"[A-Za-z0-9_.:/-]+", text):
        return text
    return "'" + text.replace("'", "''") + "'"


def update_database_block_text(text: str, updates: dict[str, Any]) -> str:
    lines = text.splitlines(keepends=True)
    start = -1
    for i, line in enumerate(lines):
        if line.startswith((" ", "\t")):
            continue
        stripped = line.split("#", 1)[0].strip()
        if stripped == "database:":
            start = i
            break

    key_order = ("host", "port", "name", "user", "pool_size")
    if start == -1:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        if lines and trim(lines[-1]):
            lines.append("\n")
        lines.append("database:\n")
        for key in key_order:
            if key in updates:
                lines.append(f"  {key}: {yaml_scalar(updates[key])}\n")
        return "".join(lines)

    end = len(lines)
    for j in range(start + 1, len(lines)):
        candidate = lines[j]
        if candidate.startswith((" ", "\t")):
            continue
        stripped = candidate.split("#", 1)[0].strip()
        if re.match(r"^[A-Za-z_][A-Za-z0-9_-]*:\s*", stripped):
            end = j
            break

    block = lines[start + 1:end]
    for key in key_order:
        if key not in updates:
            continue
        replaced = False
        for idx, block_line in enumerate(block):
            if re.match(rf"^\s{{2}}{re.escape(key)}\s*:", block_line):
                block[idx] = f"  {key}: {yaml_scalar(updates[key])}\n"
                replaced = True
                break
        if not replaced:
            block.append(f"  {key}: {yaml_scalar(updates[key])}\n")

    return "".join(lines[: start + 1] + block + lines[end:])


def save_database_config_updates(path: Path, updates: dict[str, Any]) -> None:
    try:
        original = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LifecycleError(f"failed loading config '{path}': {exc}") from exc

    updated = update_database_block_text(original, updates)
    try:
        path.write_text(updated, encoding="utf-8")
    except OSError as exc:
        raise LifecycleError(f"failed saving config '{path}': {exc}") from exc


def make_db_password(length: int = 48) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def choose_postgres_prefix() -> list[str]:
    candidates: list[list[str]] = []
    if command_exists("runuser"):
        candidates.append(
            ["runuser", "-u", "postgres", "--", "env", f"PGCONNECT_TIMEOUT={PGCONNECT_TIMEOUT_SECONDS}",
             "psql", "-X", "-v", "ON_ERROR_STOP=1"]
        )
    if command_exists("sudo"):
        probe = run_capture(["sudo", "-n", "true"])
        if probe.returncode == 0:
            candidates.append(
                ["sudo", "-n", "-u", "postgres", "env", f"PGCONNECT_TIMEOUT={PGCONNECT_TIMEOUT_SECONDS}",
                 "psql", "-X", "-v", "ON_ERROR_STOP=1"]
            )

    for prefix in candidates:
        probe = run_capture(prefix + ["-d", "postgres", "-tAc", "SELECT 1;"])
        if probe.returncode == 0 and trim(probe.stdout) == "1":
            return prefix
    raise LifecycleError(
        "unable to run PostgreSQL admin commands as 'postgres'. "
        "Verify local PostgreSQL is installed/running and root-equivalent privileges are available."
    )


def psql_sql(prefix: list[str], db: str, sql: str) -> subprocess.CompletedProcess[str]:
    # One statement per call (psql -c runs a multi-statement string as one transaction,
    # which DROP DATABASE refuses). Never put secrets here: argv is world-readable.
    return run_capture(prefix + ["-d", db, "-tAc", sql])


def psql_stdin(prefix: list[str], db: str, sql: str) -> subprocess.CompletedProcess[str]:
    # The channel for SQL that carries a secret (role passwords): fed via stdin.
    return run_capture(prefix + ["-q", "-d", db], input_text=sql)


def sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def sealed_db_secret_present() -> bool:
    return (SEALED_DB_SECRET_DIR / "psql.priv").is_file()


def pending_db_password() -> str | None:
    try:
        tokens = PENDING_DB_PASSWORD_FILE.read_text(encoding="utf-8").split()
    except OSError:
        return None
    return tokens[0] if tokens else None


def query_flag(prefix: list[str], db: str, sql: str, step: str) -> bool:
    result = psql_sql(prefix, db, sql)
    if result.returncode != 0:
        raise LifecycleError(format_failure(step, result))
    return trim(result.stdout) in ("1", "t", "true")


def local_db_has_vaulthalla_data(prefix: list[str]) -> bool:
    # Once the daemon has started even once, initdb has seeded principals into
    # public.users; an absent/empty users table means an interrupted install.
    if not query_flag(prefix, DB_NAME, "SELECT to_regclass('public.users') IS NOT NULL;", "failed inspecting database"):
        return False
    return query_flag(prefix, DB_NAME, "SELECT EXISTS (SELECT 1 FROM public.users);", "failed inspecting database")


def postgres_server_version_num(prefix: list[str]) -> int:
    result = psql_sql(prefix, "postgres", "SHOW server_version_num;")
    try:
        return int(trim(result.stdout)) if result.returncode == 0 else 0
    except ValueError:
        return 0


def drop_local_database(prefix: list[str]) -> None:
    if postgres_server_version_num(prefix) >= 130000:
        steps = [f"DROP DATABASE IF EXISTS {DB_NAME} WITH (FORCE);"]
    else:
        steps = [
            f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{DB_NAME}' AND pid <> pg_backend_pid();",
            f"DROP DATABASE IF EXISTS {DB_NAME};",
        ]
    for sql in steps:
        result = psql_sql(prefix, "postgres", sql)
        if result.returncode != 0:
            raise LifecycleError(format_failure(f"failed dropping PostgreSQL database '{DB_NAME}'", result))


def drop_local_role(prefix: list[str]) -> None:
    result = psql_sql(prefix, "postgres", f"DROP ROLE IF EXISTS {DB_USER};")
    if result.returncode != 0:
        raise LifecycleError(format_failure(f"failed dropping PostgreSQL role '{DB_USER}'", result))


def set_local_role_password(prefix: list[str], password: str, role_exists: bool) -> None:
    if role_exists:
        sql = f"ALTER ROLE {DB_USER} WITH LOGIN PASSWORD {sql_literal(password)};\n"
    else:
        sql = f"CREATE ROLE {DB_USER} LOGIN PASSWORD {sql_literal(password)};\n"
    result = psql_stdin(prefix, "postgres", sql)
    if result.returncode != 0:
        # Don't echo psql output: some errors quote the failing statement (with the password).
        action = "set password for" if role_exists else "create"
        raise LifecycleError(f"failed to {action} PostgreSQL role '{DB_USER}' (exit {result.returncode})")


def write_pending_db_password(password: str) -> None:
    try:
        account = pwd.getpwnam(DB_USER)
    except KeyError as exc:
        raise LifecycleError(f"system user '{DB_USER}' not found") from exc

    tmp = PENDING_DB_PASSWORD_FILE.with_name(PENDING_DB_PASSWORD_FILE.name + ".lifecycle-new")
    try:
        PENDING_DB_PASSWORD_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Created 0600 and renamed into place: never world-readable, never half-written.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(password + "\n")
        os.chown(tmp, account.pw_uid, account.pw_gid)
        os.chmod(tmp, 0o600)
        os.replace(tmp, PENDING_DB_PASSWORD_FILE)
    except OSError as exc:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise LifecycleError(f"failed preparing pending DB password handoff file: {exc}") from exc


def load_password_from_file(path: str) -> str:
    source = Path(path)
    if not source.exists():
        raise LifecycleError(f"password file does not exist: {source}")
    if not source.is_file():
        raise LifecycleError(f"password file is not a regular file: {source}")
    try:
        content = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise LifecycleError(f"failed opening password file: {source}") from exc
    first = content.strip().split()
    if not first:
        raise LifecycleError(f"password file is empty or invalid: {source}")
    return first[0]


def unit_properties(unit: str, *names: str) -> dict[str, str]:
    args = ["systemctl", "show", unit]
    for name in names:
        args.extend(["-p", name])
    result = run_capture(args, timeout=15)
    props: dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            props[key] = value
    return props


def restart_or_start_service() -> str:
    if not command_exists("systemctl"):
        raise LifecycleError("systemctl is not available; cannot hand off lifecycle updates to runtime startup")
    # A unit that hit StartLimitBurst refuses manual starts until its failed state is reset.
    run_capture(["systemctl", "reset-failed", SERVICE_UNIT], timeout=15)
    active = run_capture(["systemctl", "--quiet", "is-active", SERVICE_UNIT], timeout=15)
    action = "restart" if active.returncode == 0 else "start"
    result = run_capture(["systemctl", action, SERVICE_UNIT], timeout=90)
    if result.returncode != 0:
        raise LifecycleError(format_failure(f"failed to {action} {SERVICE_UNIT}", result))
    return "restarted" if action == "restart" else "started"


def wait_for_service_healthy(
    seed_expected: bool,
    timeout: float = SERVICE_HEALTH_TIMEOUT_SECONDS,
    stable: float = SERVICE_HEALTH_STABLE_SECONDS,
) -> tuple[bool, str]:
    """Report what the daemon actually did instead of assuming a started unit is healthy.

    Healthy means ActiveState=active with no new automatic restarts for `stable` seconds
    and, when a password seed was written, the daemon consumed (removed) the seed.
    """
    baseline = unit_properties(SERVICE_UNIT, "NRestarts").get("NRestarts", "0")
    deadline = time.monotonic() + timeout
    active_since: float | None = None
    while True:
        props = unit_properties(SERVICE_UNIT, "ActiveState", "SubState", "NRestarts")
        active_state = props.get("ActiveState", "unknown")
        state = f"{active_state}/{props.get('SubState', 'unknown')}"
        restarted = props.get("NRestarts", baseline) != baseline
        now = time.monotonic()
        if restarted or active_state == "failed":
            return False, f"{state}; restarts={props.get('NRestarts', '?')} (was {baseline})"
        if active_state == "active":
            if active_since is None:
                active_since = now
            seed_consumed = not seed_expected or not PENDING_DB_PASSWORD_FILE.exists()
            if seed_consumed and now - active_since >= stable:
                return True, f"{state} (stable for {stable:.0f}s)"
        else:
            active_since = None
        if now >= deadline:
            return False, f"{state} after {timeout:.0f}s"
        time.sleep(1)


def require_service_healthy(seed_expected: bool, context: str) -> str:
    healthy, detail = wait_for_service_healthy(seed_expected)
    if not healthy:
        raise LifecycleError(
            f"{context}: {SERVICE_UNIT} is not running correctly ({detail}). "
            f"See: journalctl -u {SERVICE_UNIT} -n 50"
        )
    return detail


def validate_and_reload_nginx() -> str:
    test = run_capture(["nginx", "-t"])
    if test.returncode != 0:
        output = combined_output(test)
        raise LifecycleError("nginx -t failed" + (f": {output}" if output else ""))
    if command_exists("systemctl"):
        active = run_capture(["systemctl", "--quiet", "is-active", "nginx.service"])
        if active.returncode == 0:
            reload_result = run_capture(["systemctl", "reload", "nginx.service"])
            if reload_result.returncode != 0:
                raise LifecycleError(format_failure("systemctl reload nginx.service", reload_result))
            return "nginx reloaded"
    return "not attempted (systemctl unavailable or nginx inactive)"


def is_likely_domain(raw: str) -> bool:
    if not raw or len(raw) > 253:
        return False
    if raw[0] in ".-" or raw[-1] in ".-":
        return False
    labels = raw.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not re.fullmatch(r"[A-Za-z0-9-]+", label):
            return False
    return True


def has_non_nginx_listeners_on_web_ports() -> bool:
    if not command_exists("ss"):
        return False
    listeners = run_capture(["ss", "-H", "-ltnp", "( sport = :80 or sport = :443 )"])
    if listeners.returncode != 0:
        return False
    for line in listeners.stdout.splitlines():
        if trim(line) and "nginx" not in line:
            return True
    return False


def strip_nginx_comment(line: str) -> str:
    out: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    for ch in line:
        if escaped:
            out.append(ch)
            escaped = False
            continue
        if ch == "\\":
            out.append(ch)
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            out.append(ch)
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            out.append(ch)
            continue
        if ch == "#" and not in_single and not in_double:
            break
        out.append(ch)
    return "".join(out)


def extract_server_names_from_nginx_dump(text: str) -> list[tuple[str, str]]:
    names: list[tuple[str, str]] = []
    current_file = "<unknown active config>"
    collecting = False
    pending = ""

    for raw in text.splitlines():
        marker = re.match(r"^\s*#\s*configuration file\s+(.+):\s*$", raw)
        if marker:
            current_file = trim(marker.group(1))
            continue

        line = trim(strip_nginx_comment(raw))
        if not line:
            continue

        if collecting:
            pending = f"{pending} {line}".strip()
        elif re.match(r"^server_name(?:\s|$)", line):
            pending = trim(line[len("server_name") :])
        else:
            continue

        if ";" not in pending:
            collecting = True
            continue

        collecting = False
        directive = trim(pending.split(";", 1)[0])
        pending = ""
        if not directive:
            continue
        for token in directive.split():
            names.append((token, current_file))

    return names


def server_name_matches_domain(server_name: str, domain: str) -> bool:
    name = server_name.lower()
    target = domain.lower()
    if not name or name == "_":
        return False
    if name == target:
        return True
    if name.startswith("*."):
        suffix = name[1:]
        return target.endswith(suffix) and target != name[2:]
    if name.endswith(".*"):
        prefix = name[:-1]
        return target.startswith(prefix)
    if name.startswith("."):
        return target == name[1:] or target.endswith(name)
    if name.startswith("~"):
        return False
    return False


def is_managed_nginx_path(raw_path: str) -> bool:
    managed_paths: set[str] = set()
    for path in (NGINX_SITE_AVAILABLE, NGINX_SITE_ENABLED):
        managed_paths.add(str(path))
        try:
            managed_paths.add(str(path.resolve(strict=False)))
        except OSError:
            pass

    candidate = Path(raw_path)
    if str(candidate) in managed_paths:
        return True
    try:
        return str(candidate.resolve(strict=False)) in managed_paths
    except OSError:
        return False


def active_nginx_domain_conflict_source(domain: str) -> str | None:
    dump = run_capture(["nginx", "-T"])
    if dump.returncode != 0:
        raise LifecycleError(format_failure("failed inspecting active nginx config via 'nginx -T'", dump))

    for name, source in extract_server_names_from_nginx_dump(combined_output(dump)):
        if not server_name_matches_domain(name, domain):
            continue
        if is_managed_nginx_path(source):
            continue
        return source
    return None


def normalize_local_upstream_host(host: str) -> str:
    value = trim(host)
    if value in ("", "0.0.0.0", "::", "[::]"):
        return "127.0.0.1"
    return value


def host_for_proxy_pass(host: str) -> str:
    value = normalize_local_upstream_host(host)
    if ":" in value and not value.startswith("["):
        return f"[{value}]"
    return value


def extract_managed_nginx_domain(path: Path = NGINX_SITE_AVAILABLE) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    if "Generated by 'vh setup nginx'" not in text:
        return None
    m = re.search(r"^\s*server_name\s+([^;\s]+)\s*;", text, re.MULTILINE)
    if not m:
        return None
    value = trim(m.group(1))
    return value if value and value != "_" else None


def extract_managed_nginx_s3_domain(path: Path = NGINX_SITE_AVAILABLE) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    if "Generated by 'vh setup nginx'" not in text:
        return None
    m = re.search(r"^\s*#\s*S3 domain:\s*([^\s#]+)\s*$", text, re.MULTILINE)
    if not m:
        return None
    value = trim(m.group(1))
    return value if value and value != "_" else None


def is_likely_hostname(raw: str) -> bool:
    if not raw or len(raw) > 253 or raw[0] in ".-" or raw[-1] in ".-":
        return False
    return all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in raw.split("."))


def local_tls_names() -> tuple[list[str], list[str]]:
    """The names and addresses the local certificate covers: this host's names, localhost, loopback, and the
    host's own (non link-local) addresses, so https://<name or LAN address>/ matches."""
    dns: list[str] = []
    host = socket.gethostname().strip().lower()
    for name in (host, socket.getfqdn().strip().lower(), f"{host.split('.')[0]}.local" if host else "", "localhost"):
        if name and is_likely_hostname(name) and name not in dns:
            dns.append(name)
    ips: list[str] = ["127.0.0.1", "::1"]
    if command_exists("hostname"):
        listed = run_capture(["hostname", "-I"], timeout=10)
        for token in listed.stdout.split() if listed.returncode == 0 else []:
            try:
                address = ipaddress.ip_address(token.split("%", 1)[0])
            except ValueError:
                continue
            if address.is_link_local or address.is_multicast or str(address) in ips:
                continue
            ips.append(str(address))
    return dns, ips


def _certificate_names(cert: Path) -> tuple[set[str], set[str]] | None:
    san = run_capture(["openssl", "x509", "-in", str(cert), "-noout", "-ext", "subjectAltName"], timeout=10)
    if san.returncode != 0:
        return None
    dns = {m.lower() for m in re.findall(r"DNS:([^,\s]+)", san.stdout)}
    ips: set[str] = set()
    for raw in re.findall(r"IP(?: Address)?:([0-9A-Fa-f:.]+)", san.stdout):
        try:
            ips.add(str(ipaddress.ip_address(raw)))
        except ValueError:
            continue
    return dns, ips


def local_certificate_is_current(dns: list[str], ips: list[str]) -> bool:
    if not LOCAL_TLS_CERT.is_file() or not LOCAL_TLS_KEY.is_file():
        return False
    fresh = run_capture(
        ["openssl", "x509", "-in", str(LOCAL_TLS_CERT), "-noout", "-checkend", str(LOCAL_TLS_RENEW_DAYS * 86400)],
        timeout=10,
    )
    if fresh.returncode != 0:
        return False
    covered = _certificate_names(LOCAL_TLS_CERT)
    if covered is None:
        return False
    return set(dns) <= covered[0] and set(ips) <= covered[1]


def local_certificate_fingerprint() -> str | None:
    result = run_capture(["openssl", "x509", "-in", str(LOCAL_TLS_CERT), "-noout", "-fingerprint", "-sha256"], timeout=10)
    if result.returncode != 0:
        return None
    return result.stdout.strip().split("=", 1)[-1]


def ensure_local_certificate(force: bool = False) -> str:
    """Creates (or renews) the local HTTPS certificate nginx uses when no public certificate is configured.
    The key is 0600 root in a 0700 directory; files are replaced atomically."""
    if not command_exists("openssl"):
        raise LifecycleError("openssl is required to create the local HTTPS certificate")
    dns, ips = local_tls_names()
    if not force and local_certificate_is_current(dns, ips):
        return "current"
    LOCAL_TLS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(LOCAL_TLS_DIR, 0o700)
    tmp_key = LOCAL_TLS_DIR / ".local.key.tmp"
    tmp_cert = LOCAL_TLS_DIR / ".local.crt.tmp"
    for leftover in (tmp_key, tmp_cert):
        leftover.unlink(missing_ok=True)
    old_umask = os.umask(0o077)
    try:
        key = run_capture(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(tmp_key)], timeout=30)
        if key.returncode != 0:
            raise LifecycleError(format_failure("openssl ecparam (local HTTPS key)", key))
        subject_host = (dns[0] if dns else "localhost")[:48]
        san = ",".join([f"DNS:{name}" for name in dns] + [f"IP:{address}" for address in ips])
        cert = run_capture(
            [
                "openssl", "req", "-new", "-x509", "-sha256", "-key", str(tmp_key), "-out", str(tmp_cert),
                "-days", str(LOCAL_TLS_DAYS), "-subj", f"/O=Vaulthalla local certificate/CN={subject_host}",
                "-addext", f"subjectAltName={san}",
                "-addext", "basicConstraints=critical,CA:FALSE",
                "-addext", "keyUsage=critical,digitalSignature",
                "-addext", "extendedKeyUsage=serverAuth",
            ],
            timeout=30,
        )
        if cert.returncode != 0:
            raise LifecycleError(format_failure("openssl req (local HTTPS certificate)", cert))
    finally:
        os.umask(old_umask)
    os.chmod(tmp_key, 0o600)
    os.chmod(tmp_cert, 0o644)
    os.replace(tmp_key, LOCAL_TLS_KEY)
    os.replace(tmp_cert, LOCAL_TLS_CERT)
    return "created"


def security_header_lines(hsts: bool) -> list[str]:
    """Response headers for the console and its file lanes (#324). HSTS only with a publicly trusted certificate:
    with the local self-signed one, browsers would refuse the click-through and lock people out."""
    lines = [
        "    add_header X-Content-Type-Options \"nosniff\" always;",
        "    add_header Referrer-Policy \"no-referrer\" always;",
        "    add_header X-Frame-Options \"DENY\" always;",
        "    add_header Content-Security-Policy \"frame-ancestors 'none'\" always;",
    ]
    if hsts:
        lines.append("    add_header Strict-Transport-Security \"max-age=31536000\" always;")
    return lines + [""]


def render_managed_nginx_config(
    projection: dict[str, dict[str, Any]],
    domain: str | None,
    s3_domain: str | None = None,
    cert_name: str | None = None,
    local_tls: bool = False,
) -> str:
    server_name = domain if domain else "_"
    websocket = projection["websocket_server"]
    preview = projection["http_preview_server"]
    s3_gateway = projection["s3_gateway"]
    ws_host = host_for_proxy_pass(str(websocket.get("host", "0.0.0.0")))
    preview_host = host_for_proxy_pass(str(preview.get("host", "0.0.0.0")))
    s3_host = host_for_proxy_pass(str(s3_gateway.get("host", "0.0.0.0")))
    s3_port = int(s3_gateway.get("port", 39000))

    out: list[str] = []
    out.append("# Generated by 'vh setup nginx'.")
    out.append("# Do not edit manually; rerun CLI setup to apply managed changes.")

    if domain:
        out.append(f"# Web domain: {domain}")
    if s3_domain:
        out.append(f"# S3 domain: {s3_domain}")

    def add_ssl_lines() -> None:
        if cert_name:
            certificate = f"/etc/letsencrypt/live/{cert_name}/fullchain.pem"
            key = f"/etc/letsencrypt/live/{cert_name}/privkey.pem"
        elif local_tls:
            certificate, key = str(LOCAL_TLS_CERT), str(LOCAL_TLS_KEY)
        else:
            return
        out.extend([
            f"    ssl_certificate {certificate};",
            f"    ssl_certificate_key {key};",
            "    ssl_protocols TLSv1.2 TLSv1.3;",
            "    ssl_prefer_server_ciphers off;",
            "",
        ])

    def add_web_locations() -> None:
        out.extend(security_header_lines(hsts=bool(cert_name)))
        if bool(websocket.get("enabled", True)):
            ws_port = int(websocket.get("port", 33369))
            out.extend([
                "    location /ws {",
                f"        proxy_pass http://{ws_host}:{ws_port};",
                "        proxy_http_version 1.1;",
                "        proxy_set_header Host $host;",
                "        proxy_set_header X-Real-IP $remote_addr;",
                "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
                "        proxy_set_header X-Forwarded-Proto $scheme;",
                "        proxy_set_header Upgrade $http_upgrade;",
                "        proxy_set_header Connection \"upgrade\";",
                "    }",
                "",
            ])

        if bool(preview.get("enabled", True)):
            preview_port = int(preview.get("port", 33370))
            out.extend([
                "    location /preview {",
                f"        proxy_pass http://{preview_host}:{preview_port};",
                "        proxy_http_version 1.1;",
                "        proxy_buffering off;",
                "        proxy_max_temp_file_size 0;",
                "        proxy_set_header Host $host;",
                "        proxy_set_header X-Real-IP $remote_addr;",
                "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
                "        proxy_set_header X-Forwarded-Proto $scheme;",
                "    }",
                "",
                "    location /download {",
                f"        proxy_pass http://{preview_host}:{preview_port};",
                "        proxy_http_version 1.1;",
                "        proxy_buffering off;",
                "        proxy_max_temp_file_size 0;",
                "        proxy_set_header Host $host;",
                "        proxy_set_header X-Real-IP $remote_addr;",
                "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
                "        proxy_set_header X-Forwarded-Proto $scheme;",
                "    }",
                "",
                "    location /upload {",
                f"        proxy_pass http://{preview_host}:{preview_port};",
                "        proxy_http_version 1.1;",
                "        client_max_body_size 0;",
                "        proxy_request_buffering off;",
                "        proxy_buffering off;",
                "        proxy_set_header Host $host;",
                "        proxy_set_header X-Real-IP $remote_addr;",
                "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
                "        proxy_set_header X-Forwarded-Proto $scheme;",
                "    }",
                "",
            ])

        out.extend([
            "    location / {",
            f"        proxy_pass http://{WEB_UPSTREAM_HOST}:{WEB_UPSTREAM_PORT};",
            "        proxy_http_version 1.1;",
            "        proxy_set_header Host $host;",
            "        proxy_set_header X-Real-IP $remote_addr;",
            "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
            "        proxy_set_header X-Forwarded-Proto $scheme;",
            "        proxy_set_header Upgrade $http_upgrade;",
            "        proxy_set_header Connection \"upgrade\";",
            "    }",
        ])

    def add_s3_location() -> None:
        out.extend([
            "    location / {",
            f"        proxy_pass http://{s3_host}:{s3_port};",
            "        proxy_http_version 1.1;",
            "        client_max_body_size 0;",
            "        proxy_request_buffering off;",
            "        proxy_buffering off;",
            "        proxy_read_timeout 3600s;",
            "        proxy_send_timeout 3600s;",
            "        proxy_set_header Host $http_host;",
            "        proxy_set_header X-Real-IP $remote_addr;",
            "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
            "        proxy_set_header X-Forwarded-Proto $scheme;",
            "        proxy_set_header X-Forwarded-Host $http_host;",
            "        proxy_set_header X-Vaulthalla-S3-Path-Style-Only true;",
            "    }",
        ])

    if cert_name:
        redirect_names = " ".join([name for name in (domain, s3_domain) if name]) or "_"
        out.extend([
            "server {",
            "    listen 80;",
            "    listen [::]:80;",
            f"    server_name {redirect_names};",
            "    return 308 https://$host$request_uri;",
            "}",
            "",
        ])

        if domain:
            out.extend([
                "server {",
                "    listen 443 ssl;",
                "    listen [::]:443 ssl;",
                f"    server_name {domain};",
                "",
            ])
            add_ssl_lines()
            add_web_locations()
            out.extend(["}", ""])

        if s3_domain:
            out.extend([
                "server {",
                "    listen 443 ssl;",
                "    listen [::]:443 ssl;",
                f"    server_name {s3_domain};",
                "",
            ])
            add_ssl_lines()
            add_s3_location()
            out.extend(["}", ""])
        return "\n".join(out)

    if local_tls:
        out.extend([
            "server {",
            "    listen 80;",
            "    listen [::]:80;",
            f"    server_name {server_name};",
            "    return 308 https://$host$request_uri;",
            "}",
            "",
            "server {",
            "    listen 443 ssl;",
            "    listen [::]:443 ssl;",
            f"    server_name {server_name};",
            "",
        ])
        add_ssl_lines()
        add_web_locations()
        out.extend(["}", ""])
        return "\n".join(out)

    out.append("server {")
    out.append("    listen 80;")
    out.append("    listen [::]:80;")
    out.append(f"    server_name {server_name};")
    out.append("")
    add_web_locations()
    out.extend(["}", ""])
    return "\n".join(out)


def is_managed_site_symlink_target(path: Path) -> bool:
    if not path.is_symlink():
        return False
    target = os.readlink(path)
    return target in (str(NGINX_SITE_AVAILABLE), "../sites-available/vaulthalla")


def dpkg_conffile_md5(path: Path) -> str | None:
    if not command_exists("dpkg-query"):
        return None
    owner = run_capture(["dpkg-query", "-S", str(path)], timeout=30)
    if owner.returncode != 0 or not owner.stdout.strip():
        return None
    package = owner.stdout.splitlines()[0].split(":", 1)[0].strip()
    conffiles = run_capture(["dpkg-query", "-W", "-f=${Conffiles}\n", package], timeout=30)
    if conffiles.returncode != 0:
        return None
    for line in conffiles.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == str(path) and "obsolete" not in parts[2:]:
            return parts[1]
    return None


def nginx_default_site_is_stock_symlink() -> bool:
    """True only for the unmodified distro default site enabled via its usual symlink."""
    link = NGINX_DEFAULT_SITE_ENABLED
    if not link.is_symlink() or not NGINX_DEFAULT_SITE_AVAILABLE.is_file():
        return False
    if os.readlink(link) not in (str(NGINX_DEFAULT_SITE_AVAILABLE), "../sites-available/default"):
        return False
    expected = dpkg_conffile_md5(NGINX_DEFAULT_SITE_AVAILABLE)
    if not expected:
        return False
    try:
        actual = hashlib.md5(NGINX_DEFAULT_SITE_AVAILABLE.read_bytes()).hexdigest()
    except OSError:
        return False
    return actual == expected


def disable_stock_nginx_default_site() -> bool:
    # The stock default site holds `listen 80 default_server`, so a catch-all Vaulthalla
    # site would never answer. Only the unmodified distro symlink is touched, and the
    # marker lets `vh teardown nginx` / package purge restore it.
    if not nginx_default_site_is_stock_symlink():
        return False
    target = os.readlink(NGINX_DEFAULT_SITE_ENABLED)
    NGINX_DEFAULT_SITE_ENABLED.unlink()
    NGINX_DEFAULT_DISABLED_MARKER.parent.mkdir(parents=True, exist_ok=True)
    NGINX_DEFAULT_DISABLED_MARKER.write_text(f"target={target}\n", encoding="utf-8")
    return True


def restore_nginx_default_site() -> bool:
    if not NGINX_DEFAULT_DISABLED_MARKER.exists():
        return False
    target = str(NGINX_DEFAULT_SITE_AVAILABLE)
    for line in NGINX_DEFAULT_DISABLED_MARKER.read_text(encoding="utf-8").splitlines():
        if line.startswith("target=") and line[len("target="):].strip():
            target = line[len("target="):].strip()
    restored = False
    link = NGINX_DEFAULT_SITE_ENABLED
    if not link.exists() and not link.is_symlink() and NGINX_DEFAULT_SITE_AVAILABLE.is_file():
        link.symlink_to(target)
        restored = True
    NGINX_DEFAULT_DISABLED_MARKER.unlink()
    return restored


def requested_certificate_domains(domain: str, s3_domain: str | None) -> list[str]:
    domains: list[str] = []
    for candidate in (domain, s3_domain):
        if candidate and candidate not in domains:
            domains.append(candidate)
    return domains


def live_cert_dir(cert_name: str) -> Path:
    return LETSENCRYPT_LIVE_DIR / cert_name


def has_cert_for_domain(domain: str) -> bool:
    live = live_cert_dir(domain)
    return (live / "fullchain.pem").exists() and (live / "privkey.pem").exists()


def parse_certificate_dns_names(text: str) -> set[str]:
    return {trim(match).lower() for match in re.findall(r"DNS:([^,\s]+)", text) if trim(match)}


def parse_certificate_common_name(text: str) -> str | None:
    match = re.search(r"(?:^|subject=\s*|[,/])\s*CN\s*=\s*([^,/]+)", text)
    if not match:
        return None
    value = trim(match.group(1)).lower()
    return value or None


def certificate_dns_names(fullchain: Path) -> set[str]:
    if not command_exists("openssl"):
        return set()

    names: set[str] = set()
    san = run_capture(["openssl", "x509", "-in", str(fullchain), "-noout", "-ext", "subjectAltName"])
    if san.returncode == 0:
        names.update(parse_certificate_dns_names(combined_output(san)))

    if names:
        return names

    subject = run_capture(["openssl", "x509", "-in", str(fullchain), "-noout", "-subject"])
    if subject.returncode == 0:
        common_name = parse_certificate_common_name(combined_output(subject))
        if common_name:
            names.add(common_name)
    return names


def certificate_needs_renewal(fullchain: Path) -> bool:
    if not command_exists("openssl"):
        return True
    check = run_capture([
        "openssl",
        "x509",
        "-checkend",
        str(CERTBOT_RENEWAL_WINDOW_SECONDS),
        "-noout",
        "-in",
        str(fullchain),
    ])
    return check.returncode != 0


def certificate_state(cert_name: str) -> CertificateState:
    live = live_cert_dir(cert_name)
    fullchain = live / "fullchain.pem"
    privkey = live / "privkey.pem"
    if not fullchain.exists() or not privkey.exists():
        return CertificateState(exists=False, domains=set(), renewal_due=False)
    return CertificateState(
        exists=True,
        domains=certificate_dns_names(fullchain),
        renewal_due=certificate_needs_renewal(fullchain),
    )


def certificate_covers_domains(cert_domains: set[str], requested_domains: list[str]) -> bool:
    return all(
        any(server_name_matches_domain(cert_domain, requested) for cert_domain in cert_domains)
        for requested in requested_domains
    )


def managed_nginx_has_https_block(path: Path = NGINX_SITE_AVAILABLE) -> bool:
    """Return true when the managed Vaulthalla nginx site already has HTTPS wiring.

    This intentionally checks the generated site file itself, not certificate state. A domain can
    already have valid cert files while the managed nginx file is still HTTP-only; in that case we
    still want to call `certbot --nginx` so Certbot can redeploy the 443 server block.
    """
    if not path.exists() or not path.is_file():
        return False
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    if "Generated by 'vh setup nginx'" not in text:
        return False

    for raw in text.splitlines():
        line = trim(strip_nginx_comment(raw))
        if not line:
            continue
        if re.search(r"\blisten\s+(?:\[::\]:)?443(?:\s|;)", line):
            return True
        if re.search(r"\bssl_certificate(?:_key)?\s+", line):
            return True
    return False


def ensure_certbot_prereqs() -> None:
    if not command_exists("certbot"):
        raise LifecycleError("certbot is not installed")
    plugins = run_capture(["certbot", "plugins"])
    if plugins.returncode != 0 or "nginx" not in combined_output(plugins):
        raise LifecycleError("certbot nginx plugin is not installed (expected python3-certbot-nginx)")


def ensure_certbot_dns_cloudflare_prereqs() -> None:
    if not command_exists("certbot"):
        raise LifecycleError("certbot is not installed")
    plugins = run_capture(["certbot", "plugins"])
    output = combined_output(plugins)
    if plugins.returncode != 0 or "dns-cloudflare" not in output:
        raise LifecycleError(
            "certbot Cloudflare DNS plugin is not installed (expected python3-certbot-dns-cloudflare)"
        )


def dns_cloudflare_credentials_arg(args: argparse.Namespace) -> str | None:
    """Credentials path for Cloudflare DNS-01 mode, "" when the mode is on without a path, None when it is off.

    The path normally rides on the flag itself (`--certbot-dns-cloudflare <path>`). `--cloudflare-credentials <path>`
    is the older spelling: kept for existing scripts, and on its own it also turns the mode on.
    """
    inline = getattr(args, "certbot_dns_cloudflare", None)
    legacy = getattr(args, "cloudflare_credentials", None)
    if inline is None and legacy is None:
        return None
    if inline and legacy and inline != legacy:
        raise LifecycleError(
            "conflicting Cloudflare credentials paths: --certbot-dns-cloudflare and --cloudflare-credentials differ"
        )
    return inline or legacy or ""


def validate_cloudflare_credentials_file(path: str | None) -> Path:
    if not path:
        raise LifecycleError(
            "--certbot-dns-cloudflare requires the Cloudflare credentials file path: --certbot-dns-cloudflare <path>"
        )

    credentials = Path(path)
    if not credentials.exists():
        raise LifecycleError(f"Cloudflare credentials file does not exist: {credentials}")
    if not credentials.is_file():
        raise LifecycleError(f"Cloudflare credentials path is not a regular file: {credentials}")

    try:
        mode = credentials.stat().st_mode
    except OSError as exc:
        raise LifecycleError(f"failed inspecting Cloudflare credentials file: {exc}") from exc
    if mode & 0o077:
        raise LifecycleError(f"Cloudflare credentials file must not be group/world accessible: {credentials}")
    return credentials


def request_dns_cloudflare_certificate(domain: str, s3_domain: str | None, credentials: Path) -> str:
    domains = requested_certificate_domains(domain, s3_domain)
    state = certificate_state(domain)

    if state.exists and certificate_covers_domains(state.domains, domains):
        if not state.renewal_due:
            return "existing dns-cloudflare certificate is current (certbot renewal timer will manage renewal)"

        renew = run_capture(["certbot", "renew", "--cert-name", domain, "--non-interactive"])
        if renew.returncode != 0:
            raise LifecycleError(format_failure(f"certbot renew --cert-name {domain}", renew))
        return "existing dns-cloudflare certificate renewed by certbot"

    issue_reason = "fresh issuance"
    if state.exists:
        issue_reason = "domain expansion"

    args = [
        "certbot",
        "certonly",
        "--dns-cloudflare",
        "--dns-cloudflare-credentials",
        str(credentials),
        "--non-interactive",
        "--agree-tos",
        "--register-unsafely-without-email",
        "--keep-until-expiring",
        "--expand",
        "--cert-name",
        domain,
    ]
    for cert_domain in domains:
        args.extend(["--domain", cert_domain])

    result = run_capture(args)
    if result.returncode != 0:
        raise LifecycleError(format_failure("certbot dns-cloudflare certificate request", result))
    return f"dns-cloudflare certificate request completed ({issue_reason})"


def install_nginx_renewal_deploy_hook() -> None:
    content = """#!/bin/sh
set -eu
if command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1; then
    if command -v systemctl >/dev/null 2>&1 && systemctl --quiet is-active nginx.service; then
        systemctl reload nginx.service
    fi
fi
"""
    try:
        NGINX_RENEWAL_DEPLOY_HOOK.parent.mkdir(parents=True, exist_ok=True)
        NGINX_RENEWAL_DEPLOY_HOOK.write_text(content, encoding="utf-8")
        os.chmod(NGINX_RENEWAL_DEPLOY_HOOK, 0o755)
    except OSError as exc:
        raise LifecycleError(f"failed installing nginx renewal deploy hook: {exc}") from exc


ADOPT_KEY_WARNING = (
    "vault encryption keys and stored provider API keys in an adopted database are only "
    f"recoverable if the original {STATE_DIR}/.sealed_*.blob files and the same TPM are restored"
)


def setup_db(args: argparse.Namespace) -> int:
    adopt = bool(getattr(args, "adopt", False))
    overwrite = bool(getattr(args, "overwrite", False))
    if adopt and overwrite:
        raise LifecycleError("choose only one of --adopt or --overwrite")

    schemas = schema_dir()
    if not schemas.is_dir():
        raise LifecycleError(f"canonical schema path is missing: {schemas}")
    sql_files = sorted([p for p in schemas.iterdir() if p.suffix == ".sql" and p.is_file()], key=lambda p: p.name)
    if not sql_files:
        raise LifecycleError(f"canonical schema path has no .sql files: {schemas}")
    if not command_exists("psql"):
        raise LifecycleError("PostgreSQL client 'psql' is not installed")

    prefix = choose_postgres_prefix()
    role_exists = query_flag(
        prefix, "postgres", f"SELECT 1 FROM pg_roles WHERE rolname = '{DB_USER}';", "failed querying PostgreSQL role state"
    )
    db_exists = query_flag(
        prefix, "postgres", f"SELECT 1 FROM pg_database WHERE datname = '{DB_NAME}';", "failed querying PostgreSQL database state"
    )
    sealed = sealed_db_secret_present()
    seed = pending_db_password()

    if overwrite:
        drop_local_database(prefix)
        if role_exists:
            drop_local_role(prefix)
        role_exists = db_exists = False
        seed = None

    password: str | None = None
    warnings: list[str] = []
    if not role_exists and not db_exists:
        password = seed or make_db_password()
        mode = "recreated after --overwrite" if overwrite else "created"
    elif adopt:
        password = make_db_password()
        mode = "adopted (--adopt: role password rotated)"
        warnings.append(ADOPT_KEY_WARNING)
    elif seed:
        password = seed
        mode = f"converged to pending password handoff {PENDING_DB_PASSWORD_FILE}"
    elif sealed and role_exists:
        mode = "existing (sealed credential present; password unchanged)"
    elif sealed:
        # The database survived but its role was dropped: recreate the role; the daemon
        # reseals the new password from the handoff file on startup.
        password = make_db_password()
        mode = "role recreated for the existing database (sealed credential re-seeded)"
    elif not db_exists or not local_db_has_vaulthalla_data(prefix):
        password = make_db_password()
        mode = "adopted (empty database left by an interrupted install; role password rotated)"
    else:
        raise LifecycleError(
            f"an existing '{DB_NAME}' database with Vaulthalla data was found, but this host has no sealed "
            f"credential for it ({SEALED_DB_SECRET_DIR}) and no pending {PENDING_DB_PASSWORD_FILE}. "
            f"Re-run with --adopt to keep the data and rotate the role password ({ADOPT_KEY_WARNING}), "
            "or with --overwrite to permanently delete it and start fresh."
        )

    if password is not None:
        # Seed first (atomic), then align the role; roll the seed back if the role update fails.
        write_pending_db_password(password)
        try:
            set_local_role_password(prefix, password, role_exists)
        except LifecycleError:
            try:
                PENDING_DB_PASSWORD_FILE.unlink()
            except OSError:
                pass
            raise

    if not db_exists:
        create_db = psql_sql(prefix, "postgres", f"CREATE DATABASE {DB_NAME} OWNER {DB_USER};")
        if create_db.returncode != 0:
            raise LifecycleError(format_failure(f"failed creating PostgreSQL database '{DB_NAME}'", create_db))
    elif not role_exists:
        # Best effort: the role was just (re)created for a database that outlived it.
        psql_sql(prefix, "postgres", f"ALTER DATABASE {DB_NAME} OWNER TO {DB_USER};")

    grant_db = psql_sql(prefix, "postgres", f"GRANT ALL PRIVILEGES ON DATABASE {DB_NAME} TO {DB_USER};")
    if grant_db.returncode != 0:
        raise LifecycleError(format_failure("failed granting database privileges", grant_db))

    grant_schema = psql_sql(prefix, DB_NAME, f"GRANT USAGE, CREATE ON SCHEMA public TO {DB_USER};")
    if grant_schema.returncode != 0:
        raise LifecycleError(format_failure("failed granting schema privileges", grant_schema))

    opted_back_in = False
    if DB_BOOTSTRAP_OPTOUT_MARKER.exists():
        DB_BOOTSTRAP_OPTOUT_MARKER.unlink()
        opted_back_in = True

    action = restart_or_start_service()
    for warning in warnings:
        eprint(f"setup db: WARNING: {warning}")
    health = require_service_healthy(password is not None, "setup db")

    print("setup db: local PostgreSQL bootstrap complete")
    print(f"  role/database: {mode} ({DB_USER}/{DB_NAME})")
    print(f"  canonical schema path: {schemas} (validated)")
    if password is not None:
        print(f"  runtime DB password: seeded via {PENDING_DB_PASSWORD_FILE} and consumed by the service")
    else:
        print(f"  runtime DB password: unchanged (sealed credential at {SEALED_DB_SECRET_DIR})")
    if opted_back_in:
        print(f"  package DB bootstrap opt-out removed: {DB_BOOTSTRAP_OPTOUT_MARKER}")
    print(f"  service: {SERVICE_UNIT} {action}; {health}")
    print("  migrations: delegated to normal runtime startup flow (SqlDeployer)")
    return 0


def setup_remote_db(args: argparse.Namespace) -> int:
    if args.port <= 0 or args.port > 65535:
        raise LifecycleError(f"invalid port '{args.port}' (expected integer 1-65535)")
    if args.pool_size is not None and args.pool_size <= 0:
        raise LifecycleError(f"invalid pool size '{args.pool_size}' (expected positive integer)")

    path = config_path()
    projection = load_config_projection(path)
    existing_pool = int(projection["database"].get("pool_size", 10))
    pool_size = args.pool_size if args.pool_size is not None else existing_pool

    updates = {
        "host": args.host,
        "port": args.port,
        "name": args.database,
        "user": args.user,
        "pool_size": pool_size,
    }
    save_database_config_updates(path, updates)

    password = load_password_from_file(args.password_file)
    write_pending_db_password(password)
    action = restart_or_start_service()
    health = require_service_healthy(True, "setup remote-db")

    print("setup remote-db: remote PostgreSQL configuration applied")
    print(f"  config file: {path}")
    print(f"  database.host: {updates['host']}")
    print(f"  database.port: {updates['port']}")
    print(f"  database.user: {updates['user']}")
    print(f"  database.name: {updates['name']}")
    print(f"  database.pool_size: {updates['pool_size']}")
    print(f"  seeded runtime DB password: {PENDING_DB_PASSWORD_FILE} (consumed by the service)")
    print(f"  service: {SERVICE_UNIT} {action}; {health}")
    print("  migrations: delegated to normal runtime startup flow (SqlDeployer)")
    return 0


def generated_super_admin_password_in_use() -> bool | None:
    """The DB's view; None when it can't say (no local PostgreSQL, a remote DB, a pre-1.8.0 schema)."""
    if not command_exists("psql"):
        return None
    try:
        prefix = choose_postgres_prefix()
    except LifecycleError:
        return None
    result = psql_sql(prefix, DB_NAME, "SELECT super_admin_password_generated FROM auth_bootstrap_state WHERE id = 1;")
    if result.returncode != 0:
        return None
    return trim(result.stdout) in ("1", "t", "true")


def initial_password_exposed() -> bool:
    # The plaintext copy is the risk. The DB only rules out a stale copy of a password that was already changed.
    if not INITIAL_PASSWORD_FILE.exists():
        return False
    return generated_super_admin_password_in_use() is not False


def rotate_super_admin_password_as_operator() -> bool:
    # `vh setup set-super-admin-password` only runs as the Linux user bound as the super admin, never as root.
    operator = os.environ.get("SUDO_USER")
    vh_bin = shutil.which("vh") or "/usr/bin/vh"
    if not operator or operator == "root" or not command_exists("runuser"):
        eprint("Run 'vh setup set-super-admin-password' as the Linux user bound as the Vaulthalla super admin "
               "(without sudo), then rerun this command.")
        return False
    print(f"Running 'vh setup set-super-admin-password' as {operator}...", flush=True)
    return subprocess.run(["runuser", "-u", operator, "--", vh_bin, "setup", "set-super-admin-password"]).returncode == 0


INITIAL_PASSWORD_WARNING = """
WARNING: the generated initial web console password of the super-admin account 'admin' is still in use, and a
plaintext copy of it is still on this server:
  {path}
You are about to put the web console behind nginx, which usually means reaching it over the network. The generated
password is strong (128 random bits); the concern is the copy on disk. Changing the password is recommended, but
keeping it is fine once the file is gone. nginx itself is optional.
"""

INITIAL_PASSWORD_CHOICES = """  1) Change the super-admin password now (vh setup set-super-admin-password; also removes the file)
  2) Keep the generated password and delete the plaintext file
  3) Continue without changes (not recommended)
  4) Cancel"""


def confirm_initial_password_before_exposure(interactive: bool | None = None) -> bool:
    """A safeguard, not a gate: warns and offers remediation. False only when the operator cancels."""
    if not initial_password_exposed():
        return True
    print(INITIAL_PASSWORD_WARNING.format(path=INITIAL_PASSWORD_FILE), flush=True)
    if interactive is None:
        interactive = sys.stdin.isatty() and sys.stdout.isatty()
    if not interactive:
        eprint("Non-interactive: continuing. Change the password with 'vh setup set-super-admin-password', "
               f"or delete {INITIAL_PASSWORD_FILE} to keep it.")
        return True

    while True:
        print(INITIAL_PASSWORD_CHOICES, flush=True)
        try:
            choice = input("Choose [1-4]: ").strip()
        except EOFError:
            choice = "4"
        if choice == "1":
            if rotate_super_admin_password_as_operator():
                if INITIAL_PASSWORD_FILE.exists():
                    eprint(f"The password was changed, but {INITIAL_PASSWORD_FILE} is still there; "
                           f"remove it: sudo rm -f {INITIAL_PASSWORD_FILE}")
                return True
            print("The password was not changed.", flush=True)
        elif choice == "2":
            try:
                INITIAL_PASSWORD_FILE.unlink(missing_ok=True)
            except OSError as exc:
                eprint(f"Could not delete {INITIAL_PASSWORD_FILE}: {exc}")
                continue
            print(f"Deleted {INITIAL_PASSWORD_FILE}; the generated password stays in effect.", flush=True)
            return True
        elif choice == "3":
            return True
        elif choice in ("4", ""):
            return False


def setup_nginx(args: argparse.Namespace) -> int:
    requested_domain = trim(args.domain) if args.domain else None
    requested_s3_domain = trim(args.s3_domain) if args.s3_domain else None
    existing_domain = extract_managed_nginx_domain()
    existing_s3_domain = extract_managed_nginx_s3_domain()
    domain = requested_domain or existing_domain
    s3_domain = requested_s3_domain or existing_s3_domain
    cloudflare_credentials = dns_cloudflare_credentials_arg(args)
    dns_cloudflare = cloudflare_credentials is not None

    plain_http = bool(getattr(args, "plain_http", False))
    if args.certbot and dns_cloudflare:
        raise LifecycleError("choose only one certificate mode: --certbot or --certbot-dns-cloudflare")
    if plain_http and (args.certbot or dns_cloudflare):
        raise LifecycleError("--plain-http can't be combined with a certificate mode")

    if domain and not is_likely_domain(domain):
        source = "--domain" if requested_domain else str(NGINX_SITE_AVAILABLE)
        raise LifecycleError(f"invalid domain from {source}: '{domain}'")
    if s3_domain and not is_likely_domain(s3_domain):
        source = "--s3-domain" if requested_s3_domain else str(NGINX_SITE_AVAILABLE)
        raise LifecycleError(f"invalid S3 domain from {source}: '{s3_domain}'")
    if domain and s3_domain and domain == s3_domain:
        raise LifecycleError("--domain and --s3-domain must be different hostnames")
    if args.certbot and s3_domain:
        raise LifecycleError("--s3-domain requires --certbot-dns-cloudflare <credentials> for managed HTTPS routing")
    if (args.certbot or dns_cloudflare) and not domain:
        raise LifecycleError(
            "certificate setup requires --domain <domain> unless an existing managed nginx site already has a domain"
        )

    if not command_exists("nginx") or not Path("/etc/nginx").exists():
        raise LifecycleError("nginx is not installed or /etc/nginx is missing")
    if has_non_nginx_listeners_on_web_ports():
        raise LifecycleError("detected non-nginx listeners on :80/:443; refusing automatic integration")
    for check_domain, was_requested in ((domain, requested_domain is not None), (s3_domain, requested_s3_domain is not None)):
        if not check_domain or not was_requested:
            continue
        conflict = active_nginx_domain_conflict_source(check_domain)
        if conflict:
            raise LifecycleError(f"domain {check_domain} is already configured in nginx; refusing to overwrite")

    template_path = nginx_template_path()
    marker_exists = NGINX_MANAGED_MARKER.exists()
    if NGINX_SITE_AVAILABLE.exists() and not marker_exists:
        if not template_path.exists():
            raise LifecycleError(
                f"packaged nginx template missing at {template_path} while existing unmanaged site file is present"
            )
        if not filecmp.cmp(NGINX_SITE_AVAILABLE, template_path, shallow=False):
            raise LifecycleError(f"existing site file differs and is not package-managed: {NGINX_SITE_AVAILABLE}")

    if not confirm_initial_password_before_exposure():
        print("setup nginx: cancelled; nothing was changed.")
        return 1

    projection = load_config_projection(config_path())
    cert_name = None
    certbot_mode = None
    if dns_cloudflare:
        ensure_certbot_dns_cloudflare_prereqs()
        credentials = validate_cloudflare_credentials_file(cloudflare_credentials)
        certbot_mode = request_dns_cloudflare_certificate(domain or "", s3_domain, credentials)
        install_nginx_renewal_deploy_hook()
        cert_name = domain

    # HTTPS by default (#324): without a certificate mode, serve the console with the local certificate. --certbot
    # renders plain HTTP first (certbot --nginx adds the HTTPS server to it); --plain-http is the explicit opt-out for
    # hosts behind another TLS terminator.
    local_tls = not (args.certbot or dns_cloudflare or plain_http)
    local_tls_status = ensure_local_certificate() if local_tls else None
    rendered = render_managed_nginx_config(projection, domain, s3_domain, cert_name, local_tls=local_tls)

    NGINX_SITE_AVAILABLE.parent.mkdir(parents=True, exist_ok=True)
    NGINX_SITE_ENABLED.parent.mkdir(parents=True, exist_ok=True)

    created_site_file = False
    created_site_link = False
    rewrote_site_file = False
    if NGINX_SITE_AVAILABLE.exists():
        current = NGINX_SITE_AVAILABLE.read_text(encoding="utf-8")
        if current != rendered:
            NGINX_SITE_AVAILABLE.write_text(rendered, encoding="utf-8")
            rewrote_site_file = True
    else:
        NGINX_SITE_AVAILABLE.write_text(rendered, encoding="utf-8")
        created_site_file = True
        rewrote_site_file = True

    if not NGINX_MANAGED_MARKER.exists():
        NGINX_MANAGED_MARKER.parent.mkdir(parents=True, exist_ok=True)
        NGINX_MANAGED_MARKER.write_text("managed-by=vaulthalla\n", encoding="utf-8")

    if NGINX_SITE_ENABLED.exists() and not NGINX_SITE_ENABLED.is_symlink():
        raise LifecycleError(f"target exists and is not a symlink: {NGINX_SITE_ENABLED}")
    if NGINX_SITE_ENABLED.is_symlink() and not is_managed_site_symlink_target(NGINX_SITE_ENABLED):
        raise LifecycleError("existing symlink points outside Vaulthalla-managed site")
    if not NGINX_SITE_ENABLED.exists():
        NGINX_SITE_ENABLED.symlink_to(NGINX_SITE_AVAILABLE)
        created_site_link = True

    disabled_default_site = False
    if not domain:
        disabled_default_site = disable_stock_nginx_default_site()

    try:
        reload_status = validate_and_reload_nginx()
    except LifecycleError:
        if disabled_default_site:
            restore_nginx_default_site()
        raise

    opted_back_in = False
    if NGINX_OPTOUT_MARKER.exists():
        NGINX_OPTOUT_MARKER.unlink()
        opted_back_in = True

    if args.certbot:
        ensure_certbot_prereqs()
        cert_exists = has_cert_for_domain(domain or "")
        https_configured = managed_nginx_has_https_block()

        if cert_exists and https_configured:
            certbot_mode = "existing certificate and HTTPS nginx block detected (renew-safe path)"
            renew = run_capture(["certbot", "renew", "--cert-name", domain or "", "--non-interactive"])
            if renew.returncode != 0:
                raise LifecycleError(format_failure(f"certbot renew --cert-name {domain}", renew))
        else:
            if cert_exists:
                certbot_mode = "existing certificate detected but HTTPS nginx block missing (redeploy path)"
            else:
                certbot_mode = "no existing certificate detected (fresh issuance path)"
            issue = run_capture([
                "certbot",
                "--nginx",
                "--non-interactive",
                "--agree-tos",
                "--register-unsafely-without-email",
                "--keep-until-expiring",
                "--hsts",
                "--domain",
                domain or "",
            ])
            if issue.returncode != 0:
                raise LifecycleError(format_failure(f"certbot --nginx --domain {domain}", issue))
        reload_status = validate_and_reload_nginx()

    if not args.certbot and not dns_cloudflare:
        print("setup nginx: Vaulthalla nginx integration configured")
        print(
            "  site file: "
            + ("installed" if created_site_file else "regenerated from canonical config" if rewrote_site_file else "already current")
            + f" ({NGINX_SITE_AVAILABLE})"
        )
        print(f"  site link: {'enabled' if created_site_link else 'already enabled'} ({NGINX_SITE_ENABLED})")
        if disabled_default_site:
            print(f"  distro default site: disabled ({NGINX_DEFAULT_SITE_ENABLED}; restored by 'vh teardown nginx')")
        if opted_back_in:
            print(f"  package nginx opt-out removed: {NGINX_OPTOUT_MARKER}")
        print(f"  config source: {config_path()}")
        if local_tls:
            print(f"  HTTPS: local certificate {LOCAL_TLS_CERT} ({local_tls_status}); http:// redirects to https://")
            fingerprint = local_certificate_fingerprint()
            if fingerprint:
                print(f"  certificate SHA-256: {fingerprint} (compare it when your browser asks you to trust it)")
            print("  for a publicly trusted certificate: sudo vh setup nginx --domain <fqdn> --certbot")
        else:
            print("  HTTPS: off (--plain-http); put TLS in front of this host before exposing it")
        print(f"  domain: {domain if domain else 'default catch-all (_)' }")
        if s3_domain:
            print(f"  s3 domain: {s3_domain} (HTTPS route not rendered without --certbot-dns-cloudflare <credentials>)")
        print(f"  web upstream: {WEB_UPSTREAM_HOST}:{WEB_UPSTREAM_PORT} (runtime convention)")
        print(f"  reload: {reload_status}")
        return 0

    print("setup nginx: Vaulthalla nginx integration configured with certbot handling")
    print(
        "  site file: "
        + ("installed" if created_site_file else "regenerated from canonical config" if rewrote_site_file else "already present")
        + f" ({NGINX_SITE_AVAILABLE})"
    )
    print(f"  site link: {'enabled' if created_site_link else 'already enabled'} ({NGINX_SITE_ENABLED})")
    print(f"  config source: {config_path()}")
    print(f"  certbot domain: {domain}")
    if s3_domain:
        print(f"  certbot s3 domain: {s3_domain}")
    print(f"  certbot domain source: {'--domain' if requested_domain else 'existing managed nginx site'}")
    print(f"  certbot mode: {certbot_mode}")
    if dns_cloudflare:
        print(f"  renewal deploy hook: {NGINX_RENEWAL_DEPLOY_HOOK}")
    print(f"  reload: {reload_status}")
    return 0


def setup_local_tls(args: argparse.Namespace) -> int:
    """Create or renew the local HTTPS certificate (also run by the package on install and upgrade)."""
    status = ensure_local_certificate(force=bool(getattr(args, "force", False)))
    if status == "created" and command_exists("nginx") and NGINX_SITE_ENABLED.exists():
        content = NGINX_SITE_AVAILABLE.read_text(encoding="utf-8") if NGINX_SITE_AVAILABLE.exists() else ""
        if str(LOCAL_TLS_CERT) in content:
            validate_and_reload_nginx()
    if not getattr(args, "quiet", False) or status == "created":
        print(f"local HTTPS certificate: {status} ({LOCAL_TLS_CERT})")
    return 0


def teardown_nginx(_args: argparse.Namespace) -> int:
    removed_link = False
    removed_site = False
    removed_marker = False
    removed_renewal_hook = False

    if NGINX_SITE_ENABLED.exists():
        if not NGINX_SITE_ENABLED.is_symlink():
            raise LifecycleError(f"{NGINX_SITE_ENABLED} exists and is not a symlink")
        if not is_managed_site_symlink_target(NGINX_SITE_ENABLED):
            raise LifecycleError("refusing to remove non-Vaulthalla nginx symlink target")
        NGINX_SITE_ENABLED.unlink()
        removed_link = True

    if NGINX_MANAGED_MARKER.exists():
        if NGINX_SITE_AVAILABLE.exists():
            NGINX_SITE_AVAILABLE.unlink()
            removed_site = True
        NGINX_MANAGED_MARKER.unlink()
        removed_marker = True

    if NGINX_RENEWAL_DEPLOY_HOOK.exists():
        NGINX_RENEWAL_DEPLOY_HOOK.unlink()
        removed_renewal_hook = True

    restored_default_site = restore_nginx_default_site()

    if command_exists("nginx") and command_exists("systemctl"):
        active = run_capture(["systemctl", "--quiet", "is-active", "nginx.service"])
        if active.returncode == 0:
            validate_and_reload_nginx()

    print("teardown nginx: completed")
    print(f"  removed enabled symlink: {'yes' if removed_link else 'no'}")
    print(f"  removed site file: {'yes' if removed_site else 'no'}")
    print(f"  removed managed marker: {'yes' if removed_marker else 'no'}")
    print(f"  removed renewal hook: {'yes' if removed_renewal_hook else 'no'}")
    print(f"  restored distro default site: {'yes' if restored_default_site else 'no'}")
    return 0


def teardown_db(_args: argparse.Namespace) -> int:
    if not command_exists("psql"):
        raise LifecycleError("PostgreSQL client 'psql' is not installed")
    prefix = choose_postgres_prefix()

    # Stop the daemon first: dropping its database underneath a running pool wedges it.
    stopped_service = False
    if command_exists("systemctl"):
        active = run_capture(["systemctl", "--quiet", "is-active", SERVICE_UNIT], timeout=15)
        if active.returncode == 0:
            stop = run_capture(["systemctl", "stop", SERVICE_UNIT], timeout=90)
            if stop.returncode != 0:
                raise LifecycleError(format_failure(f"failed stopping {SERVICE_UNIT} before teardown", stop))
            stopped_service = True

    # Separate psql invocations: DROP DATABASE cannot run inside a transaction block.
    drop_local_database(prefix)
    drop_local_role(prefix)

    removed_seed = False
    if PENDING_DB_PASSWORD_FILE.exists():
        PENDING_DB_PASSWORD_FILE.unlink()
        removed_seed = True

    print("teardown db: completed")
    print(f"  stopped {SERVICE_UNIT}: {'yes' if stopped_service else 'no (not active)'}")
    print(f"  dropped database: {DB_NAME}")
    print(f"  dropped role: {DB_USER}")
    print(f"  removed pending password handoff: {'yes' if removed_seed else 'no (none present)'}")
    print("  next: 'sudo vh setup db' creates a fresh role/database and restarts the service")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vaulthalla-lifecycle",
        description="Local privileged lifecycle utility for Vaulthalla setup/teardown tasks.",
    )
    root = parser.add_subparsers(dest="root", required=True)

    setup_cmd = root.add_parser("setup", help="Lifecycle setup operations")
    setup_sub = setup_cmd.add_subparsers(dest="setup_cmd", required=True)
    setup_database = setup_sub.add_parser("db", help="Bootstrap local PostgreSQL role/database integration")
    existing_db = setup_database.add_mutually_exclusive_group()
    existing_db.add_argument(
        "--adopt",
        action="store_true",
        help="Keep an existing 'vaulthalla' database that has no sealed credential on this host; rotate the role password.",
    )
    existing_db.add_argument(
        "--overwrite",
        action="store_true",
        help="Permanently drop the existing 'vaulthalla' database and role, then bootstrap fresh.",
    )

    setup_remote = setup_sub.add_parser("remote-db", help="Configure remote PostgreSQL settings in local config")
    setup_remote.add_argument("--host", required=True)
    setup_remote.add_argument("--user", required=True)
    setup_remote.add_argument("--database", required=True)
    setup_remote.add_argument("--password-file", required=True)
    setup_remote.add_argument("--port", type=int, default=5432)
    setup_remote.add_argument("--pool-size", type=int)

    setup_ng = setup_sub.add_parser("nginx", help="Configure Vaulthalla-managed nginx integration")
    setup_ng.add_argument(
        "--certbot",
        action="store_true",
        help="Request/renew a certificate for --domain, or for the existing managed site domain if omitted",
    )
    setup_ng.add_argument(
        "--certbot-dns-cloudflare",
        nargs="?",
        const="",
        metavar="CREDENTIALS",
        help=(
            "Request/renew a DNS-01 certificate with the Certbot Cloudflare plugin and render HTTPS nginx. "
            "CREDENTIALS is a root-owned 0600 file containing 'dns_cloudflare_api_token = <token>'."
        ),
    )
    setup_ng.add_argument(
        "--cloudflare-credentials",
        help="Older spelling of the --certbot-dns-cloudflare credentials path; on its own it enables that mode.",
    )
    setup_ng.add_argument(
        "--domain",
        help="Set the nginx server_name. Without a certificate mode the site uses the local HTTPS certificate.",
    )
    setup_ng.add_argument(
        "--plain-http",
        action="store_true",
        help="Serve plain HTTP only (no local certificate). Only behind another TLS terminator.",
    )
    setup_tls = setup_sub.add_parser("local-tls", help="Create or renew the local HTTPS certificate nginx uses")
    setup_tls.add_argument("--force", action="store_true", help="Regenerate even if the current one is valid")
    setup_tls.add_argument("--quiet", action="store_true", help="Print only when a certificate was created")
    setup_ng.add_argument(
        "--s3-domain",
        help="Set the dedicated HTTPS S3 server_name. Requires --certbot-dns-cloudflare for route rendering.",
    )

    teardown_cmd = root.add_parser("teardown", help="Lifecycle teardown operations")
    teardown_sub = teardown_cmd.add_subparsers(dest="teardown_cmd", required=True)
    teardown_sub.add_parser("nginx", help="Remove Vaulthalla-managed nginx integration")
    teardown_sub.add_parser("db", help="Drop Vaulthalla local PostgreSQL role/database integration")

    return parser


def dispatch(args: argparse.Namespace) -> int:
    if args.root == "setup" and args.setup_cmd == "db":
        return setup_db(args)
    if args.root == "setup" and args.setup_cmd == "remote-db":
        return setup_remote_db(args)
    if args.root == "setup" and args.setup_cmd == "nginx":
        return setup_nginx(args)
    if args.root == "setup" and args.setup_cmd == "local-tls":
        return setup_local_tls(args)
    if args.root == "teardown" and args.teardown_cmd == "nginx":
        return teardown_nginx(args)
    if args.root == "teardown" and args.teardown_cmd == "db":
        return teardown_db(args)
    raise LifecycleError("unsupported lifecycle command")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    ensure_privileged_or_reexec()
    return dispatch(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LifecycleError as exc:
        eprint(f"lifecycle error: {exc}")
        raise SystemExit(2)
