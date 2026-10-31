#!/usr/bin/env python3
"""Render an isolated instance's config and systemd units from the production ones (`make dev` -> instance "dev").

    render.py config  --instance dev [--db-port N] IN OUT
                                                      config.yaml: listener ports +100, database vaulthalla_dev
                                                      (on 127.0.0.1:N when the instance has its own cluster)
    render.py systemd --instance dev --bindir DIR --node NODE --web-dir DIR IN OUT
                                                      a deploy/systemd/*.service.in template, renamed and re-pathed

An instance shares nothing with production: not a path, port, account, unit, database, swtpm state or socket. The
production files stay the single source; this only rewrites the identifiers an instance must not share, and refuses
(exit 1) when a production identifier would survive the rewrite. With an empty --instance it copies IN unchanged.
"""
import argparse
import re
import sys

PORT_OFFSET = 100
# Every listener the daemon, the web console and swtpm bind (config.yaml and the units).
PORTS = {36968: "web", 36969: "websocket", 36970: "http preview", 36972: "device listener", 39000: "s3 gateway",
         2321: "swtpm", 2322: "swtpm ctrl"}


def names(instance):
    n = f"vaulthalla-{instance}"
    return {
        "name": n,                                   # account, unit stem, /etc /var/lib /var/log /run dir names
        "db": f"vaulthalla_{instance}",              # PostgreSQL role and database
        "mount": f"/mnt/vh_{instance}",
    }


def shift_port(m):
    port = int(m.group(0))
    return str(port + PORT_OFFSET) if port in PORTS else m.group(0)


def render_config(text, instance, db_port=None):
    n = names(instance)
    out = []
    section = None
    for line in text.splitlines(keepends=True):
        top = re.match(r"^([A-Za-z0-9_]+):", line)
        if top:
            section = top.group(1)
        if section in ("websocket_server", "http_preview_server", "device_server", "s3_gateway") and \
                re.match(r"^  port:\s*\d+", line):
            line = re.sub(r"\d+", shift_port, line, count=1)
        if section == "database" and re.match(r"^  (name|user):\s*vaulthalla\b", line):
            line = re.sub(r"vaulthalla\b", n["db"], line, count=1)
        if section == "database" and db_port and re.match(r"^  port:\s*\d+", line):
            line = re.sub(r"\d+", str(db_port), line, count=1)
        if section == "database" and db_port and re.match(r"^  host:\s*localhost\b", line):
            line = line.replace("localhost", "127.0.0.1", 1)
        out.append(line)
    rendered = "".join(out)
    for key in ("websocket_server", "http_preview_server", "device_server", "s3_gateway"):
        block = re.search(rf"(?ms)^{key}:\n(.*?)(?=^\S)", rendered)
        if block and re.search(r"(?m)^  port:\s*(36969|36970|36972|39000)\b", block.group(1)):
            raise SystemExit(f"render: {key}.port is still a production port")
    if re.search(r"(?m)^  (name|user):\s*vaulthalla\s", rendered):
        raise SystemExit("render: database name/user is still the production one")
    return rendered


def render_systemd(text, instance, bindir, node, web_dir):
    n = names(instance)["name"]
    subs = [
        # unit names first, so the generic name rewrite below never sees them
        (r"vaulthalla-swtpm\.service", f"{n}-swtpm.service"),
        (r"vaulthalla-web\.service", f"{n}-web.service"),
        (r"vaulthalla\.service", f"{n}.service"),
        (r"/mnt/vaulthalla\b", names(instance)["mount"]),
        (r"/var/lib/swtpm/vaulthalla\b", f"/var/lib/swtpm/{n}"),
        (r"/var/lib/vaulthalla\b", f"/var/lib/{n}"),
        (r"/etc/vaulthalla\b", f"/etc/{n}"),
        (r"/usr/share/vaulthalla-web\b", web_dir),
        (r"@BINDIR@/node\b", node),
        (r"@BINDIR@", bindir),
        (r"(?m)^(User|Group)=vaulthalla$", rf"\1={n}"),
        (r"(?m)^SyslogIdentifier=vaulthalla$", f"SyslogIdentifier={n}"),
        (r"\b(36968|36969|36970|39000|2321|2322)\b", shift_port),
    ]
    out = text
    for pattern, repl in subs:
        out = re.sub(pattern, repl, out)
    out = re.sub(r"(?m)^(Description=.*)$", rf"\1 ({instance} instance)", out, count=1)
    leftovers = re.findall(r"/mnt/vaulthalla(?![-\w])|/var/lib/vaulthalla(?![-\w])|/usr/share/vaulthalla-web(?![-\w])|"
                           r"(?<![-\w])vaulthalla(?:-web|-swtpm)?\.service|^(?:User|Group)=vaulthalla$|"
                           r"\b(?:36968|36969|36970|39000|2321|2322)\b|@\w+@", out, flags=re.M)
    if leftovers:
        raise SystemExit(f"render: production identifiers survived: {sorted(set(leftovers))}")
    return out


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=["config", "systemd"])
    ap.add_argument("--instance", required=True)
    ap.add_argument("--bindir")
    ap.add_argument("--node")
    ap.add_argument("--web-dir")
    ap.add_argument("--db-port", type=int, help="config: the instance's own PostgreSQL (macOS: a private cluster)")
    ap.add_argument("input")
    ap.add_argument("output")
    a = ap.parse_args(argv)
    if a.instance and not re.fullmatch(r"[a-z0-9_]+", a.instance):
        raise SystemExit("render: --instance must be [a-z0-9_]+")
    text = open(a.input, encoding="utf-8").read()
    if not a.instance:
        out = text
    elif a.kind == "config":
        out = render_config(text, a.instance, a.db_port)
    else:
        if not (a.bindir and a.node and a.web_dir):
            raise SystemExit("render systemd: --bindir, --node and --web-dir are required")
        out = render_systemd(text, a.instance, a.bindir, a.node, a.web_dir)
    with open(a.output, "w", encoding="utf-8") as f:
        f.write(out)


if __name__ == "__main__":
    main(sys.argv[1:])
