#!/usr/bin/env python3
"""CLI <-> web-console (websocket) parity smoke against a packaged Vaulthalla host.

Each scenario performs an operation through one surface and verifies the resulting state through the
other, and checks that both surfaces *reject* invalid operations (duplicates, missing entities) instead
of reporting success. Nothing here stress-tests providers; it only creates/deletes `parity-*` objects.

Requires: `pip install websockets`; an ssh alias with passwordless sudo on the host; the web admin's
(non-default) password in a 0600 file.

  parity_smoke.py --host vh-storage --ws-url ws://10.0.0.33/ws --admin-password-file F [--evidence out.json]

Exit status: 0 when every check passed, 1 otherwise. Passwords are never printed.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import shlex
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field

import websockets


@dataclass
class Check:
    scenario: str
    name: str
    ok: bool
    detail: str = ""


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    def add(self, scenario: str, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append(Check(scenario, name, bool(ok), detail[:400]))
        print(f"[{'PASS' if ok else 'FAIL'}] {scenario}: {name}" + (f" -- {detail[:200]}" if detail and not ok else ""))
        return bool(ok)


class Cli:
    def __init__(self, host: str) -> None:
        self.host = host

    def run(self, *args: str, timeout: int = 30) -> tuple[int, str]:
        remote = "sudo timeout {} vh {}".format(timeout, " ".join(shlex.quote(a) for a in args))
        proc = subprocess.run(["ssh", "-o", "BatchMode=yes", self.host, remote],
                              capture_output=True, text=True, timeout=timeout + 20)
        return proc.returncode, (proc.stdout + proc.stderr)


class Ws:
    def __init__(self, url: str) -> None:
        self.url = url
        self.token = ""
        self.conn = None

    async def __aenter__(self) -> "Ws":
        self.conn = await websockets.connect(self.url, open_timeout=10, close_timeout=5, max_size=2**24)
        return self

    async def __aexit__(self, *exc) -> None:
        await self.conn.close()

    async def send(self, command: str, payload=None, timeout: float = 20) -> dict:
        rid = str(uuid.uuid4())
        await self.conn.send(json.dumps({"command": command, "payload": payload if payload is not None else {},
                                         "requestId": rid, "token": self.token}))
        while True:
            msg = json.loads(await asyncio.wait_for(self.conn.recv(), timeout=timeout))
            if msg.get("requestId") != rid:
                continue
            if msg.get("token"):
                self.token = msg["token"]
            return msg


def ok_status(msg: dict) -> bool:
    return str(msg.get("status", "")).upper() in ("OK", "SUCCESS")


def names(items, key="name") -> set[str]:
    return {i.get(key) for i in (items or []) if isinstance(i, dict)}


async def scenarios(cli: Cli, ws: Ws, r: Report, ws_user: str) -> None:
    tag = time.strftime("%H%M%S")

    # --- vaults ---------------------------------------------------------------
    s = "vault"
    v_cli, v_ws = f"parity-cli-{tag}", f"parity-ws-{tag}"
    rc, out = cli.run("vault", "create", v_cli, "--local", "--desc", "parity", "--quota", "1G")
    r.add(s, "CLI create succeeds", rc == 0, out)
    lst = await ws.send("storage.vault.list")
    r.add(s, "ws list sees CLI-created vault", v_cli in names(lst.get("data", {}).get("vaults")), json.dumps(lst)[:300])
    rc, out = cli.run("vault", "create", v_cli, "--local")
    r.add(s, "CLI duplicate create is rejected (non-zero)", rc != 0, out)
    add = await ws.send("storage.vault.add", {"name": v_ws, "type": "local", "mount_point": v_ws})
    r.add(s, "ws create succeeds", ok_status(add), json.dumps(add)[:300])
    dup = await ws.send("storage.vault.add", {"name": v_ws, "type": "local", "mount_point": v_ws})
    r.add(s, "ws duplicate create is rejected", not ok_status(dup), json.dumps(dup)[:300])
    rc, out = cli.run("vaults")
    r.add(s, "CLI list sees ws-created vault", rc == 0 and v_ws in out, out[-300:])
    lst = await ws.send("storage.vault.list")
    ids = {v.get("name"): v.get("id") for v in lst.get("data", {}).get("vaults", [])}
    rc, out = cli.run("vault", "delete", v_ws, "--owner", ws_user)  # names are per-owner; the ws caller owns it
    r.add(s, "CLI deletes ws-created vault", rc == 0, out)
    if ids.get(v_cli) is not None:
        rm = await ws.send("storage.vault.remove", {"id": ids[v_cli]})
        r.add(s, "ws deletes CLI-created vault", ok_status(rm), json.dumps(rm)[:300])
    rc, out = cli.run("vaults")
    r.add(s, "both vaults gone (CLI view)", v_cli not in out and v_ws not in out, out[-300:])
    rm = await ws.send("storage.vault.remove", {"id": 987654})
    r.add(s, "ws delete of missing vault is rejected", not ok_status(rm), json.dumps(rm)[:300])
    rc, out = cli.run("vault", "delete", "parity-does-not-exist")
    r.add(s, "CLI delete of missing vault is rejected (non-zero)", rc != 0, out)

    # --- groups ---------------------------------------------------------------
    s = "group"
    g_cli, g_ws = f"parity-g-cli-{tag}", f"parity-g-ws-{tag}"
    rc, out = cli.run("group", "create", g_cli)
    r.add(s, "CLI create succeeds", rc == 0, out)
    lst = await ws.send("groups.list")
    r.add(s, "ws list sees CLI-created group", g_cli in names(lst.get("data", {}).get("groups")), json.dumps(lst)[:300])
    add = await ws.send("group.add", {"name": g_ws})
    r.add(s, "ws create succeeds", ok_status(add), json.dumps(add)[:300])
    dup = await ws.send("group.add", {"name": g_ws})
    r.add(s, "ws duplicate create is rejected", not ok_status(dup), json.dumps(dup)[:300])
    rc, out = cli.run("group", "create", g_ws)
    r.add(s, "CLI duplicate of ws-created group is rejected", rc != 0, out)
    rc, out = cli.run("group", "delete", g_ws)
    r.add(s, "CLI deletes ws-created group", rc == 0, out)
    lst = await ws.send("groups.list")
    gid = {g.get("name"): g.get("id") for g in lst.get("data", {}).get("groups", [])}.get(g_cli)
    if gid is not None:
        rm = await ws.send("group.remove", {"id": gid})
        r.add(s, "ws deletes CLI-created group", ok_status(rm), json.dumps(rm)[:300])
    rm = await ws.send("group.remove", {"id": 987654})
    r.add(s, "ws delete of missing group is rejected", not ok_status(rm), json.dumps(rm)[:300])
    rc, out = cli.run("group", "info", "parity-no-such-group")
    r.add(s, "CLI info of missing group is rejected and daemon survives", rc != 0, out)
    rc, _ = cli.run("status")
    r.add(s, "daemon healthy after group error paths", rc == 0)

    # --- users ----------------------------------------------------------------
    s = "user"
    u_ws, u_cli = f"parity_u_ws_{tag}", f"parity_u_cli_{tag}"
    reg = await ws.send("auth.register", {"name": u_ws, "email": f"{u_ws}@example.invalid",
                                          "password": "Zq9#" + uuid.uuid4().hex + "!Xw", "is_active": True,
                                          "role": "unprivileged"})
    r.add(s, "ws register succeeds", ok_status(reg), json.dumps(reg)[:300])
    rc, out = cli.run("user", "info", u_ws)
    r.add(s, "CLI sees ws-registered user", rc == 0 and u_ws in out, out[-300:])
    rc, out = cli.run("user", "create", u_cli, "--role", "unprivileged")
    r.add(s, "CLI create succeeds", rc == 0, "exit %d" % rc)  # output contains a generated password; not logged
    got = await ws.send("auth.user.get.byName", {"name": u_cli})
    uid = (got.get("data") or {}).get("user", {}).get("id")
    r.add(s, "ws sees CLI-created user", ok_status(got) and uid is not None, json.dumps(got)[:200])
    if uid is not None:
        upd = await ws.send("auth.user.update", {"id": uid, "name": u_cli, "email": f"{u_cli}@example.invalid",
                                                "is_active": True, "role": "unprivileged"})
        r.add(s, "ws edit targets the selected user (#126)", ok_status(upd) and
              (upd.get("data") or {}).get("user", {}).get("id") == uid, json.dumps(upd)[:300])
        me = await ws.send("auth.isAuthenticated", {"token": ws.token})
        r.add(s, "editing another user leaves the caller unchanged (#126)",
              (me.get("data") or {}).get("user", {}).get("name") == ws_user, json.dumps(me)[:200])
        dele = await ws.send("auth.user.delete", {"id": uid})
        r.add(s, "ws deletes CLI-created user", ok_status(dele), json.dumps(dele)[:300])
    rc, out = cli.run("user", "delete", u_ws)
    r.add(s, "CLI deletes ws-registered user", rc == 0, out)
    rc, out = cli.run("user", "info", u_ws)
    r.add(s, "deleted user is gone (CLI)", rc != 0, out)
    self_role = await ws.send("auth.user.update", {"role": "unprivileged"})
    r.add(s, "ws self role change is rejected", not ok_status(self_role), json.dumps(self_role)[:300])


def daemon_pid(host: str) -> str:
    proc = subprocess.run(["ssh", "-o", "BatchMode=yes", host, "systemctl show -p MainPID --value vaulthalla.service"],
                          capture_output=True, text=True, timeout=30)
    return proc.stdout.strip()


async def phase2_scenarios(cli: Cli, ws: Ws, r: Report, ws_user: str, ws_url: str, host: str) -> None:
    """Behaviour Phase 2 made shared between the CLI and the web console (core/ops)."""
    tag = time.strftime("%H%M%S")
    pid_before = daemon_pid(host)

    # --- CLI input is validated at the definition layer ------------------------
    s = "cli-input"
    rc, out = cli.run("vault", "list", "--bogus-option")
    r.add(s, "unknown option is rejected", rc != 0, out)
    rc, out = cli.run("user", "list", "--sort", "id; SELECT 1")
    r.add(s, "SQL in --sort is rejected", rc != 0, out)

    # --- accounts: escalation ceiling and session revocation -------------------
    s = "accounts"
    helper, password = f"parity_idadm_{tag}", "Zq9#" + uuid.uuid4().hex + "!Xw"
    reg = await ws.send("auth.register", {"name": helper, "email": f"{helper}@example.invalid", "password": password,
                                          "is_active": True, "role": "identity_admin"})
    r.add(s, "admin registers an identity_admin", ok_status(reg), json.dumps(reg)[:300])
    async with Ws(ws_url) as ws2:
        login = await ws2.send("auth.login", {"name": helper, "password": password})
        r.add(s, "identity_admin logs in", ok_status(login), str(login.get("error", "")))
        mint = await ws2.send("auth.register", {"name": f"parity_mint_{tag}", "email": f"mint{tag}@example.invalid",
                                                "password": password, "is_active": True, "role": "admin"})
        r.add(s, "identity_admin cannot mint an admin account (S3)", not ok_status(mint), json.dumps(mint)[:300])
        rc, out = cli.run("user", "update", helper, "--disable")
        r.add(s, "CLI deactivates the account", rc == 0, out)
        after = await ws2.send("auth.users.list")
        r.add(s, "the deactivated account's open session is refused (S9)", not ok_status(after), json.dumps(after)[:300])
    async with Ws(ws_url) as ws3:
        relogin = await ws3.send("auth.login", {"name": helper, "password": password})
        r.add(s, "a deactivated account cannot log in", not ok_status(relogin), json.dumps(relogin)[:200])
    rc, out = cli.run("user", "update", helper, "--enable")
    r.add(s, "CLI reactivates the account", rc == 0, out)
    rc, out = cli.run("user", "delete", helper)
    r.add(s, "CLI deletes the account", rc == 0, out)

    # --- roles: --from and documented flags apply -----------------------------
    s = "roles"
    role = f"parity-role-{tag}"
    rc, out = cli.run("role", "admin", "create", role, "--from", "auditor", "--allow-users-add")
    r.add(s, "CLI creates a role --from auditor with an extra flag", rc == 0, out)
    got = await ws.send("role.admin.get.byName", {"name": role})
    perms = json.dumps((got.get("data") or {}).get("role", {}))
    r.add(s, "ws sees the inherited and added permissions", ok_status(got) and "true" in perms, perms[:300])
    rc, out = cli.run("role", "admin", "delete", role)
    r.add(s, "CLI deletes the role", rc == 0, out)

    # --- vaults: CLI updates reach what the web reads, and back ----------------
    s = "vault-update"
    vname = f"parity-upd-{tag}"
    rc, out = cli.run("vault", "create", vname, "--local", "--desc", "before")
    r.add(s, "CLI create", rc == 0, out)
    lst = await ws.send("storage.vault.list")
    vid = {v.get("name"): v.get("id") for v in (lst.get("data") or {}).get("vaults", [])}.get(vname)
    if vid is not None:
        rc, out = cli.run("vault", "update", str(vid), "--desc", "from-cli")
        got = await ws.send("storage.vault.get", {"id": vid})
        r.add(s, "ws sees the CLI update", rc == 0 and (got.get("data") or {}).get("vault", {}).get("description") == "from-cli",
              json.dumps(got)[:300])
        upd = await ws.send("storage.vault.update", {"id": vid, "description": "from-web"})
        rc, out = cli.run("vault", "info", str(vid))
        r.add(s, "a partial ws update is a patch the CLI sees", ok_status(upd) and "from-web" in out and vname in out, out[-300:])
        pol = await ws.send("pricing.budget.policy.upsert", {"scope": "vault", "vault_id": vid, "max_monthly_cost": "1.00"})
        r.add(s, "price budgets are refused on a local vault (ws)", not ok_status(pol), json.dumps(pol)[:200])
        rc, out = cli.run("pricing", "budget", "set-vault", str(vid), "--max-monthly", "1.00")
        r.add(s, "price budgets are refused on a local vault (CLI)", rc != 0, out)
        rm = await ws.send("storage.vault.remove", {"id": vid})
        r.add(s, "ws delete", ok_status(rm), json.dumps(rm)[:200])

    # --- API keys: bad credentials are refused, nothing leaks ------------------
    s = "api-keys"
    bad = await ws.send("storage.apiKey.add", {"name": f"parity-key-{tag}", "provider": "AWS", "access_key": "AKIAPARITY",
                                               "secret_access_key": "not-a-secret", "region": "us-east-1",
                                               "endpoint": "https://s3.invalid.example"})
    r.add(s, "ws refuses credentials the provider rejects", not ok_status(bad), json.dumps(bad)[:200])
    rc, out = cli.run("api-key", "create", f"parity-key-cli-{tag}", "--access", "AKIAPARITY", "--secret", "not-a-secret",
                      "--provider", "aws", "--endpoint", "https://s3.invalid.example")
    r.add(s, "CLI refuses credentials the provider rejects", rc != 0, "exit %d" % rc)
    lst = await ws.send("storage.apiKey.list")
    r.add(s, "no key was stored", f"parity-key-{tag}" not in json.dumps(lst), "")

    # --- S3 gateway: credentials and buckets agree -----------------------------
    s = "s3-gateway"
    st = await ws.send("s3.gateway.status")
    r.add(s, "ws status", ok_status(st), json.dumps(st)[:200])
    rc, _ = cli.run("s3-gateway", "status")
    r.add(s, "CLI status", rc == 0)
    cred = f"parity-cred-{tag}"
    made = await ws.send("s3.gateway.credentials.create", {"name": cred})
    r.add(s, "ws creates a user-access credential", ok_status(made), str(made.get("error", "")))
    rc, out = cli.run("s3-gateway", "creds", "list", "--user", ws_user)  # the CLI lists one principal's credentials
    r.add(s, "CLI lists it (secret not shown)", rc == 0 and cred in out and "secret" not in out.lower(), "exit %d" % rc)
    rc, out = cli.run("s3-gateway", "creds", "revoke", cred)
    r.add(s, "CLI revokes it", rc == 0, out)
    again = await ws.send("s3.gateway.credentials.revoke", {"name": cred})
    r.add(s, "revoking it again is an error (ws)", not ok_status(again), json.dumps(again)[:200])
    bvault, bucket = f"parity-bkt-{tag}", f"parity-bkt-{tag}"
    # Bucket listings show buckets on vaults the caller can reach, so the vault belongs to the ws caller.
    made_v = await ws.send("storage.vault.add", {"name": bvault, "type": "local"})
    rc2, out2 = cli.run("s3-gateway", "bucket", "bind", bucket, "--vault", bvault, "--owner", ws_user)
    r.add(s, "CLI binds a bucket to the ws caller's vault", ok_status(made_v) and rc2 == 0, out2)
    # Listings are filtered by the caller's vault filesystem rights (ObjectStore::listBuckets, one function for both
    # surfaces); the CLI runs as the super admin, so it is the one that must see the binding.
    rc, out = cli.run("s3-gateway", "bucket", "list")
    r.add(s, "the binding is listed", rc == 0 and bucket in out, out[-200:])
    ub = await ws.send("s3.gateway.buckets.unbind", {"bucket_name": bucket})
    r.add(s, "ws unbinds it", ok_status(ub), json.dumps(ub)[:200])
    ub2 = await ws.send("s3.gateway.buckets.unbind", {"bucket_name": bucket})
    r.add(s, "unbinding a missing bucket is an error, not {unbound:false}", not ok_status(ub2), json.dumps(ub2)[:200])
    cli.run("vault", "delete", bvault, "--owner", ws_user)

    # --- settings and health ---------------------------------------------------
    s = "settings-health"
    bad = await ws.send("settings.update", {"email": {"from": "not an address"}})
    r.add(s, "settings.update validates email settings", not ok_status(bad), json.dumps(bad)[:200])
    health = await ws.send("stats.system.health")
    stats = (health.get("data") or {}).get("stats", {})
    r.add(s, "web health carries a live DB probe", (stats.get("database") or {}).get("reachable") is True, json.dumps(stats)[:300])
    rc, out = cli.run("status")
    # vh status exits 0/1/2 for healthy/degraded/critical. A host can be degraded on purpose (e.g. an S3 vault without
    # recovery material, #370): the check is that both surfaces say the same.
    severity = {0: "healthy", 1: "degraded", 2: "critical"}.get(rc)
    r.add(s, "CLI and web agree on severity", severity is not None and stats.get("overall_status") == severity, out[:200])

    # --- malformed and unauthorized requests never take the daemon down --------
    s = "robustness"
    await ws.conn.send("{not json")
    await ws.conn.send(json.dumps({"command": "no.such.command", "payload": {}, "requestId": "x", "token": ws.token}))
    missing = await ws.send("storage.vault.get", {})
    r.add(s, "a request missing fields is an error", not ok_status(missing), json.dumps(missing)[:200])
    async with Ws(ws_url) as anon:
        unauth = await anon.send("auth.users.list")
        r.add(s, "an unauthenticated account command is refused", not ok_status(unauth), json.dumps(unauth)[:200])
    still = await ws.send("auth.isAuthenticated", {"token": ws.token})
    r.add(s, "the session still works after garbage", ok_status(still), json.dumps(still)[:200])
    r.add(s, "same daemon PID throughout", daemon_pid(host) == pid_before and pid_before not in ("", "0"),
          f"{pid_before} -> {daemon_pid(host)}")


async def main_async(args) -> int:
    with open(args.admin_password_file) as fh:
        password = fh.read().strip()
    cli, report = Cli(args.host), Report()
    async with Ws(args.ws_url) as ws:
        login = await ws.send("auth.login", {"name": args.admin_user, "password": password})
        if not report.add("setup", "ws admin login", ok_status(login), str(login.get("error", ""))):
            return 1
        await scenarios(cli, ws, report, args.admin_user)
        await phase2_scenarios(cli, ws, report, args.admin_user, args.ws_url, args.host)
    failed = [c for c in report.checks if not c.ok]
    print(f"\n{len(report.checks) - len(failed)}/{len(report.checks)} checks passed")
    if args.evidence:
        with open(args.evidence, "w") as fh:
            json.dump({"host": args.host, "ws_url": args.ws_url, "checks": [asdict(c) for c in report.checks]}, fh, indent=2)
    return 0 if not failed else 1


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--host", required=True)
    ap.add_argument("--ws-url", required=True)
    ap.add_argument("--admin-user", default="admin")
    ap.add_argument("--admin-password-file", required=True)
    ap.add_argument("--evidence")
    sys.exit(asyncio.run(main_async(ap.parse_args())))


if __name__ == "__main__":
    main()
