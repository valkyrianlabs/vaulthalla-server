#!/usr/bin/env python3
"""Live end-to-end smoke of the upstream control plane (#237, #96) against real AWS S3 and/or Cloudflare R2.

NOT for CI. Launches a private test-mode daemon (tools/harness Instance: own DB, run dir, socket), registers the
provider credentials through `vh api-key create`, and drives everything through the real CLI:

  admin enable + capability probe, inventory (counts only), protection lock refuses vault binding and create-new,
  create a managed bucket + vault, name collision refused without changes, a file uploaded through the vault reaches
  the bucket encrypted, read-only adoption check + adoption of a bucket holding plaintext objects written by another
  tool (they sync into the vault), cleanup refused for the adopted bucket, vault deletion keeps the bucket, cleanup of
  the managed bucket (preflight token) deletes it. With SQS/Queues permissions present, event subscription + external
  PUT → targeted sync too; otherwise that step reports the missing capability and is skipped.

Only buckets named vaulthalla-test-<run>-* are created, modified or deleted; everything created is removed at the end
(also on failure). Credentials come from the environment and are never printed:
  AWS: VH_AWS_ADMIN_API_KEY, VH_AWS_ADMIN_SECRET_KEY            (region: VH_LIVE_AWS_REGION, default us-east-2)
  R2:  VH_R2_ADMIN_ACCESS_KEY, VH_R2_ADMIN_SECRET_KEY, VH_R2_ADMIN_ENDPOINT   (+ optional VH_CF_API_TOKEN)

  sudo --preserve-env=VH_AWS_ADMIN_API_KEY,VH_AWS_ADMIN_SECRET_KEY,VH_R2_ADMIN_ACCESS_KEY,VH_R2_ADMIN_SECRET_KEY,\
VH_R2_ADMIN_ENDPOINT,VH_CF_API_TOKEN python3 tools/lab/upstream_live_smoke.py --build build [--provider aws|r2|both]
"""
from __future__ import annotations

import argparse
import json
import os
import pwd
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "harness"))
from vhh.instance import Instance  # noqa: E402

SECRET_ENV = ("VH_AWS_ADMIN_API_KEY", "VH_AWS_ADMIN_SECRET_KEY", "VH_R2_ADMIN_ACCESS_KEY", "VH_R2_ADMIN_SECRET_KEY",
              "VH_CF_API_TOKEN")


def redact(text: str) -> str:
    for name in SECRET_ENV:
        value = os.environ.get(name)
        if value:
            text = text.replace(value, "[REDACTED]")
    return text


class Failure(RuntimeError):
    pass


class Smoke:
    def __init__(self, build: Path, provider: str):
        self.build = build
        self.provider = provider
        self.run = time.strftime("%m%d%H%M%S") + secrets.token_hex(2)
        self.user = pwd.getpwuid(int(os.environ.get("SUDO_UID", "1000")))
        self.results: list[tuple[str, str, str]] = []
        self.created_buckets: dict[str, set[str]] = {"aws": set(), "r2": set()}
        self.inst: Instance | None = None
        self.region = os.environ.get("VH_LIVE_AWS_REGION", "us-east-2")
        # sudo resets PATH; the AWS CLI is often a per-user install.
        self.aws = shutil.which("aws", path=f"{self.user.pw_dir}/.local/bin:/usr/local/bin:/usr/bin:/bin")
        if not self.aws:
            raise SystemExit("aws CLI not found (needed to inspect and seed test buckets)")

    # ------------------------------------------------------------------ helpers
    def bucket(self, provider: str, suffix: str) -> str:
        return f"vaulthalla-test-{self.run}-{provider}-{suffix}"

    def vh(self, *args: str, ok: bool = True, timeout: float = 240) -> subprocess.CompletedProcess:
        env = {"PATH": "/usr/bin:/bin", "HOME": self.user.pw_dir, "VAULTHALLA_CLI_SOCKET": str(self.inst.socket_path),
               "VAULTHALLA_NONINTERACTIVE": "1", "VAULTHALLA_CLI_TIMEOUT": str(int(timeout))}
        cmd = ["runuser", "-u", self.user.pw_name, "--", "env", *[f"{k}={v}" for k, v in env.items()],
               str(self.build / "core" / "vaulthalla-cli"), *args]
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
        cp.stdout, cp.stderr = redact(cp.stdout), redact(cp.stderr)
        if ok and cp.returncode != 0:
            shown = " ".join(a if not any(os.environ.get(s) == a for s in SECRET_ENV) else "[REDACTED]" for a in args)
            raise Failure(f"vh {shown} -> exit {cp.returncode}: {(cp.stdout + cp.stderr).strip()[:800]}")
        return cp

    def vault_id(self, name: str) -> str:
        data = self.vh_json("vaults")
        rows = data.get("vaults", data) if isinstance(data, dict) else data
        for v in rows:
            if v.get("name") == name:
                return str(v.get("id") or v.get("vault_id"))
        raise Failure(f"vault {name} not found")

    def vault(self, cmd: tuple[str, ...], name: str, *rest: str, ok: bool = True, timeout: float = 240):
        """A vault command addressed by ID (names need --owner on some commands and are refused by others)."""
        return self.vh(*cmd, self.vault_id(name), *rest, ok=ok, timeout=timeout)

    def vh_json(self, *args: str):
        out = self.vh(*args, "--json").stdout
        start = min([i for i in (out.find("{"), out.find("[")) if i >= 0], default=-1)
        if start < 0:
            raise Failure(f"no JSON from vh {' '.join(args)}: {out[:300]}")
        return json.loads(out[start:])

    def cloud(self, provider: str, *args: str, ok: bool = True) -> subprocess.CompletedProcess:
        env = dict(os.environ, AWS_PAGER="")
        if provider == "aws":
            env.update(AWS_ACCESS_KEY_ID=os.environ["VH_AWS_ADMIN_API_KEY"],
                       AWS_SECRET_ACCESS_KEY=os.environ["VH_AWS_ADMIN_SECRET_KEY"], AWS_DEFAULT_REGION=self.region)
            extra = []
        else:
            env.update(AWS_ACCESS_KEY_ID=os.environ["VH_R2_ADMIN_ACCESS_KEY"],
                       AWS_SECRET_ACCESS_KEY=os.environ["VH_R2_ADMIN_SECRET_KEY"], AWS_DEFAULT_REGION="auto")
            extra = ["--endpoint-url", os.environ["VH_R2_ADMIN_ENDPOINT"]]
        cp = subprocess.run([self.aws, *args, *extra], capture_output=True, text=True, env=env, timeout=120)
        cp.stdout, cp.stderr = redact(cp.stdout), redact(cp.stderr)
        if ok and cp.returncode != 0:
            raise Failure(f"aws {' '.join(args[:3])} -> {cp.stderr.strip()[:400]}")
        return cp

    def bucket_exists(self, provider: str, bucket: str) -> bool:
        return self.cloud(provider, "s3api", "head-bucket", "--bucket", bucket, ok=False).returncode == 0

    def step(self, name: str, fn) -> None:
        t0 = time.monotonic()
        try:
            detail = fn() or ""
            self.results.append(("PASS", name, str(detail)))
        except Skip as s:
            self.results.append(("SKIP", name, str(s)))
        except Exception as e:  # noqa: BLE001
            self.results.append(("FAIL", name, redact(str(e))[:900]))
        print(f"[{self.results[-1][0]}] {name} ({time.monotonic() - t0:.1f}s) {self.results[-1][2][:300]}", flush=True)

    def wait(self, what: str, predicate, timeout: float = 120, every: float = 3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(every)
        raise Failure(f"timed out after {timeout:.0f}s waiting for {what}")

    # ------------------------------------------------------------------ flows
    def keys(self) -> None:
        if self.provider in ("aws", "both"):
            self.vh("api-key", "create", "live-aws", "--provider", "aws",
                    "--access", os.environ["VH_AWS_ADMIN_API_KEY"], "--secret", os.environ["VH_AWS_ADMIN_SECRET_KEY"],
                    "--endpoint", f"https://s3.{self.region}.amazonaws.com", "--region", self.region)
        if self.provider in ("r2", "both"):
            self.vh("api-key", "create", "live-r2", "--provider", "cloudflare-r2",
                    "--access", os.environ["VH_R2_ADMIN_ACCESS_KEY"], "--secret", os.environ["VH_R2_ADMIN_SECRET_KEY"],
                    "--endpoint", os.environ["VH_R2_ADMIN_ENDPOINT"], "--region", "auto")

    def flow(self, p: str) -> None:
        key = f"live-{p}"
        managed = self.bucket(p, "managed")
        adopt = self.bucket(p, "adopt")
        locked = self.bucket(p, "locked")
        vault, adopted_vault = f"live_{p}_{self.run}", f"live_{p}_adopt_{self.run}"
        ws = Path(tempfile.mkdtemp(prefix="vhlive_", dir="/tmp"))
        os.chown(ws, self.user.pw_uid, self.user.pw_gid)

        def admin():
            self.vh("upstream", "admin", "enable", key)
            status = self.vh_json("upstream", "admin", "status", key, "--probe")
            admin_obj = status.get("admin", status)
            caps = {c["name"]: c["ok"] for c in (admin_obj.get("capabilities") or {}).get("items", [])}
            if not admin_obj.get("enabled"):
                raise Failure("admin not enabled")
            return f"account resolved={bool(admin_obj.get('account_ref'))} capabilities={caps}"
        self.step(f"{p}: admin enable + probe", admin)

        def inventory():
            inv = self.vh_json("upstream", "buckets", key)
            inv = inv.get("inventory", inv)
            states = {}
            for b in inv["buckets"]:
                states[b["state"]] = states.get(b["state"], 0) + 1
            return f"{len(inv['buckets'])} buckets listed (names not printed), states={states}"
        self.step(f"{p}: inventory (account-level only)", inventory)

        def lock():
            self.created_buckets[p].add(locked)   # must never exist; removed by teardown if it ever does
            self.vh("upstream", "protect", key, locked, "--reason", "live smoke: must never be touched")
            bind = self.vh("vault", "create", vault + "_x", "--s3", "--api-key", key, "--bucket", locked, ok=False)
            create = self.vh("vault", "create", vault + "_y", "--s3", "--api-key", key, "--bucket", locked,
                             "--bucket-mode", "create", ok=False)
            if bind.returncode == 0 or create.returncode == 0:
                raise Failure("a protected bucket name was bound or created")
            if self.bucket_exists(p, locked):
                raise Failure("protected bucket name was created upstream")
            self.vh("upstream", "unprotect", key, locked, "--yes")
            return "bind and create-new refused; nothing created; unlock with --yes"
        self.step(f"{p}: protection lock refuses binding and creation", lock)

        def create():
            self.created_buckets[p].add(managed)   # before the call: teardown must see it whatever fails next
            self.vh("vault", "create", vault, "--s3", "--api-key", key, "--bucket", managed, "--bucket-mode", "create",
                    "--abort-multipart-days", "3", timeout=300)
            if not self.bucket_exists(p, managed):
                raise Failure("managed bucket not found upstream")
            lc = self.cloud(p, "s3api", "get-bucket-lifecycle-configuration", "--bucket", managed, ok=False)
            if "vaulthalla-managed" not in lc.stdout:
                raise Failure(f"our lifecycle rule missing: {lc.stdout[:200]} {lc.stderr[:200]}")
            inv = self.vh_json("upstream", "buckets", key, "--filter", managed)
            row = [b for b in inv.get("inventory", inv).get("buckets", []) if b["name"] == managed]
            if not row or row[0]["state"] != "managed":
                raise Failure(f"inventory state: {row}")
            return "bucket created, lifecycle rule present, state managed"
        self.step(f"{p}: create managed bucket + vault", create)

        def lifecycle_rules(bucket: str):
            # Parsed and sorted: S3 lifecycle reads are eventually consistent right after a write, and key order varies.
            out = self.cloud(p, "s3api", "get-bucket-lifecycle-configuration", "--bucket", bucket, ok=False).stdout
            rules = json.loads(out or "{}").get("Rules", [])
            return sorted(json.dumps(r, sort_keys=True) for r in rules)

        def collision():
            # Settle until two reads agree, then snapshot.
            before = self.wait("a stable lifecycle read", lambda: (lambda a, b: a if a == b and a else None)(
                lifecycle_rules(managed), (time.sleep(2), lifecycle_rules(managed))[1]), 60, 1)
            cp = self.vh("vault", "create", vault + "_dup", "--s3", "--api-key", key, "--bucket", managed,
                         "--bucket-mode", "create", ok=False)
            time.sleep(3)
            after = lifecycle_rules(managed)
            if cp.returncode == 0:
                raise Failure("create-new took over an existing bucket")
            if before != after or not self.bucket_exists(p, managed):
                raise Failure("collision changed the existing bucket")
            return f"refused (exit {cp.returncode}); bucket unchanged"
        self.step(f"{p}: name collision is non-destructive", collision)

        def upload():
            src = ws / "hello.txt"
            src.write_text("hello from the vault " + self.run)
            os.chown(src, self.user.pw_uid, self.user.pw_gid)
            self.vault(("fs", "put"), vault, str(src), "/hello.txt")
            self.vault(("vault", "sync"), vault)
            head = self.wait("hello.txt upstream", lambda: (
                lambda cp: cp.returncode == 0 and cp.stdout)(self.cloud(p, "s3api", "head-object", "--bucket", managed,
                                                                         "--key", "hello.txt", ok=False)), 150)
            meta = json.loads(head).get("Metadata", {})
            if meta.get("vh-encrypted") != "true":
                raise Failure(f"object not Vaulthalla-encrypted: {meta}")
            return "uploaded and encrypted upstream (vh-encrypted=true)"
        self.step(f"{p}: vault upload reaches the bucket encrypted", upload)

        def lock_bound():
            self.vh("upstream", "protect", key, managed, "--reason", "live smoke: lock a bound bucket")
            src = ws / "while-locked.txt"
            src.write_text("must not reach the bucket while locked")
            os.chown(src, self.user.pw_uid, self.user.pw_gid)
            self.vault(("fs", "put"), vault, str(src), "/while-locked.txt")
            self.vault(("vault", "sync"), vault, ok=False)
            time.sleep(15)
            leaked = self.cloud(p, "s3api", "head-object", "--bucket", managed, "--key", "while-locked.txt", ok=False)
            refused_lc = self.vh("upstream", "lifecycle", key, managed, "--abort-multipart-days", "9", ok=False)
            self.vh("upstream", "unprotect", key, managed, "--yes")
            if leaked.returncode == 0:
                raise Failure("a protected bucket received a write")
            if refused_lc.returncode == 0:
                raise Failure("lifecycle changed on a protected bucket")
            self.vault(("vault", "sync"), vault)
            self.wait("the upload after unlocking", lambda: self.cloud(
                p, "s3api", "head-object", "--bucket", managed, "--key", "while-locked.txt", ok=False).returncode == 0, 150)
            return "locked: no write reached the bucket, lifecycle refused; unlocked: the pending upload went through"
        self.step(f"{p}: a lock stops a bound vault's sync until unlocked", lock_bound)

        def events():
            cp = self.vault(("upstream", "events", "enable"), vault, ok=False)
            if cp.returncode != 0:
                raise Skip(f"event subscription refused (credential capability): {(cp.stdout + cp.stderr).strip()[:300]}")
            ext = ws / "external.txt"
            ext.write_text("written by another tool " + self.run)
            self.cloud(p, "s3", "cp", str(ext), f"s3://{managed}/inbox/external.txt")
            self.wait("event-synced external.txt", lambda: "external.txt" in self.vault(("fs", "ls"), vault, "/inbox", ok=False).stdout, 180)
            status = self.vh_json("upstream", "events", "status", self.vault_id(vault))
            self.vault(("upstream", "events", "disable"), vault)
            return f"external PUT synced via events; status={json.dumps(status)[:300]}"
        self.step(f"{p}: event-driven sync of an external upload", events)

        def adoption():
            self.created_buckets[p].add(adopt)
            if p == "aws":
                self.cloud(p, "s3api", "create-bucket", "--bucket", adopt, "--create-bucket-configuration",
                           f"LocationConstraint={self.region}")
            else:
                self.cloud(p, "s3api", "create-bucket", "--bucket", adopt)
            self.created_buckets[p].add(adopt)
            for name, body in (("external.txt", "plain one"), ("dir/b.txt", "plain two")):
                f = ws / name.replace("/", "_")
                f.write_text(body)
                self.cloud(p, "s3", "cp", str(f), f"s3://{adopt}/{name}")
            report = self.vh_json("upstream", "adopt-check", key, adopt)
            report = report.get("report", report)
            if report.get("objects_scanned") != 2 or report.get("blockers"):
                raise Failure(f"admission report: {json.dumps(report)[:400]}")
            refused = self.vh("vault", "create", adopted_vault, "--s3", "--api-key", key, "--bucket", adopt,
                              "--bucket-mode", "adopt", ok=False)
            if refused.returncode == 0:
                raise Failure("adoption without confirmation succeeded")
            self.vh("vault", "create", adopted_vault, "--s3", "--api-key", key, "--bucket", adopt, "--bucket-mode",
                    "adopt", "--yes", timeout=300)
            self.vault(("vault", "sync"), adopted_vault)
            self.wait("adopted objects in the vault",
                      lambda: "external.txt" in self.vault(("fs", "ls"), adopted_vault, "/", ok=False).stdout, 150)
            out = ws / "got.txt"
            self.vault(("fs", "get"), adopted_vault, "/external.txt", "-o", str(out))
            if out.read_text() != "plain one":
                raise Failure("adopted content differs")
            listing = self.cloud(p, "s3api", "list-objects-v2", "--bucket", adopt).stdout
            if '"external.txt"' not in listing or '"dir/b.txt"' not in listing:
                raise Failure("adoption changed the existing objects")
            return f"preflight {report.get('sampled_plaintext')} plaintext sampled; confirmation required; objects synced; upstream untouched"
        self.step(f"{p}: adopt a bucket with foreign objects", adoption)

        def refuse_cleanup_adopted():
            cp = self.vh("upstream", "cleanup", key, adopt, "--preflight", "--json", ok=False)
            text = cp.stdout + cp.stderr
            if cp.returncode == 0 and '"blockers":[]' in text.replace(" ", ""):
                raise Failure("cleanup of an adopted bucket was not blocked")
            if not self.bucket_exists(p, adopt):
                raise Failure("adopted bucket disappeared")
            return "blocked (adopted, bound)"
        self.step(f"{p}: cleanup refuses an adopted, bound bucket", refuse_cleanup_adopted)

        def delete_keeps_bucket():
            for v in (vault, adopted_vault):
                try:
                    vid = self.vault_id(v)
                except Failure:
                    continue   # never created (an earlier step failed)
                self.vh("vault", "delete", vid, "--now", "--yes", "--keep-upstream", "--accept-key-loss")

            def purged() -> bool:
                plan = self.vh("upstream", "cleanup", key, managed, "--preflight", "--json", ok=False).stdout
                return "used by vault" not in plan
            self.wait("the retention purge of the deleted vaults", purged, 180, 5)
            if not self.bucket_exists(p, managed):
                raise Failure("vault deletion deleted the managed bucket")
            head = self.cloud(p, "s3api", "head-object", "--bucket", managed, "--key", "hello.txt", ok=False)
            if head.returncode != 0:
                raise Failure("vault deletion removed upstream objects")
            return "vaults purged; bucket and objects kept"
        self.step(f"{p}: vault deletion keeps upstream data", delete_keeps_bucket)

        def cleanup():
            plan = self.vh_json("upstream", "cleanup", key, managed, "--preflight")
            plan = plan.get("plan", plan)
            if plan.get("blockers"):
                raise Failure(f"blocked: {plan['blockers']}")
            token = plan["confirm_token"]
            self.vh("upstream", "cleanup", key, managed, "--confirm-token", token, timeout=300)
            if self.bucket_exists(p, managed):
                raise Failure("bucket still exists after cleanup")
            self.created_buckets[p].discard(managed)
            audit = self.vh_json("upstream", "audit", "--bucket", managed)
            entries = audit.get("entries", []) if isinstance(audit, dict) else audit
            actions = sorted({f"{e['action']}:{e['outcome']}" for e in entries})
            return f"objects={plan.get('objects')} versions={plan.get('versions')}; deleted; audit actions={actions}"
        self.step(f"{p}: cleanup of the managed bucket", cleanup)

    def teardown(self) -> None:
        for p, names in self.created_buckets.items():
            for name in sorted(names):
                if not name.startswith(f"vaulthalla-test-{self.run}-"):
                    continue  # never touch anything else
                try:
                    if not self.bucket_exists(p, name):
                        continue
                    self.cloud(p, "s3", "rm", f"s3://{name}", "--recursive", ok=False)
                    if p == "aws":
                        vers = self.cloud(p, "s3api", "list-object-versions", "--bucket", name, ok=False).stdout
                        data = json.loads(vers or "{}")
                        for v in (data.get("Versions") or []) + (data.get("DeleteMarkers") or []):
                            self.cloud(p, "s3api", "delete-object", "--bucket", name, "--key", v["Key"],
                                       "--version-id", v["VersionId"], ok=False)
                    self.cloud(p, "s3api", "delete-bucket", "--bucket", name, ok=False)
                    gone = False
                    for _ in range(10):   # S3 HeadBucket can still answer briefly after DeleteBucket
                        if not self.bucket_exists(p, name):
                            gone = True
                            break
                        time.sleep(2)
                    print(f"[teardown] removed leftover {name}: {'ok' if gone else 'STILL PRESENT'}")
                except Exception as e:  # noqa: BLE001 - keep going: every bucket must get its chance
                    print(f"[teardown] {name}: {redact(str(e))[:300]}")

    def main(self) -> int:
        with Instance(self.build, run_id=f"live{self.run}") as inst:
            self.inst = inst
            try:
                self.step("register provider credentials", self.keys)
                for p in ("aws", "r2"):
                    if self.provider in (p, "both"):
                        self.flow(p)
            finally:
                self.teardown()
                left = []
                for p in ("aws", "r2"):
                    if self.provider in (p, "both"):
                        names = self.cloud(p, "s3api", "list-buckets", "--query", "Buckets[].Name", "--output", "text").stdout.split()
                        left += [n for n in names if n.startswith(f"vaulthalla-test-{self.run}-")]
                print(f"[teardown] leftover test buckets: {left or 'none'}")
                print(f"[instance] daemon log: {inst.log_path}")
        fails = [r for r in self.results if r[0] == "FAIL"]
        print("\nSummary: " + ", ".join(f"{s}={sum(1 for r in self.results if r[0] == s)}" for s in ("PASS", "SKIP", "FAIL")))
        return 1 if fails else 0


class Skip(Exception):
    pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--build", type=Path, default=REPO / "build")
    ap.add_argument("--provider", choices=["aws", "r2", "both"], default="both")
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("run with sudo (the private instance needs root); see the module docstring")
    sys.exit(Smoke(a.build.resolve(), a.provider).main())
