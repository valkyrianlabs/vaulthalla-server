"""`vh setup caddy` contract (deploy/launchd/vaulthalla-caddy, macOS HTTPS).

The tool runs here against a temporary --root with stub caddy/launchctl/lsof and the real openssl, so it works on
Linux CI too. Where a real Caddy is on PATH (a Mac with Homebrew's caddy), the generated Caddyfiles are also validated
by Caddy itself. What is pinned:

- the certificate source follows the hostname: Vaulthalla's own CA for internal names, Let's Encrypt for public ones,
  Cloudflare DNS-01 with a certbot-format credentials file, or the operator's own files; never a public CA for an
  internal name and never TLS verification switched off;
- the internal CA is name-constrained to the configured hostnames (or --ca-scope), and replaced, not widened, when a
  hostname outside it is configured;
- the Caddyfile routes like `vh setup nginx` (WebSockets, streamed transfers, S3 path-style header), with Caddy's admin
  API off; secrets (the CA key, the Cloudflare token, a provided key) are readable by the service only;
- a configuration that doesn't validate never replaces the working one; ports held by someone else are refused;
- teardown keeps certificates unless --purge, and vaulthalla-provision manages the LaunchDaemon once configured.
"""
from __future__ import annotations

import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LAUNCHD = REPO / "deploy" / "launchd"
SUPPORT = "/Library/Application Support/Vaulthalla"
PATHS = {
    "SERVICE": "_vaulthalla",
    "ALIAS": "vaulthalla",
    "LABEL_PREFIX": "sh.vaulthalla",
    "PORT_OFFSET": "0",
    "SUPPORT_DIR": SUPPORT,
    "STATE_DIR": f"{SUPPORT}/state",
    "RUN_DIR": f"{SUPPORT}/run",
    "MOUNT_DIR": f"{SUPPORT}/mount",
    "LOG_DIR": "/Library/Logs/Vaulthalla",
    "CONFIG_PATH": f"{SUPPORT}/config.yaml",
    "SHARE_DIR": "/usr/local/share/vaulthalla",
    "BINDIR": "/usr/local/bin",
    "WEB_DIR": "/usr/local/share/vaulthalla-web",
    "NODE": "/usr/local/libexec/vaulthalla/node/bin/node",
    "PG_BIN": "/usr/local/libexec/vaulthalla/postgresql/bin",
    "CADDY_BIN": "/usr/local/libexec/vaulthalla/caddy/caddy",
    "PROVISION": "/usr/local/lib/vaulthalla/vaulthalla-provision",
}
CONFIG = """websocket_server:
  enabled: true
  host: 0.0.0.0
  port: 36969

http_preview_server:
  enabled: true
  host: 0.0.0.0
  port: 36970

s3_gateway:
  enabled: true
  host: 127.0.0.1
  port: 39123
"""

STUB_CADDY = r'''#!/bin/sh
echo "caddy $*" >> "$STUB_LOG"
case "$1" in
  validate) if [ "${STUB_CADDY_INVALID:-0}" = 1 ]; then echo "Error: adapting config using caddyfile: bad" >&2; exit 1; fi ;;
  list-modules) printf 'http\ntls\n'; [ "${STUB_CADDY_CLOUDFLARE:-1}" = 1 ] && echo dns.providers.cloudflare ;;
esac
exit 0
'''
STUB_LAUNCHCTL = r'''#!/bin/sh
echo "launchctl $*" >> "$STUB_LOG"
loaded="$STUB_DIR/loaded"; mkdir -p "$loaded"
case "$1" in
  print) [ -e "$loaded/${2#system/}" ] ;;
  bootstrap) touch "$loaded/$(basename "$3" .plist)" ;;
  bootout) rm -f "$loaded/${2#system/}" ;;
esac
'''
# lsof -t: the pid listening on a port, from STUB_LSOF="<port>:<pid>".
STUB_LSOF = r'''#!/bin/sh
for a in "$@"; do case "$a" in -iTCP:*) port=${a#-iTCP:} ;; esac; done
case "${STUB_LSOF:-}" in "$port":*) echo "${STUB_LSOF#*:}" ;; esac
exit 0
'''


def render(text: str, values: dict[str, str]) -> str:
    for key, value in values.items():
        text = text.replace(f"@{key}@", value)
    return text


def openssl(*args: str, stdin: bytes | None = None) -> str:
    return subprocess.run(["openssl", *args], input=stdin, capture_output=True, check=True).stdout.decode()


class CaddySetup(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.root = base / "root"
        self.stubs = base / "stubs"
        self.stubs.mkdir()
        for name, body in (("caddy", STUB_CADDY), ("launchctl", STUB_LAUNCHCTL), ("lsof", STUB_LSOF)):
            (self.stubs / name).write_text(body)
            (self.stubs / name).chmod(0o755)
        self.log = base / "calls.log"
        self.support = self.path(SUPPORT)
        self.support.mkdir(parents=True)
        (self.support / "config.yaml").write_text(CONFIG)
        (self.root / "etc").mkdir()
        (self.root / "etc" / "hosts").write_text("127.0.0.1 localhost\n")
        self.script = base / "vaulthalla-caddy"
        self.script.write_text(render((LAUNCHD / "vaulthalla-caddy.in").read_text(), PATHS))
        self.script.chmod(0o755)
        self.caddy = str(self.stubs / "caddy")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def path(self, absolute: str) -> Path:
        return self.root / absolute.lstrip("/")

    def run_tool(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        full = dict(os.environ, VH_CADDY=self.caddy, VH_LAUNCHCTL=str(self.stubs / "launchctl"),
                    VH_LSOF=str(self.stubs / "lsof"), STUB_LOG=str(self.log), STUB_DIR=self.tmp.name, **(env or {}))
        full.pop("VH_CURL", None)
        return subprocess.run(["bash", str(self.script), *args, "--root", str(self.root)], env=full,
                              capture_output=True, text=True, timeout=120)

    def ok(self, *args: str, **kw) -> subprocess.CompletedProcess:
        r = self.run_tool(*args, **kw)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        return r

    @property
    def caddyfile(self) -> str:
        return (self.support / "caddy" / "Caddyfile").read_text()

    def mode(self, p: Path) -> int:
        return stat.S_IMODE(p.stat().st_mode)

    def constraints(self) -> str:
        text = openssl("x509", "-in", str(self.support / "caddy" / "ca" / "root.crt"), "-noout", "-text")
        return text.split("Name Constraints", 1)[1].split("X509v3", 1)[0] if "Name Constraints" in text else ""

    # --- internal ------------------------------------------------------------------------------------------------
    def test_internal_name_gets_a_name_constrained_vaulthalla_ca(self) -> None:
        self.ok("setup", "caddy", "--domain", "Vault.Home.Arpa")
        cf = self.caddyfile
        self.assertIn("vault.home.arpa {", cf)
        self.assertIn("issuer internal {", cf)
        self.assertIn("ca vaulthalla {", cf)
        self.assertNotIn("acme_ca", cf)
        self.assertIn("DNS:vault.home.arpa", self.constraints())
        ca = self.support / "caddy" / "ca"
        self.assertEqual(self.mode(ca / "root.key"), 0o600)
        self.assertEqual(self.mode(ca), 0o700)
        self.assertEqual(self.mode(self.support / "caddy"), 0o700)
        self.assertEqual(self.mode(self.support / "caddy" / "Caddyfile"), 0o600)
        exported = self.support / "vaulthalla-local-ca.crt"
        self.assertEqual(self.mode(exported), 0o644)
        self.assertEqual(exported.read_bytes(), (ca / "root.crt").read_bytes())

    def test_ca_scope_permits_the_subtree_and_survives_new_names_inside_it(self) -> None:
        self.ok("--domain", "vault.home.arpa", "--ca-scope", "home.arpa")
        self.assertIn("DNS:home.arpa", self.constraints())
        first = (self.support / "caddy" / "ca" / "root.crt").read_bytes()
        self.ok("--domain", "photos.home.arpa")
        self.assertEqual((self.support / "caddy" / "ca" / "root.crt").read_bytes(), first)

    def test_a_name_outside_the_ca_replaces_it_and_never_widens_it(self) -> None:
        self.ok("--domain", "vault.home.arpa")
        first = (self.support / "caddy" / "ca" / "root.crt").read_bytes()
        r = self.ok("--domain", "vault.lan")
        self.assertIn("clients must trust it again", r.stdout)
        self.assertNotEqual((self.support / "caddy" / "ca" / "root.crt").read_bytes(), first)
        self.assertIn("DNS:vault.lan", self.constraints())
        self.assertNotIn("home.arpa", self.constraints())
        self.assertTrue(any(p.name.startswith("ca.replaced-") for p in (self.support / "caddy").iterdir()))

    def test_routes_match_nginx_and_admin_api_is_off(self) -> None:
        self.ok("--domain", "vault.home.arpa", "--s3-domain", "s3.home.arpa")
        cf = self.caddyfile
        self.assertIn("admin off", cf)
        self.assertIn("skip_install_trust", cf)
        self.assertIn("@ws path /ws /ws/*", cf)
        self.assertIn("reverse_proxy @ws 127.0.0.1:36969", cf)
        self.assertIn("@http path /preview* /download* /upload*", cf)
        self.assertIn("reverse_proxy @http 127.0.0.1:36970 {", cf)
        self.assertIn("flush_interval -1", cf)
        self.assertIn("reverse_proxy 127.0.0.1:36968 {", cf)
        s3 = cf.split("s3.home.arpa {", 1)[1]
        self.assertIn("reverse_proxy 127.0.0.1:39123 {", s3)
        self.assertIn("header_up X-Vaulthalla-S3-Path-Style-Only true", s3)
        self.assertIn('Strict-Transport-Security "max-age=31536000"', cf)
        self.assertIn("DNS:s3.home.arpa", self.constraints())

    def test_a_bare_rerun_reuses_the_saved_settings(self) -> None:
        self.ok("--domain", "vault.home.arpa", "--listen", "192.168.1.10")
        before = self.caddyfile
        self.ok()
        self.assertEqual(self.caddyfile, before)
        self.assertIn("bind 192.168.1.10", self.caddyfile)
        settings = (self.support / "caddy" / "settings").read_text()
        self.assertIn(f"caddy={self.caddy}", settings)
        self.assertEqual(self.mode(self.support / "caddy" / "settings"), 0o600)

    # --- public --------------------------------------------------------------------------------------------------
    def test_public_name_uses_lets_encrypt(self) -> None:
        self.ok("--domain", "vault.example.com", "--email", "ops@example.com")
        cf = self.caddyfile
        self.assertIn("acme_ca https://acme-v02.api.letsencrypt.org/directory", cf)
        self.assertIn("email ops@example.com", cf)
        self.assertNotIn("pki {", cf)
        self.assertNotIn("issuer internal", cf)
        self.assertFalse((self.support / "caddy" / "ca").exists())

    def test_staging_rehearsal_uses_the_staging_directory(self) -> None:
        self.ok("--domain", "vault.example.com", "--acme-staging")
        self.assertIn("acme_ca https://acme-staging-v02.api.letsencrypt.org/directory", self.caddyfile)

    def test_a_public_ca_is_never_asked_for_an_internal_name(self) -> None:
        cred = self.cloudflare_file()
        r = self.run_tool("--domain", "vault.home.arpa", "--dns-cloudflare", str(cred))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("internal name", r.stderr)
        r = self.run_tool("--domain", "vault.example.com", "--s3-domain", "s3.home.arpa")
        self.assertNotEqual(r.returncode, 0)

    def cloudflare_file(self, mode: int = 0o600, body: str = "dns_cloudflare_api_token = cf-secret-token-123\n") -> Path:
        p = Path(self.tmp.name) / "cloudflare.ini"
        p.write_text(body)
        p.chmod(mode)
        return p

    def test_cloudflare_dns_reads_the_certbot_credentials_file(self) -> None:
        cred = self.cloudflare_file()
        self.ok("--domain", "vault.example.com", "--dns-cloudflare", str(cred))
        cf = self.caddyfile
        self.assertIn("dns cloudflare cf-secret-token-123", cf)
        self.assertIn("acme_ca https://acme-v02.api.letsencrypt.org/directory", cf)
        self.assertEqual(self.mode(self.support / "caddy" / "Caddyfile"), 0o600)

    def test_cloudflare_credentials_must_be_private_and_well_formed(self) -> None:
        r = self.run_tool("--domain", "vault.example.com", "--dns-cloudflare", str(self.cloudflare_file(0o644)))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("0600", r.stderr)
        r = self.run_tool("--domain", "vault.example.com", "--dns-cloudflare",
                          str(self.cloudflare_file(body="dns_cloudflare_email = x\n")))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("dns_cloudflare_api_token", r.stderr)

    def test_cloudflare_needs_a_caddy_with_the_dns_module(self) -> None:
        r = self.run_tool("--domain", "vault.example.com", "--dns-cloudflare", str(self.cloudflare_file()),
                          env={"STUB_CADDY_CLOUDFLARE": "0"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Cloudflare DNS module", r.stderr)
        self.assertFalse((self.support / "caddy" / "Caddyfile").exists())

    def test_dry_run_prints_without_the_token_and_changes_nothing(self) -> None:
        r = self.ok("--domain", "vault.example.com", "--dns-cloudflare", str(self.cloudflare_file()), "--dry-run")
        self.assertIn("dns cloudflare <token from", r.stdout)
        self.assertNotIn("cf-secret-token-123", r.stdout)
        self.assertFalse((self.support / "caddy").exists())

    # --- own certificate ------------------------------------------------------------------------------------------
    def own_cert(self, name: str) -> tuple[Path, Path]:
        d = Path(self.tmp.name)
        key, crt = d / f"{name}.key", d / f"{name}.crt"
        cnf = d / f"{name}.cnf"
        cnf.write_text(f"[req]\ndistinguished_name=dn\nprompt=no\nx509_extensions=ext\n[dn]\nCN={name}\n"
                       f"[ext]\nsubjectAltName=DNS:{name}\n")
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key))
        openssl("req", "-new", "-x509", "-days", "30", "-key", str(key), "-config", str(cnf), "-out", str(crt))
        return crt, key

    def test_own_certificate_is_copied_in_privately(self) -> None:
        crt, key = self.own_cert("vault.home.arpa")
        self.ok("--domain", "vault.home.arpa", "--cert", str(crt), "--key", str(key))
        tls = self.support / "caddy" / "tls"
        self.assertEqual(self.mode(tls / "key.pem"), 0o600)
        self.assertIn(f'tls "{self.root}{SUPPORT}/caddy/tls/cert.pem"', self.caddyfile)
        self.assertNotIn("issuer internal", self.caddyfile)
        self.ok()  # a bare rerun keeps using the files
        self.assertIn("/caddy/tls/cert.pem", self.caddyfile)

    def test_own_certificate_must_match_its_key_and_cover_the_name(self) -> None:
        crt, _ = self.own_cert("vault.home.arpa")
        _, other_key = self.own_cert("other.home.arpa")
        r = self.run_tool("--domain", "vault.home.arpa", "--cert", str(crt), "--key", str(other_key))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("don't belong together", r.stderr)
        crt2, key2 = self.own_cert("elsewhere.home.arpa")
        r = self.run_tool("--domain", "vault.home.arpa", "--cert", str(crt2), "--key", str(key2))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("doesn't cover vault.home.arpa", r.stderr)
        r = self.run_tool("--domain", "vault.home.arpa", "--cert", str(crt))
        self.assertNotEqual(r.returncode, 0)

    # --- refusals and lifecycle ---------------------------------------------------------------------------------------
    def test_bad_input_is_refused(self) -> None:
        for args in (["--domain", "not a host"], ["--domain", "*.home.arpa"], ["--domain", "localhost"],
                     ["--domain", "vault.home.arpa", "--s3-domain", "vault.home.arpa"],
                     ["--domain", "vault.example.com", "--email", "nope"], ["--frobnicate"], []):
            with self.subTest(args=args):
                self.assertNotEqual(self.run_tool(*args).returncode, 0)

    def test_an_invalid_configuration_never_replaces_the_working_one(self) -> None:
        self.ok("--domain", "vault.home.arpa")
        working = self.caddyfile
        r = self.run_tool("--domain", "vault.home.arpa", "--s3-domain", "s3.home.arpa", env={"STUB_CADDY_INVALID": "1"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("nothing was changed", r.stderr)
        self.assertEqual(self.caddyfile, working)
        self.assertFalse((self.support / "caddy" / "Caddyfile.next").exists())

    def test_ports_held_by_something_else_are_refused(self) -> None:
        r = self.run_tool("--domain", "vault.home.arpa", env={"STUB_LSOF": f"443:{os.getpid()}"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("port 443 is in use", r.stderr)

    def test_hosts_entry_is_marked_and_removed_by_teardown(self) -> None:
        self.ok("--domain", "vault.home.arpa", "--hosts-entry")
        hosts = (self.root / "etc" / "hosts").read_text()
        self.assertIn("127.0.0.1\tvault.home.arpa # vaulthalla-caddy", hosts)
        self.ok("--domain", "vault.home.arpa", "--hosts-entry")
        self.assertEqual((self.root / "etc" / "hosts").read_text().count("vaulthalla-caddy"), 1)
        self.ok("teardown", "caddy")
        self.assertEqual((self.root / "etc" / "hosts").read_text(), "127.0.0.1 localhost\n")

    def test_teardown_keeps_certificates_unless_purged(self) -> None:
        self.ok("--domain", "vault.home.arpa")
        self.ok("teardown", "caddy")
        self.assertFalse((self.support / "caddy" / "Caddyfile").exists())
        self.assertTrue((self.support / "caddy" / "ca" / "root.key").exists())
        self.ok("teardown", "caddy", "--purge")
        self.assertFalse((self.support / "caddy").exists())
        self.assertFalse((self.support / "vaulthalla-local-ca.crt").exists())
        self.assertNotEqual(self.run_tool("setup", "caddy", "--purge").returncode, 0)

    @unittest.skipUnless(shutil.which("caddy"), "no caddy on PATH")
    def test_real_caddy_accepts_every_generated_configuration(self) -> None:
        self.caddy = shutil.which("caddy") or ""
        crt, key = self.own_cert("vault.home.arpa")
        for args in (["--domain", "vault.home.arpa", "--s3-domain", "s3.home.arpa", "--listen", "127.0.0.1"],
                     ["--domain", "vault.example.com", "--s3-domain", "none", "--email", "ops@example.com"],
                     ["--domain", "vault.home.arpa", "--cert", str(crt), "--key", str(key)]):
            with self.subTest(args=args):
                self.ok(*args)

    def test_saved_mode_wins_on_a_bare_rerun_but_not_over_a_new_domain(self) -> None:
        cred = self.cloudflare_file()
        self.ok("--domain", "vault.example.com", "--dns-cloudflare", str(cred))
        self.ok()
        self.assertIn("dns cloudflare cf-secret-token-123", self.caddyfile)
        self.ok("--domain", "vault.home.arpa")
        self.assertIn("issuer internal", self.caddyfile)

    def test_s3_domain_none_removes_it(self) -> None:
        self.ok("--domain", "vault.home.arpa", "--s3-domain", "s3.home.arpa")
        self.ok("--s3-domain", "none")
        self.assertNotIn("s3.home.arpa {", self.caddyfile)


class RealInstallPaths(unittest.TestCase):
    """The tests run with --root; a real install runs with ROOT empty. `${ROOT:?}` aborts exactly there (the first
    real `vh teardown caddy --purge` died on it), so no macOS script may use it."""

    def test_no_script_aborts_on_an_empty_root(self) -> None:
        for path in (LAUNCHD / "vaulthalla-caddy.in", LAUNCHD / "vaulthalla-provision.in"):
            with self.subTest(path=path.name):
                self.assertNotIn("${ROOT:?}", path.read_text())


class CaddyDaemon(unittest.TestCase):
    """The LaunchDaemon template, and vaulthalla-provision managing it once a Caddyfile exists."""

    def load(self, values: dict[str, str]) -> dict:
        return plistlib.loads(render((LAUNCHD / "sh.vaulthalla.caddy.plist.in").read_text(), values).encode())

    def test_runs_as_the_service_account_with_its_state_private(self) -> None:
        p = self.load({"CADDY_BIN": PATHS["CADDY_BIN"], "CADDY_DIR": f"{SUPPORT}/caddy", "LOG_DIR": PATHS["LOG_DIR"]})
        self.assertEqual(p["Label"], "sh.vaulthalla.caddy")
        self.assertEqual(p["ProgramArguments"], [PATHS["CADDY_BIN"], "run", "--config", f"{SUPPORT}/caddy/Caddyfile",
                                                 "--adapter", "caddyfile"])
        self.assertEqual((p["UserName"], p["GroupName"]), ("_vaulthalla", "_vaulthalla"))
        self.assertEqual(p["Umask"], 0o077)
        self.assertIs(p["KeepAlive"], True)
        self.assertEqual(p["EnvironmentVariables"]["XDG_DATA_HOME"], f"{SUPPORT}/caddy/data")

    def test_provisioning_manages_the_daemon_only_once_configured(self) -> None:
        text = (LAUNCHD / "vaulthalla-provision.in").read_text()
        self.assertIn('if caddy_configured; then ensure_daemons "$CADDY_LABEL"; fi', text)
        self.assertIn("for label in $LABELS $PG_LABEL $CADDY_LABEL; do", text)
        self.assertIn('"$CADDY_DIR"', text.split("purge() {", 1)[1])
        preinstall = (REPO / "tools" / "macos" / "pkg" / "scripts" / "preinstall").read_text()
        self.assertIn("sh.vaulthalla.caddy", preinstall)


if __name__ == "__main__":
    unittest.main()
