import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from deploy.lifecycle import main


class ConfigProjectionTests(unittest.TestCase):
    def test_parse_projection_reads_nested_sections(self) -> None:
        text = """
websocket_server:
  enabled: false
  host: 127.0.0.1
  port: 36969
http_preview_server:
  enabled: true
  host: ::1
  port: 36970
s3_gateway:
  enabled: true
  host: 0.0.0.0
  port: 39000
database:
  host: db.example.net
  port: 5433
  name: vault
  user: vault_user
  pool_size: 42
"""
        projection = main.parse_config_projection_from_text(text)
        self.assertEqual(projection["websocket_server"]["enabled"], False)
        self.assertEqual(projection["websocket_server"]["host"], "127.0.0.1")
        self.assertEqual(projection["websocket_server"]["port"], 36969)
        self.assertEqual(projection["http_preview_server"]["host"], "::1")
        self.assertEqual(projection["s3_gateway"]["enabled"], True)
        self.assertEqual(projection["s3_gateway"]["host"], "0.0.0.0")
        self.assertEqual(projection["s3_gateway"]["port"], 39000)
        self.assertEqual(projection["database"]["host"], "db.example.net")
        self.assertEqual(projection["database"]["pool_size"], 42)

    def test_parse_projection_uses_s3_defaults_when_section_missing(self) -> None:
        projection = main.parse_config_projection_from_text("database:\n  host: localhost\n")
        self.assertEqual(projection["s3_gateway"], {"enabled": False, "host": "127.0.0.1", "port": 39000})

    def test_render_managed_nginx_config_includes_dedicated_https_s3_host(self) -> None:
        projection = {
            "websocket_server": {"enabled": True, "host": "127.0.0.1", "port": 36969},
            "http_preview_server": {"enabled": True, "host": "::", "port": 36970},
            "s3_gateway": {"enabled": False, "host": "0.0.0.0", "port": 39000},
            "database": {
                "host": "localhost",
                "port": 5432,
                "name": "vaulthalla",
                "user": "vaulthalla",
                "pool_size": 10,
            },
        }
        rendered = main.render_managed_nginx_config(
            projection,
            "vaulthalla.dev",
            "s3.vaulthalla.dev",
            "vaulthalla.dev",
        )

        self.assertIn("    server_name vaulthalla.dev s3.vaulthalla.dev;\n", rendered)
        self.assertIn("    return 308 https://$host$request_uri;\n", rendered)
        self.assertIn("    server_name vaulthalla.dev;\n", rendered)
        self.assertIn("    server_name s3.vaulthalla.dev;\n", rendered)
        self.assertIn("    ssl_certificate /etc/letsencrypt/live/vaulthalla.dev/fullchain.pem;\n", rendered)
        self.assertIn("    ssl_certificate_key /etc/letsencrypt/live/vaulthalla.dev/privkey.pem;\n", rendered)
        self.assertIn("        proxy_pass http://127.0.0.1:39000;\n", rendered)
        self.assertNotIn("proxy_pass http://127.0.0.1:39000/;", rendered)
        self.assertIn("        proxy_request_buffering off;\n", rendered)
        self.assertIn("        proxy_set_header Host $http_host;\n", rendered)
        self.assertIn("        proxy_set_header X-Vaulthalla-S3-Path-Style-Only true;\n", rendered)
        self.assertNotIn("/api/s3", rendered)

    def test_render_managed_nginx_config_uses_configured_s3_loopback_safe_host(self) -> None:
        projection = {
            "websocket_server": {"enabled": False, "host": "127.0.0.1", "port": 36969},
            "http_preview_server": {"enabled": False, "host": "127.0.0.1", "port": 36970},
            "s3_gateway": {"enabled": False, "host": "::", "port": 39123},
            "database": {
                "host": "localhost",
                "port": 5432,
                "name": "vaulthalla",
                "user": "vaulthalla",
                "pool_size": 10,
            },
        }
        rendered = main.render_managed_nginx_config(
            projection,
            "vaulthalla.dev",
            "s3.vaulthalla.dev",
            "vaulthalla.dev",
        )
        self.assertIn("        proxy_pass http://127.0.0.1:39123;\n", rendered)

    def test_render_managed_nginx_config_without_cert_does_not_emit_s3_route(self) -> None:
        projection = {
            "websocket_server": {"enabled": False, "host": "127.0.0.1", "port": 36969},
            "http_preview_server": {"enabled": False, "host": "127.0.0.1", "port": 36970},
            "s3_gateway": {"enabled": False, "host": "0.0.0.0", "port": 39000},
            "database": {
                "host": "localhost",
                "port": 5432,
                "name": "vaulthalla",
                "user": "vaulthalla",
                "pool_size": 10,
            },
        }
        rendered = main.render_managed_nginx_config(projection, "vaulthalla.dev", "s3.vaulthalla.dev")

        self.assertIn("    server_name vaulthalla.dev;\n", rendered)
        self.assertNotIn("server_name s3.vaulthalla.dev", rendered)
        self.assertNotIn("127.0.0.1:39000", rendered)
        self.assertNotIn("/api/s3", rendered)

    def test_cloudflare_credentials_file_requires_private_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            credentials = Path(tmp) / "cloudflare.ini"
            credentials.write_text("dns_cloudflare_api_token = token\n", encoding="utf-8")
            credentials.chmod(0o600)
            self.assertEqual(main.validate_cloudflare_credentials_file(str(credentials)), credentials)

            credentials.chmod(0o644)
            with self.assertRaises(main.LifecycleError):
                main.validate_cloudflare_credentials_file(str(credentials))

    def test_request_dns_cloudflare_certificate_builds_multi_domain_command(self) -> None:
        cp = subprocess.CompletedProcess(["certbot"], 0, stdout="", stderr="")
        state = main.CertificateState(exists=False, domains=set(), renewal_due=False)
        with mock.patch.object(main, "certificate_state", return_value=state):
            with mock.patch.object(main, "run_capture", return_value=cp) as run:
                mode = main.request_dns_cloudflare_certificate(
                    "vaulthalla.dev",
                    "s3.vaulthalla.dev",
                    Path("/etc/vaulthalla/certbot/cloudflare.ini"),
                )

        self.assertEqual(mode, "dns-cloudflare certificate request completed (fresh issuance)")
        command = run.call_args.args[0]
        self.assertEqual(command[0:2], ["certbot", "certonly"])
        self.assertIn("--dns-cloudflare", command)
        self.assertIn("--expand", command)
        self.assertIn("--cert-name", command)
        self.assertIn("vaulthalla.dev", command)
        self.assertIn("s3.vaulthalla.dev", command)

    def test_request_dns_cloudflare_certificate_reuses_complete_current_cert(self) -> None:
        state = main.CertificateState(
            exists=True,
            domains={"vaulthalla.dev", "s3.vaulthalla.dev"},
            renewal_due=False,
        )
        with mock.patch.object(main, "certificate_state", return_value=state):
            with mock.patch.object(main, "run_capture") as run:
                mode = main.request_dns_cloudflare_certificate(
                    "vaulthalla.dev",
                    "s3.vaulthalla.dev",
                    Path("/etc/vaulthalla/certbot/cloudflare.ini"),
                )

        self.assertEqual(
            mode,
            "existing dns-cloudflare certificate is current (certbot renewal timer will manage renewal)",
        )
        run.assert_not_called()

    def test_request_dns_cloudflare_certificate_renews_complete_due_cert(self) -> None:
        cp = subprocess.CompletedProcess(["certbot"], 0, stdout="", stderr="")
        state = main.CertificateState(
            exists=True,
            domains={"vaulthalla.dev", "s3.vaulthalla.dev"},
            renewal_due=True,
        )
        with mock.patch.object(main, "certificate_state", return_value=state):
            with mock.patch.object(main, "run_capture", return_value=cp) as run:
                mode = main.request_dns_cloudflare_certificate(
                    "vaulthalla.dev",
                    "s3.vaulthalla.dev",
                    Path("/etc/vaulthalla/certbot/cloudflare.ini"),
                )

        self.assertEqual(mode, "existing dns-cloudflare certificate renewed by certbot")
        self.assertEqual(
            run.call_args.args[0],
            ["certbot", "renew", "--cert-name", "vaulthalla.dev", "--non-interactive"],
        )

    def test_request_dns_cloudflare_certificate_expands_missing_s3_domain(self) -> None:
        cp = subprocess.CompletedProcess(["certbot"], 0, stdout="", stderr="")
        state = main.CertificateState(exists=True, domains={"vaulthalla.dev"}, renewal_due=False)
        with mock.patch.object(main, "certificate_state", return_value=state):
            with mock.patch.object(main, "run_capture", return_value=cp) as run:
                mode = main.request_dns_cloudflare_certificate(
                    "vaulthalla.dev",
                    "s3.vaulthalla.dev",
                    Path("/etc/vaulthalla/certbot/cloudflare.ini"),
                )

        self.assertEqual(mode, "dns-cloudflare certificate request completed (domain expansion)")
        command = run.call_args.args[0]
        self.assertEqual(command[0:2], ["certbot", "certonly"])
        self.assertIn("--expand", command)
        self.assertIn("s3.vaulthalla.dev", command)

    def test_certificate_name_parsing_reads_sans_and_subject_cn(self) -> None:
        san_text = "X509v3 Subject Alternative Name:\n    DNS:vaulthalla.dev, DNS:s3.vaulthalla.dev"
        self.assertEqual(main.parse_certificate_dns_names(san_text), {"vaulthalla.dev", "s3.vaulthalla.dev"})
        self.assertEqual(main.parse_certificate_common_name("subject=CN = vaulthalla.dev"), "vaulthalla.dev")

    def test_certificate_covers_domains_accepts_wildcard_san(self) -> None:
        self.assertTrue(main.certificate_covers_domains({"*.vaulthalla.dev"}, ["s3.vaulthalla.dev"]))
        self.assertFalse(main.certificate_covers_domains({"*.vaulthalla.dev"}, ["vaulthalla.dev"]))

    def test_update_database_block_rewrites_existing_keys(self) -> None:
        text = """
database:
  host: localhost
  port: 5432
  name: vaulthalla
  user: vaulthalla

sharing:
  enabled: true
"""
        updated = main.update_database_block_text(
            text,
            {
                "host": "db.example.net",
                "port": 5433,
                "name": "vault",
                "user": "vault_user",
                "pool_size": 15,
            },
        )
        self.assertIn("  host: db.example.net\n", updated)
        self.assertIn("  port: 5433\n", updated)
        self.assertIn("  name: vault\n", updated)
        self.assertIn("  user: vault_user\n", updated)
        self.assertIn("  pool_size: 15\n", updated)
        self.assertIn("sharing:\n", updated)


class DispatchTests(unittest.TestCase):
    def test_setup_db_dispatches(self) -> None:
        parser = main.build_parser()
        args = parser.parse_args(["setup", "db"])
        with mock.patch.object(main, "setup_db", return_value=0) as handler:
            rc = main.dispatch(args)
        self.assertEqual(rc, 0)
        handler.assert_called_once_with(args)

    def test_certbot_dns_cloudflare_takes_credentials_path_inline(self) -> None:
        parser = main.build_parser()
        path = "/etc/vaulthalla/certbot/cloudflare.ini"
        inline = parser.parse_args(["setup", "nginx", "--certbot-dns-cloudflare", path, "--domain", "vault.example.com"])
        self.assertEqual(main.dns_cloudflare_credentials_arg(inline), path)
        self.assertEqual(inline.domain, "vault.example.com")

        # Older two-flag spelling, and the credentials flag on its own, still select DNS-01 mode.
        legacy = parser.parse_args(["setup", "nginx", "--certbot-dns-cloudflare", "--cloudflare-credentials", path])
        self.assertEqual(main.dns_cloudflare_credentials_arg(legacy), path)
        alone = parser.parse_args(["setup", "nginx", "--cloudflare-credentials", path])
        self.assertEqual(main.dns_cloudflare_credentials_arg(alone), path)

        bare = parser.parse_args(["setup", "nginx", "--certbot-dns-cloudflare"])
        self.assertEqual(main.dns_cloudflare_credentials_arg(bare), "")
        with self.assertRaises(main.LifecycleError):
            main.validate_cloudflare_credentials_file(main.dns_cloudflare_credentials_arg(bare))

        self.assertIsNone(main.dns_cloudflare_credentials_arg(parser.parse_args(["setup", "nginx", "--certbot"])))

        conflicting = parser.parse_args(
            ["setup", "nginx", "--certbot-dns-cloudflare", path, "--cloudflare-credentials", "/root/other.ini"]
        )
        with self.assertRaises(main.LifecycleError):
            main.dns_cloudflare_credentials_arg(conflicting)

    def test_teardown_nginx_dispatches(self) -> None:
        parser = main.build_parser()
        args = parser.parse_args(["teardown", "nginx"])
        with mock.patch.object(main, "teardown_nginx", return_value=0) as handler:
            rc = main.dispatch(args)
        self.assertEqual(rc, 0)
        handler.assert_called_once_with(args)


class NginxDomainConflictTests(unittest.TestCase):
    def test_extract_server_names_from_nginx_dump_tracks_active_source_file(self) -> None:
        dump = """
# configuration file /etc/nginx/sites-enabled/default:
server {
    server_name default.example.net www.default.example.net;
}
# configuration file /etc/nginx/sites-enabled/vaulthalla:
server {
    server_name demo.vaulthalla.io;
}
"""
        names = main.extract_server_names_from_nginx_dump(dump)
        self.assertIn(("default.example.net", "/etc/nginx/sites-enabled/default"), names)
        self.assertIn(("www.default.example.net", "/etc/nginx/sites-enabled/default"), names)
        self.assertIn(("demo.vaulthalla.io", "/etc/nginx/sites-enabled/vaulthalla"), names)

    def test_active_nginx_domain_conflict_source_ignores_managed_site(self) -> None:
        dump = """
# configuration file /etc/nginx/sites-enabled/vaulthalla:
server {
    server_name demo.vaulthalla.io;
}
# configuration file /etc/nginx/sites-enabled/custom-site:
server {
    server_name demo.vaulthalla.io;
}
"""
        cp = subprocess.CompletedProcess(["nginx", "-T"], 0, stdout=dump, stderr="")
        with mock.patch.object(main, "run_capture", return_value=cp):
            with mock.patch.object(main, "is_managed_nginx_path", side_effect=lambda p: p.endswith("/vaulthalla")):
                conflict = main.active_nginx_domain_conflict_source("demo.vaulthalla.io")
        self.assertEqual(conflict, "/etc/nginx/sites-enabled/custom-site")

    def test_server_name_matches_domain_handles_exact_and_wildcard(self) -> None:
        self.assertTrue(main.server_name_matches_domain("demo.vaulthalla.io", "demo.vaulthalla.io"))
        self.assertTrue(main.server_name_matches_domain("*.vaulthalla.io", "demo.vaulthalla.io"))
        self.assertFalse(main.server_name_matches_domain("*.vaulthalla.io", "vaulthalla.io"))
        self.assertFalse(main.server_name_matches_domain("_", "demo.vaulthalla.io"))



PROJECTION = {
    "websocket_server": {"enabled": True, "host": "127.0.0.1", "port": 36969},
    "http_preview_server": {"enabled": True, "host": "127.0.0.1", "port": 36970},
    "s3_gateway": {"enabled": False, "host": "127.0.0.1", "port": 39000},
    "database": {"host": "localhost", "port": 5432, "name": "vaulthalla", "user": "vaulthalla", "pool_size": 10},
}


class RedactedAccessLogTests(unittest.TestCase):
    """#327: every server block logs through the redacting format; the map and format are declared exactly once."""

    def _check(self, rendered: str) -> None:
        self.assertEqual(rendered.count("map $request_uri $vaulthalla_log_uri {"), 1)
        self.assertEqual(rendered.count("log_format vaulthalla "), 1)
        self.assertEqual(rendered.count("server {"), rendered.count(main.ACCESS_LOG_LINE.strip()))
        self.assertIn('~^/share/                "/share/[redacted]";', rendered)
        self.assertNotIn("$http_referer", rendered)
        self.assertLess(rendered.index("log_format vaulthalla"), rendered.index("server {"))

    def test_every_mode_logs_redacted(self) -> None:
        self._check(main.render_managed_nginx_config(PROJECTION, None, local_tls=True))
        self._check(main.render_managed_nginx_config(PROJECTION, None))
        self._check(main.render_managed_nginx_config(PROJECTION, "vault.example.com", "s3.example.com",
                                                     "vault.example.com"))

    def test_packaged_site_logs_redacted(self) -> None:
        packaged = (Path(__file__).resolve().parents[2] / "nginx" / "vaulthalla.conf").read_text()
        self._check(packaged)


class HttpsByDefaultTests(unittest.TestCase):
    """#324: the managed site is HTTPS by default (local certificate), HTTP redirects, security headers everywhere,
    HSTS only with a publicly trusted certificate."""

    def test_local_tls_renders_redirect_ssl_and_headers_without_hsts(self) -> None:
        rendered = main.render_managed_nginx_config(PROJECTION, None, local_tls=True)
        self.assertIn("return 308 https://$host$request_uri;", rendered)
        self.assertIn("listen 443 ssl;", rendered)
        self.assertIn(f"ssl_certificate {main.LOCAL_TLS_CERT};", rendered)
        self.assertIn(f"ssl_certificate_key {main.LOCAL_TLS_KEY};", rendered)
        self.assertIn('add_header X-Frame-Options "DENY" always;', rendered)
        self.assertIn('add_header Referrer-Policy "no-referrer" always;', rendered)
        self.assertIn("frame-ancestors 'none'", rendered)
        self.assertNotIn("Strict-Transport-Security", rendered)
        # The console is only served on 443; port 80 only redirects.
        port80 = rendered.split("listen 443 ssl;")[0]
        self.assertNotIn("location /", port80)

    def test_public_certificate_adds_hsts(self) -> None:
        rendered = main.render_managed_nginx_config(PROJECTION, "vault.example.com", None, "vault.example.com")
        self.assertIn('add_header Strict-Transport-Security "max-age=31536000" always;', rendered)
        self.assertIn("ssl_certificate /etc/letsencrypt/live/vault.example.com/fullchain.pem;", rendered)

    def test_plain_http_still_sends_headers(self) -> None:
        rendered = main.render_managed_nginx_config(PROJECTION, None)
        self.assertNotIn("ssl_certificate", rendered)
        self.assertIn('add_header X-Content-Type-Options "nosniff" always;', rendered)

    def test_plain_http_and_certificate_modes_are_exclusive(self) -> None:
        args = main.build_parser().parse_args(["setup", "nginx", "--plain-http", "--certbot", "--domain", "a.example.com"])
        with self.assertRaisesRegex(main.LifecycleError, "--plain-http"):
            main.setup_nginx(args)

    def test_local_tls_subcommand_parses(self) -> None:
        args = main.build_parser().parse_args(["setup", "local-tls", "--force", "--quiet"])
        self.assertTrue(args.force and args.quiet)


@unittest.skipUnless(main.command_exists("openssl"), "openssl not available")
class LocalCertificateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="vh-local-tls-"))
        patches = [
            mock.patch.object(main, "LOCAL_TLS_DIR", self.tmp / "tls"),
            mock.patch.object(main, "LOCAL_TLS_CERT", self.tmp / "tls" / "local.crt"),
            mock.patch.object(main, "LOCAL_TLS_KEY", self.tmp / "tls" / "local.key"),
            mock.patch.object(main, "local_tls_names", lambda: (["vault-host", "vault-host.local", "localhost"],
                                                                 ["127.0.0.1", "::1", "192.168.1.20"])),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.tmp)], check=False))

    def test_creates_a_private_key_and_a_certificate_for_the_host(self) -> None:
        self.assertEqual(main.ensure_local_certificate(), "created")
        self.assertEqual(main.LOCAL_TLS_KEY.stat().st_mode & 0o777, 0o600)
        self.assertEqual(main.LOCAL_TLS_DIR.stat().st_mode & 0o777, 0o700)
        names = main._certificate_names(main.LOCAL_TLS_CERT)
        self.assertIsNotNone(names)
        dns, ips = names
        self.assertTrue({"vault-host", "vault-host.local", "localhost"} <= dns)
        self.assertTrue({"127.0.0.1", "::1", "192.168.1.20"} <= ips)
        text = subprocess.run(["openssl", "x509", "-in", str(main.LOCAL_TLS_CERT), "-noout", "-text"],
                              capture_output=True, text=True, check=True).stdout
        self.assertIn("CA:FALSE", text)
        self.assertIn("TLS Web Server Authentication", text)
        self.assertIsNotNone(main.local_certificate_fingerprint())

    def test_current_certificate_is_kept_and_changes_regenerate_it(self) -> None:
        main.ensure_local_certificate()
        first = main.LOCAL_TLS_CERT.read_bytes()
        self.assertEqual(main.ensure_local_certificate(), "current")
        self.assertEqual(main.LOCAL_TLS_CERT.read_bytes(), first)
        # The host got a new address: the certificate no longer covers it.
        with mock.patch.object(main, "local_tls_names", lambda: (["vault-host"], ["127.0.0.1", "10.0.0.9"])):
            self.assertEqual(main.ensure_local_certificate(), "created")
        self.assertNotEqual(main.LOCAL_TLS_CERT.read_bytes(), first)
        self.assertEqual(main.ensure_local_certificate(force=True), "created")

    def test_expiring_certificate_is_renewed(self) -> None:
        with mock.patch.object(main, "LOCAL_TLS_DAYS", 10):
            main.ensure_local_certificate()
        self.assertEqual(main.ensure_local_certificate(), "created")  # within the 30-day renewal window


if __name__ == "__main__":
    unittest.main()


class InitialPasswordSafeguardTests(unittest.TestCase):
    """`vh setup nginx` warns before exposing the web console while the generated super-admin password is still in
    use and its plaintext copy is on disk. A safeguard, not a gate: only an explicit cancel stops it."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.file = Path(self.tmp.name) / "super_admin_initial_password"
        self.file.write_text("0123456789abcdef0123456789abcdef\n", encoding="utf-8")
        patcher = mock.patch.object(main, "INITIAL_PASSWORD_FILE", self.file)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def generated(self, value):
        return mock.patch.object(main, "generated_super_admin_password_in_use", return_value=value)

    def test_nothing_to_warn_about_without_the_file(self) -> None:
        self.file.unlink()
        with self.generated(True), mock.patch("builtins.input") as prompt:
            self.assertTrue(main.confirm_initial_password_before_exposure(interactive=True))
        prompt.assert_not_called()

    def test_a_stale_copy_of_a_changed_password_is_not_flagged(self) -> None:
        with self.generated(False), mock.patch("builtins.input") as prompt:
            self.assertFalse(main.initial_password_exposed())
            self.assertTrue(main.confirm_initial_password_before_exposure(interactive=True))
        prompt.assert_not_called()

    def test_without_a_readable_db_the_file_alone_counts(self) -> None:
        with self.generated(None):
            self.assertTrue(main.initial_password_exposed())

    def test_non_interactive_runs_warn_and_continue(self) -> None:
        with self.generated(True), mock.patch("builtins.input") as prompt, \
                mock.patch("builtins.print") as out, mock.patch.object(main, "eprint") as err:
            self.assertTrue(main.confirm_initial_password_before_exposure(interactive=False))
        prompt.assert_not_called()
        self.assertIn(str(self.file), " ".join(str(c) for c in out.call_args_list))
        err.assert_called()
        self.assertTrue(self.file.exists())

    def test_keeping_the_password_deletes_only_the_file(self) -> None:
        with self.generated(True), mock.patch("builtins.input", return_value="2"), mock.patch("builtins.print"):
            self.assertTrue(main.confirm_initial_password_before_exposure(interactive=True))
        self.assertFalse(self.file.exists())

    def test_cancel_stops_and_keeps_everything(self) -> None:
        with self.generated(True), mock.patch("builtins.input", return_value="4"), mock.patch("builtins.print"):
            self.assertFalse(main.confirm_initial_password_before_exposure(interactive=True))
        self.assertTrue(self.file.exists())

    def test_continuing_without_changes_is_allowed(self) -> None:
        with self.generated(True), mock.patch("builtins.input", return_value="3"), mock.patch("builtins.print"):
            self.assertTrue(main.confirm_initial_password_before_exposure(interactive=True))
        self.assertTrue(self.file.exists())

    def test_rotation_runs_the_cli_as_the_operator(self) -> None:
        def rotate():
            self.file.unlink()
            return True

        with self.generated(True), mock.patch("builtins.input", return_value="1"), mock.patch("builtins.print"), \
                mock.patch.object(main, "rotate_super_admin_password_as_operator", side_effect=rotate) as rotated:
            self.assertTrue(main.confirm_initial_password_before_exposure(interactive=True))
        rotated.assert_called_once()

    def test_a_failed_rotation_asks_again(self) -> None:
        with self.generated(True), mock.patch("builtins.input", side_effect=["1", "4"]), mock.patch("builtins.print"), \
                mock.patch.object(main, "rotate_super_admin_password_as_operator", return_value=False):
            self.assertFalse(main.confirm_initial_password_before_exposure(interactive=True))
        self.assertTrue(self.file.exists())

    def test_rotation_never_runs_as_root(self) -> None:
        with mock.patch.dict(main.os.environ, {"SUDO_USER": "root"}), mock.patch.object(main, "eprint"), \
                mock.patch.object(main.subprocess, "run") as run:
            self.assertFalse(main.rotate_super_admin_password_as_operator())
        run.assert_not_called()

    def test_setup_nginx_stops_before_touching_anything_when_cancelled(self) -> None:
        args = main.build_parser().parse_args(["setup", "nginx"])
        with mock.patch.object(main, "command_exists", return_value=True), \
                mock.patch.object(main.Path, "exists", return_value=True), \
                mock.patch.object(main, "has_non_nginx_listeners_on_web_ports", return_value=False), \
                mock.patch.object(main, "extract_managed_nginx_domain", return_value=None), \
                mock.patch.object(main, "extract_managed_nginx_s3_domain", return_value=None), \
                mock.patch.object(main, "confirm_initial_password_before_exposure", return_value=False), \
                mock.patch.object(main, "load_config_projection") as projection, mock.patch("builtins.print"):
            self.assertEqual(main.setup_nginx(args), 1)
        projection.assert_not_called()
