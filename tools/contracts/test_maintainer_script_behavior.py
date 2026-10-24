"""Behavioral tests: execute the real maintainer-script functions under dash with stub tools.

The function section of each script (everything before the final `case "$1" in`) is
sourced into a harness; systemctl/psql/runuser/pg_isready/id/chown/sleep are replaced by
stubs on PATH that log their argv/stdin. Nothing touches the host's PostgreSQL, systemd,
nginx or /mnt/vaulthalla.
Run by module: python3 -m unittest tools.contracts.test_maintainer_script_behavior
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest

SHELL = shutil.which("dash") or "/bin/sh"
# The few cases that depend on the host being what the scripts run on (Debian: /proc/self/mountinfo, GNU stat), not
# just on the stubs. The rest of the module runs anywhere, macOS included.
LINUX_HOST = unittest.skipUnless(sys.platform.startswith("linux"), "needs a Linux host (/proc, GNU coreutils)")

FAKE_PSQL = r"""#!/bin/sh
# Fake psql: logs argv, answers the queries the maintainer scripts make, logs stdin SQL.
printf '%s\n' "$*" >> "$VH_TEST_LOG/psql.argv"
sql=""
while [ $# -gt 0 ]; do
    case "$1" in
        -c) sql="$2"; shift 2 ;;
        *) shift ;;
    esac
done
if [ -z "$sql" ]; then
    cat >> "$VH_TEST_LOG/psql.stdin"
    exit "${FAKE_PSQL_STDIN_RC:-0}"
fi
case "$sql" in
    *pg_roles*) [ "${FAKE_ROLE_EXISTS:-0}" = "1" ] && echo 1 ;;
    *pg_database*) [ "${FAKE_DB_EXISTS:-0}" = "1" ] && echo 1 ;;
    *to_regclass*) echo "${FAKE_USERS_TABLE:-f}" ;;
    *"FROM public.users"*) echo "${FAKE_USERS_ROWS:-f}" ;;
    *server_version_num*) echo 160004 ;;
    *) printf '%s\n' "$sql" >> "$VH_TEST_LOG/psql.exec" ;;
esac
exit 0
"""

FAKE_RUNUSER = """#!/bin/sh
# runuser -u postgres -- cmd...
shift 3
exec "$@"
"""

FAKE_SYSTEMCTL = r"""#!/bin/sh
# Fake systemctl: ActiveState walks a scripted sequence (one entry per poll).
printf '%s\n' "$*" >> "$VH_TEST_LOG/systemctl.argv"
for last_arg; do :; done
if [ -n "${last_arg:-}" ] && [ -f "$VH_TEST_LOG/unit-state.$last_arg" ]; then
    case "$*" in
        *"-p ActiveState"*) cat "$VH_TEST_LOG/unit-state.$last_arg"; exit 0 ;;
        *"-p LoadState"*) echo not-found; exit 0 ;;
    esac
fi
case "$*" in
    *"-p ActiveState"*)
        n=$(cat "$VH_TEST_LOG/state.n" 2>/dev/null || echo 0)
        n=$((n + 1)); echo "$n" > "$VH_TEST_LOG/state.n"
        state=$(printf '%s\n' $FAKE_STATES | sed -n "${n}p")
        [ -n "$state" ] || state=$(printf '%s\n' $FAKE_STATES | tail -n 1)
        echo "$state"; echo "$state" > "$VH_TEST_LOG/state.last" ;;
    *"-p MainPID"*)
        if [ "$(cat "$VH_TEST_LOG/state.last" 2>/dev/null)" = "inactive" ]; then echo 0; else echo 4242; fi ;;
esac
exit 0
"""


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class _Harness:
    def __init__(self, script: str) -> None:
        self.repo = Path(__file__).resolve().parents[2]
        self.tmp = Path(tempfile.mkdtemp(prefix="vh-maint-"))
        self.bin = self.tmp / "bin"
        self.log = self.tmp / "log"
        self.state = self.tmp / "state"
        self.run_dir = self.tmp / "run"
        for d in (self.bin, self.log, self.state, self.run_dir):
            d.mkdir()
        text = (self.repo / "debian" / script).read_text(encoding="utf-8")
        functions = text[: text.rindex('\ncase "$1" in')]
        (self.tmp / "functions.sh").write_text(functions + "\n", encoding="utf-8")
        _write_exec(self.bin / "psql", FAKE_PSQL)
        _write_exec(self.bin / "pg_isready", "#!/bin/sh\nexit 0\n")
        _write_exec(self.bin / "runuser", FAKE_RUNUSER)
        _write_exec(self.bin / "systemctl", FAKE_SYSTEMCTL)
        _write_exec(self.bin / "id", "#!/bin/sh\nexit 0\n")
        _write_exec(self.bin / "chown", "#!/bin/sh\nexit 0\n")
        _write_exec(self.bin / "sleep", "#!/bin/sh\nexit 0\n")
        _write_exec(self.bin / "mountpoint", f"#!/bin/sh\necho called >> {self.log}/mountpoint.called\nexit 0\n")
        self.config = self.tmp / "config.yaml"
        self.config.write_text("database:\n  host: localhost\n  port: 5432\n", encoding="utf-8")

    def cleanup(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run(self, body: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        preamble = textwrap.dedent(
            f"""
            . "{self.tmp}/functions.sh"
            STATE_DIR="{self.state}"
            RUNTIME_DIR="{self.run_dir}"
            PENDING_DB_PASS_FILE="{self.run_dir}/db_password"
            SEALED_DB_SECRET_DIR="{self.state}/.sealed_psql.blob"
            DB_BOOTSTRAP_OPTOUT_MARKER="{self.state}/db_bootstrap_disabled"
            CONFIG_FILE="{self.config}"
            create_dir() {{ mkdir -p "$1"; }}
            """
        )
        full_env = {
            "PATH": f"{self.bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "VH_TEST_LOG": str(self.log),
            "DEBIAN_FRONTEND": "noninteractive",
            "HOME": str(self.tmp),
        }
        full_env.update(env or {})
        return subprocess.run(
            [SHELL, "-c", preamble + textwrap.dedent(body)],
            capture_output=True,
            text=True,
            env=full_env,
            stdin=subprocess.DEVNULL,
            timeout=60,
        )

    def read_log(self, name: str) -> str:
        path = self.log / name
        return path.read_text(encoding="utf-8") if path.exists() else ""


class PostinstDbBootstrapBehaviorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = _Harness("postinst")
        self.addCleanup(self.h.cleanup)

    def _bootstrap(self, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return self.h.run('bootstrap_db_if_safe\necho "STATUS=$DB_BOOTSTRAP_STATUS"\n', env)

    def _seed(self) -> Path:
        return self.h.run_dir / "db_password"

    def test_fresh_bootstrap_seeds_before_creating_role_and_keeps_password_out_of_argv(self) -> None:
        result = self._bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("STATUS=done (created local DB role/database", result.stdout)
        password = self._seed().read_text(encoding="utf-8").strip()
        self.assertRegex(password, r"^[0-9a-f]{64}$")
        self.assertEqual(stat.S_IMODE(self._seed().stat().st_mode), 0o600)
        self.assertIn(f"CREATE ROLE vaulthalla LOGIN PASSWORD '{password}';", self.h.read_log("psql.stdin"))
        self.assertNotIn(password, self.h.read_log("psql.argv"))
        self.assertIn("CREATE DATABASE vaulthalla OWNER vaulthalla", self.h.read_log("psql.exec"))

    def test_orphan_with_data_aborts_noninteractively_with_resolution_commands(self) -> None:
        env = {"FAKE_ROLE_EXISTS": "1", "FAKE_DB_EXISTS": "1", "FAKE_USERS_TABLE": "t", "FAKE_USERS_ROWS": "t"}
        result = self._bootstrap(env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("sudo env VH_EXISTING_DB_ACTION=adopt dpkg --configure -a", result.stderr)
        self.assertIn("sudo env VH_EXISTING_DB_ACTION=overwrite dpkg --configure -a", result.stderr)
        self.assertEqual(self.h.read_log("psql.stdin"), "")
        self.assertFalse(self._seed().exists())

    def test_orphan_adopt_rotates_password_via_stdin_and_warns_about_keys(self) -> None:
        env = {
            "FAKE_ROLE_EXISTS": "1", "FAKE_DB_EXISTS": "1", "FAKE_USERS_TABLE": "t", "FAKE_USERS_ROWS": "t",
            "VH_EXISTING_DB_ACTION": "adopt",
        }
        result = self._bootstrap(env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("STATUS=done (adopted existing DB", result.stdout)
        self.assertIn(".sealed_*.blob", result.stderr)
        password = self._seed().read_text(encoding="utf-8").strip()
        self.assertIn(f"ALTER ROLE vaulthalla WITH LOGIN PASSWORD '{password}';", self.h.read_log("psql.stdin"))
        self.assertNotIn(password, self.h.read_log("psql.argv"))
        self.assertNotIn("DROP DATABASE", self.h.read_log("psql.exec"))

    def test_orphan_overwrite_drops_with_force_then_bootstraps(self) -> None:
        env = {
            "FAKE_ROLE_EXISTS": "1", "FAKE_DB_EXISTS": "1", "FAKE_USERS_TABLE": "t", "FAKE_USERS_ROWS": "t",
            "VH_EXISTING_DB_ACTION": "overwrite",
        }
        result = self._bootstrap(env)
        self.assertEqual(result.returncode, 0, result.stderr)
        executed = self.h.read_log("psql.exec")
        self.assertIn("DROP DATABASE IF EXISTS vaulthalla WITH (FORCE)", executed)
        self.assertIn("DROP ROLE IF EXISTS vaulthalla", executed)
        self.assertLess(executed.index("DROP DATABASE"), executed.index("CREATE DATABASE"))
        self.assertIn("CREATE ROLE vaulthalla LOGIN PASSWORD", self.h.read_log("psql.stdin"))
        self.assertIn("STATUS=done (existing DB overwritten", result.stdout)

    def test_invalid_action_aborts(self) -> None:
        env = {
            "FAKE_ROLE_EXISTS": "1", "FAKE_DB_EXISTS": "1", "FAKE_USERS_TABLE": "t", "FAKE_USERS_ROWS": "t",
            "VH_EXISTING_DB_ACTION": "yolo",
        }
        result = self._bootstrap(env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("invalid VH_EXISTING_DB_ACTION", result.stderr)

    def test_empty_orphan_from_interrupted_install_is_adopted_automatically(self) -> None:
        result = self._bootstrap({"FAKE_ROLE_EXISTS": "1", "FAKE_DB_EXISTS": "1", "FAKE_USERS_TABLE": "f"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("STATUS=done (adopted empty DB", result.stdout)
        self.assertIn("ALTER ROLE vaulthalla WITH LOGIN PASSWORD", self.h.read_log("psql.stdin"))

    def test_pending_seed_is_resumed_not_regenerated(self) -> None:
        self._seed().write_text("feedface\n", encoding="utf-8")
        result = self._bootstrap({"FAKE_ROLE_EXISTS": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("STATUS=done (resumed from pending runtime password handoff", result.stdout)
        self.assertIn("ALTER ROLE vaulthalla WITH LOGIN PASSWORD 'feedface';", self.h.read_log("psql.stdin"))
        self.assertEqual(self._seed().read_text(encoding="utf-8").strip(), "feedface")

    def test_sealed_secret_means_no_db_changes(self) -> None:
        sealed = self.h.state / ".sealed_psql.blob"
        sealed.mkdir()
        (sealed / "psql.priv").write_bytes(b"x")
        result = self._bootstrap({"FAKE_ROLE_EXISTS": "1", "FAKE_DB_EXISTS": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("STATUS=reused (sealed DB credential present", result.stdout)
        self.assertEqual(self.h.read_log("psql.argv"), "")

    def test_remote_database_host_is_never_bootstrapped(self) -> None:
        self.h.config.write_text("database:\n  host: db.example.net   # remote\n", encoding="utf-8")
        result = self._bootstrap()
        self.assertIn("STATUS=skipped (config.yaml database.host is remote: db.example.net)", result.stdout)
        self.assertEqual(self.h.read_log("psql.argv"), "")
        self.assertFalse(self._seed().exists())

    def test_skip_db_bootstrap_opt_out_persists(self) -> None:
        first = self._bootstrap({"VH_SKIP_DB_BOOTSTRAP": "1"})
        self.assertIn("persisted at", first.stdout)
        second = self._bootstrap()
        self.assertIn("STATUS=skipped (persisted opt-out", second.stdout)
        self.assertEqual(self.h.read_log("psql.argv"), "")

    def test_role_failure_rolls_back_seed(self) -> None:
        result = self._bootstrap({"FAKE_PSQL_STDIN_RC": "1"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("STATUS=failed (could not create PostgreSQL role", result.stdout)
        self.assertFalse(self._seed().exists())


class MountDetectionBehaviorTests(unittest.TestCase):
    @LINUX_HOST  # reads the real /proc/self/mountinfo
    def test_is_mountpoint_uses_mountinfo_and_never_calls_mountpoint(self) -> None:
        for script in ("postinst", "postrm"):
            h = _Harness(script)
            self.addCleanup(h.cleanup)
            result = h.run(
                f"""
                is_mountpoint /proc && echo proc=yes
                is_mountpoint "{h.tmp}" || echo tmp=no
                is_mountpoint /mnt/vaulthalla-definitely-not-mounted || echo absent=no
                """
            )
            self.assertIn("proc=yes", result.stdout, script)
            self.assertIn("tmp=no", result.stdout, script)
            self.assertIn("absent=no", result.stdout, script)
            self.assertEqual(h.read_log("mountpoint.called"), "", script)


class PostrmPurgeTreeBehaviorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = _Harness("postrm")
        self.addCleanup(self.h.cleanup)
        self.target = self.h.tmp / "data"
        (self.target / "vaults" / "a").mkdir(parents=True)
        (self.target / "vaults" / "a" / "blob").write_bytes(b"x")
        (self.target / ".sealed_psql.blob").mkdir()

    def test_plain_directory_is_removed(self) -> None:
        result = self.h.run(f'purge_tree "{self.target}"\necho rc=$?\n')
        self.assertIn("rc=0", result.stdout)
        self.assertFalse(self.target.exists())

    def test_mount_point_keeps_directory_and_removes_contents(self) -> None:
        result = self.h.run(
            f"""
            is_mountpoint() {{ [ "$1" = "{self.target}" ]; }}
            purge_tree "{self.target}"
            echo rc=$?
            """
        )
        self.assertIn("rc=0", result.stdout)
        self.assertIn("is a mount point: removed its contents", result.stdout)
        self.assertTrue(self.target.is_dir())
        self.assertEqual(list(self.target.iterdir()), [])


class PostrmConfigPurgeBehaviorTests(unittest.TestCase):
    def test_purge_removes_package_config_but_keeps_operator_files(self) -> None:
        h = _Harness("postrm")
        self.addCleanup(h.cleanup)
        etc = h.tmp / "etc-vaulthalla"
        (etc / "testing").mkdir(parents=True)
        (etc / "certbot").mkdir()
        (etc / "testing" / "providers.env").write_text("AWS_ACCESS_KEY_ID=placeholder\n", encoding="utf-8")
        (etc / "certbot" / "cloudflare.ini").write_text("dns_cloudflare_api_token=placeholder\n", encoding="utf-8")
        for name in ("config.yaml", "config_template.yaml.in", "config.yaml.dpkg-old"):
            (etc / name).write_text("x\n", encoding="utf-8")
        result = h.run(f'CONFIG_DIR="{etc}"\nCERTBOT_CREDENTIALS_DIR="{etc}/certbot"\npurge_config_dir\necho rc=$?\n')
        self.assertIn("rc=0", result.stdout)
        self.assertFalse((etc / "config.yaml").exists())
        self.assertFalse((etc / "config_template.yaml.in").exists())
        self.assertFalse((etc / "config.yaml.dpkg-old").exists())
        self.assertTrue((etc / "testing" / "providers.env").is_file())
        self.assertTrue((etc / "certbot" / "cloudflare.ini").is_file())
        self.assertIn("Preserved operator-managed", result.stdout)

    def test_purge_removes_empty_config_dir(self) -> None:
        h = _Harness("postrm")
        self.addCleanup(h.cleanup)
        etc = h.tmp / "etc-vaulthalla"
        etc.mkdir()
        (etc / "config.yaml").write_text("x\n", encoding="utf-8")
        h.run(f'CONFIG_DIR="{etc}"\nCERTBOT_CREDENTIALS_DIR="{etc}/certbot"\npurge_config_dir\n')
        self.assertFalse(etc.exists())


FAKE_DEB_SYSTEMD_INVOKE = r"""#!/bin/sh
printf '%s\n' "$*" >> "$VH_TEST_LOG/deb-systemd-invoke.argv"
if [ -n "${FAKE_INVOKE_RC:-}" ]; then
    exit "$FAKE_INVOKE_RC"
fi
shift
for unit; do echo inactive > "$VH_TEST_LOG/unit-state.$unit"; done
exit 0
"""

FAKE_DEB_SYSTEMD_HELPER = r"""#!/bin/sh
printf '%s\n' "$*" >> "$VH_TEST_LOG/deb-systemd-helper.argv"
exit 0
"""


class PostinstLegacyCliUnitBehaviorTests(unittest.TestCase):
    """Upgrades from <= 1.6.6 must stop and purge vaulthalla-cli.{socket,service} (#110)."""

    def setUp(self) -> None:
        self.h = _Harness("postinst")
        self.addCleanup(self.h.cleanup)
        _write_exec(self.h.bin / "deb-systemd-invoke", FAKE_DEB_SYSTEMD_INVOKE)
        _write_exec(self.h.bin / "deb-systemd-helper", FAKE_DEB_SYSTEMD_HELPER)
        self.etc = self.h.tmp / "etc-systemd"
        (self.etc / "sockets.target.wants").mkdir(parents=True)
        (self.etc / "multi-user.target.wants").mkdir()
        self.socket_link = self.etc / "sockets.target.wants" / "vaulthalla-cli.socket"
        self.service_link = self.etc / "multi-user.target.wants" / "vaulthalla-cli.service"
        self.unit_dir = self.h.tmp / "lib-systemd"
        self.unit_dir.mkdir()
        self.helper_state = self.h.tmp / "var-lib-systemd"
        (self.helper_state / "deb-systemd-helper-enabled").mkdir(parents=True)

    def _set_state(self, unit: str, state: str) -> None:
        (self.h.log / f"unit-state.{unit}").write_text(state + "\n", encoding="utf-8")

    def _retire(self, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return self.h.run(
            f"""
            systemd_running() {{ return 0; }}
            LEGACY_CLI_WANTS_LINKS="{self.socket_link} {self.service_link}"
            LEGACY_CLI_UNIT_DIRS="{self.unit_dir}"
            DEB_SYSTEMD_HELPER_STATE_DIR="{self.helper_state}"
            SERVICE_TRANSITION_TIMEOUT_SECONDS=5
            SERVICE_KILL_SETTLE_SECONDS=1
            retire_legacy_cli_units
            echo "rc=$? retired=$LEGACY_CLI_UNITS_RETIRED"
            """,
            env,
        )

    def test_upgrade_stops_purges_and_reloads(self) -> None:
        self._set_state("vaulthalla-cli.socket", "active")
        self._set_state("vaulthalla-cli.service", "activating")
        self.socket_link.symlink_to("/lib/systemd/system/vaulthalla-cli.socket")
        self.service_link.symlink_to("/lib/systemd/system/vaulthalla-cli.service")
        result = self._retire()
        self.assertIn("rc=0 retired=1", result.stdout, result.stderr)
        invoked = self.h.read_log("deb-systemd-invoke.argv").splitlines()
        self.assertEqual(invoked, ["stop vaulthalla-cli.socket", "stop vaulthalla-cli.service"])
        helper = self.h.read_log("deb-systemd-helper.argv")
        self.assertIn("purge vaulthalla-cli.socket vaulthalla-cli.service", helper)
        self.assertIn("unmask vaulthalla-cli.socket vaulthalla-cli.service", helper)
        self.assertFalse(self.socket_link.is_symlink())
        self.assertFalse(self.service_link.is_symlink())
        systemctl = self.h.read_log("systemctl.argv")
        self.assertIn("daemon-reload", systemctl)
        self.assertNotIn("enable", systemctl)
        self.assertNotIn("start vaulthalla-cli", systemctl)

    def test_second_run_is_a_no_op(self) -> None:
        self._set_state("vaulthalla-cli.socket", "active")
        self.socket_link.symlink_to("/lib/systemd/system/vaulthalla-cli.socket")
        self._retire()
        for name in ("deb-systemd-invoke.argv", "deb-systemd-helper.argv", "systemctl.argv"):
            (self.h.log / name).unlink(missing_ok=True)
        result = self._retire()
        self.assertIn("rc=0 retired=0", result.stdout)
        self.assertEqual(self.h.read_log("deb-systemd-invoke.argv"), "")
        self.assertEqual(self.h.read_log("deb-systemd-helper.argv"), "")
        self.assertNotIn("daemon-reload", self.h.read_log("systemctl.argv"))

    def test_fresh_host_without_legacy_units_is_untouched(self) -> None:
        self._set_state("vaulthalla-cli.socket", "inactive")
        self._set_state("vaulthalla-cli.service", "inactive")
        result = self._retire()
        self.assertIn("rc=0 retired=0", result.stdout)
        self.assertEqual(self.h.read_log("deb-systemd-helper.argv"), "")
        self.assertEqual(self.h.read_log("deb-systemd-invoke.argv"), "")

    def test_inactive_units_with_helper_state_are_purged_without_stopping(self) -> None:
        self._set_state("vaulthalla-cli.socket", "inactive")
        self._set_state("vaulthalla-cli.service", "inactive")
        (self.helper_state / "deb-systemd-helper-enabled" / "vaulthalla-cli.socket.dsh-also").write_text("", encoding="utf-8")
        result = self._retire()
        self.assertIn("rc=0 retired=1", result.stdout)
        self.assertEqual(self.h.read_log("deb-systemd-invoke.argv"), "")
        self.assertIn("purge vaulthalla-cli.socket vaulthalla-cli.service", self.h.read_log("deb-systemd-helper.argv"))

    def test_hung_stop_escalates_to_cgroup_kill_and_never_fails(self) -> None:
        self._set_state("vaulthalla-cli.socket", "inactive")
        self._set_state("vaulthalla-cli.service", "deactivating")
        result = self._retire({"FAKE_INVOKE_RC": "124"})
        self.assertIn("rc=0 retired=1", result.stdout)
        self.assertIn("kill -s KILL vaulthalla-cli.service", self.h.read_log("systemctl.argv"))
        self.assertIn("sending SIGKILL", result.stderr + result.stdout)

    def test_cli_socket_verification_reports_bound_and_missing(self) -> None:
        import socket as socket_mod

        sock_path = self.h.run_dir / "cli.sock"
        self._set_state("vaulthalla.service", "active")
        body = f"""
            systemd_running() {{ return 0; }}
            CLI_SOCKET_PATH="{sock_path}"
            CLI_SOCKET_WAIT_SECONDS=2
            verify_cli_socket_owned_by_daemon
            echo "status=$CLI_SOCKET_STATUS"
            """
        missing = self.h.run(body)
        self.assertIn("missing 2s after vaulthalla.service", missing.stdout)
        server = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM)
        self.addCleanup(server.close)
        server.bind(str(sock_path))
        bound = self.h.run(body)
        self.assertIn(f"status={sock_path} bound by vaulthalla.service", bound.stdout)


class PostrmLegacyCliUnitBehaviorTests(unittest.TestCase):
    def test_purge_removes_legacy_enablement_leftovers(self) -> None:
        h = _Harness("postrm")
        self.addCleanup(h.cleanup)
        _write_exec(h.bin / "deb-systemd-helper", FAKE_DEB_SYSTEMD_HELPER)
        link = h.tmp / "vaulthalla-cli.socket"
        link.symlink_to("/lib/systemd/system/vaulthalla-cli.socket")
        result = h.run(f'LEGACY_CLI_WANTS_LINKS="{link}"\npurge_legacy_cli_units\necho rc=$?\n')
        self.assertIn("rc=0", result.stdout)
        self.assertFalse(link.is_symlink())
        self.assertIn("purge vaulthalla-cli.socket vaulthalla-cli.service", h.read_log("deb-systemd-helper.argv"))


class PrermStopBehaviorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = _Harness("prerm")
        self.addCleanup(self.h.cleanup)

    def _stop(self, states: str) -> subprocess.CompletedProcess[str]:
        return self.h.run(
            """
            systemd_running() { return 0; }
            stop_service_bounded vaulthalla.service
            echo rc=$?
            """,
            {"FAKE_STATES": states},
        )

    def test_waits_through_deactivating_without_killing(self) -> None:
        result = self._stop("active deactivating deactivating deactivating inactive")
        self.assertIn("rc=0", result.stdout)
        calls = self.h.read_log("systemctl.argv")
        self.assertIn("stop --no-block vaulthalla.service", calls)
        self.assertNotIn("kill", calls)
        self.assertGreaterEqual(calls.count("-p ActiveState"), 5)

    def test_escalates_to_cgroup_sigkill_when_stop_never_finishes(self) -> None:
        result = self._stop("deactivating")
        self.assertIn("rc=0", result.stdout)
        calls = self.h.read_log("systemctl.argv")
        self.assertIn("kill -s KILL vaulthalla.service", calls)
        self.assertIn("reset-failed vaulthalla.service", calls)


if __name__ == "__main__":
    unittest.main()


class PostinstNginxVerifyBehaviorTests(unittest.TestCase):
    """nginx reloads asynchronously; the welcome page right after a reload is not conclusive (vh-storage)."""

    def setUp(self) -> None:
        self.h = _Harness("postinst")
        self.addCleanup(self.h.cleanup)

    def _verify(self, responses: str) -> subprocess.CompletedProcess[str]:
        body = f"""
        probe_local_http_root() {{
            # Called via $(...), i.e. in a subshell: keep the call counter in a file.
            n=$(cat "$VH_TEST_LOG/probe.n" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$VH_TEST_LOG/probe.n"
            r=$(printf '%s\\n' {responses} | sed -n "${{n}}p" | tr '_' ' ')
            [ -n "$r" ] || r=$(printf '%s\\n' {responses} | tail -n 1 | tr '_' ' ')
            printf '%s\\n' "$r"
        }}
        if verify_nginx_serves_vaulthalla; then echo "RC=0"; else echo "RC=1"; fi
        echo "STATUS=$NGINX_VERIFY_STATUS"
        """
        return self.h.run(body)

    def test_welcome_page_during_reload_then_app_is_verified(self) -> None:
        result = self._verify("200_1 200_1 307_0")
        self.assertIn("RC=0", result.stdout, result.stderr)
        self.assertIn("STATUS=verified (HTTP 307", result.stdout)

    def test_welcome_page_for_the_whole_window_is_reported_as_shadowed(self) -> None:
        result = self._verify("200_1")
        self.assertIn("RC=1", result.stdout, result.stderr)
        self.assertIn("NOT serving Vaulthalla", result.stdout)


class PostinstUpgradeRestartBehaviorTests(unittest.TestCase):
    """An upgrade restarts running units, starts units that had *failed*, and leaves stopped ones stopped."""

    def setUp(self) -> None:
        self.h = _Harness("postinst")
        self.addCleanup(self.h.cleanup)

    def _upgrade(self, core_state: str) -> str:
        (self.h.log / "unit-state.vaulthalla.service").write_text(core_state + "\n", encoding="utf-8")
        (self.h.log / "unit-state.vaulthalla-web.service").write_text("active\n", encoding="utf-8")
        body = """
        POSTINST_ACTION=configure
        INSTALL_MODE=upgrade
        systemd_running() { return 0; }
        core_start_blocker() { :; }
        configure_systemd_units
        echo "STATUS=$SERVICE_STATUS"
        """
        result = self.h.run(body)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout + "\n" + self.h.read_log("systemctl.argv")

    def test_failed_core_unit_is_started_by_the_upgrade(self) -> None:
        out = self._upgrade("failed")
        self.assertIn("start vaulthalla.service", out)
        self.assertIn("started previously failed vaulthalla.service", out)

    def test_operator_stopped_core_unit_stays_stopped(self) -> None:
        out = self._upgrade("inactive")
        self.assertNotIn("--system start vaulthalla.service", out)
        self.assertIn("try-restart vaulthalla.service", out)


class PostinstOutputPolicyTests(unittest.TestCase):
    """Terminal output is operator status: a clean upgrade prints one line (two with a pending action), a hard
    failure or a fresh install prints the full summary, and every detail is in the package log either way."""

    def setUp(self) -> None:
        self.h = _Harness("postinst")
        self.addCleanup(self.h.cleanup)
        self.package_log = self.h.tmp / "vaulthalla-package.log"

    def _configure(self, body: str, mode: str = "upgrade", env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        preamble = f"""
        PACKAGE_LOG="{self.package_log}"
        INITIAL_PASSWORD_FILE="{self.h.state}/super_admin_initial_password"
        POSTINST_ACTION=configure
        INSTALL_MODE={mode}
        LAST_CONFIGURED_VERSION=1.9.1-1
        systemd_running() {{ return 0; }}
        installed_package_version() {{ printf '%s' 1.9.2-1; }}
        open_package_log
        CONFIG_STATUS="preserved existing /etc/vaulthalla/config.yaml"
        DB_BOOTSTRAP_STATUS="reused (sealed DB credential present)"
        TPM_BACKEND_STATUS="hardware (device-backed TPM detected)"
        SERVICE_STATUS="restarted active units"
        CLI_SOCKET_STATUS="/run/vaulthalla/cli.sock bound by vaulthalla.service"
        NGINX_CONFIG_STATUS="done (verified)"
        """
        result = self.h.run(preamble + textwrap.dedent(body), env)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def _log(self) -> str:
        return self.package_log.read_text(encoding="utf-8") if self.package_log.exists() else ""

    def test_clean_upgrade_prints_one_line_and_logs_the_details(self) -> None:
        result = self._configure("""
        detail "TPM backend: hardware TPM detected (/dev/tpmrm0 or /dev/tpm0)."
        CORE_EXPECTED_UP=1
        report_configure_outcome
        """)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 1, result.stdout)
        self.assertEqual(
            lines[0],
            f"[vaulthalla] Upgraded 1.9.1-1 -> 1.9.2-1: services restarted, daemon healthy. Log: {self.package_log}",
        )
        self.assertEqual(result.stderr, "")
        log = self._log()
        self.assertIn("postinst configure (mode upgrade, previous '1.9.1-1')", log)
        self.assertIn("TPM backend: hardware TPM detected", log)
        self.assertIn("Install summary (upgrade):", log)
        self.assertIn("  DB bootstrap: reused", log)

    def test_clean_upgrade_with_a_pending_action_prints_two_lines(self) -> None:
        (self.h.state / "super_admin_initial_password").write_text("s3cr3t-value\n", encoding="utf-8")
        result = self._configure("CORE_EXPECTED_UP=1\nreport_configure_outcome\n")
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 2, result.stdout)
        self.assertTrue(lines[1].startswith("[vaulthalla] Action: the generated web 'admin' password"), lines[1])
        self.assertNotIn("s3cr3t-value", result.stdout + self._log())

    def test_operator_stopped_daemon_is_reported_not_flagged(self) -> None:
        result = self._configure("report_configure_outcome\n")
        self.assertIn("vaulthalla.service was not running and was left stopped", result.stdout)
        self.assertEqual(len(result.stdout.splitlines()), 1)

    def test_hard_failure_prints_the_full_summary(self) -> None:
        result = self._configure("""
        CORE_EXPECTED_UP=1
        unit_active_state() { printf '%s' failed; }
        verify_cli_socket_owned_by_daemon
        report_configure_outcome
        """)
        self.assertIn("ERROR: configure finished with problems: vaulthalla.service is 'failed'", result.stderr)
        self.assertIn("[vaulthalla] Install summary (upgrade):", result.stdout)
        self.assertIn("[vaulthalla]   CLI socket: not checked", result.stdout)
        self.assertIn("[vaulthalla]   Services: restarted active units; vaulthalla.service is 'failed'", result.stdout)
        self.assertIn(f"[vaulthalla] Full log: {self.package_log}", result.stdout)
        self.assertIn("DEGRADED: vaulthalla.service is 'failed'", self._log())

    def test_failed_db_bootstrap_is_a_hard_failure(self) -> None:
        result = self._configure("""
        DB_BOOTSTRAP_STATUS="failed (could not create PostgreSQL role 'vaulthalla')"
        report_configure_outcome
        """)
        self.assertIn("DB bootstrap: failed", result.stderr)
        self.assertIn("[vaulthalla] Install summary (upgrade):", result.stdout)

    def test_warnings_reach_the_terminal_without_the_summary(self) -> None:
        result = self._configure("""
        CORE_EXPECTED_UP=1
        warn_nonfatal "nginx: site active, but the web upstream is not answering yet"
        report_configure_outcome
        """)
        self.assertIn("[vaulthalla] WARNING: nginx: site active", result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 1, result.stdout)
        self.assertIn("WARNING: nginx: site active", self._log())

    def test_verbose_upgrade_prints_details_and_the_summary(self) -> None:
        result = self._configure(
            """
            detail "FUSE config: user_allow_other already enabled"
            CORE_EXPECTED_UP=1
            report_configure_outcome
            """,
            env={"VH_PACKAGE_VERBOSE": "1"},
        )
        self.assertIn("[vaulthalla] FUSE config: user_allow_other already enabled", result.stdout)
        self.assertIn("[vaulthalla] Install summary (upgrade):", result.stdout)

    def test_fresh_install_prints_the_summary_and_next_steps(self) -> None:
        result = self._configure("CORE_EXPECTED_UP=1\nreport_configure_outcome\n", mode="fresh")
        self.assertIn("[vaulthalla] Install summary (fresh):", result.stdout)
        self.assertIn("Web console: the generated password for 'admin' is written to", result.stdout)
        self.assertIn("Super-admin ownership: deferred to first CLI use", result.stdout)

    def test_package_log_refuses_a_symlink(self) -> None:
        target = self.h.tmp / "elsewhere"
        target.write_text("", encoding="utf-8")
        self.package_log.symlink_to(target)
        result = self._configure('detail "secret-free detail"\necho "SINK=$PACKAGE_LOG_SINK"\n')
        self.assertIn("SINK=/dev/null", result.stdout)
        self.assertEqual(target.read_text(encoding="utf-8"), "")

    @LINUX_HOST  # the size check is GNU `stat -c %s`
    def test_package_log_rotates_when_large(self) -> None:
        self.package_log.write_text("old\n", encoding="utf-8")
        self._configure("PACKAGE_LOG_MAX_BYTES=1\nopen_package_log\n")
        self.assertTrue((self.h.tmp / "vaulthalla-package.log.1").read_text(encoding="utf-8").startswith("old\n"))
        self.assertNotIn("old", self._log())
