"""The isolated dev instance (`make dev`, meson -Dinstance=dev) shares nothing with a production install.

bin/lib/platform.sh decides the layout the source install scripts use; production's must stay exactly the paths the
Linux scripts always used (`make install` is the CI install path), and the dev instance's must differ from it in
every path, account, unit, port, database, socket and swtpm state. deploy/instance/render.py derives the instance's
config and systemd units from production's and must leave no production identifier behind.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RENDER = REPO / "deploy" / "instance" / "render.py"
KEYS = ("VH_NAME", "VH_PREFIX", "VH_BINDIR", "VH_DATADIR", "VH_CONFIG_PATH", "VH_STATE_DIR", "VH_LOG_DIR",
        "VH_RUNTIME_DIR", "VH_MOUNT_DIR", "VH_USER", "VH_GROUP", "VH_DB_NAME", "VH_DB_ROLE", "VH_WEB_PORT",
        "VH_WEB_DIR", "VH_CLI_NAME", "VH_SWTPM_STATE_DIR", "VH_SWTPM_PORT", "VH_UNIT_CORE", "VH_UNIT_WEB",
        "VH_UNIT_SWTPM", "VH_SUPPORT_DIR", "VH_ACCOUNT", "VH_LABEL_PREFIX", "VH_PG_PORT", "VH_PG_LABEL")


def layout(os_name: str, instance: str, env: dict[str, str] | None = None) -> dict[str, str]:
    with tempfile.TemporaryDirectory() as tmp:
        uname = Path(tmp) / "uname"
        uname.write_text(f"#!/bin/sh\necho {os_name}\n")
        uname.chmod(0o755)
        script = (f'source "{REPO}/bin/lib/platform.sh"; vh_instance_layout "{instance}"; '
                  + "; ".join(f'echo "{k}=${{{k}:-}}"' for k in KEYS))
        clean = {k: v for k, v in os.environ.items()
                 if k not in ("VH_USER", "VH_GROUP", "PREFIX", "BINDIR", "DATADIR", "SYSCONFDIR", "SYSTEMD_UNIT_DIR")}
        run_env = dict(clean, PATH=f"{tmp}:{os.environ['PATH']}", **(env or {}))
        out = subprocess.run(["bash", "-c", script], env=run_env, capture_output=True, text=True, check=True).stdout
    return dict(line.split("=", 1) for line in out.splitlines())


class Layout(unittest.TestCase):
    def test_linux_production_is_the_paths_the_scripts_always_used(self) -> None:
        p = layout("Linux", "")
        self.assertEqual(p["VH_PREFIX"], "/usr")
        self.assertEqual(p["VH_BINDIR"], "/usr/bin")
        self.assertEqual(p["VH_CONFIG_PATH"], "/etc/vaulthalla/config.yaml")
        self.assertEqual(p["VH_STATE_DIR"], "/var/lib/vaulthalla")
        self.assertEqual(p["VH_LOG_DIR"], "/var/log/vaulthalla")
        self.assertEqual(p["VH_RUNTIME_DIR"], "/run/vaulthalla")
        self.assertEqual(p["VH_MOUNT_DIR"], "/mnt/vaulthalla")
        self.assertEqual((p["VH_USER"], p["VH_GROUP"], p["VH_DB_NAME"]), ("vaulthalla",) * 3)
        self.assertEqual((p["VH_UNIT_CORE"], p["VH_UNIT_WEB"], p["VH_UNIT_SWTPM"]),
                         ("vaulthalla.service", "vaulthalla-web.service", "vaulthalla-swtpm.service"))
        self.assertEqual(p["VH_SWTPM_STATE_DIR"], "/var/lib/swtpm/vaulthalla")
        self.assertEqual(p["VH_WEB_DIR"], "/usr/share/vaulthalla-web")
        self.assertEqual(p["VH_CLI_NAME"], "vh")

    def test_linux_production_keeps_honoring_its_overrides_and_the_instance_never_does(self) -> None:
        env = {"PREFIX": "/usr/local", "VH_USER": "svc", "VH_GROUP": "svc"}
        self.assertEqual(layout("Linux", "", env)["VH_BINDIR"], "/usr/local/bin")
        self.assertEqual(layout("Linux", "", env)["VH_USER"], "svc")
        dev = layout("Linux", "dev", dict(env, VH_USER="vaulthalla"))
        self.assertEqual((dev["VH_PREFIX"], dev["VH_USER"]), ("/opt/vaulthalla-dev", "vaulthalla-dev"))

    def assert_disjoint(self, prod: dict[str, str], dev: dict[str, str]) -> None:
        for key in KEYS:
            if prod.get(key):
                self.assertNotEqual(prod[key], dev[key], key)
        prod_paths = [v for k, v in prod.items() if v.startswith("/") and k != "VH_BINDIR"]
        for key, value in dev.items():
            if value.startswith("/"):
                for p in prod_paths:
                    self.assertFalse(value == p or value.startswith(p + "/") and p not in ("/usr", "/usr/local"),
                                     f"{key}={value} lies inside production's {p}")

    def test_the_dev_instance_shares_nothing_with_production_on_linux(self) -> None:
        dev = layout("Linux", "dev")
        self.assert_disjoint(layout("Linux", ""), dev)
        self.assertEqual(dev["VH_MOUNT_DIR"], "/mnt/vh_dev")
        self.assertEqual(dev["VH_UNIT_CORE"], "vaulthalla-dev.service")
        self.assertEqual(dev["VH_WEB_PORT"], "37068")
        self.assertEqual(dev["VH_CLI_NAME"], "vh-dev")

    def test_the_dev_instance_shares_nothing_with_production_on_macos(self) -> None:
        dev = layout("Darwin", "dev")
        self.assert_disjoint(layout("Darwin", ""), dev)
        self.assertEqual(dev["VH_SUPPORT_DIR"], "/Library/Application Support/Vaulthalla-dev")
        self.assertEqual(dev["VH_ACCOUNT"], "_vaulthalla_dev")
        self.assertEqual(dev["VH_LABEL_PREFIX"], "sh.vaulthalla.dev")
        self.assertEqual(dev["VH_PG_PORT"], "5532")

    def test_make_dev_selects_the_instance_and_make_install_production(self) -> None:
        script = f'source "{REPO}/bin/lib/platform.sh"; vh_selected_instance'
        env = {k: v for k, v in os.environ.items() if k not in ("VH_INSTANCE", "VH_BUILD_MODE")}
        run = lambda extra: subprocess.run(["bash", "-c", script], env=dict(env, **extra), capture_output=True,
                                           text=True, check=True).stdout.strip()  # noqa: E731
        self.assertEqual(run({}), "")
        self.assertEqual(run({"VH_BUILD_MODE": "dev"}), "dev")
        self.assertEqual(run({"VH_BUILD_MODE": "dev", "VH_INSTANCE": ""}), "", "explicit opt-out")


class Render(unittest.TestCase):
    def render(self, kind: str, src: Path, *args: str) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            subprocess.run(["python3", str(RENDER), kind, "--instance", "dev", *args, str(src), str(out)], check=True)
            return out.read_text()

    def test_units_keep_no_production_identifier(self) -> None:
        for name in ("vaulthalla", "vaulthalla-web", "vaulthalla-swtpm"):
            unit = self.render("systemd", REPO / "deploy" / "systemd" / f"{name}.service.in", "--bindir",
                               "/opt/vaulthalla-dev/bin", "--node", "/usr/bin/node", "--web-dir",
                               "/opt/vaulthalla-dev/share/vaulthalla-web")
            self.assertNotRegex(unit, r"/mnt/vaulthalla(?![-\w])|/var/lib/vaulthalla(?![-\w])|/etc/vaulthalla(?![-\w])")
            self.assertNotRegex(unit, r"(?m)^(User|Group)=vaulthalla$")
            self.assertNotRegex(unit, r"\b(36968|36969|36970|2321|2322)\b")
            self.assertNotRegex(unit, r"(?<![-\w])vaulthalla(-web|-swtpm)?\.service")
            self.assertNotIn("@", unit.replace("@INPUT@", ""))
        core = self.render("systemd", REPO / "deploy" / "systemd" / "vaulthalla.service.in", "--bindir",
                           "/opt/vaulthalla-dev/bin", "--node", "/usr/bin/node", "--web-dir", "/x")
        self.assertIn("ExecStart=/opt/vaulthalla-dev/bin/vaulthalla-server", core)
        self.assertIn("fusermount3 -uz /mnt/vh_dev", core)
        self.assertRegex(core, r"(?m)^Wants=.*vaulthalla-dev-swtpm\.service")

    def test_config_moves_every_listener_and_the_database(self) -> None:
        config = self.render("config", REPO / "deploy" / "config" / "config.yaml")
        for port in ("37069", "37070", "39100"):
            self.assertRegex(config, rf"(?m)^  port: {port}\b")
        self.assertRegex(config, r"(?m)^  name: vaulthalla_dev\b")
        self.assertRegex(config, r"(?m)^  user: vaulthalla_dev\b")
        self.assertRegex(config, r"(?m)^  port: 5432\b", "Linux: the host's PostgreSQL")
        mac = self.render("config", REPO / "deploy" / "config" / "config.yaml", "--db-port", "5532")
        self.assertRegex(mac, r"(?m)^  port: 5532\b")
        self.assertRegex(mac, r"(?m)^  host: 127\.0\.0\.1\b")

    def test_production_render_is_the_identity(self) -> None:
        src = REPO / "deploy" / "systemd" / "vaulthalla.service.in"
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            subprocess.run(["python3", str(RENDER), "systemd", "--instance", "", str(src), str(out)], check=True)
            self.assertEqual(out.read_text(), src.read_text())


class Build(unittest.TestCase):
    def test_an_instance_never_installs_production_service_files(self) -> None:
        meson = (REPO / "meson.build").read_text()
        self.assertIn("if host_machine.system() == 'linux' and vh_instance == ''\n        unit_conf", meson)
        core = (REPO / "core" / "meson.build").read_text()
        self.assertIn("vh_instance_name = vh_instance == '' ? meson.project_name()", core)
        # The production default must stay: an empty instance.
        options = (REPO / "meson.options").read_text()
        self.assertRegex(options, r"option\(\s*'instance',\s*type: 'string',\s*value: '',")

    def test_dev_teardown_targets_only_the_instance(self) -> None:
        uninstall = (REPO / "bin" / "uninstall.sh").read_text()
        self.assertIn('export VH_UNIT_STEM="$VH_NAME"', uninstall)
        self.assertIn('VH_INSTANCE_BINDIRS="$VH_BINDIR"', uninstall)
        binaries = (REPO / "bin" / "teardown" / "uninstall_binaries.sh").read_text()
        self.assertIn("/opt/vaulthalla-?*|/usr/local/vaulthalla-?*) ;;", binaries)


if __name__ == "__main__":
    unittest.main()
