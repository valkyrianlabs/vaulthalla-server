"""macOS system service contract (deploy/launchd, #216 / #202 / #199).

The LaunchDaemons mirror the systemd units' invariants, and vaulthalla-provision sets up the hidden _vaulthalla
account, the private state tree and the daemons idempotently, without ever enrolling a human user. The provisioning
script runs here against stub dscl/launchctl/install/plutil under a temporary --root, so this works on Linux CI too.
"""
from __future__ import annotations

import json
import os
import plistlib
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LAUNCHD = REPO / "deploy" / "launchd"

PATHS = {
    "SUPPORT_DIR": "/Library/Application Support/Vaulthalla",
    "STATE_DIR": "/Library/Application Support/Vaulthalla/state",
    "RUN_DIR": "/Library/Application Support/Vaulthalla/run",
    "MOUNT_DIR": "/Library/Application Support/Vaulthalla/mount",
    "LOG_DIR": "/Library/Logs/Vaulthalla",
    "CONFIG_PATH": "/Library/Application Support/Vaulthalla/config.yaml",
    "SHARE_DIR": "/usr/local/share/vaulthalla",
    "BINDIR": "/usr/local/bin",
    "WEB_DIR": "/usr/local/share/vaulthalla-web",
    "NODE": "/usr/local/libexec/vaulthalla/node/bin/node",
}


def render(text: str, values: dict[str, str]) -> str:
    for key, value in values.items():
        text = text.replace(f"@{key}@", value)
    return text


class LaunchDaemonPlists(unittest.TestCase):
    def load(self, name: str) -> dict:
        return plistlib.loads(render((LAUNCHD / f"{name}.plist.in").read_text(), PATHS).encode())

    def test_server_is_a_system_daemon_for_the_service_account(self) -> None:
        p = self.load("sh.vaulthalla.server")
        self.assertEqual(p["Label"], "sh.vaulthalla.server")
        self.assertEqual(p["ProgramArguments"], [f"{PATHS['BINDIR']}/vaulthalla-server"])
        self.assertEqual((p["UserName"], p["GroupName"]), ("_vaulthalla", "_vaulthalla"))
        self.assertTrue(p["RunAtLoad"])
        # Restart=on-failure, RestartSec=10, TimeoutStopSec=30s, LimitNOFILE=65535, LimitCORE=0.
        self.assertEqual(p["KeepAlive"], {"SuccessfulExit": False})
        self.assertEqual(p["ThrottleInterval"], 10)
        self.assertEqual(p["ExitTimeOut"], 30)
        for limits in (p["SoftResourceLimits"], p["HardResourceLimits"]):
            self.assertEqual(limits["NumberOfFiles"], 65535)
            self.assertEqual(limits["Core"], 0)
        self.assertEqual(p["Umask"], 0o077)
        self.assertEqual(p["WorkingDirectory"], PATHS["STATE_DIR"])
        # A system LaunchDaemon: never tied to a login session (no LaunchAgent session types).
        self.assertNotIn("LimitLoadToSessionType", p)

    def test_web_mirrors_the_systemd_unit(self) -> None:
        p = self.load("sh.vaulthalla.web")
        self.assertEqual(p["ProgramArguments"], [PATHS["NODE"], f"{PATHS['WEB_DIR']}/server.js"])
        self.assertEqual((p["UserName"], p["GroupName"]), ("_vaulthalla", "_vaulthalla"))
        self.assertTrue(p["KeepAlive"])
        env = p["EnvironmentVariables"]
        self.assertEqual(env["HOSTNAME"], "127.0.0.1")
        self.assertEqual(env["PORT"], "36968")
        systemd = (REPO / "deploy" / "systemd" / "vaulthalla-web.service.in").read_text()
        for key in ("NODE_ENV", "PORT", "HOSTNAME", "VAULTHALLA_WEB_INTERNAL_ORIGIN", "VAULTHALLA_AUTH_ORIGIN",
                    "VAULTHALLA_PREVIEW_ORIGIN"):
            self.assertIn(f"Environment={key}={env[key]}", systemd, key)


STUB_DSCL = r'''#!/usr/bin/env python3
import json, os, sys
state = os.environ["STUB_STATE"]
db = json.load(open(state)) if os.path.exists(state) else {"Users": {}, "Groups": {}}
args = sys.argv[2:]  # after "."
with open(os.environ["STUB_LOG"], "a") as log:
    log.write("dscl " + " ".join(args) + "\n")
def rec(path):
    kind, name = path.strip("/").split("/", 1)
    return kind, name
op = args[0]
if op == "-read":
    kind, name = rec(args[1])
    r = db[kind].get(name)
    if r is None: sys.exit(56)
    if len(args) > 2: print(f"{args[2]}: {r.get(args[2], [''])[0]}")
    sys.exit(0)
if op == "-list":
    kind = args[1].strip("/"); key = args[2]
    for name, r in db[kind].items():
        if key in r: print(f"{name} {r[key][0]}")
    sys.exit(0)
if os.environ.get("STUB_APPLY") != "1": sys.exit(0)
kind, name = rec(args[1])
if op == "-create":
    r = db[kind].setdefault(name, {})
    if len(args) > 3: r[args[2]] = [args[3]]
elif op == "-append":
    db[kind].setdefault(name, {}).setdefault(args[2], []).append(args[3])
elif op == "-delete":
    db[kind].pop(name, None)
json.dump(db, open(state, "w"))
'''

STUB_LAUNCHCTL = r'''#!/bin/sh
echo "launchctl $*" >> "$STUB_LOG"
loaded="$STUB_DIR/loaded"; mkdir -p "$loaded"
case "$1" in
  print) [ -e "$loaded/${2#system/}" ] ;;
  bootstrap) label=$(basename "$3" .plist); touch "$loaded/$label" ;;
  bootout) rm -f "$loaded/${2#system/}" ;;
esac
'''

# install(1) without the owner part (tests aren't root): -d dirs or one file copy, with the mode.
STUB_INSTALL = r'''#!/bin/sh
echo "install $*" >> "$STUB_LOG"
dir=false; mode=0755
while [ $# -gt 2 ] || [ "${1#-}" != "$1" ]; do
  case "$1" in
    -d) dir=true; shift ;;
    -o|-g) shift 2 ;;
    -m) mode=$2; shift 2 ;;
    *) break ;;
  esac
done
if [ "$dir" = true ]; then mkdir -p "$1"; chmod "$mode" "$1"; else mkdir -p "$(dirname "$2")"; cp "$1" "$2"; chmod "$mode" "$2"; fi
'''

STUB_PLUTIL = r'''#!/usr/bin/env python3
import plistlib, sys
plistlib.loads(open(sys.argv[-1], "rb").read())
'''


class Provisioning(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.root = base / "root"
        self.stubs = base / "stubs"
        self.stubs.mkdir()
        for name, body in (("dscl", STUB_DSCL), ("launchctl", STUB_LAUNCHCTL), ("install", STUB_INSTALL),
                           ("plutil", STUB_PLUTIL)):
            path = self.stubs / name
            path.write_text(body)
            path.chmod(0o755)
        self.log = base / "calls.log"
        self.state = base / "dscl.json"
        share = self.root / PATHS["SHARE_DIR"].lstrip("/")
        (share / "launchd").mkdir(parents=True)
        (share / "config").mkdir()
        (share / "config" / "config.yaml").write_text("shipped: true\n")
        for name in ("sh.vaulthalla.server", "sh.vaulthalla.web"):
            (share / "launchd" / f"{name}.plist.in").write_text((LAUNCHD / f"{name}.plist.in").read_text())
        (self.root / "Library" / "LaunchDaemons").mkdir(parents=True)
        self.script = base / "vaulthalla-provision"
        self.script.write_text(render((LAUNCHD / "vaulthalla-provision.in").read_text(), PATHS))
        self.script.chmod(0o755)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_provision(self, *args: str, apply: bool = False) -> subprocess.CompletedProcess:
        env = dict(os.environ, VH_DSCL=str(self.stubs / "dscl"), VH_LAUNCHCTL=str(self.stubs / "launchctl"),
                   VH_INSTALL=str(self.stubs / "install"), VH_PLUTIL=str(self.stubs / "plutil"),
                   STUB_LOG=str(self.log), STUB_STATE=str(self.state), STUB_DIR=self.tmp.name,
                   STUB_APPLY="1" if apply else "0")
        argv = ["bash", str(self.script), "--root", str(self.root), *args, *(["--apply"] if apply else [])]
        return subprocess.run(argv, env=env, capture_output=True, text=True, timeout=60)

    def path(self, absolute: str) -> Path:
        return self.root / absolute.lstrip("/")

    def calls(self) -> str:
        return self.log.read_text() if self.log.exists() else ""

    def test_plan_mode_changes_nothing(self) -> None:
        r = self.run_provision()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("would run", r.stdout)
        self.assertFalse(self.path(PATHS["STATE_DIR"]).exists())
        self.assertNotIn("dscl -create", self.calls())
        self.assertNotIn("launchctl bootstrap", self.calls())

    def test_apply_creates_account_private_tree_config_and_daemons(self) -> None:
        r = self.run_provision(apply=True)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        db = json.loads(self.state.read_text())
        user, group = db["Users"]["_vaulthalla"], db["Groups"]["_vaulthalla"]
        uid = int(user["UniqueID"][0])
        self.assertTrue(200 <= uid <= 399)
        self.assertEqual(user["PrimaryGroupID"], group["PrimaryGroupID"])
        self.assertEqual(user["UserShell"], ["/usr/bin/false"])
        self.assertEqual(user["IsHidden"], ["1"])
        self.assertIn("vaulthalla", user["RecordName"])
        self.assertIn("vaulthalla", group["RecordName"])
        modes = {k: stat.S_IMODE(self.path(PATHS[k]).stat().st_mode) for k in
                 ("SUPPORT_DIR", "STATE_DIR", "RUN_DIR", "MOUNT_DIR", "LOG_DIR")}
        self.assertEqual(modes, {"SUPPORT_DIR": 0o755, "STATE_DIR": 0o700, "RUN_DIR": 0o750, "MOUNT_DIR": 0o700,
                                 "LOG_DIR": 0o750})
        self.assertEqual(self.path(PATHS["CONFIG_PATH"]).read_text(), "shipped: true\n")
        self.assertEqual(stat.S_IMODE(self.path(PATHS["CONFIG_PATH"]).stat().st_mode), 0o640)
        server = plistlib.loads(self.path("/Library/LaunchDaemons/sh.vaulthalla.server.plist").read_bytes())
        self.assertEqual(server["WorkingDirectory"], PATHS["STATE_DIR"])
        self.assertIn("launchctl bootstrap system /Library/LaunchDaemons/sh.vaulthalla.server.plist", self.calls())
        self.assertIn("launchctl bootstrap system /Library/LaunchDaemons/sh.vaulthalla.web.plist", self.calls())

    def test_second_apply_is_a_no_op(self) -> None:
        self.assertEqual(self.run_provision(apply=True).returncode, 0)
        self.log.unlink()
        r = self.run_provision(apply=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("done (0 change(s))", r.stdout)
        self.assertNotRegex(self.calls(), r"dscl -(create|append|delete)|install |launchctl (bootstrap|bootout)")

    def test_existing_config_is_never_overwritten(self) -> None:
        config = self.path(PATHS["CONFIG_PATH"])
        config.parent.mkdir(parents=True)
        config.write_text("operator: edited\n")
        self.assertEqual(self.run_provision(apply=True).returncode, 0)
        self.assertEqual(config.read_text(), "operator: edited\n")

    def test_never_enrolls_anyone_in_the_vaulthalla_group(self) -> None:
        self.assertEqual(self.run_provision(apply=True).returncode, 0)
        self.assertNotIn("GroupMembership", self.calls())
        self.assertNotIn("dseditgroup", self.script.read_text())
        db = json.loads(self.state.read_text())
        self.assertNotIn("GroupMembership", db["Groups"]["_vaulthalla"])

    def test_remove_unloads_and_purge_deletes_account_and_data(self) -> None:
        self.assertEqual(self.run_provision(apply=True).returncode, 0)
        r = self.run_provision("--remove", apply=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("launchctl bootout system/sh.vaulthalla.server", self.calls())
        self.assertFalse(self.path("/Library/LaunchDaemons/sh.vaulthalla.server.plist").exists())
        self.assertTrue(self.path(PATHS["STATE_DIR"]).exists(), "--remove alone keeps the data")
        r = self.run_provision("--remove", "--purge", apply=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.path(PATHS["STATE_DIR"]).exists())
        self.assertNotIn("_vaulthalla", json.loads(self.state.read_text())["Users"])

    def test_purge_requires_remove(self) -> None:
        self.assertEqual(self.run_provision("--purge").returncode, 2)


class BuildInstallsPlatformServiceFiles(unittest.TestCase):
    def test_linux_keeps_systemd_and_macos_gets_launchd(self) -> None:
        meson = (REPO / "meson.build").read_text()
        linux = meson.split("if host_machine.system() == 'linux'\n        unit_conf", 1)
        self.assertEqual(len(linux), 2, "systemd units must stay inside the Linux-only block")
        darwin = meson.split("if host_machine.system() == 'darwin'", 1)[1]
        self.assertIn("deploy/launchd/vaulthalla-provision.in", darwin)
        self.assertNotIn("systemd", darwin.split("endif", 1)[0])


if __name__ == "__main__":
    unittest.main()
