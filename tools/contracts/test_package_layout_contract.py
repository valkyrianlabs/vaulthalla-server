"""Contract for package metadata, systemd units and config ownership.

Run by module: python3 -m unittest tools.contracts.test_package_layout_contract
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest


class PackageLayoutContractTests(unittest.TestCase):
    def _repo_root(self) -> Path:
        return Path(__file__).resolve().parents[2]

    def _read(self, relative: str) -> str:
        return (self._repo_root() / relative).read_text(encoding="utf-8")

    def _depends(self) -> list[str]:
        control = self._read("debian/control")
        block = control.split("Package: vaulthalla", 1)[1]
        depends = block.split("Depends:", 1)[1].split("Recommends:", 1)[0]
        return [item.strip().rstrip(",") for item in depends.splitlines() if item.strip()]

    def _field(self, name: str) -> list[str]:
        control = self._read("debian/control")
        block = control.split("Package: vaulthalla\n", 1)[1].split("\nPackage:", 1)[0]
        value = block.split(f"\n{name}:", 1)[1]
        lines = []
        for line in value.splitlines()[1:]:
            if not line.startswith(" "):
                break
            lines.append(line.strip().rstrip(","))
        return lines

    def test_depends_include_fuse3_and_python3(self) -> None:
        depends = self._depends()
        self.assertIn("fuse3", depends)  # fusermount3 in ExecStopPost, /etc/fuse.conf allow_other
        self.assertIn("python3", depends)  # /usr/lib/vaulthalla/lifecycle behind vh setup/teardown
        lifecycle = self._read("deploy/lifecycle/main.py")
        self.assertTrue(lifecycle.startswith("#!/usr/bin/env python3"))

    def test_depends_include_archive_keyring(self) -> None:
        # vaulthalla-archive-keyring owns /usr/share/keyrings/vaulthalla.gpg, the signed-by= path install.sh and the
        # manual setup wrote before the move to apt.valkyrianlabs.com; it now ships the Valkyrian Labs LLC key, so
        # those sources keep verifying apt.vaulthalla.sh (an alias of the same index) without being edited.
        # It must be a hard Depends: Recommends is skipped by --no-install-recommends (install.sh --lean).
        self.assertIn("vaulthalla-archive-keyring", self._depends())
        self.assertNotRegex(self._read("debian/control"), r"vaulthalla-archive-keyring\s*\(")
        # New installs use the Valkyrian Labs keyring. vl-release refuses a Depends on it (a release .deb must
        # install without the repository), so it is a Recommends.
        self.assertIn("valkyrianlabs-archive-keyring", self._field("Recommends"))
        self.assertNotIn("valkyrianlabs-archive-keyring", self._depends())
        install_sh = self._read("bin/vh/install.sh")
        self.assertIn('KEY_FILE="/usr/share/keyrings/valkyrianlabs.gpg"', install_sh)
        self.assertIn('https://apt.valkyrianlabs.com/pubkey.asc', install_sh)
        self.assertIn('LEGACY_SOURCE_LINE="deb [arch=${REPO_ARCH} signed-by=/usr/share/keyrings/vaulthalla.gpg] '
                      'https://apt.vaulthalla.sh ${REPO_DIST} ${REPO_COMPONENT}"', install_sh)

    def test_nodejs_dependency_stays_installable_on_noble(self) -> None:
        # Next 16 wants >= 20.9, but noble ships 18.19; a version constraint would make
        # the package uninstallable there. Documented in README.Debian instead.
        self.assertIn("nodejs", self._depends())
        self.assertNotRegex(self._read("debian/control"), r"nodejs\s*\(")
        self.assertIn("Node.js >= 20.9", self._read("debian/README.Debian"))

    def test_build_depends_match_meson_build(self) -> None:
        control = self._read("debian/control")
        build_depends = control.split("Build-Depends:", 1)[1].split("Standards-Version", 1)[0]
        for package in (
            "meson",
            "ninja-build",
            "pkg-config",
            "pandoc",
            "libfuse3-dev",
            "libpqxx-vh-dev",
            "libpdfium-dev",
            "libspdlog-dev",
            "libfmt-dev",
            "libtss2-dev",
            "libssl-dev",
            "libturbojpeg0-dev",
            "libgtest-dev",
        ):
            self.assertIn(package, build_depends)
        self.assertNotIn("cmake", build_depends)
        # Ubuntu's shared libpqxx-dev is not a substitute: core links apt.valkyrianlabs.com's static libpqxx-vh SDK.
        self.assertNotRegex(build_depends, r"(?m)^\s*libpqxx-dev\b")

    def test_core_consumes_the_vaulthalla_db_and_pdf_sdks(self) -> None:
        meson = self._read("core/meson.build")
        # Read through pkg-config itself (meson can't parse the SDK's `-l:libpq.so.5` and warned): the static SDK by
        # name, at least 8.0.2, with --static link flags.
        self.assertIn("run_command(pqxx_pkgconfig, '--atleast-version=8.0.2', 'libpqxx-vh'", meson)
        self.assertIn("run_command(pqxx_pkgconfig, '--libs', '--static', 'libpqxx-vh'", meson)
        self.assertIn("pqxx_dep = declare_dependency(", meson)
        self.assertNotIn("dependency('libpqxx'", meson)
        # The retired 2025.06.29 PDFium fork snapshot sorts above Chromium milestones; only the upper bound keeps a
        # stale build host from producing a package that depends on it.
        self.assertIn("dependency('pdfium', version: ['>=155.8059', '<1000']", meson)

    def test_core_unit_wants_postgresql_and_bounds_restarts(self) -> None:
        unit = self._read("deploy/systemd/vaulthalla.service.in")
        self.assertNotRegex(unit, r"(?m)^Requires=")
        self.assertRegex(unit, r"(?m)^Wants=.*postgresql\.service")
        self.assertRegex(unit, r"(?m)^After=.*postgresql\.service")
        self.assertRegex(unit, r"(?m)^StartLimitIntervalSec=\d+")
        self.assertRegex(unit, r"(?m)^StartLimitBurst=\d+")
        self.assertRegex(unit, r"(?m)^Restart=on-failure$")
        unit_section = unit.split("[Service]", 1)[0]
        self.assertIn("StartLimitBurst", unit_section, "StartLimit* belongs in [Unit]")
        self.assertIn("fusermount3 -uz /mnt/vaulthalla", unit)
        self.assertIn("findmnt -rn -M /mnt/vaulthalla", unit)

    def test_web_unit_has_no_demo_server_address(self) -> None:
        unit = self._read("deploy/systemd/vaulthalla-web.service.in")
        self.assertNotIn("NEXT_PUBLIC_SERVER_ADDR", unit)
        self.assertNotIn("demo.vaulthalla.io", unit)
        self.assertRegex(unit, r"(?m)^StartLimitBurst=\d+")

    def test_web_unit_treats_sigterm_exit_as_success(self) -> None:
        # #136: node exits 143 (128 + SIGTERM) when systemd stops it, so every package stop/upgrade left
        # vaulthalla-web.service "failed" unless 143 counts as a clean exit.
        units = sorted((self._repo_root() / "deploy/systemd").glob("vaulthalla-web.service*"))
        self.assertTrue(units, "no vaulthalla-web unit found under deploy/systemd")
        for path in units:
            unit = path.read_text(encoding="utf-8")
            service = unit.split("[Service]", 1)[1].split("\n[", 1)[0] if "[Service]" in unit else ""
            statuses = re.findall(r"(?m)^SuccessExitStatus=(.*)$", service)
            self.assertTrue(
                # The exit *code* 143, not the signal name: node handles SIGTERM and exits normally with 143.
                any("143" in value.split() for value in statuses),
                f"{path.name}: [Service] needs SuccessExitStatus=143",
            )

    def test_config_is_not_a_conffile(self) -> None:
        repo = self._repo_root()
        install = self._read("debian/install")
        self.assertNotIn("etc/vaulthalla/config.yaml", install)
        self.assertNotIn("etc/vaulthalla/config_template.yaml.in", install)
        self.assertIn("usr/share/vaulthalla/config", install)
        self.assertFalse((repo / "debian" / "conffiles").exists())
        meson = self._read("meson.build")
        self.assertIn("install_dir: data_dir / 'config'", meson)
        self.assertNotRegex(meson, r"install_dir: sysconf_dir,\n    \)\n\n    install_subdir")

    def test_repo_root_config_override_is_source_install_opt_in(self) -> None:
        meson = self._read("meson.build")
        options = self._read("meson.options")
        self.assertIn("get_option('install_local_config_override') and fs.exists", meson)
        self.assertRegex(options, r"'install_local_config_override',\s*type: 'boolean',\s*value: false")
        self.assertFalse((self._repo_root() / "meson_options.txt").exists(), "keep a single meson.options")
        self.assertNotIn("install_local_config_override", self._read("debian/rules"))

    def test_postinst_installs_config_only_when_missing(self) -> None:
        postinst = self._read("debian/postinst")
        start = postinst.index("install_default_config_if_missing() {")
        body = postinst[start:postinst.index("\n}\n", start)]
        self.assertLess(
            body.index('if [ -e "$CONFIG_FILE" ] || [ -L "$CONFIG_FILE" ]; then'),
            body.index('install_file_atomically "$packaged_config" "$CONFIG_FILE"'),
        )
        self.assertIn('PACKAGED_CONFIG_DIR="/usr/share/vaulthalla/config"', postinst)

    def test_shipped_config_has_no_duplicate_keys(self) -> None:
        # yaml-cpp keeps one of two same-named keys without a word; two branches each adding a `vaults:` section
        # merged without a conflict and shipped one of them unread.
        import yaml

        class StrictLoader(yaml.SafeLoader):
            pass

        def mapping(loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
            keys = [loader.construct_object(key, deep=deep) for key, _ in node.value]
            duplicates = sorted({str(key) for key in keys if keys.count(key) > 1})
            self.assertEqual(duplicates, [], f"duplicate keys at line {node.start_mark.line + 1}")
            return loader.construct_mapping(node, deep)

        StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
        for path in ("deploy/config/config.yaml", "deploy/config/config_template.yaml.in"):
            with self.subTest(path=path):
                yaml.load(self._read(path), Loader=StrictLoader)

    def test_shipped_config_binds_ws_and_preview_to_loopback(self) -> None:
        config = self._read("deploy/config/config.yaml")

        def section_host(name: str) -> str:
            block = config.split(f"\n{name}:\n", 1)[1]
            return re.search(r"(?m)^  host:\s*(\S+)", block).group(1)

        self.assertEqual(section_host("websocket_server"), "127.0.0.1")
        self.assertEqual(section_host("http_preview_server"), "127.0.0.1")
        self.assertEqual(section_host("s3_gateway"), "0.0.0.0")
        template = self._read("deploy/nginx/vaulthalla.conf")
        self.assertIn("proxy_pass http://127.0.0.1:36969;", template)
        self.assertIn("proxy_pass http://127.0.0.1:36970;", template)

    def test_runtime_package_hygiene(self) -> None:
        repo = self._repo_root()
        for leftover in ("vaulthalla.doc-base.ex", "README", "vaulthalla-docs.docs"):
            self.assertFalse((repo / "debian" / leftover).exists(), leftover)
        self.assertNotIn("run/vaulthalla", self._read("debian/dirs"))
        self.assertIn("override_dh_installudev:", self._read("debian/rules"))
        install = self._read("debian/install")
        self.assertNotIn("usr/include", install)
        self.assertNotIn(".a ", install)

    def test_preinst_marks_reinstall_over_config_files(self) -> None:
        preinst = self._read("debian/preinst")
        self.assertIn('if [ -n "${2:-}" ]; then', preinst)
        self.assertIn('REINSTALL_MARKER="${STATE_DIR}/.reinstall_from_config_files"', preinst)
        postinst = self._read("debian/postinst")
        self.assertIn('INSTALL_MODE="reinstall"', postinst)
        self.assertIn('rm -f "$REINSTALL_MARKER"', postinst)

    def test_legacy_cli_units_are_not_shipped_and_retired_on_upgrade(self) -> None:
        # vaulthalla-cli.socket was an orphaned listener on the daemon's socket path; `vh` hung (#110).
        repo = self._repo_root()
        self.assertFalse((repo / "deploy" / "systemd" / "vaulthalla-cli.socket").exists())
        self.assertFalse((repo / "deploy" / "systemd" / "vaulthalla-cli.service.in").exists())
        for relative in ("debian/install", "meson.build", "debian/prerm", "bin/setup/install_dirs.sh"):
            self.assertNotIn("vaulthalla-cli.s", self._read(relative), relative)
        # The source installer only ever disables/removes them (older dev installs).
        dev_installer = self._read("bin/setup/install_systemd.sh")
        self.assertNotIn("enable --now vaulthalla-cli", dev_installer)
        self.assertNotIn("deploy/systemd/vaulthalla-cli", dev_installer)
        self.assertIn('systemctl disable --now "$unit"', dev_installer)

        postinst = self._read("debian/postinst")
        for fragment in ("CLI_SOCKET_SYSTEMD_UNIT", "CLI_SYSTEMD_UNIT", "enable vaulthalla-cli", "start vaulthalla-cli"):
            self.assertNotIn(fragment, postinst)
        start = postinst.index("retire_legacy_cli_units() {")
        body = postinst[start:postinst.index("\n}\n", start)]
        self.assertIn("deb-systemd-helper purge $LEGACY_CLI_UNITS", body)
        self.assertIn("deb-systemd-helper unmask $LEGACY_CLI_UNITS", body)
        self.assertIn("safe_systemctl daemon-reload", body)
        stop_start = postinst.index("stop_legacy_cli_unit_bounded() {")
        stop_body = postinst[stop_start:postinst.index("\n}\n", stop_start)]
        self.assertIn('run_bounded "$SERVICE_TRANSITION_TIMEOUT_SECONDS" deb-systemd-invoke stop "$unit"', stop_body)
        self.assertIn('kill -s KILL "$unit"', stop_body)

        configure = postinst[postinst.index("  configure)\n"):]
        # Retire early (before anything that can abort configure), and before the core restart
        # that makes the daemon bind /run/vaulthalla/cli.sock again.
        self.assertLess(configure.index("retire_legacy_cli_units"), configure.index("bootstrap_db_if_safe"))
        self.assertLess(configure.index("retire_legacy_cli_units"), configure.index("configure_systemd_units"))
        self.assertLess(configure.index("configure_systemd_units"), configure.index("verify_cli_socket_owned_by_daemon"))

        postrm = self._read("debian/postrm")
        purge = postrm[postrm.index("purge_package_state() {"):]
        self.assertIn("purge_legacy_cli_units", purge)

    def test_swtpm_disable_runs_after_debhelper_enable(self) -> None:
        postinst = self._read("debian/postinst")
        configure = postinst[postinst.index("  configure)\n"):]
        self.assertLess(configure.index("#DEBHELPER#"), configure.index("reconcile_swtpm_unit_enablement"))
        self.assertLess(configure.index("#DEBHELPER#"), configure.index("configure_systemd_units"))

    def test_daemon_crash_exits_instead_of_wedging_its_mount(self) -> None:
        # A core dump waits for every thread, and a thread closing a file on the daemon's own FUSE mount waits for a
        # reply the crashing daemon cannot send: the dump, the mount and apt hang forever. The daemon must be
        # non-dumpable from the first line of main() so a crash exits and Restart=on-failure recovers it.
        main = self._read("core/main/main.cpp")
        self.assertIn("vh::platform::process::disableCoreDumps()", main.split("void installCrashGuard() {", 1)[1])
        self.assertIn("prctl(PR_SET_DUMPABLE, 0", self._read("core/src/platform/linux/Process.cpp"))
        body = main.split("int main() {", 1)[1]
        self.assertLess(body.index("installCrashGuard();"), body.index("try {"))
        unit = self._read("deploy/systemd/vaulthalla.service.in")
        self.assertRegex(unit, r"(?m)^Restart=on-failure$")
        self.assertRegex(unit, r"(?m)^LimitCORE=0$")


if __name__ == "__main__":
    unittest.main()
