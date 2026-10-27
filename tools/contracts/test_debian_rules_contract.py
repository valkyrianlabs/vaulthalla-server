from __future__ import annotations

from pathlib import Path
import unittest


class DebianRulesContractTests(unittest.TestCase):
    def test_debian_rules_uses_repo_root_meson_entrypoint(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        rules_path = repo_root / "debian" / "rules"
        rules = rules_path.read_text(encoding="utf-8")

        self.assertIn(
            "dh_auto_configure -- -Doptimization=3 -Dwerror=true -Dmanpage=true",
            rules,
        )
        self.assertIn(
            "dh_auto_install --destdir=debian/tmp",
            rules,
        )

    def test_shipped_binaries_build_at_o3_with_hardening(self) -> None:
        # 1.8.x packages shipped -O0 and unhardened: a cpp_args default_option made meson ignore the flags
        # dpkg-buildflags exported, and the build had no explicit optimization level.
        repo_root = Path(__file__).resolve().parents[2]
        rules = (repo_root / "debian" / "rules").read_text(encoding="utf-8")
        self.assertIn("export DEB_BUILD_MAINT_OPTIONS = hardening=+all optimize=-lto", rules)
        self.assertIn("export DEB_CXXFLAGS_MAINT_STRIP = -O2", rules)
        meson = (repo_root / "meson.build").read_text(encoding="utf-8")
        default_options = meson.split("default_options:", 1)[1].split("]", 1)[0]
        self.assertNotIn("cpp_args", default_options)
        self.assertNotIn("c_args", default_options)
        self.assertIn("'buildtype=debug'", default_options)

    def test_build_flag_checker_rejects_unoptimized_and_noisy_builds(self) -> None:
        import importlib.util

        repo_root = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location("check_build_flags", repo_root / "tools/dev/check_build_flags.py")
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        good = ("c++ -Icore -O3 -g -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=3 "
                "-o x.o -c ../core/src/a.cpp")
        self.assertEqual(checker.check(good), [])
        self.assertTrue(checker.check(good.replace("-O3", "-O0")))
        self.assertTrue(checker.check(good.replace(" -O3", "")))
        self.assertTrue(checker.check(good.replace(" -D_FORTIFY_SOURCE=3", "")))
        self.assertTrue(checker.check(good + "\n../core/src/a.cpp:1:2: warning: unused [-Wunused]"))
        self.assertTrue(checker.check("dh_auto_build"), "no compile lines is a failure")

    def test_debian_rules_leaves_static_payloads_to_meson(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        rules = (repo_root / "debian" / "rules").read_text(encoding="utf-8")

        meson_owned_fragments = (
            "deploy/config/config.yaml",
            "deploy/config/config_template.yaml.in",
            "deploy/systemd/vaulthalla.service.in",
            "deploy/systemd/vaulthalla-web.service.in",
            "deploy/systemd/vaulthalla-swtpm.service.in",
            "deploy/nginx/vaulthalla.conf",
            "deploy/psql/.",
            "deploy/lifecycle/main.py",
            "debian/vaulthalla.udev",
            "debian/tmpfiles.d/vaulthalla.conf",
        )
        for fragment in meson_owned_fragments:
            self.assertNotIn(fragment, rules)

        debian_assembled_fragments = (
            "cp -a web/.next/standalone/. debian/tmp/usr/share/vaulthalla-web/",
            "cp -a web/.next/static debian/tmp/usr/share/vaulthalla-web/.next/",
        )
        for fragment in debian_assembled_fragments:
            self.assertIn(fragment, rules)

    def test_root_meson_installs_static_runtime_payloads_when_enabled(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        meson = (repo_root / "meson.build").read_text(encoding="utf-8")

        required_fragments = (
            "if get_option('install_data')",
            "install_emptydir(state_dir)",
            "install_emptydir(log_dir)",
            "'deploy/config/config.yaml'",
            "'deploy/config/config_template.yaml.in'",
            "install_subdir(\n        'deploy/psql'",
            "'deploy/nginx/vaulthalla.conf'",
            "'deploy/lifecycle/main.py'",
            "'debian/vaulthalla.udev'",
            "'debian/tmpfiles.d/vaulthalla.conf'",
            "install_symlink(\n        'vaulthalla'",
            "install_symlink(\n        'vh'",
        )
        for fragment in required_fragments:
            self.assertIn(fragment, meson)
        # The daemon owns /run/vaulthalla/cli.sock; the old socket unit was an orphaned listener (#110).
        self.assertNotIn("vaulthalla-cli.socket", meson)
        self.assertNotIn("'vaulthalla-cli.service'", meson)
        self.assertFalse((repo_root / "deploy" / "systemd" / "vaulthalla-cli.socket").exists())
        self.assertFalse((repo_root / "deploy" / "systemd" / "vaulthalla-cli.service.in").exists())

    def test_debian_install_declares_meson_staged_payloads(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        install_manifest = (repo_root / "debian" / "install").read_text(encoding="utf-8")

        # The runtime package ships no static libraries or headers; dh_missing
        # (--fail-missing in compat 13) is satisfied through debian/not-installed.
        self.assertNotIn("libvaulthalla.a", install_manifest)
        self.assertNotIn("libvhusage.a", install_manifest)
        self.assertNotIn("usr/include", install_manifest)
        not_installed = (repo_root / "debian" / "not-installed").read_text(encoding="utf-8")
        self.assertIn("usr/lib/*/libvaulthalla.a", not_installed)
        self.assertIn("usr/lib/*/libvhusage.a", not_installed)
        self.assertIn("usr/include/vaulthalla/paths.h", not_installed)
        self.assertIn("usr/share/vaulthalla/config", install_manifest)
        self.assertIn("var/lib/vaulthalla", install_manifest)
        self.assertIn("var/log/vaulthalla", install_manifest)
        self.assertIn("usr/lib/udev/rules.d/60-vaulthalla-tpm.rules", install_manifest)
        self.assertIn("usr/lib/tmpfiles.d/vaulthalla.conf", install_manifest)
        self.assertIn(
            "lib/systemd/system/vaulthalla-web.service",
            install_manifest,
        )
        self.assertIn(
            "lib/systemd/system/vaulthalla-swtpm.service",
            install_manifest,
        )
        self.assertIn(
            "usr/share/vaulthalla/nginx/vaulthalla",
            install_manifest,
        )
        self.assertIn(
            "usr/share/vaulthalla/psql",
            install_manifest,
        )
        self.assertIn(
            "usr/share/vaulthalla-web usr/share/",
            install_manifest,
        )

    def test_debian_control_declares_web_runtime_and_proxy_expectations(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        control = (repo_root / "debian" / "control").read_text(encoding="utf-8")

        self.assertIn("nodejs,", control)
        self.assertIn("openssl,", control)
        self.assertIn(
            "Recommends:\n valkyrianlabs-archive-keyring,\n postgresql,\n nginx,\n certbot,\n python3-certbot-nginx,\n python3-certbot-dns-cloudflare",
            control,
        )
        self.assertIn("swtpm,", control)
        self.assertIn("swtpm-tools", control)
        self.assertIn("Depends:\n adduser,\n nodejs,\n openssl,", control)


if __name__ == "__main__":
    unittest.main()
