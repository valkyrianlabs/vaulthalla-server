"""`make test` / `make itest` reconfigure build-itest when the set of source files changes (#270).

core/meson.build discovers sources with `find` at configure time, so a build directory configured before a branch added
a .cpp linked against the stale list (undefined symbols). bin/tests/lib/itest.sh `itest_ensure_build` keeps a
fingerprint of the discovered source set next to the build and runs `meson setup --reconfigure` when it changes. These
cases run the real function against a scratch tree with a fake `meson` that records its calls.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ITEST = REPO / "bin" / "tests" / "lib" / "itest.sh"

FAKE_MESON = r"""#!/bin/sh
# Records each call; `setup` creates build.ninja, `introspect` reports the options in $FAKE_OPTIONS.
printf '%s\n' "$*" >>"$FAKE_LOG"
case "$1" in
  setup)
    for a in "$@"; do case "$a" in -*) ;; setup) ;; *) mkdir -p "$a"; touch "$a/build.ninja"; break ;; esac; done ;;
  introspect) cat "$FAKE_OPTIONS" ;;
esac
"""


def options_json(overrides: dict[str, object] | None = None) -> str:
    opts: dict[str, object] = {"buildtype": "debug", "build_unit_tests": True, "integration_tests": True,
                               "install_data": False, "manpage": False, "b_sanitize": ["address", "undefined"]}
    opts.update(overrides or {})
    return json.dumps([{"name": k, "value": v} for k, v in opts.items()])


class ItestEnsureBuild(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="itest-build-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        lib = self.tmp / "repo" / "bin" / "tests" / "lib"
        lib.mkdir(parents=True)
        shutil.copy(ITEST, lib / "itest.sh")
        self.root = self.tmp / "repo"
        for f in ("core/src/a.cpp", "core/tests/unit/test_a.cpp"):
            (self.root / f).parent.mkdir(parents=True, exist_ok=True)
            (self.root / f).write_text("")
        fakebin = self.tmp / "bin"
        fakebin.mkdir()
        (fakebin / "meson").write_text(FAKE_MESON)
        (fakebin / "meson").chmod(0o755)
        self.log = self.tmp / "meson.log"
        self.options = self.tmp / "options.json"
        self.options.write_text(options_json())
        self.build = self.root / "build-itest"
        self.env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}", "FAKE_LOG": str(self.log),
                    "FAKE_OPTIONS": str(self.options)}
        # A fixed job count, so the compile call is the same on every host (CI's container sets its own).
        self.env["VH_BUILD_JOBS"] = "3"

    def ensure(self) -> list[str]:
        """Runs itest_ensure_build once and returns the meson calls it made."""
        self.log.write_text("")
        subprocess.run(["bash", "-c", f'source "{self.root}/bin/tests/lib/itest.sh"; '
                                      f'itest_ensure_build "{self.build}" core/vh_unit_tests'],
                       env=self.env, check=True, capture_output=True, text=True)
        return self.log.read_text().splitlines()

    @staticmethod
    def reconfigures(calls: list[str]) -> list[str]:
        return [c for c in calls if c.startswith("setup --reconfigure")]

    def test_configures_once_then_only_compiles(self) -> None:
        calls = self.ensure()
        self.assertTrue(calls[0].startswith(f"setup {self.build} {self.root} -Dbuildtype=debug"), calls)
        self.assertEqual(calls[-1], f"compile -C {self.build} -j 3 core/vh_unit_tests")
        self.assertEqual(self.reconfigures(self.ensure()), [])

    def test_an_added_source_file_reconfigures(self) -> None:
        self.ensure()
        (self.root / "core/src/b.cpp").write_text("")
        calls = self.ensure()
        self.assertEqual(self.reconfigures(calls), [f"setup --reconfigure {self.build} {self.root}"])
        self.assertEqual(calls[-1], f"compile -C {self.build} -j 3 core/vh_unit_tests")
        self.assertEqual(self.reconfigures(self.ensure()), [], "the new set is recorded")

    def test_a_removed_or_renamed_source_file_reconfigures(self) -> None:
        self.ensure()
        (self.root / "core/tests/unit/test_a.cpp").rename(self.root / "core/tests/unit/test_b.cpp")
        self.assertEqual(len(self.reconfigures(self.ensure())), 1)
        (self.root / "core/src/a.cpp").unlink()
        self.assertEqual(len(self.reconfigures(self.ensure())), 1)

    def test_editing_a_source_file_does_not_reconfigure(self) -> None:
        self.ensure()
        (self.root / "core/src/a.cpp").write_text("int x;\n")
        (self.root / "core/src/a.hpp").write_text("")
        self.assertEqual(self.reconfigures(self.ensure()), [])

    def test_a_changed_build_definition_reconfigures(self) -> None:
        # A new target (an alias in core/meson.build) is unknown to `meson compile` until the directory is re-configured.
        (self.root / "core/meson.build").write_text("project('x')\n")
        self.ensure()
        (self.root / "core/meson.build").write_text("project('x')\nalias_target('helpers', [])\n")
        self.assertEqual(len(self.reconfigures(self.ensure())), 1)
        self.assertEqual(self.reconfigures(self.ensure()), [], "the new definition is recorded")

    def test_a_build_configured_before_the_fingerprint_reconfigures_once(self) -> None:
        self.ensure()
        (self.build / ".itest-sources").unlink()
        self.assertEqual(len(self.reconfigures(self.ensure())), 1)
        self.assertEqual(self.reconfigures(self.ensure()), [])

    def compile_call(self, jobs: str | None) -> str:
        if jobs is None:
            self.env.pop("VH_BUILD_JOBS", None)
        else:
            self.env["VH_BUILD_JOBS"] = jobs
        return self.ensure()[-1]

    def test_the_compile_is_bounded_by_vh_build_jobs(self) -> None:
        self.assertEqual(self.compile_call("7"), f"compile -C {self.build} -j 7 core/vh_unit_tests")

    def test_without_vh_build_jobs_the_compile_is_sized_from_memory(self) -> None:
        # ninja's own default (processors + 2) got the sanitizer build OOM-killed: where the host says how much memory
        # is available, the compile gets one job per 2.4 GiB of it, at least 2 and at most one per processor.
        call = self.compile_call(None)
        if not Path("/proc/meminfo").is_file():
            self.assertEqual(call, f"compile -C {self.build} core/vh_unit_tests")  # macOS: ninja picks
            return
        match = re.fullmatch(rf"compile -C {re.escape(str(self.build))} -j (\d+) core/vh_unit_tests", call)
        self.assertIsNotNone(match, call)
        self.assertGreaterEqual(int(match.group(1)), 2)
        self.assertLessEqual(int(match.group(1)), max(2, os.cpu_count() or 2))

    def test_a_job_count_that_is_not_a_number_is_refused(self) -> None:
        self.env["VH_BUILD_JOBS"] = "many"
        self.log.write_text("")
        done = subprocess.run(["bash", "-c", f'source "{self.root}/bin/tests/lib/itest.sh"; '
                                             f'itest_ensure_build "{self.build}" core/vh_unit_tests'],
                              env=self.env, capture_output=True, text=True)
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn("compile", self.log.read_text())

    def test_changed_options_reconfigure_with_just_those_options(self) -> None:
        self.ensure()
        self.options.write_text(options_json({"b_sanitize": ["none"], "manpage": True}))
        self.assertEqual(self.reconfigures(self.ensure()),
                         [f"setup --reconfigure {self.build} {self.root} -Dmanpage=false -Db_sanitize=address,undefined"])


if __name__ == "__main__":
    unittest.main()
