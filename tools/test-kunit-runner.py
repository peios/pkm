#!/usr/bin/env python3
"""Exercise the real KUnit verdict script with controlled emulator output.

No kernel is built or booted. KUNIT_RUNNER can select an earlier script for
negative-control runs; temporary files are removed when each case finishes.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


RUNNER = Path(os.environ.get(
    "KUNIT_RUNNER", Path(__file__).resolve().parents[1] / "build/test-kunit.sh"
))
FULL = """[    0.010000] pkm: kunit scaffold smoke passed
[    0.020000] KTAP version 1
[    0.020001] 1..1
[    0.030000]     KTAP version 1
[    0.030001]     # Subtest: pkm_kunit_file
[    0.030002]     1..1
[    0.040000]     ok 1 a_case
[    0.040001] # pkm_kunit_file: pass:1 fail:0 skip:0 total:1
[    0.040002] ok 1 pkm_kunit_file
[    0.050000] reboot: Power down
"""
FILTERED = "\n".join(line for line in FULL.splitlines()
                     if "smoke passed" not in line) + "\n"


class KUnitVerdict(unittest.TestCase):
    def run_log(self, log, *, filtered=False, emulator_status=0):
        with tempfile.TemporaryDirectory(prefix="pkm-kunit-verdict-") as tmp:
            root = Path(tmp)
            kernel = root / "bzImage"
            kernel.touch()
            fixture = root / "serial.txt"
            fixture.write_text(log)
            emulator = root / "qemu-fixture"
            emulator.write_text(
                '#!/bin/sh\ncat "$KUNIT_FIXTURE"\n'
                'exit "$KUNIT_EMULATOR_STATUS"\n'
            )
            emulator.chmod(0o700)
            env = os.environ.copy()
            env.pop("PKM_KUNIT_INITRD", None)
            env.pop("PKM_KUNIT_FILTER", None)
            env.update(QEMU_BIN=str(emulator), KUNIT_FIXTURE=str(fixture),
                       KUNIT_EMULATOR_STATUS=str(emulator_status),
                       PKM_KUNIT_LOG=str(root / "actual.log"),
                       PKM_KUNIT_TIMEOUT="5")
            if filtered:
                env["PKM_KUNIT_FILTER"] = "*.a_case"
            result = subprocess.run(
                ["bash", str(RUNNER), str(kernel)], env=env,
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual((root / "actual.log").read_text(), log)
            return result

    def assert_verdict(self, log, passed, **kwargs):
        result = self.run_log(log, **kwargs)
        self.assertEqual(result.returncode == 0, passed,
                         result.stdout + result.stderr)

    def test_complete_full_run(self):
        self.assert_verdict(FULL, True)

    def test_full_run_still_requires_smoke_marker(self):
        self.assert_verdict(FILTERED, False)

    def test_complete_filtered_run_without_smoke(self):
        self.assert_verdict(FILTERED, True, filtered=True)

    def test_filtered_single_case_without_aggregate_summary(self):
        log = "\n".join(line.replace("pkm_kunit_file", "rust_allocator")
                        for line in FILTERED.splitlines()
                        if "# pkm_kunit_file:" not in line) + "\n"
        self.assert_verdict(log, True, filtered=True)

    def test_empty_filter_result_is_not_success(self):
        self.assert_verdict(
            "[    0.02] KTAP version 1\n[    0.03] 1..0\n"
            "[    0.05] reboot: Power down\n", False, filtered=True,
        )

    def test_top_level_result_without_cases_is_not_success(self):
        log = "\n".join(line for line in FILTERED.splitlines()
                        if "     ok " not in line) + "\n"
        self.assert_verdict(log, False, filtered=True)

    def test_failed_case(self):
        self.assert_verdict(FULL.replace("ok 1 a_case", "not ok 1 a_case"), False)

    def test_kernel_diagnostics_cannot_hide_behind_passing_ktap(self):
        diagnostics = [
            "WARNING: possible circular locking dependency detected",
            "WARNING: suspicious RCU usage",
            "WARNING: include/linux/fsnotify.h:145 at rw_verify_area",
            "INFO: trying to register non-static key.",
            "turning off the locking correctness validator.",
            "BUG: kernel stack guard hit",
        ]
        for diagnostic in diagnostics:
            with self.subTest(diagnostic=diagnostic):
                log = FULL.replace("[    0.040000]", "[    0.039000] " +
                                   diagnostic + "\n[    0.040000]")
                self.assert_verdict(log, False)

    def test_clean_poweroff_is_required(self):
        self.assert_verdict(FULL.replace("reboot: Power down", "still running"), False)

    def test_incomplete_top_level_plan(self):
        self.assert_verdict(FULL.replace(
            "[    0.020001] 1..1", "[    0.020001] 1..2"), False)

    def test_nonzero_emulator_exit_is_failure(self):
        self.assert_verdict(FULL, False, emulator_status=2)


if __name__ == "__main__":
    unittest.main()
