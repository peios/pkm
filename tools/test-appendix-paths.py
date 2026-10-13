#!/usr/bin/env python3
"""Exercise the real appendix generators in isolated checkout layouts.

Run with PKM_LEARN_ROOT pointing at a matching learn checkout. No kernel or
documentation file in either checkout is modified.
"""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from appendix_paths import PKM, LEARN


BOOK = Path("peios.product/3--advanced-peios.antho/300--trms.shelf/100--peios-kernel.book")
APPENDICES = {
    "gen-kacs-abi": BOOK / "3--kacs/a1--kacs-abi.md",
    "gen-lcs-abi": BOOK / "5--lcs/a1--lcs-abi.md",
    "gen-ntfe-abi": BOOK / "6--ntfe/a1--ntfe-abi.md",
    "gen-stratafs-constants": BOOK / "4--stratafs/a1--constants.md",
}


class AppendixPathsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pkm-appendix-paths-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = os.environ.copy()
        self.env.pop("PKM_LEARN_ROOT", None)
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"

    def kernel(self, name):
        kernel = self.root / name
        (kernel / "tools").mkdir(parents=True)
        for script in ["appendix_paths", *APPENDICES]:
            shutil.copyfile(PKM / "tools" / (script + ".py"), kernel / "tools" / (script + ".py"))
        for directory in ["uapi", "kacs", "lcs", "stratafs", "kernel", "crates"]:
            (kernel / directory).symlink_to(PKM / directory, target_is_directory=True)
        return kernel

    def docs(self, name):
        docs = self.root / name
        for relative in APPENDICES.values():
            target = docs / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(LEARN / relative, target)
        return docs

    def run_generator(self, kernel, generator, *, docs=None, check=True):
        env = self.env.copy()
        if docs is not None:
            env["PKM_LEARN_ROOT"] = str(docs)
        return subprocess.run(
            ["python3", str(kernel / "tools" / (generator + ".py")), *(["--check"] if check else [])],
            cwd=self.root, env=env, capture_output=True, text=True,
        )

    def assert_checked(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("skipped:", result.stdout + result.stderr)

    def test_conventional_siblings(self):
        kernel = self.kernel("pkm")
        self.docs("learn")
        for generator in APPENDICES:
            with self.subTest(generator=generator):
                self.assert_checked(self.run_generator(kernel, generator))

    def test_named_worktrees_ignore_wrong_sibling_and_detect_drift(self):
        kernel = self.kernel("kernel review")
        docs = self.docs("docs review")
        # The old source lookup reads this unrelated tree instead of kernel.
        (self.root / "pkm").mkdir()
        (self.root / "pkm" / "uapi").write_text("not the kernel's headers")
        # A conventional companion also exists, so the old generators cannot
        # hide the bad source lookup behind their optional-docs skip.
        (self.root / "learn").symlink_to(docs, target_is_directory=True)
        for generator, relative in APPENDICES.items():
            with self.subTest(generator=generator):
                target = docs / relative
                original = target.read_bytes()
                self.assert_checked(self.run_generator(kernel, generator, docs=docs))
                target.write_bytes(original + b"\nSTALE\n")
                result = self.run_generator(kernel, generator, docs=docs)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(target.read_bytes(), original + b"\nSTALE\n")
                target.unlink()
                self.assertNotEqual(self.run_generator(kernel, generator, docs=docs).returncode, 0)
                self.assert_checked(self.run_generator(kernel, generator, docs=docs, check=False))
                self.assertEqual(target.read_bytes(), original)

    def test_explicit_invalid_companion_fails(self):
        kernel = self.kernel("review")
        self.docs("learn")
        for generator in APPENDICES:
            for docs in ["", self.root / "missing", self.root]:
                with self.subTest(generator=generator, docs=docs):
                    result = self.run_generator(kernel, generator, docs=docs)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("PKM_LEARN_ROOT", result.stderr)
                    self.assertNotIn("skipped:", result.stderr)

    def test_standalone_checkout_still_skips(self):
        kernel = self.kernel("standalone")
        for generator in APPENDICES:
            with self.subTest(generator=generator):
                result = self.run_generator(kernel, generator)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("skipped:", result.stderr)


if __name__ == "__main__":
    unittest.main()
