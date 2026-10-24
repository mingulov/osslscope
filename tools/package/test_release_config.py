# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the actual Python 3.11+ TOML adapter using owned fixtures."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

PRODUCT = Path(__file__).resolve().parents[2]
ADAPTER = PRODUCT / "scripts/package-release.py"


class ReleaseConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="release-config-", dir=os.environ["TMPDIR"])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "packaging").mkdir()
        (self.root / "Cargo.toml").write_text('[package]\nname = "osslscope"\nversion = "0.1.0"\n')
        self.policy = (PRODUCT / "packaging/release.toml").read_text() if (PRODUCT / "packaging/release.toml").exists() else ""
        (self.root / "packaging/release.toml").write_text(self.policy)

    def run_adapter(self, *extra):
        return subprocess.run(["python3", str(ADAPTER), "--root", str(self.root), "--profile", "gnu", "--emit-config", *extra], text=True, capture_output=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})

    def test_epoch_one_candidate_uses_actual_cargo_version(self):
        result = self.run_adapter()
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(result.stdout)
        self.assertEqual((config["product_version"], config["package_epoch"], config["package_revision"], config["jobs"], config["source_epoch"]), ("0.1.0", 1, 1, 2, 1792799804))
        (self.root / "Cargo.toml").write_text('[package]\nname="osslscope"\nversion="0.2.7"\n')
        result = self.run_adapter()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["product_version"], "0.2.7")
        self.assertNotEqual(self.run_adapter("--version", "9.9.9").returncode, 0)

    def test_duplicate_unknown_bad_epoch_revision_and_types_refuse(self):
        for policy in [self.policy.replace("package_epoch = 1", "package_epoch = 1\npackage_epoch = 1"), self.policy + '\nunknown = "injected"\n', self.policy.replace("package_epoch = 1", "package_epoch = 0"), self.policy.replace("package_revision = 1", "package_revision = 2"), self.policy.replace("jobs = 2", "jobs = true"), self.policy.replace("source_epoch = 1792799804", "source_epoch = 1792799805"), self.policy.replace('formats = ["deb", "rpm", "prefix"]', 'formats = ["prefix"]'), self.policy.replace('builder = "packaging/builders/gnu.json"', 'builder = "../escape.json"')]:
            with self.subTest(policy=policy):
                (self.root / "packaging/release.toml").write_text(policy)
                self.assertNotEqual(self.run_adapter().returncode, 0)

    def test_structural_toml_and_explicit_profile_required(self):
        (self.root / "Cargo.toml").write_text('[package]\nname="osslscope"\n# version="99"\nversion="0.3.1"\n[package.metadata]\nversion="88"\n')
        result = self.run_adapter()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["product_version"], "0.3.1")
        result = subprocess.run(["python3", str(ADAPTER), "--root", str(self.root), "--emit-config"], capture_output=True)
        self.assertEqual(result.returncode, 2)
        (self.root / "Cargo.toml").write_text('[package]\nname="osslscope"\nversion="0.1.0"\nversion="0.1.0"\n')
        self.assertNotEqual(self.run_adapter().returncode, 0)


if __name__ == "__main__":
    unittest.main()
