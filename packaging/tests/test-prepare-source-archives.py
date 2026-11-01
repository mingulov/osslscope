#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise pinned source-archive preparation without network access."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "prepare-source-archives.py"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def digest(data):
    return hashlib.sha256(data).hexdigest()


class PrepareSourceArchives(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.assertTrue(SCRIPT.is_file(), "source archive preparation helper is missing")
        spec = importlib.util.spec_from_file_location("prepare_source_archives", SCRIPT)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

        self.product = self.root / "product"
        self.cache = self.root / "cache"
        self.output = self.root / "archives"
        (self.product / "crates/ebpf").mkdir(parents=True)
        (self.product / "packaging").mkdir()
        self.cache.mkdir()

        self.locked = b"locked crate bytes"
        self.host_std = b"host std crate bytes"
        self.component = b"rust-src component bytes"
        (self.cache / "sample-1.0.0.crate").write_bytes(self.locked)
        (self.cache / "stdonly-2.0.0.crate").write_bytes(self.host_std)
        (self.cache / "rust-src-test.tar.xz").write_bytes(self.component)

        lock = f"""version = 4

[[package]]
name = "local"
version = "0.1.0"

[[package]]
name = "sample"
version = "1.0.0"
source = "{REGISTRY}"
checksum = "{digest(self.locked)}"
"""
        (self.product / "Cargo.lock").write_text(lock)
        (self.product / "crates/ebpf/Cargo.lock").write_text(lock)
        pins = {
            "schema": "osslscope-runtime-sources-v1",
            "components": [
                {
                    "archive": "rust-src-test.tar.xz",
                    "bytes": len(self.component),
                    "sha256": digest(self.component),
                    "url": "https://example.invalid/rust-src-test.tar.xz",
                }
            ],
            "host_std_crates": [
                {
                    "name": "stdonly",
                    "version": "2.0.0",
                    "bytes": len(self.host_std),
                    "sha256": digest(self.host_std),
                }
            ],
        }
        (self.product / "packaging/runtime-sources.json").write_text(json.dumps(pins))
        self.module.ROOT = self.product

    def test_offline_stages_locked_runtime_and_host_std_archives(self):
        self.assertEqual(self.module.prepare(self.output, [self.cache], offline=True), 0)
        self.assertEqual((self.output / "sample-1.0.0.crate").read_bytes(), self.locked)
        self.assertEqual((self.output / "stdonly-2.0.0.crate").read_bytes(), self.host_std)
        self.assertEqual(
            (self.output / "rust-src-test.tar.xz").read_bytes(), self.component
        )

    def test_offline_missing_archive_is_a_prerequisite_failure(self):
        (self.cache / "sample-1.0.0.crate").unlink()
        self.assertEqual(self.module.prepare(self.output, [self.cache], offline=True), 3)
        self.assertFalse((self.output / "sample-1.0.0.crate").exists())

    def test_download_hash_mismatch_leaves_no_partial_output(self):
        bad = self.root / "bad.crate"
        bad.write_bytes(b"wrong bytes")
        destination = self.root / "downloaded.crate"
        with self.assertRaisesRegex(ValueError, "hash or size mismatch"):
            self.module.stage_one(
                destination,
                digest(b"expected bytes"),
                url=bad.as_uri(),
            )
        self.assertFalse(destination.exists())
        self.assertFalse((self.root / "downloaded.crate.part").exists())


if __name__ == "__main__":
    unittest.main()
