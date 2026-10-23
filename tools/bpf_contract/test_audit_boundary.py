# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail-closed controls for the independent BPF source boundary."""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit_boundary as audit

ROOT = Path(__file__).resolve().parents[2]


class BoundaryControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for rel in audit.INPUT_PATHS:
            dest = self.root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / rel, dest)

    def assert_bad(self, relative, before, after, needle):
        path = self.root / relative
        body = path.read_text()
        self.assertIn(before, body)
        path.write_text(body.replace(before, after, 1))
        self.assertIn(needle, '\n'.join(audit.inspect(self.root)))

    def test_current_source_or_preswitch_dependency_is_reported(self):
        problems = '\n'.join(audit.inspect(self.root))
        self.assertTrue(not problems or 'forbidden common dependency' in problems, problems)

    def test_forbidden_common_dependency(self):
        self.assert_bad('crates/ebpf/Cargo.toml',
                        'osslscope-bpf-contract = { path = "../bpf-contract" }',
                        'osslscope-bpf-contract = { path = "../bpf-contract" }\nosslscope-ebpf-common = { path = "../ebpf-common" }',
                        'forbidden common dependency')

    def test_common_include(self):
        self.assert_bad('crates/bpf-contract/src/lib.rs', '#![no_std]',
                        '#![no_std]\ninclude!("../../ebpf-common/src/lib.rs");',
                        'include or generated source')

    def test_generated_body(self):
        self.assert_bad('crates/bpf-contract/Cargo.toml', '[lib]',
                        'build = "build.rs"\n[lib]', 'build script')

    def test_implicit_build_script(self):
        (self.root / 'crates/bpf-contract/build.rs').write_text('fn main() {}\n')
        self.assertIn('build script', '\n'.join(audit.inspect(self.root)))

    def test_missing_import(self):
        self.assert_bad('crates/ebpf/src/bin/count.rs', 'CountValue, ', '',
                        'import/source delta')

    def test_map_flag_or_dimension_change(self):
        self.assert_bad('crates/ebpf/src/bin/count.rs',
                        'PerCpuHashMap::with_max_entries(8192, 0)',
                        'PerCpuHashMap::with_max_entries(8193, 1)',
                        'import/source delta')

    def test_host_common_change(self):
        self.assert_bad('crates/ebpf-common/src/lib.rs', 'pub ', 'pub /* drift */ ',
                        'host common changed')

    def test_named_surface_and_old_dependency(self):
        result = audit.inspect(self.root)
        joined = '\n'.join(result)
        if 'osslscope-ebpf-common' in (self.root/'crates/ebpf/Cargo.toml').read_text():
            self.assertIn('forbidden common dependency', joined)
        self.assertEqual(len(audit.imports(audit.base_text('crates/ebpf/src/bin/count.rs'), audit.OLD)), 6)

    def test_actual_candidate_passes(self):
        self.assertEqual(audit.inspect(ROOT), [])

    def test_count_comment_describes_separate_abi(self):
        body = (ROOT / 'crates/ebpf/src/bin/count.rs').read_text()
        self.assertTrue('Userspace retains separate ABI-compatible common types.' in body,
                        'separate ABI comment missing')


if __name__ == '__main__':
    unittest.main()
