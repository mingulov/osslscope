#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline staging contract; synthetic ELFs do not qualify installed tracing."""
import hashlib
import contextlib
import io
import sys
from unittest.mock import patch
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'build-package.py'


class CurrentPackage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.assertTrue(SCRIPT.is_file(), 'current five-role package builder is missing')
        spec = importlib.util.spec_from_file_location('package_builder', SCRIPT)
        self.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.builder)
        self.roles = ('harvest', 'count', 'members', 'provider-observation', 'focused-count')
        self.arts = []
        for name in ('osslscope', *('osslscope-' + r for r in self.roles)):
            host = name == 'osslscope'
            data = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01' + bytes(9), 3 if host else 1, 62 if host else 247, 1, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0) + name.encode()
            path = self.root / name
            path.write_bytes(data)
            path.chmod(0o755 if host else 0o644)
            entry = {'role': 'host-binary' if host else 'bpf-object', 'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'product_ref': 'a'*40, 'product_tree': 'b'*40}
            if not host:
                entry['bin'] = name
            self.arts.append(entry)
        self.manifest = {'schema': 'osslscope-dev-build-manifest-v1', 'product_ref': 'a'*40, 'product_tree': 'b'*40, 'product_dirty': False, 'host_toolchain': '1.88.0', 'bpf_toolchain': 'nightly-2026-05-20', 'bpf_linker': 'bpf-linker 0.10.4', 'bpf_target': 'bpfel-unknown-none', 'host_profile': 'release', 'mode': 'both', 'artifacts': self.arts}
        rows=[{key:entry[key] for key in ('bin','bytes','sha256')} for entry in sorted(self.arts[1:],key=lambda a:a['bin'])]
        encoded=(json.dumps(rows,sort_keys=True,separators=(',',':'))+'\n').encode()
        self.manifest['bpf_runtime_source']={'schema':'osslscope-bpf-runtime-source-v1','toolchain':'nightly-2026-05-20',
            'capture':'before-and-after-build','library':{'schema':'osslscope-rust-library-v1','files':1,'bytes':4,'sha256':'f'*64},
            'artifacts_sha256':hashlib.sha256(encoded).hexdigest()}


    def test_current_manifest_requires_exactly_all_five_nonempty_roles(self):
        selected = self.builder.select_artifacts(self.manifest, 'a'*40, 'b'*40)
        self.assertEqual(set(selected), {'osslscope', *('osslscope-'+r for r in self.roles)})
        self.manifest['artifacts'] = self.arts[:4]
        with self.assertRaisesRegex(ValueError, 'six|five|role'):
            self.builder.select_artifacts(self.manifest, 'a'*40, 'b'*40)

    def test_rejects_each_stale_mixed_duplicate_empty_or_wrong_elf_role(self):
        for i in range(6):
            for mutation in ('hash', 'source', 'missing', 'duplicate', 'empty', 'elf', 'symlink'):
                with self.subTest(i=i, mutation=mutation):
                    entries = json.loads(json.dumps(self.arts))
                    manifest = dict(self.manifest, artifacts=entries)
                    path = Path(entries[i]['path'])
                    original = path.read_bytes()
                    if mutation == 'hash': entries[i]['sha256'] = '0'*64
                    elif mutation == 'source': entries[i]['product_ref'] = 'c'*40
                    elif mutation == 'missing': entries.pop(i)
                    elif mutation == 'duplicate': entries[i] = entries[(i+1)%6]
                    elif mutation == 'empty': path.write_bytes(b'')
                    elif mutation == 'elf':
                        path.write_bytes(b'not elf')
                        entries[i].update(bytes=7, sha256=hashlib.sha256(b'not elf').hexdigest())
                    else:
                        path.rename(path.with_suffix('.saved'))
                        path.symlink_to(path.with_suffix('.saved'))
                    try:
                        with self.assertRaises(ValueError):
                            self.builder.select_artifacts(manifest, 'a'*40, 'b'*40)
                    finally:
                        if path.is_symlink(): path.unlink()
                        path.write_bytes(original)

    def test_rejects_unproven_source_debug_and_wrong_recipe(self):
        for key, value in [('schema', 'old'), ('product_dirty', True), ('product_ref', 'c'*40), ('product_tree', 'c'*40), ('host_profile', 'dev'), ('mode', 'host'), ('bpf_toolchain', 'nightly'), ('host_toolchain', 'stable'), ('bpf_linker', 'bpf-linker 0.10.5')]:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    self.builder.select_artifacts(dict(self.manifest, **{key:value}), 'a'*40, 'b'*40)

    def test_missing_old_or_different_artifact_runtime_binding_refuses_current_packages(self):
        for mutation in ('missing','old','artifact','library'):
            candidate=json.loads(json.dumps(self.manifest))
            if mutation=='missing': del candidate['bpf_runtime_source']
            elif mutation=='old': candidate['bpf_runtime_source']['schema']='old'
            elif mutation=='artifact': candidate['bpf_runtime_source']['artifacts_sha256']='0'*64
            else: candidate['bpf_runtime_source']['library']['files']=0
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError,'runtime source'):
                self.builder.select_artifacts(candidate,'a'*40,'b'*40)

    def test_staging_is_deterministic_receipt_binds_host_and_five_roles(self):
        artifacts = self.builder.select_artifacts(self.manifest, 'a'*40, 'b'*40)
        receipts = []
        for name in ('one', 'two'):
            dest = self.root / name
            self.builder.stage_artifacts(dest, '/usr', self.manifest, artifacts)
            receipt = (dest / 'share/osslscope/install-manifest.json').read_bytes()
            receipts.append(receipt)
            parsed = json.loads(receipt)
            self.assertEqual(parsed['schema'], 'osslscope-install-manifest-v2')
            self.assertEqual(len(parsed['artifacts']), 6)
            for entry in parsed['artifacts']:
                relative = Path(entry['dest']).relative_to('/usr')
                data = (dest/relative).read_bytes()
                self.assertEqual(entry['sha256'], hashlib.sha256(data).hexdigest())
                self.assertGreater(len(data), 64)
                self.assertEqual((dest/relative).stat().st_mode & 0o777, 0o755 if entry['role']=='host-binary' else 0o644)
        self.assertEqual(*receipts)
        with self.assertRaises(FileExistsError):
            self.builder.stage_artifacts(self.root/'one', '/usr', self.manifest, artifacts)

    def test_full_prefix_install_emits_current_runtime_receipt(self):
        manifest = self.root/'build.json'
        manifest.write_text(json.dumps(self.manifest))
        prefix = self.root/'installed'
        result = subprocess.run(['sh', str(SCRIPT.parents[1]/'scripts/install-dev.sh'), '--manifest', str(manifest), '--prefix', str(prefix)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        receipt = json.loads((prefix/'share/osslscope/install-manifest.json').read_bytes())
        self.assertEqual(receipt['schema'], 'osslscope-install-manifest-v2')
        self.assertEqual(len(receipt['artifacts']), 6)
        self.assertEqual(set(receipt), {'schema','prefix','product_ref','product_dirty','artifacts'})

    def test_prefix_install_rejects_mixed_current_source_before_writing(self):
        self.manifest['artifacts'][4]['product_ref'] = 'c'*40
        manifest = self.root/'build.json'
        manifest.write_text(json.dumps(self.manifest))
        prefix = self.root/'installed'
        result = subprocess.run(['sh', str(SCRIPT.parents[1]/'scripts/install-dev.sh'), '--manifest', str(manifest), '--prefix', str(prefix)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertFalse(prefix.exists())

    def test_source_bearing_partial_manifests_compose_explicit_v1_installs(self):
        # These are the actual producer modes: --bpf-only emits five BPF
        # records, --host-only emits the CLI. Explicit selections complete
        # diagnostic installs without promoting them to a normal v2 set.
        installer = str(SCRIPT.parents[1]/'scripts/install-dev.sh')
        for mode, entries, options, expected_count, explicit_names in [
            ('bpf', self.arts[1:], ['--binary', self.arts[0]['path']], 6, {'osslscope'}),
            ('host', self.arts[:1], ['--harvest', self.arts[1]['path'], '--count', self.arts[2]['path']], 3, {'osslscope-harvest','osslscope-count'}),
        ]:
            with self.subTest(mode=mode):
                manifest = self.root/(mode+'.json')
                manifest.write_text(json.dumps(dict(self.manifest, mode=mode, artifacts=entries)))
                prefix = self.root/('installed-'+mode)
                result = subprocess.run(['sh', installer, '--manifest', str(manifest), '--prefix', str(prefix), *options], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
                receipt = json.loads((prefix/'share/osslscope/install-manifest.json').read_bytes())
                self.assertEqual(receipt['schema'], 'osslscope-install-manifest-v1')
                self.assertEqual(len(receipt['artifacts']), expected_count)
                self.assertIsNone(receipt['product_ref'])
                for entry in receipt['artifacts']:
                    name = entry.get('bin','osslscope')
                    self.assertEqual(entry['selection'], 'explicit-override' if name in explicit_names else 'manifest-verified')
                    self.assertEqual(entry['product_ref'], None if name in explicit_names else 'a'*40)
                    self.assertEqual(hashlib.sha256(Path(entry['dest']).read_bytes()).hexdigest(), entry['sha256'])
                # The same partial input cannot become a normal current install.
                normal = self.root/('normal-'+mode)
                denied = subprocess.run(['sh', installer, '--manifest', str(manifest), '--prefix', str(normal)], capture_output=True, text=True)
                self.assertNotEqual(denied.returncode, 0)
                self.assertFalse(normal.exists())
                # Implicitly selected records still need source and byte proof
                # even when explicit inputs complete a diagnostic v1 install.
                original = manifest.read_bytes()
                for field, value in [('product_ref', 'c'*40), ('sha256', '0'*64)]:
                    changed = json.loads(original)
                    changed['artifacts'][0][field] = value
                    manifest.write_text(json.dumps(changed))
                    refused = self.root/('bad-'+mode+'-'+field)
                    result = subprocess.run(['sh', installer, '--manifest', str(manifest), '--prefix', str(refused), *options], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(refused.exists())

    def test_restored_aya_notices_require_exact_registry_and_vcs_source(self):
        # Lockfile identity is independently read; source VCS identity is fixed
        # by the published crate archive, not selected by the caller.
        import tomllib
        lock = tomllib.loads((SCRIPT.parents[1]/'crates/ebpf/Cargo.lock').read_text())
        checksum = next(p['checksum'] for p in lock['package'] if p['name']=='aya-ebpf' and p['version']=='0.2.1')
        self.assertTrue(hasattr(self.builder, 'restored_notices'), 'exact-source license notice restoration is missing')
        notice = self.builder.restored_notices('aya-ebpf', '0.2.1', checksum, '773ca715385b97eb0c26a581b53246c0c4306959')
        self.assertEqual(notice['selected_license'], 'MIT')
        self.assertEqual(len(notice['texts']), 2)
        self.assertTrue(any(b'Copyright (c) 2021 Alessandro Decina' in n['data'] for n in notice['texts']))
        for version, digest, vcs in [('0.2.2', checksum, '773ca715385b97eb0c26a581b53246c0c4306959'), ('0.2.1', '0'*64, '773ca715385b97eb0c26a581b53246c0c4306959'), ('0.2.1', checksum, '0'*40)]:
            with self.assertRaises(ValueError):
                self.builder.restored_notices('aya-ebpf', version, digest, vcs)

    def test_compiler_revision_validation_keeps_product_version_for_source_archive(self):
        # The external Git/Cargo boundaries are stopped at the archive command;
        # exercise main's actual version selection and artifact validation.
        (self.root/'Cargo.toml').write_text('[package]\nversion="12.34.56"\n')
        (self.root/'packaging').mkdir()
        (self.root/'packaging/runtime-sources.json').write_text(json.dumps({'components':[
            {'toolchain':'1.88.0','rust_revision':'a'*40}]}))
        manifest=self.root/'build.json'; manifest.write_text(json.dumps(self.manifest))
        archive_names=[]
        def run(command, **kwargs):
            if command[0]=='rustc': return ('rustc 1.88.0\ncommit-hash: '+'a'*40+'\n').encode()
            if command[-1]=='a'*40 and 'show' in command: return b'1\n'
            if 'archive' in command:
                archive_names.append(Path(next(arg.removeprefix('--output=') for arg in command if arg.startswith('--output='))).name)
                raise ValueError('archive boundary reached')
            raise AssertionError(command)
        argv=[str(SCRIPT),'--manifest',str(manifest),'--source-archives',str(self.root),'--output',str(self.root/'output')]
        with patch.object(self.builder,'ROOT',self.root), patch.object(self.builder,'source_identity',return_value=('a'*40,'b'*40)), patch.object(self.builder,'dependency_notices',return_value=({},{})), patch.object(self.builder,'run',side_effect=run), patch.object(sys,'argv',argv), patch.object(sys,'path',[str(SCRIPT.parent),*sys.path]), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit): self.builder.main()
        self.assertEqual(archive_names,['osslscope-12.34.56-source.tar'])
        self.assertFalse((self.root/'output').exists())

    def test_rejects_artifact_changed_after_selection_before_receipt_publication(self):
        artifacts = self.builder.select_artifacts(self.manifest, 'a'*40, 'b'*40)
        Path(self.arts[4]['path']).write_bytes(b'changed')
        with self.assertRaises(ValueError):
            self.builder.stage_artifacts(self.root/'stage', '/usr', self.manifest, artifacts)
        self.assertFalse((self.root/'stage/share/osslscope/install-manifest.json').exists())


if __name__ == '__main__':
    unittest.main()
