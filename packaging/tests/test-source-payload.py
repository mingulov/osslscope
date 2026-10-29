#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise source payload integrity and a usable Cargo directory source."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'source_payload.py'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def archive(path, files):
    with tarfile.open(path, 'w:gz') as output:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            output.addfile(info, io.BytesIO(data))
    return path.read_bytes()


class SourcePayload(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.assertTrue(SCRIPT.is_file(), 'actual accompanying-source payload builder is missing')
        spec = importlib.util.spec_from_file_location('source_payload', SCRIPT)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.inputs = self.root/'inputs'
        self.inputs.mkdir()

    def fixture(self):
        product = self.root/'product'
        (product/'packaging').mkdir(parents=True)
        (product/'packaging/SOURCE-README.md').write_text('Source build instructions\n')
        (product/'packaging/source_payload.py').write_bytes(SCRIPT.read_bytes())
        source = self.root/'source.tar'
        archive(source, {'Cargo.toml': b'[package]\nname="sample"\nversion="0.1.0"\n', 'Cargo.lock':b'# host lock', 'crates/ebpf/Cargo.lock':b'# bpf lock'})
        crate = archive(self.inputs/'sample-1.0.0.crate', {'sample-1.0.0/Cargo.toml':b'[package]\nname="sample"\nversion="1.0.0"\nlicense="MIT"\n', 'sample-1.0.0/src/lib.rs':b'pub fn sample() {}\n', 'sample-1.0.0/LICENSE':b'original permission'})
        package = {'name':'sample', 'version':'1.0.0','source':'registry+https://github.com/rust-lang/crates.io-index','source_url':'https://static.crates.io/crates/sample/sample-1.0.0.crate','source_sha256':digest(crate),'license':'MIT','notices':[]}
        notices = {'graphs':[{'graph':'host','lock_sha256':digest(b'# host lock'),'packages':[package]}, {'graph':'bpf','lock_sha256':digest(b'# bpf lock'),'packages':[package]}]}
        pins = {'schema':'osslscope-runtime-sources-v1','components':[], 'host_std_crates':[], 'notices':[]}
        for toolchain, revision in [('1.88.0','a'*40), ('nightly-2026-05-20','b'*40)]:
            name = 'rust-src-'+toolchain
            content = {name+'/git-commit-hash':revision.encode(), name+'/rust-src/lib/rustlib/src/rust/library/Cargo.lock': b'version = 4\npackage = []\n', name+'/LICENSE-MIT': b'original Rust permission'}
            if toolchain=='nightly-2026-05-20':
                content[name+'/rust-src/lib/rustlib/src/rust/library/core/lib.rs']=b'original core source'
                content[name+'/rust-src/lib/rustlib/src/rust/library/core.rs']=b'rootcore'
                prefix=name+'/rust-src/lib/rustlib/src/rust/library/vendor/stdlib-only-2.0.0/'
                content[prefix+'Cargo.toml']=b'[package]\nname="stdlib-only"\nversion="2.0.0"\n'
                content[prefix+'LICENSE']=b'original std resolver notice'
                content[prefix+'.cargo-checksum.json']=json.dumps({'package':'f'*64,'files':{}}).encode()
            if toolchain=='nightly-2026-05-20':
                prefix=name+'/rust-src/lib/rustlib/src/rust/library/'
                library_files={path[len(prefix):]:data for path,data in content.items() if path.startswith(prefix)}
                self.library_source=self.root/'installed-library'
                for path,data in library_files.items():
                    dest=self.library_source/path;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
                rows=[{'path':path,'bytes':len(data),'sha256':digest(data)} for path,data in sorted(library_files.items())]
                encoded=(json.dumps(rows,sort_keys=True,separators=(',',':'))+'\n').encode()
                self.runtime_source={'schema':'osslscope-bpf-runtime-source-v1','toolchain':toolchain,'capture':'before-and-after-build',
                                     'library':{'schema':'osslscope-rust-library-v1','files':len(rows),'bytes':sum(row['bytes'] for row in rows),'sha256':digest(encoded)},
                                     'artifacts_sha256':digest(b'[]\n')}
            data = archive(self.inputs/(name+'.tar.xz'), content)
            pins['components'].append({'toolchain':toolchain,'archive':name+'.tar.xz','root':name,'rust_revision':revision,'bytes':len(data),'sha256':digest(data),'url':'https://static.rust-lang.org/dist/'+name+'.tar.xz'})
        (product/'packaging/runtime-sources.json').write_text(json.dumps(pins))
        return product, source, notices

    def build(self):
        product, source, notices = self.fixture()
        payload = self.root/'payload'
        manifest = self.module.stage_payload(product, self.inputs, payload, source, 'c'*40, 'd'*40,
                                             [{'role':'host-binary','bytes':123,'sha256':'e'*64}], notices, {},self.runtime_source)
        return payload, manifest

    def test_payload_binds_unique_current_graph_sources_and_prepares_vendor(self):
        payload, manifest = self.build()
        self.assertEqual(manifest['product_ref'], 'c'*40)
        self.assertEqual(manifest['product_tree'], 'd'*40)
        crates = [p for p in manifest['files'] if p['role']=='project-cargo-crate']
        self.assertEqual(len(crates), 1)
        self.assertEqual(crates[0]['graphs'], ['bpf','host'])
        self.assertEqual(manifest['artifacts'][0]['sha256'], 'e'*64)
        output = self.root/'prepared'
        self.module.prepare(payload, output)
        self.assertEqual((output/'product/vendor/sample-1.0.0/LICENSE').read_bytes(), b'original permission')
        checksum = json.loads((output/'product/vendor/sample-1.0.0/.cargo-checksum.json').read_bytes())
        self.assertEqual(checksum['files']['src/lib.rs'], digest(b'pub fn sample() {}\n'))
        self.assertEqual(checksum['package'], crates[0]['sha256'])
        self.assertTrue((output/'product/.cargo/config.toml').is_file())
        self.assertEqual((output/'product/Cargo.lock').read_bytes(), b'# host lock')
        with self.assertRaises(FileExistsError):
            self.module.prepare(payload, output)

    def test_snapshot_binds_relative_names_lengths_and_all_source_bytes(self):
        self.fixture()
        self.assertTrue(hasattr(self.module,'capture_library'),'build-time runtime source snapshot is missing')
        snapshot=self.module.capture_library(self.library_source)
        self.assertEqual(snapshot,self.runtime_source['library'])
        for mutation in ('changed','missing','extra'):
            core=self.library_source/'core/lib.rs'; original=core.read_bytes()
            if mutation=='changed': core.write_bytes(b'modified core source')
            if mutation=='missing': core.unlink()
            extra=self.library_source/'extra.rs'
            if mutation=='extra': extra.write_bytes(b'extra source')
            changed=self.module.capture_library(self.library_source)
            self.assertNotEqual(changed,snapshot)
            core.write_bytes(original);extra.unlink(missing_ok=True)

    def test_restored_installed_source_cannot_replace_the_earlier_build_snapshot(self):
        product,source,notices=self.fixture()
        self.assertTrue(hasattr(self.module,'capture_library'),'build-time runtime source snapshot is missing')
        core=self.library_source/'core/lib.rs';original=core.read_bytes();core.write_bytes(b'changed before build')
        altered=self.module.capture_library(self.library_source)
        core.write_bytes(original)  # restored before packaging; same compiler pin
        recorded=dict(self.runtime_source,library=altered)
        with self.assertRaisesRegex(ValueError,'runtime source|library source'):
            self.module.stage_payload(product,self.inputs,self.root/'restored-payload',source,'c'*40,'d'*40,[],notices,{},recorded)

    def test_preparation_includes_component_vendor_for_build_std_resolution(self):
        payload, manifest=self.build()
        output=self.root/'sysroot-vendor'
        self.module.prepare(payload,output)
        dependency=output/'product/vendor/stdlib-only-2.0.0'
        self.assertTrue(dependency.is_dir(),'nightly component resolver sources are missing from Cargo directory source')
        self.assertEqual((dependency/'LICENSE').read_bytes(),b'original std resolver notice')
        self.assertEqual(json.loads((dependency/'.cargo-checksum.json').read_bytes())['package'],'f'*64)

    def test_missing_or_mutated_locked_source_refuses_payload(self):
        product, source, notices = self.fixture()
        crate = self.inputs/'sample-1.0.0.crate'
        original = crate.read_bytes()
        for mutation in ('missing','changed','symlink'):
            with self.subTest(mutation=mutation):
                crate.unlink()
                if mutation=='changed': crate.write_bytes(b'wrong bytes')
                if mutation=='symlink': crate.symlink_to(source)
                with self.assertRaises((ValueError, OSError)):
                    self.module.stage_payload(product,self.inputs,self.root/('payload-'+mutation),source,'c'*40,'d'*40,[],notices,{},self.runtime_source)
                if crate.is_symlink(): crate.unlink()
                crate.write_bytes(original)

    def test_cached_notice_must_match_original_locked_crate(self):
        product, source, notices = self.fixture()
        package=notices['graphs'][0]['packages'][0]
        package['notices']=[{'path':'dependency-notices/sample-1.0.0/LICENSE'}]
        with self.assertRaises(ValueError):
            self.module.stage_payload(product,self.inputs,self.root/'payload',source,'c'*40,'d'*40,[],notices,
                                      {'sample-1.0.0/LICENSE':b'wrong copyright'},self.runtime_source)

    def test_stale_runtime_revision_or_host_std_checksum_refuses_payload(self):
        product, source, notices = self.fixture()
        pins_path = product/'packaging/runtime-sources.json'
        original = json.loads(pins_path.read_text())
        for mutation in ('revision','host-std'):
            pins = json.loads(json.dumps(original))
            if mutation=='revision': pins['components'][0]['rust_revision'] = 'f'*40
            else: pins['host_std_crates'] = [{'name':'sample','version':'1.0.0','sha256':'f'*64}]
            pins_path.write_text(json.dumps(pins))
            with self.assertRaises(ValueError):
                self.module.stage_payload(product,self.inputs,self.root/mutation,source,'c'*40,'d'*40,[],notices,{},self.runtime_source)

    def test_preparation_rejects_mutation_missing_and_unlisted_payloads_before_output(self):
        payload, manifest = self.build()
        source = payload/'product-source.tar'
        original = source.read_bytes()
        for mutation in ('changed','missing','unlisted'):
            output = self.root/('denied-'+mutation)
            if mutation=='changed': source.write_bytes(b'corrupt source')
            if mutation=='missing': source.unlink()
            if mutation=='unlisted': (payload/'extra.txt').write_text('unlisted')
            with self.assertRaises((ValueError,OSError)):
                self.module.prepare(payload, output)
            self.assertFalse(output.exists())
            source.write_bytes(original)
            (payload/'extra.txt').unlink(missing_ok=True)

    def test_preparation_rejects_unlisted_directory_alias(self):
        payload, manifest = self.build()
        outside = self.root/'outside'; outside.mkdir(); (outside/'private.txt').write_text('private')
        (payload/'runtime-notices/alias').symlink_to(outside,target_is_directory=True)
        output = self.root/'denied-alias'
        with self.assertRaises(ValueError):
            self.module.prepare(payload,output)
        self.assertFalse(output.exists())

    def test_preparation_preserves_executable_source_modes(self):
        payload, manifest = self.build()
        path = payload/'product-source.tar'
        files = self.module.archive_files(path.read_bytes())
        with tarfile.open(path,'w') as out:
            for name,data in files.items():
                info=tarfile.TarInfo(name); info.size=len(data); out.addfile(info,io.BytesIO(data))
            member = tarfile.TarInfo('scripts/tool'); member.mode=0o755; member.size=3
            out.addfile(member,io.BytesIO(b'run'))
        entry = next(p for p in manifest['files'] if p['path']=='product-source.tar')
        entry.update(bytes=path.stat().st_size,sha256=digest(path.read_bytes()))
        (payload/'source-manifest.json').write_text(json.dumps(manifest))
        output = self.root/'executable'
        self.module.prepare(payload,output)
        self.assertEqual((output/'product/scripts/tool').stat().st_mode & 0o777,0o755)

    def test_first_party_internal_file_link_is_materialized_but_escape_refuses(self):
        for target in ('AGENTS.md','../outside'):
            path = self.root/'first-party.tar'
            with tarfile.open(path,'w') as out:
                member=tarfile.TarInfo('AGENTS.md'); member.size=5
                out.addfile(member,io.BytesIO(b'rules'))
                link=tarfile.TarInfo('CLAUDE.md'); link.type=tarfile.SYMTYPE;link.linkname=target;out.addfile(link)
            if target=='AGENTS.md':
                self.assertEqual(self.module.archive_files(path.read_bytes(),source_links=True)['CLAUDE.md'],b'rules')
            else:
                with self.assertRaises(ValueError):
                    self.module.archive_files(path.read_bytes(),source_links=True)

    def test_archive_traversal_and_symlinks_are_rejected(self):
        for name in ('../escape', '/absolute', 'good/../../escape'):
            path = self.root/'unsafe.tar'
            data = archive(path, {name:b'forbidden'})
            with self.assertRaises(ValueError):
                self.module.archive_files(data)
        path = self.root/'link.tar'
        with tarfile.open(path,'w') as out:
            member = tarfile.TarInfo('link'); member.type = tarfile.SYMTYPE; member.linkname = '/outside'; out.addfile(member)
        with self.assertRaises(ValueError):
            self.module.archive_files(path.read_bytes())


if __name__=='__main__':
    unittest.main()
