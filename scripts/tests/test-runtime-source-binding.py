#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build-manifest source custody with owned trees and synthetic Cargo outputs.

No Rust compilation, installed source mutation, tracing or privileged work.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SHIM = r'''#!/usr/bin/env python3
import json,os,struct,sys
from pathlib import Path
root=Path(os.environ['SOURCE_BINDING_FIXTURE']); tool=Path(sys.argv[0]).name;args=sys.argv[1:]
if tool=='rustup': print('rust-src');sys.exit()
if tool=='bpf-linker': print('bpf-linker 0.10.4');sys.exit()
nightly=any('nightly-' in arg for arg in args)
if tool=='rustc':
 if '--print' in args: print(root/'sysroot')
 else: print('rustc 1.97.0-nightly (unchanged fixture revision)' if nightly else 'rustc 1.88.0 (unchanged fixture revision)')
 sys.exit()
if '--version' in args: print('cargo fixture');sys.exit()
if 'metadata' in args: print(json.dumps({'target_directory':str(root/'outputs')}));sys.exit()
if 'build' not in args: raise SystemExit('unexpected fixture command')
names=['osslscope-'+name for name in ('harvest','count','members','provider-observation','focused-count')] if nightly else ['osslscope']
for name in names:
 host=name=='osslscope';data=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),3 if host else 1,62 if host else 247,1,0,0,0,0,64,0,0,0,0,0)+name.encode()
 path=root/'outputs'/('host' if host else 'bpf')/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(0o755 if host else 0o644)
 print(json.dumps({'reason':'compiler-artifact','target':{'name':name,'kind':['bin']},'executable':str(path)}))
if nightly:
 source=root/'sysroot/lib/rustlib/src/rust/library/core/lib.rs';mutation=os.environ.get('SOURCE_BINDING_MUTATION')
 if mutation=='changed': source.write_bytes(b'changed source during build')
 elif mutation=='missing': source.unlink()
 elif mutation=='extra': (source.parent/'extra.rs').write_bytes(b'extra source during build')
'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


class BuildSourceBinding(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.product=self.root/'product'
        for name in ('scripts','packaging','crates/ebpf'):(self.product/name).mkdir(parents=True)
        shutil.copyfile(ROOT/'scripts/build-dev.sh',self.product/'scripts/build-dev.sh')
        shutil.copyfile(ROOT/'packaging/source_payload.py',self.product/'packaging/source_payload.py')
        self.library=self.root/'sysroot/lib/rustlib/src/rust/library'
        (self.library/'core').mkdir(parents=True)
        (self.library/'Cargo.lock').write_bytes(b'lock')
        (self.library/'core/lib.rs').write_bytes(b'core')
        self.bin=self.root/'tools';self.bin.mkdir()
        for name in ('cargo','rustc','rustup','bpf-linker'):
            path=self.bin/name;path.write_text(SHIM);path.chmod(0o755)
        self.env=dict(os.environ,PATH=str(self.bin)+os.pathsep+os.environ['PATH'],SOURCE_BINDING_FIXTURE=str(self.root))
        self.manifest=self.root/'build.json'

    def build(self,options=(),**environment):
        return subprocess.run(['sh','scripts/build-dev.sh','--release','--offline','--manifest',str(self.manifest),*options],cwd=self.product,env=dict(self.env,**environment),capture_output=True,text=True)

    def test_actual_entrypoint_binds_before_after_source_and_exact_bpf_outputs(self):
        run=self.build();self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        data=json.loads(self.manifest.read_bytes())
        self.assertIn('bpf_runtime_source',data,'manifest lacks the source used by build-std')
        binding=data['bpf_runtime_source'];self.assertIsNotNone(binding)
        rows=[{'path':'Cargo.lock','bytes':4,'sha256':digest(b'lock')},{'path':'core/lib.rs','bytes':4,'sha256':digest(b'core')}]
        encoded=(json.dumps(rows,sort_keys=True,separators=(',',':'))+'\n').encode()
        self.assertEqual(binding['library'],{'schema':'osslscope-rust-library-v1','files':2,'bytes':8,'sha256':digest(encoded)})
        bpf=[{key:entry[key] for key in ('bin','bytes','sha256')} for entry in sorted(data['artifacts'],key=lambda a:a.get('bin','')) if entry['role']=='bpf-object']
        self.assertEqual(binding['artifacts_sha256'],digest((json.dumps(bpf,sort_keys=True,separators=(',',':'))+'\n').encode()))
        self.assertEqual(binding['capture'],'before-and-after-build')
        self.assertNotIn(str(self.library),json.dumps(binding))
        self.assertIsNone(data['product_ref']);self.assertIsNone(data['product_tree'])

    def test_source_changed_missing_or_extra_during_build_refuses_manifest(self):
        for mutation in ('changed','missing','extra'):
            with self.subTest(mutation=mutation):
                (self.library/'core/lib.rs').write_bytes(b'core');(self.library/'core/extra.rs').unlink(missing_ok=True)
                self.manifest.unlink(missing_ok=True)
                run=self.build(SOURCE_BINDING_MUTATION=mutation)
                self.assertNotEqual(run.returncode,0,'source change under unchanged compiler revision was accepted')
                self.assertIn('runtime',run.stderr)
                self.assertFalse(self.manifest.exists())

    def test_missing_effective_source_and_override_refuse_preflight(self):
        shutil.rmtree(self.library)
        run=self.build(('--check-only',))
        self.assertNotEqual(run.returncode,0,'missing installed rust-src bytes passed preflight')
        self.assertFalse(self.manifest.exists())
        self.library.mkdir(parents=True);(self.library/'core.rs').write_bytes(b'core')
        run=self.build(('--check-only',),__CARGO_TESTS_ONLY_SRC_ROOT=str(self.library))
        self.assertNotEqual(run.returncode,0,'Cargo source override bypassed the captured installed source')

    def test_host_only_and_check_only_do_not_claim_a_bpf_source_build(self):
        for options in (('--host-only',),('--check-only',)):
            with self.subTest(options=options):
                run=self.build(options);self.assertEqual(run.returncode,0,run.stdout+run.stderr)
                self.assertIsNone(json.loads(self.manifest.read_bytes()).get('bpf_runtime_source'))


if __name__=='__main__':
    unittest.main()
