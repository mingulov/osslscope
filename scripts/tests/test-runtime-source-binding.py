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
import json,os,struct,subprocess,sys,tomllib
from pathlib import Path
root=Path(os.environ['SOURCE_BINDING_FIXTURE']); tool=Path(sys.argv[0]).name;args=sys.argv[1:]
if tool=='rustup':
 if args and args[0]=='which':
  print(root/'tools'/('pinned-nightly-rustc' if any('nightly-' in arg for arg in args) else 'pinned-host-rustc'))
 else: print('rust-src')
 sys.exit()
if tool=='bpf-linker': print(os.environ.get('SOURCE_BINDING_LINKER_VERSION','bpf-linker 0.10.4'));sys.exit()
nightly=any('nightly-' in arg for arg in args)
if tool=='rustc' or tool.endswith('-rustc'):
 nightly=nightly or tool in ('pinned-nightly-rustc','alternate-rustc')
 if '--print' in args:
  explicit=next((arg.split('=',1)[1] for arg in args if arg.startswith('--sysroot=')),None)
  if '--sysroot' in args: explicit=args[args.index('--sysroot')+1]
  print(explicit or root/('alternate-sysroot' if tool=='alternate-rustc' else 'sysroot'))
 else: print('rustc 1.97.0-nightly (unchanged fixture revision)' if nightly else 'rustc 1.88.0 (unchanged fixture revision)')
 sys.exit()
if tool=='cache-wrapper':
 with (root/'wrapper-invocations.jsonl').open('a') as out: out.write(json.dumps(args)+'\n')
 os.execv(args[0],args)
if '--version' in args: print('cargo fixture');sys.exit()
config_path=root/'product/.cargo/config.toml'
config=tomllib.loads(config_path.read_text()) if config_path.exists() else {}
compiler=os.environ.get('RUSTC') or os.environ.get('CARGO_BUILD_RUSTC') or config.get('build',{}).get('rustc') or str(root/'tools'/('pinned-nightly-rustc' if nightly else 'pinned-host-rustc'))
wrapper=os.environ.get('RUSTC_WRAPPER') or config.get('build',{}).get('rustc-wrapper')
host_enabled=nightly and config.get('unstable',{}).get('host-config',False)
if 'CARGO_UNSTABLE_HOST_CONFIG' in os.environ: host_enabled=nightly and os.environ['CARGO_UNSTABLE_HOST_CONFIG']=='true'
if 'unstable.host-config=false' in args: host_enabled=False
_tvar='CARGO_TARGET_'+('BPFEL_UNKNOWN_NONE' if nightly else 'X86_64_UNKNOWN_LINUX_GNU')+'_RUSTFLAGS'
_ttriple='bpfel-unknown-none' if nightly else 'x86_64-unknown-linux-gnu'
if host_enabled:
 host=config.get('host',{});flags=host.get('x86_64-unknown-linux-gnu',host).get('rustflags',[])
elif 'CARGO_ENCODED_RUSTFLAGS' in os.environ: flags=os.environ['CARGO_ENCODED_RUSTFLAGS'].split('\x1f') if os.environ['CARGO_ENCODED_RUSTFLAGS'] else []
elif 'RUSTFLAGS' in os.environ: flags=os.environ['RUSTFLAGS'].split()
elif 'CARGO_BUILD_RUSTFLAGS' in os.environ: flags=os.environ['CARGO_BUILD_RUSTFLAGS'].split()
elif _tvar in os.environ: flags=os.environ[_tvar].split()
else: flags=config.get('target',{}).get(_ttriple,{}).get('rustflags',config.get('build',{}).get('rustflags',[]))
command=([wrapper] if wrapper else [])+[compiler,*flags,'--print','sysroot']
sysroot=subprocess.check_output(command,text=True).strip()
with (root/'cargo-compilers.jsonl').open('a') as out: out.write(json.dumps({'nightly':nightly,'compiler':compiler,'sysroot':sysroot,'metadata':'metadata' in args})+'\n')
with (root/'cargo-linkers.jsonl').open('a') as out: out.write(json.dumps({'nightly':nightly,'metadata':'metadata' in args,'env_linker':os.environ.get('CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER'),'flags':flags})+'\n')
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


def flags_carry_linker(flags):
    for i, flag in enumerate(flags):
        if flag == '-C' and i + 1 < len(flags) and flags[i + 1].startswith('linker'):
            return True
        if flag.startswith('-Clinker'):
            return True
    return False


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
        for name in ('cargo','rustc','rustup','bpf-linker','pinned-host-rustc','pinned-nightly-rustc','alternate-rustc','cache-wrapper'):
            path=self.bin/name;path.write_text(SHIM);path.chmod(0o755)
        self.env=dict(os.environ,PATH=str(self.bin)+os.pathsep+os.environ['PATH'],SOURCE_BINDING_FIXTURE=str(self.root))
        for selector in ('RUSTC','CARGO_BUILD_RUSTC','RUSTC_WRAPPER','CARGO_BUILD_RUSTC_WRAPPER','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_RUSTFLAGS','CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER','CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS','CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS','CARGO_UNSTABLE_HOST_CONFIG','CARGO_UNSTABLE_TARGET_APPLIES_TO_HOST'):
            self.env.pop(selector,None)
        self.manifest=self.root/'build.json'

    def build(self,options=(),**environment):
        return subprocess.run(['sh','scripts/build-dev.sh','--release','--offline','--manifest',str(self.manifest),*options],cwd=self.product,env=dict(self.env,**environment),capture_output=True,text=True)

    def test_actual_entrypoint_binds_before_after_source_and_exact_bpf_outputs(self):
        run=self.build();self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        data=json.loads(self.manifest.read_bytes())
        self.assertIn('bpf_runtime_source',data,'manifest lacks the source used by build-std')
        binding=data['bpf_runtime_source'];self.assertIsNotNone(binding)
        self.assertEqual(binding['schema'],'osslscope-bpf-runtime-source-v3')
        self.assertEqual(binding['compiler_selection'],'resolved-pinned-rustc')
        self.assertEqual(binding['source_selection'],'pinned-default-sysroot')
        self.assertEqual(data['host_rustc_path'],str(self.bin/'pinned-host-rustc'))
        self.assertEqual(data['bpf_rustc_path'],str(self.bin/'pinned-nightly-rustc'))
        rows=[{'path':'Cargo.lock','bytes':4,'sha256':digest(b'lock')},{'path':'core/lib.rs','bytes':4,'sha256':digest(b'core')}]
        encoded=(json.dumps(rows,sort_keys=True,separators=(',',':'))+'\n').encode()
        self.assertEqual(binding['library'],{'schema':'osslscope-rust-library-v1','files':2,'bytes':8,'sha256':digest(encoded)})
        bpf=[{key:entry[key] for key in ('bin','bytes','sha256')} for entry in sorted(data['artifacts'],key=lambda a:a.get('bin','')) if entry['role']=='bpf-object']
        self.assertEqual(binding['artifacts_sha256'],digest((json.dumps(bpf,sort_keys=True,separators=(',',':'))+'\n').encode()))
        self.assertEqual(binding['capture'],'before-and-after-build')
        self.assertNotIn(str(self.library),json.dumps(binding))
        self.assertIsNone(data['product_ref']);self.assertIsNone(data['product_tree'])

    def test_env_and_config_compiler_selection_cannot_diverge_from_capture(self):
        alternate=self.root/'alternate-sysroot/lib/rustlib/src/rust/library/core'
        alternate.mkdir(parents=True);(alternate/'lib.rs').write_bytes(b'different source same compiler revision')
        alt=str(self.bin/'alternate-rustc')
        for selector in ('RUSTC','CARGO_BUILD_RUSTC','build.rustc'):
            with self.subTest(selector=selector):
                config=self.product/'.cargo/config.toml';config.parent.mkdir(exist_ok=True)
                config.write_text('[build]\nrustc = '+json.dumps(alt)+'\n' if selector=='build.rustc' else '')
                log=self.root/'cargo-compilers.jsonl';log.unlink(missing_ok=True)
                environment={selector:alt} if selector!='build.rustc' else {}
                run=self.build(**environment);self.assertEqual(run.returncode,0,run.stdout+run.stderr)
                calls=[json.loads(line) for line in log.read_text().splitlines()]
                self.assertTrue(any(call['metadata'] for call in calls))
                self.assertTrue(any(not call['metadata'] for call in calls))
                for call in calls:
                    expected=self.bin/('pinned-nightly-rustc' if call['nightly'] else 'pinned-host-rustc')
                    self.assertEqual(call['compiler'],str(expected),'Cargo used a compiler/sysroot different from capture')
                    self.assertEqual(call['sysroot'],str(self.root/'sysroot'))
                data=json.loads(self.manifest.read_text())
                self.assertIn('rustc 1.88.0',data['host_rustc']);self.assertIn('rustc 1.97.0-nightly',data['bpf_rustc'])

    def test_same_compiler_host_sysroot_flags_cannot_redirect_source(self):
        alternate=self.root/'alternate-sysroot/lib/rustlib/src/rust/library/core'
        alternate.mkdir(parents=True);(alternate/'lib.rs').write_bytes(b'different source same executable')
        for table in ('host','host.x86_64-unknown-linux-gnu'):
            with self.subTest(table=table):
                config=self.product/'.cargo/config.toml';config.parent.mkdir(exist_ok=True)
                config.write_text('target-applies-to-host = false\n[unstable]\nhost-config = true\ntarget-applies-to-host = true\n['+table+']\nrustflags = ["--sysroot", '+json.dumps(str(self.root/'alternate-sysroot'))+']\n')
                log=self.root/'cargo-compilers.jsonl';log.unlink(missing_ok=True)
                run=self.build();self.assertEqual(run.returncode,0,run.stdout+run.stderr)
                calls=[json.loads(line) for line in log.read_text().splitlines()]
                self.assertTrue(any(call['nightly'] and not call['metadata'] for call in calls))
                for call in calls:
                    self.assertEqual(call['compiler'],str(self.bin/('pinned-nightly-rustc' if call['nightly'] else 'pinned-host-rustc')))
                    self.assertEqual(call['sysroot'],str(self.root/'sysroot'),'effective host sysroot differs from captured pinned root')

    def test_environment_build_and_target_flags_cannot_redirect_source(self):
        alternate=str(self.root/'alternate-sysroot')
        config=self.product/'.cargo/config.toml';config.parent.mkdir(exist_ok=True)
        for selector in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_RUSTFLAGS','CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS','build.rustflags','target.rustflags'):
            with self.subTest(selector=selector):
                config.write_text('')
                environment={}
                if selector=='CARGO_ENCODED_RUSTFLAGS': environment[selector]='--sysroot\x1f'+alternate
                elif selector in ('RUSTFLAGS','CARGO_BUILD_RUSTFLAGS','CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS'): environment[selector]='--sysroot '+alternate
                else: config.write_text(('['+('build' if selector=='build.rustflags' else 'target.x86_64-unknown-linux-gnu')+']\nrustflags = ["--sysroot='+alternate+'"]\n'))
                log=self.root/'cargo-compilers.jsonl';log.unlink(missing_ok=True)
                run=self.build(('--host-only','--check-only'),**environment);self.assertEqual(run.returncode,0,run.stdout+run.stderr)
                for call in [json.loads(line) for line in log.read_text().splitlines()]:
                    self.assertEqual(call['sysroot'],str(self.root/'sysroot'),'ambient flag source changed the pinned sysroot')

    def test_compatible_cache_wrapper_receives_the_resolved_pinned_compilers(self):
        for selector in ('RUSTC_WRAPPER','build.rustc-wrapper'):
            with self.subTest(selector=selector):
                config=self.product/'.cargo/config.toml';config.parent.mkdir(exist_ok=True)
                wrapper=str(self.bin/'cache-wrapper')
                config.write_text('[build]\nrustc-wrapper = '+json.dumps(wrapper)+'\n' if selector=='build.rustc-wrapper' else '')
                log=self.root/'wrapper-invocations.jsonl';log.unlink(missing_ok=True)
                environment={selector:wrapper} if selector=='RUSTC_WRAPPER' else {}
                run=self.build(**environment)
                self.assertEqual(run.returncode,0,run.stdout+run.stderr)
                calls=[json.loads(line) for line in log.read_text().splitlines()]
                self.assertTrue(calls,'ordinary Cargo cache wrapper was bypassed')
                self.assertEqual({args[0] for args in calls},{str(self.bin/'pinned-host-rustc'),str(self.bin/'pinned-nightly-rustc')})

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

    # System tools the entrypoint may exec, beyond the fixture's own
    # cargo/rustc/rustup shims (bpf-linker is deliberately absent).
    LINKERLESS_TOOLS = ('sh','python3','git','cat','cp','grep','dirname',
                        'sed','rm','mkdir','date','sha256sum','basename',
                        'file','readelf','pwd')

    def linkerless_path(self):
        # Hermetic absence: fixture tools first, then a private dir of
        # symlinks to exactly the system tools the script needs. No
        # system directory is retained, so an installed bpf-linker
        # cannot leak in from the ambient PATH on any machine; the
        # trailing assertion guards the construction loudly.
        tools = self.root/'linkerless-tools'
        if not tools.exists():
            tools.mkdir()
            for name in self.LINKERLESS_TOOLS:
                target = shutil.which(name)
                self.assertIsNotNone(target,'system tool missing: '+name)
                (tools/name).symlink_to(target)
        path = str(self.bin)+os.pathsep+str(tools)
        self.assertIsNone(shutil.which('bpf-linker',path=path),
                          'bpf-linker leaked into the linkerless PATH')
        return path

    def test_linker_missing_refuses_check_only(self):
        (self.bin/'bpf-linker').unlink()
        run=self.build(('--check-only',),PATH=self.linkerless_path())
        self.assertEqual(run.returncode,3,run.stdout+run.stderr)
        self.assertIn('bpf-linker not found',run.stderr)
        self.assertIn('0.10.4',run.stderr)
        self.assertFalse(self.manifest.exists())

    def test_linker_wrong_version_refuses_check_only(self):
        run=self.build(('--check-only',),SOURCE_BINDING_LINKER_VERSION='bpf-linker 0.9.1')
        self.assertEqual(run.returncode,3,run.stdout+run.stderr)
        self.assertIn('0.9.1',run.stderr)
        self.assertIn('0.10.4',run.stderr)
        self.assertFalse(self.manifest.exists())

    def test_linker_wrong_version_refuses_build(self):
        run=self.build((),SOURCE_BINDING_LINKER_VERSION='bpf-linker 0.10.5')
        self.assertEqual(run.returncode,3,run.stdout+run.stderr)
        self.assertIn('0.10.4',run.stderr)
        self.assertFalse(self.manifest.exists())

    def test_linker_pinned_version_passes_check_only(self):
        run=self.build(('--check-only',))
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        self.assertIn('bpf-linker 0.10.4',run.stdout)

    def test_host_only_ignores_linker_absence(self):
        # Host-only builds need no BPF linker; the pin applies to
        # BPF modes only, where a wrong linker would miscompile.
        (self.bin/'bpf-linker').unlink()
        run=self.build(('--host-only','--check-only'),PATH=self.linkerless_path())
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)

    def linker_calls(self):
        log=self.root/'cargo-linkers.jsonl'
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines()]

    def assert_bpf_linker_bound(self):
        # Every BPF compilation must receive the CHECKED absolute
        # linker through cargo's own selection variable, and no
        # `-C linker` may arrive through rustflags (which would
        # last-win over the binding under real cargo).
        checked=str(self.bin/'bpf-linker')
        calls=[call for call in self.linker_calls() if call['nightly'] and not call['metadata']]
        self.assertTrue(calls,'no BPF compilation cargo calls logged')
        for call in calls:
            self.assertEqual(call['env_linker'],checked,'BPF cargo call did not receive the checked linker binding')
            self.assertFalse(flags_carry_linker(call['flags']),'rustflags-carried -C linker reached BPF compilation: %r' % (call['flags'],))

    def test_bpf_linker_override_env_cannot_divert_selection(self):
        log=self.root/'cargo-linkers.jsonl';log.unlink(missing_ok=True)
        run=self.build(('--bpf-only',),CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER='/usr/bin/false')
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        self.assert_bpf_linker_bound()

    def test_bpf_linker_config_file_cannot_divert_selection(self):
        config=self.product/'.cargo/config.toml';config.parent.mkdir(exist_ok=True)
        bodies={'triple': '[target.bpfel-unknown-none]\nlinker = "/usr/bin/false"\n',
                'cfg': '[target."cfg(unix)"]\nlinker = "/usr/bin/false"\n'}
        for name, body in bodies.items():
            with self.subTest(table=name):
                config.write_text(body)
                log=self.root/'cargo-linkers.jsonl';log.unlink(missing_ok=True)
                run=self.build(('--bpf-only',))
                self.assertEqual(run.returncode,0,run.stdout+run.stderr)
                self.assert_bpf_linker_bound()

    def test_rustflags_linker_smuggling_stays_suppressed(self):
        config=self.product/'.cargo/config.toml';config.parent.mkdir(exist_ok=True)
        hostile='-C linker=/usr/bin/false'
        for selector in ('CARGO_BUILD_RUSTFLAGS','CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS','build.rustflags','target.rustflags'):
            with self.subTest(selector=selector):
                config.write_text('')
                environment={'CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER': '/usr/bin/false'}
                if selector in ('CARGO_BUILD_RUSTFLAGS','CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS'):
                    environment[selector]=hostile
                elif selector == 'build.rustflags':
                    config.write_text('[build]\nrustflags = ["-Clinker=/usr/bin/false"]\n')
                else:
                    config.write_text('[target.bpfel-unknown-none]\nrustflags = ["-Clinker=/usr/bin/false"]\n')
                log=self.root/'cargo-linkers.jsonl';log.unlink(missing_ok=True)
                run=self.build(('--bpf-only',),**environment)
                self.assertEqual(run.returncode,0,run.stdout+run.stderr)
                self.assert_bpf_linker_bound()


if __name__=='__main__':
    unittest.main()
