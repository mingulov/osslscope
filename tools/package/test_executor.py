# SPDX-License-Identifier: GPL-3.0-or-later
"""Tiny independent source controls; these do not admit a worker or real SDK."""
import copy
import contextlib
import errno
import gzip
import hashlib
import importlib.util
import io
import json
import pathlib
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

PRODUCT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = PRODUCT / 'scripts/package-executor.py'


def load():
    if not SCRIPT.exists():
        raise AssertionError('missing pure descriptor/layout API: package-executor.py')
    spec = importlib.util.spec_from_file_location('package_executor', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


COMMON = [('LC_ALL', 'C'), ('TZ', 'UTC'), ('SOURCE_DATE_EPOCH', '1792799804'),
          ('CARGO_NET_OFFLINE', 'true'), ('CARGO_BUILD_JOBS', '2'),
          ('RUSTFLAGS', '--remap-path-prefix=/build=.')]
GNU = 'x86_64-unknown-linux-gnu'
MUSL = 'x86_64-unknown-linux-musl'
HOST = ['cargo', 'build', '--release', '--frozen', '--offline', '--target', GNU,
        '--jobs', '2', '--bin', 'osslscope', '--message-format=json-render-diagnostics']
BPF = ['cargo', 'build', '--release', '--frozen', '--offline', '-Z', 'build-std=core',
       '--target', 'bpfel-unknown-none', '--jobs', '2', '--bin', 'osslscope-harvest',
       '--bin', 'osslscope-count', '--bin', 'osslscope-members',
       '--message-format=json-render-diagnostics']


def recipe(target=GNU):
    argv = HOST.copy()
    argv[6] = target
    return dict(schema='osslscope-build-recipe-v2', host_profile={'target': target},
                jobs=2, argv=argv, bpf_argv=BPF.copy(),
                environment=[dict(name=n, value=v) for n, v in COMMON],
                determinism={'path_remap': '--remap-path-prefix=/build=.'})


def tree_archive(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        rows = []
        for path, kind, content in entries:
            info = tarfile.TarInfo(path)
            mode = {'file': 0o755, 'directory': 0o755, 'symlink': 0o777}[kind]
            info.mode = mode
            row = dict(path=path, kind=kind, mode=mode)
            if kind == 'file':
                info.size = len(content)
                row.update(bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
                tar.addfile(info, io.BytesIO(content))
            elif kind == 'directory':
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.type = tarfile.SYMTYPE
                info.linkname = content
                row['target'] = content
                tar.addfile(info)
            rows.append(row)
    return out.getvalue(), dict(schema='osslscope-tool-tree-v1', entries=sorted(rows, key=lambda r: r['path']))


def layout_fixture(m, target=GNU, std_lock=None):
    """Independent tiny member packet; no fixture represents an actual SDK."""
    assets = {}
    def add(path, data):
        entry = dict(path=path, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        assets[canonical(entry)] = data
        return entry
    structures = {
        'rootfs': [('build', 'directory', None), ('dev', 'directory', None), ('proc', 'directory', None)],
        'host': [('bin', 'directory', None), ('bin/cargo', 'file', b'cargo'), ('bin/rustc', 'file', b'rustc'),
                 ('lib', 'directory', None), ('lib/rustlib', 'directory', None), ('lib/rustlib/host', 'file', b'host')],
        'bpf': [('bin', 'directory', None), ('bin/cargo', 'file', b'bpf-cargo'), ('bin/rustc', 'file', b'bpf-rustc'),
                ('lib', 'directory', None), ('lib/rustlib', 'directory', None), ('lib/rustlib/src', 'directory', None),
                ('lib/rustlib/src/rust', 'directory', None), ('lib/rustlib/src/rust/source', 'file', b'rust-source')],
        'linker': [('bin', 'directory', None), ('bin/bpf-linker', 'file', b'linker')],
        'llvm': [('lib', 'directory', None), ('lib/libExact.so', 'file', b'llvm')],
        'native': [('bin', 'directory', None), ('bin/ar', 'file', b'ar'), ('bin/cc', 'file', b'cc'),
                   ('bin/ld', 'file', b'ld'), ('lib', 'directory', None), ('sysroot', 'directory', None), ('sysroot/header', 'file', b'header')],
        'build': [('bin', 'directory', None), ('bin/ar', 'file', b'ar'), ('bin/cc', 'file', b'cc'),
                  ('bin/ld', 'file', b'ld'), ('sysroot', 'directory', None), ('sysroot/header', 'file', b'header')],
        'package': [('format-tool', 'file', b'package')],
    }
    if std_lock is not None:
        structures['bpf'] += [('lib/rustlib/src/rust/library', 'directory', None),
                             ('lib/rustlib/src/rust/library/Cargo.lock', 'file', std_lock)]
    trees, acquisitions, archives = {}, {}, []
    for root, entries in structures.items():
        raw, trees[root] = tree_archive(entries)
        acquisitions[root] = add(root+'.tar', raw)
        tree_entry = add(root+'.tree.json', canonical(trees[root]))
        archives.append(dict(acquisition=acquisitions[root], tree=tree_entry, root=root))
    mapping = {
        'host': ('host', 'bin/rustc', 'file'), 'host-cargo': ('host', 'bin/cargo', 'file'),
        'bpf': ('bpf', 'bin/rustc', 'file'), 'bpf-cargo': ('bpf', 'bin/cargo', 'file'),
        'linker': ('linker', 'bin/bpf-linker', 'file'), 'llvm': ('llvm', 'lib', 'tree'),
        'llvm-library': ('llvm', 'lib/libExact.so', 'file'), 'builder': ('rootfs', '', 'tree'),
        'host-sysroot': ('host', 'lib/rustlib', 'tree'), 'bpf-sysroot': ('bpf', 'lib/rustlib', 'tree'),
        'rust-src': ('bpf', 'lib/rustlib/src/rust', 'tree'), 'sysroot': ('native', 'sysroot', 'tree'),
        'native-compiler': ('native', 'bin/cc', 'file'), 'native-linker': ('native', 'bin/ld', 'file'),
        'archive': ('native', 'bin/ar', 'file'), 'build-compiler': ('build', 'bin/cc', 'file'),
        'build-linker': ('build', 'bin/ld', 'file'), 'build-archive': ('build', 'bin/ar', 'file'),
        'build-sysroot': ('build', 'sysroot', 'tree'), 'package': ('package', '', 'tree')}
    # Whole-tree data resources bind each tree manifest without inventing a phase.
    mapping.update({root+'-tree': (root, '', 'tree') for root in structures})
    resources, bindings = [], []
    for role, (root, member, kind) in sorted(mapping.items()):
        if kind == 'file':
            data = next(v for p, k, v in structures[root] if p == member)
        else:
            entries = []
            for row in trees[root]['entries']:
                if not member or row['path'].startswith(member+'/'):
                    entries.append(dict(row, path=row['path'][len(member)+1:] if member else row['path']))
            data = canonical(dict(schema='osslscope-tool-tree-v1', entries=entries))
        content = add(role+'.content', data)
        resources.append(dict(role=role, content=content, acquisition=acquisitions[root]))
        bindings.append(dict(role=role, archive_sha256=acquisitions[root]['sha256'], member=member, kind=kind))
    # Reuse exactly the retained tree entry identities, independent of its locator.
    for row in archives:
        row['tree'] = next(r['content'] for r in resources if r['role'] == row['root']+'-tree')
    host_entries = [('usr', 'directory', None), ('usr/bin', 'directory', None),
                    ('usr/bin/bwrap', 'file', b'bwrap'), ('usr/bin/python3.11', 'file', b'python')]
    host_tar, host_tree = tree_archive(host_entries)
    host = dict(schema='osslscope-executor-host-v1', files=[{k: v for k, v in dict(row, path='/'+row['path']).items() if k != 'kind'}
                for row in host_tree['entries'] if row['kind'] == 'file'], links=[])
    resources.append(dict(role='executor-host', content=add('host.json', canonical(host)), acquisition=add('host-runtime.tar', host_tar)))
    layout = dict(schema='osslscope-executor-layout-v1', archives=sorted(archives, key=lambda r: (r['root'], r['acquisition']['path'])), bindings=bindings)
    layout_bytes = canonical(layout)
    layout_tar, _ = tree_archive([('layout.json', 'file', layout_bytes)])
    # Layout acquisition is an ordinary 0644 file, not an executable.
    raw = bytearray(layout_tar)
    raw[100:108] = b'0000644\0'
    raw[148:156] = b'        '
    raw[148:156] = ('%06o\0 ' % sum(raw[:512])).encode()
    resources.append(dict(role='executor-layout', content=add('layout.json', layout_bytes), acquisition=add('layout.tar', bytes(raw))))
    rec = recipe(target)
    rec['resources'] = resources
    return rec, layout, host, assets


def public_packet(m, parent, target):
    """Closed SOURCE packet; its real-lock vendor integration remains unavailable.

    Selected policy files are copied verbatim. No fixed hash/table/validator is
    replaced. All other resource/terms bytes are explicitly synthetic.
    """
    source, inputs = parent/'source', parent/'inputs'
    source.mkdir()
    inputs.mkdir()
    rec, layout, _, assets = layout_fixture(m, target)
    def add(path, data):
        entry = dict(path=path, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        assets[canonical(entry)] = data
        return entry
    for path in list(m.POLICY_FILES)+['crates/ebpf/Cargo.lock', 'packaging/release.toml']:
        (source/path).parent.mkdir(parents=True, exist_ok=True)
        (source/path).write_bytes((PRODUCT/path).read_bytes())
    (source/'crates/ebpf/Cargo.toml').write_bytes(b'[package]\nname="osslscope-ebpf"\nversion="0.0.0"\nlicense="GPL-2.0-only"\n')
    tiny_source, _ = tree_archive([('source.c', 'file', b'/* synthetic source only */\n')])
    tiny = add('sources/synthetic.tar', tiny_source)
    license_entry = add('terms/synthetic.txt', b'Synthetic source fixture; actual rights not established.\n')
    availability = add('terms/availability.txt', b'Synthetic fixture source is retained.\n')
    terms = dict(spdx='MIT', license_files=[license_entry], notice_files=[], source_availability=availability)
    required = ['host', 'bpf', 'linker', 'llvm', 'builder', 'rust-src', 'sysroot', 'native-compiler',
                'native-linker', 'archive', 'package', 'host-cargo', 'bpf-cargo', 'llvm-library',
                'host-sysroot', 'bpf-sysroot', 'build-compiler', 'build-linker', 'build-archive',
                'build-sysroot', 'executor-host', 'executor-layout']
    resources = sorted(rec['resources'], key=lambda r: required.index(r['role']) if r['role'] in required else len(required))
    components = []
    for row in resources:
        role = row['role']
        version = ('1.88.0' if role in ['host', 'host-cargo', 'host-sysroot'] else
                   'nightly-2026-05-20' if role in ['bpf', 'bpf-cargo', 'bpf-sysroot', 'rust-src'] else
                   '0.10.4' if role == 'linker' else 'synthetic')
        row['identity'] = dict(name=role+'-synthetic', version=version, sha256=row['content']['sha256'])
        row['source_component'] = role+'-source'
        components.append(dict(id=role+'-source', name=role+'-source', version='synthetic',
                               source=dict(kind='native', location='https://example.invalid/synthetic', archive=tiny),
                               terms=terms, dependencies=[]))
    tool_sources = [r['source_component'] for r in resources]
    for identifier in ['core', 'compiler_builtins', 'stdarch', 'portable-simd', 'linker-build', 'native-runtime']:
        components.append(dict(id=identifier, name=identifier, version='synthetic',
                               source=dict(kind='native', location='https://example.invalid/synthetic', archive=tiny),
                               terms=terms, dependencies=[]))
    for identifier, name, version, manifest in [('host', 'osslscope', '0.1.0', 'Cargo.toml'),
                                               ('bpf', 'osslscope-ebpf', '0.0.0', 'crates/ebpf/Cargo.toml')]:
        components.append(dict(id=identifier, name=name, version=version, source=dict(kind='path', manifest=manifest), terms=terms, dependencies=[]))
    tools = dict(zip(['host', 'bpf', 'linker', 'llvm', 'builder'], [r['identity'] for r in resources[:5]]))
    tools['components'] = [r['identity'] for r in resources[5:]]
    locks = dict(host_sha256=hashlib.sha256((source/'Cargo.lock').read_bytes()).hexdigest(),
                 bpf_sha256=hashlib.sha256((source/'crates/ebpf/Cargo.lock').read_bytes()).hexdigest())
    deps = dict(schema='osslscope-dependency-inventory-v1', locks=locks, components=components,
                host=['host'], bpf=['bpf'], build_std=['core', 'compiler_builtins', 'stdarch', 'portable-simd'],
                linker_build=['linker-build'], runtime=['native-runtime'], tool_sources=tool_sources+['core', 'compiler_builtins', 'stdarch', 'portable-simd', 'linker-build'])
    profile = 'gnu' if target == GNU else 'musl'
    rec.update(profile=profile, resources=resources, tools=tools, formats=['deb', 'rpm', 'prefix'] if profile == 'gnu' else ['prefix'],
               host_profile=dict(target=target, abi_profile='linux-x86_64-'+profile, abi_floor='synthetic evidence only'),
               required_cells=['synthetic'], determinism=dict(locale='C', timezone='UTC', umask=18, uid=0, gid=0,
               file_mode=420, executable_mode=493, symlink_mode=511, mtime=1792799804, archive_order='lexical', compression='none', path_remap='--remap-path-prefix=/build=.'))
    rec['abi_evidence'] = add('abi/evidence.json', canonical(dict(schema='osslscope-abi-evidence-v1', host_profile=rec['host_profile'],
        cells=[dict(name='synthetic', interpreter=dict(kind='static'), needed=[], symbol_versions=[])])))
    recipe_bytes = canonical(rec)
    (source/'packaging/builders').mkdir(parents=True)
    (source/'packaging/builders'/str(profile+'.json')).write_bytes(recipe_bytes)
    (source/'packaging/builders'/str(profile+'.layout.json')).write_bytes(canonical(layout))
    release_sha = hashlib.sha256((source/'packaging/release.toml').read_bytes()).hexdigest()
    artifacts = dict(source_archive='source.tar', offline_inventory='offline-inventory.json', notices='notices.json',
                     license_index='license-index.json', sbom='source.spdx.json', source_availability='source-availability.json')
    config = dict(schema='osslscope-release-config-v1', product_version='0.1.0', cargo_toml_sha256=m.POLICY_FILES['Cargo.toml'],
                  release_toml_sha256=release_sha, package_epoch=1, package_revision=1, source_epoch=1792799804, jobs=2,
                  selected_profile=profile, artifacts=artifacts, profiles=[dict(id=p, target=t, abi_profile='linux-x86_64-'+p,
                  builder='packaging/builders/'+p+'.json', formats=['deb', 'rpm', 'prefix'] if p == 'gnu' else ['prefix']) for p, t in [('gnu', GNU), ('musl', MUSL)]])
    rows = []
    for path in sorted(source.rglob('*')):
        if path.is_file():
            path.chmod(0o644)
            content = path.read_bytes()
            rows.append(dict(path=str(path.relative_to(source)), mode=0o100644, bytes=len(content), sha256=hashlib.sha256(content).hexdigest(), node=dict(kind='file')))
    inventory = dict(schema='osslscope-original-source-v1', files=sorted(rows, key=lambda row: row['path']))
    identity = dict(revision='a'*40, inventory_sha256=hashlib.sha256(canonical(inventory)).hexdigest())
    manifest = dict(schema='osslscope-source-manifest-v1', source=identity, inventory=inventory)
    (source/'osslscope-source.json').write_bytes(canonical(manifest))
    kit = io.BytesIO()
    with tarfile.open(fileobj=kit, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted(source.rglob('*'), key=lambda p: str(p.relative_to(source))):
            if path.is_file():
                content = path.read_bytes()
                info = tarfile.TarInfo(str(path.relative_to(source)))
                info.mode, info.mtime, info.size = 0o644, 1792799804, len(content)
                archive.addfile(info, io.BytesIO(content))
    groups = dict(source_archive=add('source.tar', kit.getvalue()), dependency_archives=[tiny], tool_source_archives=[tiny],
                  tool_archives=list({canonical(r['acquisition']): r['acquisition'] for r in resources}.values()),
                  notices=add('notices.json', canonical(dict(components=[]))), license_index=add('license-index.json', canonical(dict(components=[]))),
                  license_texts=[license_entry], sbom=add('source.spdx.json', canonical(dict(spdxVersion='SPDX-2.3', SPDXID='SPDXRef-DOCUMENT'))),
                  source_availability=add('source-availability.json', canonical(dict(source=identity))))
    offline = canonical(dict(schema='osslscope-offline-inventory-v1', source=identity, locks=locks, dependencies=deps,
                             recipe_sha256=hashlib.sha256(recipe_bytes).hexdigest(), config_sha256=release_sha, tools=tools, source_assets=groups,
                             assets=sorted([json.loads(key) for key in assets], key=lambda e: e['path'])))
    inputs_record = dict(schema='osslscope-build-inputs-v1', source=identity, product_version='0.1.0', package_epoch=1, package_revision=1,
                         source_epoch=1792799804, host_profile=rec['host_profile'], locks=locks,
                         recipe=dict(recipe_sha256=hashlib.sha256(recipe_bytes).hexdigest(), config_sha256=release_sha),
                         tools=tools, jobs=2, argv=rec['argv'], environment=rec['environment'], offline_inventory_sha256=hashlib.sha256(offline).hexdigest())
    for key, content in assets.items():
        path = inputs/json.loads(key)['path']
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    (inputs/'offline-inventory.json').write_bytes(offline)
    (inputs/'build-inputs.json').write_bytes(canonical(inputs_record))
    return dict(config=config, dependencies=deps, tools=tools), source, inputs


class LayoutTests(unittest.TestCase):
    def test_fix2_tool_numeric_grammar_fresh_and_cached(self):
        m = load()
        raw, tree = tree_archive([('tool', 'file', b'tool-bytes')])
        cases = {
            'all-NUL': (b'\0'*16, None, True),
            'encoded-zero': (b'0000000\0'*2, None, True),
            'spaces': (b' '*16, None, False),
            'zero-blank': (b'0000000\0'+b' '*8, None, False),
            'blank-zero': (b' '*8+b'0000000\0', None, False),
            'zero-NUL': (b'0000000\0'+b'\0'*8, None, False),
            'NUL-zero': (b'\0'*8+b'0000000\0', None, False),
            'leading-NUL-mode': (b'\0'*16, 'mode-NUL', False),
            'leading-NUL-checksum': (b'\0'*16, 'checksum-NUL', False),
            'plus-checksum': (b'\0'*16, 'checksum-plus', False),
            'leading-space-checksum': (b'\0'*16, 'checksum-space', True),
        }
        for name, (devices, lexical, accepted) in cases.items():
            candidate = bytearray(raw)
            candidate[329:345] = devices
            if lexical == 'mode-NUL':
                candidate[100] = 0
            candidate[148:156] = b' '*8
            checksum = sum(candidate[:512])
            spelling = ('%06o\0 ' % checksum).encode()
            if lexical == 'checksum-NUL':
                spelling = b'\0'+('%06o' % checksum).encode()+b'\0'
            elif lexical == 'checksum-plus':
                spelling = ('+%06o\0' % checksum).encode()
            elif lexical == 'checksum-space':
                spelling = (' %06o\0' % checksum).encode()
            candidate[148:156] = spelling
            candidate = bytes(candidate)
            acquisition = dict(path='numeric.tar', bytes=len(candidate), sha256=m.digest(candidate))
            with tempfile.TemporaryDirectory() as name:
                root = pathlib.Path(name)
                (root/'numeric.tar').write_bytes(candidate)
                acquired = m.retained(root, acquisition)
            self.assertEqual(acquisition['bytes'], len(raw))
            for cached in [False, True]:
                with self.subTest(case=name, cached=cached):
                    owner = m._ArchiveAdmission()
                    # A plus checksum is already refused by Python's shared
                    # parser, so no compatible cached record exists for it.
                    if cached and lexical == 'checksum-plus':
                        with self.assertRaises(ValueError):
                            owner.decode(acquired, 'source')
                        self.assertTrue(owner.state.poisoned)
                        continue
                    if cached:
                        owner.decode(acquired, 'source')
                    before = (owner.state.decoded, owner.state.entries)
                    if accepted:
                        _, files = m._archive_members_in(owner, acquired, tree, retain=True)
                        self.assertEqual(files, {'tool': b'tool-bytes'})
                    else:
                        with self.assertRaises(ValueError):
                            m._archive_members_in(owner, acquired, tree, retain=True)
                        self.assertTrue(owner.state.poisoned)
                        with self.assertRaises(ValueError):
                            owner.decode(acquired, 'source')
                    if cached:
                        self.assertEqual((owner.state.decoded, owner.state.entries), before)
                    self.assertEqual(owner.decode_count, 0 if lexical == 'checksum-plus' else 1)

    def test_fix2_vendor_full_ancestors_and_real_parent_collisions(self):
        m = load()
        cargo = b'[package]\nname="tiny"\nversion="1.0.0"\n'
        topologies = [('compatible', ['a', 'z/a/b'], True),
                      ('root-parent', ['a', 'a/b'], False),
                      ('nested-parent', ['z/a', 'z/a/b'], False)]
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            (root/'crates/ebpf').mkdir(parents=True)
            (root/'crates/ebpf/Cargo.lock').write_bytes(b'version=4\npackage=[]\n')
            source_id = 'registry+https://github.com/rust-lang/crates.io-index'
            for label, paths, accepted in topologies:
                for reverse in ([False] if accepted else [False, True]):
                    rows = [('Cargo.toml', 'file', cargo)]+[(path, 'file', path.encode()) for path in paths]
                    if reverse:
                        rows.reverse()
                    normalized, _ = tree_archive(rows)
                    original_tar, _ = tree_archive([('tiny-1.0.0/'+path, kind, data) for path, kind, data in rows])
                    original = gzip.compress(original_tar, mtime=0)
                    original_sha = hashlib.sha256(original).hexdigest()
                    (root/'Cargo.lock').write_text('version=4\n[[package]]\nname="tiny"\nversion="1.0.0"\nsource="'+source_id+'"\nchecksum="'+original_sha+'"\n')
                    (root/'tiny.crate').write_bytes(original)
                    (root/'tiny.tar').write_bytes(normalized)
                    component = dict(id='tiny', name='tiny', version='1.0.0', source=dict(kind='registry', location=source_id,
                        checksum=original_sha, archive=dict(path='tiny.crate', bytes=len(original), sha256=original_sha),
                        corresponding_source=dict(path='tiny.tar', bytes=len(normalized), sha256=hashlib.sha256(normalized).hexdigest())))
                    admitted = SimpleNamespace(source=root, inputs=root, request=dict(dependencies=dict(components=[component], host=['tiny'], bpf=[], build_std=[])))
                    owner = m._ArchiveAdmission()
                    with self.subTest(topology=label, reverse=reverse), mock.patch.dict(m.os.environ, {'HOME': str(root), 'CARGO_HOME': str(root)}):
                        if accepted:
                            plan = m._vendor_plan_in(admitted, owner)
                            usage = (owner.state.decoded, owner.state.entries, owner.decode_count)
                            again = m._vendor_plan_in(admitted, owner)
                            self.assertEqual((owner.state.decoded, owner.state.entries, owner.decode_count), usage)
                            base = next(iter(plan.mappings.values()))+'/tiny-1.0.0/'
                            for path, _, data in rows:
                                self.assertEqual((plan.files[base+path].data, plan.files[base+path].mode), (data, 0o755))
                                self.assertIs(again.files[base+path].data, plan.files[base+path].data)
                        else:
                            with self.assertRaises(ValueError):
                                m._vendor_plan_in(admitted, owner)
                            self.assertTrue(owner.state.poisoned)
                            with self.assertRaises(ValueError):
                                m._vendor_plan_in(admitted, owner)

    def test_fix1_i6_complete_parser_ledger_with_registry_and_cache(self):
        m = load()
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            (root/'crates/ebpf').mkdir(parents=True)
            cargo = b'[package]\nname="tiny"\nversion="1.0.0"\n'
            normalized, _ = tree_archive([('Cargo.toml', 'file', cargo)])
            original_tar, _ = tree_archive([('tiny-1.0.0/Cargo.toml', 'file', cargo)])
            original = gzip.compress(original_tar, mtime=0)
            source_id = 'registry+https://github.com/rust-lang/crates.io-index'
            package_sha = hashlib.sha256(original).hexdigest()
            (root/'Cargo.lock').write_text('version=4\n[[package]]\nname="tiny"\nversion="1.0.0"\nsource="'+source_id+'"\nchecksum="'+package_sha+'"\n')
            (root/'crates/ebpf/Cargo.lock').write_text('version=4\npackage=[]\n')
            (root/'tiny.crate').write_bytes(original)
            (root/'tiny.tar').write_bytes(normalized)
            component = dict(id='tiny', name='tiny', version='1.0.0', dependencies=[], source=dict(kind='registry', location=source_id,
                checksum=package_sha, archive=dict(path='tiny.crate', bytes=len(original), sha256=package_sha),
                corresponding_source=dict(path='tiny.tar', bytes=len(normalized), sha256=hashlib.sha256(normalized).hexdigest())))
            request = dict(dependencies=dict(components=[component], host=['tiny'], bpf=[], build_std=[]))
            rec, document, host, assets = layout_fixture(m)
            def attempt(limits=None):
                if limits is None:
                    owner = m._ArchiveAdmission()
                else:
                    with mock.patch.object(m, 'BudgetLimits', return_value=limits):
                        owner = m._ArchiveAdmission()
                roots, files, usage = m._admit_documents_in(owner, rec, document, host, lambda e: assets[canonical(e)], canonical(document))
                layout = m.AdmittedLayout(rec, request, roots, files, assets, root, root, usage, owner)
                return owner, layout
            with mock.patch.dict(m.os.environ, {'HOME': str(root), 'CARGO_HOME': str(root)}):
                owner, layout = attempt()
                plan = m._vendor_plan_in(layout, owner)
                expected = (owner.state.decoded, owner.state.entries)
                self.assertEqual(owner.decode_count, 12)
                self.assertEqual(m._vendor_plan_in(layout, owner).files, plan.files)
                self.assertEqual((owner.state.decoded, owner.state.entries), expected)
                self.assertEqual(owner.decode_count, 12)
                normalized_cache = owner.cache[(hashlib.sha256(normalized).hexdigest(), len(normalized))]
                node = next(value for path, value in plan.files.items() if path.endswith('/Cargo.toml'))
                self.assertIs(node.data, normalized_cache.nodes[0].data)
                with self.assertRaises(TypeError):
                    plan.files['extra'] = node
                limits = m.dataclasses.replace(m.BudgetLimits(), decoded=expected[0], entries=expected[1])
                exact, layout = attempt(limits)
                m._vendor_plan_in(layout, exact)
                for limits in [m.dataclasses.replace(limits, decoded=expected[0]-1), m.dataclasses.replace(limits, entries=expected[1]-1)]:
                    limited, layout = attempt(limits)
                    prefix = limited.retained_rows
                    with self.assertRaises(ValueError):
                        m._vendor_plan_in(layout, limited)
                    self.assertEqual(limited.retained_rows, prefix+1, 'normalized member fits; violating original member is not retained')
                    with self.assertRaises(ValueError):
                        limited.decode(normalized, 'source')
                # Policy replays cached compression facts instead of blessing
                # an original registry gzip as normalized tool acquisition.
                unusual = bytearray(original)
                unusual[4] = 1
                raw = bytes(unusual)
                other = m._ArchiveAdmission()
                other.decode(raw, 'registry')
                with self.assertRaises(ValueError):
                    other.decode(raw, 'tool')
                self.assertEqual(other.decode_count, 1)
                many, _ = tree_archive([('a', 'file', b''), ('b', 'file', b'')])
                with mock.patch.object(m, 'BudgetLimits', return_value=m.dataclasses.replace(m.BudgetLimits(), entries=1)):
                    small = m._ArchiveAdmission()
                with self.assertRaises(ValueError):
                    m._source_members_in(small, many)
                self.assertEqual(small.retained_rows, 1)
                for mutation in ['missing', 'mixed', 'collision', 'checksum', 'files', 'mode', 'content']:
                    altered = copy.deepcopy(request)
                    c = altered['dependencies']['components'][0]
                    reset = None
                    if mutation == 'missing':
                        altered['dependencies']['host'] = ['missing']
                    elif mutation == 'mixed':
                        c['source']['location'] += '-other'
                    elif mutation == 'collision':
                        altered['dependencies']['components'].append(copy.deepcopy(c))
                    elif mutation == 'checksum':
                        c['source']['checksum'] = 'f'*64
                    else:
                        if mutation == 'files':
                            changed, _ = tree_archive([('other', 'file', cargo)])
                        elif mutation == 'content':
                            changed, _ = tree_archive([('Cargo.toml', 'file', cargo+b'# changed\n')])
                        else:
                            changed = bytearray(normalized)
                            changed[100:108] = b'0000644\0'
                            changed[148:156] = b'        '
                            changed[148:156] = ('%06o\0 ' % sum(changed[:512])).encode()
                            changed = bytes(changed)
                        reset = normalized
                        (root/'tiny.tar').write_bytes(changed)
                        c['source']['corresponding_source'] = dict(path='tiny.tar', bytes=len(changed), sha256=hashlib.sha256(changed).hexdigest())
                    fresh = m._ArchiveAdmission()
                    layout = SimpleNamespace(source=root, inputs=root, request=altered)
                    try:
                        with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                            m._vendor_plan_in(layout, fresh)
                        self.assertTrue(fresh.state.poisoned)
                    finally:
                        if reset is not None:
                            (root/'tiny.tar').write_bytes(reset)

    def test_fix1_i8_overlay_controls(self):
        m = load()
        rec, document, host, assets = layout_fixture(m)
        for conflict in [False, True]:
            candidate, mapping, retained = copy.deepcopy(rec), copy.deepcopy(document), dict(assets)
            raw, tree = tree_archive([('format-tool', 'file', b'changed' if conflict else b'package'), ('marker', 'file', b'overlay')])
            acq = dict(path='overlay.tar', bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            tree_bytes = canonical(tree)
            entry = dict(path='overlay.tree.json', bytes=len(tree_bytes), sha256=hashlib.sha256(tree_bytes).hexdigest())
            retained[canonical(acq)], retained[canonical(entry)] = raw, tree_bytes
            candidate['resources'].append(dict(role='overlay', content=entry, acquisition=acq))
            mapping['archives'].append(dict(root='package', acquisition=acq, tree=entry))
            mapping['archives'].sort(key=lambda r: (r['root'], r['acquisition']['path']))
            mapping['bindings'].append(dict(role='overlay', archive_sha256=acq['sha256'], member='', kind='tree'))
            mapping['bindings'].sort(key=lambda r: r['role'])
            layout_bytes = canonical(mapping)
            layout_tar, _ = tree_archive([('layout.json', 'file', layout_bytes)])
            revised = bytearray(layout_tar)
            revised[100:108] = b'0000644\0'
            revised[148:156] = b'        '
            revised[148:156] = ('%06o\0 ' % sum(revised[:512])).encode()
            revised = bytes(revised)
            special = next(row for row in candidate['resources'] if row['role'] == 'executor-layout')
            special['content'] = dict(path='revised-layout.json', bytes=len(layout_bytes), sha256=hashlib.sha256(layout_bytes).hexdigest())
            special['acquisition'] = dict(path='revised-layout.tar', bytes=len(revised), sha256=hashlib.sha256(revised).hexdigest())
            retained[canonical(special['content'])], retained[canonical(special['acquisition'])] = layout_bytes, revised
            if conflict:
                with self.assertRaises(ValueError):
                    m._admit_documents(candidate, mapping, host, lambda e: retained[canonical(e)], canonical(mapping))
            else:
                roots, files, _ = m._admit_documents(candidate, mapping, host, lambda e: retained[canonical(e)], canonical(mapping))
                self.assertEqual(files[('package', 'format-tool')], b'package')
                self.assertIn('marker', roots['package'])
    def test_fix1_i8_public_packets_and_cached_source_refusal(self):
        m = load()
        for target in [GNU, MUSL]:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as name:
                parent = pathlib.Path(name)
                request, source, inputs = public_packet(m, parent, target)
                with mock.patch.dict(m.os.environ, {'HOME': str(parent/'home'), 'CARGO_HOME': str(parent/'cargo')}):
                    admitted = m.admit_layout(request, source, inputs)
                    self.assertEqual(set(admitted.roots), {'rootfs', 'host', 'bpf', 'linker', 'llvm', 'native', 'build', 'package'})
                    for field, value in [('jobs', 3), ('package_epoch', 2), ('source_epoch', True)]:
                        path = inputs/'build-inputs.json'
                        original = path.read_bytes()
                        bad = json.loads(original)
                        bad[field] = value
                        path.write_bytes(canonical(bad))
                        try:
                            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'release/build inputs duplicate'):
                                m.admit_layout(request, source, inputs)
                        finally:
                            path.write_bytes(original)
                    for extra_name in ['crates/bpf-sys/src/unlisted.rs', 'crates/ebpf/.cargo/config.toml']:
                        extra = source/extra_name
                        extra.parent.mkdir(parents=True, exist_ok=True)
                        extra.write_bytes(b'unlisted source\n')
                        try:
                            with self.subTest(extra=extra_name), mock.patch.object(m, 'phase_spec', wraps=m.phase_spec) as phases:
                                with self.assertRaisesRegex(ValueError, 'unlisted source file'):
                                    m.admit_layout(request, source, inputs)
                                self.assertEqual(phases.call_count, 0)
                        finally:
                            extra.unlink()
                    mode_path = source/'crates/bpf-sys/src/lib.rs'
                    mode_path.chmod(0o755)
                    try:
                        with self.assertRaisesRegex(ValueError, 'source executable-mode drift'):
                            m.admit_layout(request, source, inputs)
                    finally:
                        mode_path.chmod(0o644)
                    original_lstat = pathlib.Path.lstat
                    def lstat(path, *args, **kwargs):
                        observed = original_lstat(path, *args, **kwargs)
                        return SimpleNamespace(st_mode=observed.st_mode & ~0o022, st_uid=m.os.getuid())
                    device = parent.stat().st_dev
                    mount = (42, str(m.os.major(device))+':'+str(m.os.minor(device)), '/', str(parent), 'ext4', '/dev/synthetic-owned')
                    volume = SimpleNamespace(f_blocks=16, f_frsize=4096, f_bfree=12, f_bavail=10)
                    with mock.patch.object(pathlib.Path, 'lstat', lstat), mock.patch.object(m, '_mounts', return_value=[mount]), mock.patch.object(m.os, 'fstatvfs', return_value=volume):
                        owned = m.materialize(admitted, dict(work_root=parent/'work', output_root=parent/'output'))
                        try:
                            self.assertEqual((owned.roots['host']/'bin/cargo').read_bytes(), b'cargo')
                        finally:
                            owned.close()
                        path = source/'src/package/records.rs'
                        original = path.read_bytes()
                        changed = original.replace(b'osslscope-harvest', b'osslscope-harvesX')
                        self.assertNotEqual(changed, original)
                        self.assertEqual(len(changed), len(original))
                        path.write_bytes(changed)
                        unexpected = None
                        try:
                            with self.assertRaisesRegex(ValueError, 'source file identity drift|loader policy source drift'):
                                unexpected = m.materialize(admitted, dict(work_root=parent/'bad-work', output_root=parent/'bad-output'))
                        finally:
                            if unexpected is not None:
                                unexpected.close()
                            path.write_bytes(original)
                        self.assertTrue(admitted._archives.state.poisoned)
                        with mock.patch.object(m, 'read_nofollow', side_effect=AssertionError('poisoned owner attempted a read')), self.assertRaisesRegex(ValueError, 'poisoned'):
                            m.materialize(admitted, dict(work_root=parent/'never-work', output_root=parent/'never-output'))
                        self.assertFalse((parent/'bad-work').exists())
    def test_fix1_i6_owner_ledger_and_no_preretention(self):
        m = load()
        self.assertTrue(hasattr(m, '_ArchiveAdmission'), 'missing shared acquisition owner')
        data, _ = tree_archive([('a', 'file', b'a')])
        limits = m.dataclasses.replace(m.BudgetLimits(), decoded=len(data)*2, entries=2)
        with mock.patch.object(m, 'BudgetLimits', return_value=limits):
            owner = m._ArchiveAdmission()
        first = owner.decode(data, 'tool')
        self.assertIs(owner.decode(data, 'tool'), first)
        self.assertEqual(owner.decode_count, 1)
        other, _ = tree_archive([('b', 'file', b'b')])
        owner.decode(other, 'tool')
        self.assertEqual((owner.state.decoded, owner.state.entries), (len(data)*2, 2))
        third, _ = tree_archive([('c', 'file', b'c')])
        with self.assertRaises(ValueError):
            owner.decode(third, 'tool')
        self.assertEqual(owner.retained_rows, 2)
        with self.assertRaises(ValueError):
            owner.decode(data, 'tool')

    def test_fix1_i7_vendor_mixed_modes_are_readonly(self):
        m = load()
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            (root/'crates/ebpf').mkdir(parents=True)
            source_id = 'git+https://example.invalid/tiny#'+'1'*40
            (root/'Cargo.lock').write_text('version=4\n[[package]]\nname="tiny"\nversion="1.0.0"\nsource="'+source_id+'"\n')
            (root/'crates/ebpf/Cargo.lock').write_text('version=4\npackage=[]\n')
            out = io.BytesIO()
            with tarfile.open(fileobj=out, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                for path, mode, data in [('Cargo.toml', 0o644, b'[package]\nname="tiny"\nversion="1.0.0"\n'), ('helper', 0o755, b'#!/bin/sh\n')]:
                    node = tarfile.TarInfo(path)
                    node.mode, node.size = mode, len(data)
                    archive.addfile(node, io.BytesIO(data))
            raw = out.getvalue()
            (root/'tiny.tar').write_bytes(raw)
            entry = dict(path='tiny.tar', bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            component = dict(id='tiny', name='tiny', version='1.0.0', dependencies=[], source=dict(kind='git', repository='https://example.invalid/tiny', revision='1'*40, archive=entry))
            admitted = SimpleNamespace(source=root, inputs=root, request=dict(dependencies=dict(components=[component], host=['tiny'], bpf=[], build_std=[])))
            with mock.patch.dict(m.os.environ, {'HOME': str(root), 'CARGO_HOME': str(root)}):
                plan = m._vendor_plan_in(admitted, m._ArchiveAdmission())
            modes = {path.rsplit('/', 1)[-1]: getattr(node, 'mode', None) for path, node in plan.files.items()}
            self.assertEqual(modes, {'Cargo.toml': 0o644, 'helper': 0o755, '.cargo-checksum.json': 0o644})
    def test_fix1_i1_directory_and_first_recheck_custody(self):
        m = load()
        rec, document, host, assets = layout_fixture(m)
        roots, files, usage = m._admit_documents(rec, document, host, lambda e: assets[canonical(e)], canonical(document))
        points = 3+len(roots)+sum(row['kind'] == 'directory' for nodes in roots.values() for row in nodes.values())
        for point in range(points+2):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as name:
                root = pathlib.Path(name)
                real_open, real_close, real_dup, real_fchmod = m.os.open, m.os.close, m.os.dup, m.os.fchmod
                parents = (real_open(root, m.os.O_RDONLY | m.os.O_DIRECTORY), real_open(root, m.os.O_RDONLY | m.os.O_DIRECTORY))
                owned = set(parents)
                def opened(path, flags, *args, **kwargs):
                    fd = real_open(path, flags, *args, **kwargs)
                    if flags & m.os.O_DIRECTORY or point == points+1:
                        owned.add(fd)
                    return fd
                def duplicated(fd):
                    result = real_dup(fd)
                    owned.add(result)
                    return result
                def closed(fd):
                    owned.discard(fd)
                    return real_close(fd)
                count = 0
                def chmod(fd, mode):
                    nonlocal count
                    if stat.S_ISDIR(m.os.fstat(fd).st_mode):
                        count += 1
                        if count == point:
                            raise OSError(errno.EIO, 'directory initialization fault')
                    return real_fchmod(fd, mode)
                admission = m.StorageAdmission(parents, (), m.BudgetLimits())
                admitted = m.AdmittedLayout(rec, {}, roots, files, assets, root, root, usage)
                try:
                    with mock.patch.object(m, 'admit_storage', return_value=admission), mock.patch.object(m, 'check_storage', side_effect=OSError(errno.EIO, 'first recheck') if point == 0 else None), mock.patch.object(m.os, 'open', opened), mock.patch.object(m.os, 'dup', duplicated), mock.patch.object(m.os, 'close', closed), mock.patch.object(m.os, 'fchmod', chmod), mock.patch.object(m.os, 'fdopen', side_effect=OSError(errno.EIO, 'file wrapper transfer fault')) if point == points+1 else contextlib.nullcontext():
                        with self.assertRaises(OSError):
                            m._materialize_trees(admitted, dict(work_root=root/'work', output_root=root/'output'))
                    self.assertEqual(owned, set(), 'opened directory/admission handles must transfer or close')
                finally:
                    # These are exact test-owned handles: all tested closes go
                    # through closed(), which removes ownership before reuse.
                    for fd in tuple(owned):
                        owned.remove(fd)
                        real_close(fd)

    def test_fix1_i2_fifo_nonblocking_before_delegate(self):
        m = load()
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            m.os.mkfifo(root/'fifo')
            real_open = m.os.open
            def opened(path, flags, *args, **kwargs):
                if path == 'fifo':
                    self.assertTrue(flags & m.os.O_NONBLOCK, 'FIFO leaf must be nonblocking before open')
                return real_open(path, flags, *args, **kwargs)
            before = set(m.os.listdir('/proc/self/fd'))
            with mock.patch.object(m.os, 'open', opened), self.assertRaises(ValueError):
                m.read_nofollow(root, 'fifo', 16)
            self.assertEqual(set(m.os.listdir('/proc/self/fd')), before)
            (root/'regular').write_bytes(b'data')
            self.assertEqual(m.read_nofollow(root, 'regular', 4), b'data')
            real_stat = m.os.fstat
            for kind in [stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFBLK]:
                def observed(fd):
                    original = real_stat(fd)
                    return SimpleNamespace(st_mode=kind | 0o644, st_nlink=1, st_size=0)
                with self.subTest(kind=kind), mock.patch.object(m.os, 'fstat', observed), mock.patch.object(m.os, 'read', side_effect=AssertionError('nonregular descriptor read')), self.assertRaises(ValueError):
                    m.read_nofollow(root, 'regular', 4)
                self.assertEqual(set(m.os.listdir('/proc/self/fd')), before)

    def test_fix1_i3_actual_selected_addition_and_mode(self):
        m = load()
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            rows = []
            for path in m.POLICY_FILES:
                target = root/path
                target.parent.mkdir(parents=True, exist_ok=True)
                data = (PRODUCT/path).read_bytes()
                target.write_bytes(data)
                target.chmod(0o644)
                rows.append(dict(path=path, mode=0o100644, bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), node=dict(kind='file')))
            manifest = dict(inventory=dict(files=sorted(rows, key=lambda r: r['path'])))
            (root/'osslscope-source.json').write_bytes(canonical(manifest))
            m.loader_expectation(root)
            for path in ['crates/bpf-sys/src/additional.rs', 'crates/ebpf/.cargo/config.toml']:
                extra = root/path
                extra.parent.mkdir(parents=True, exist_ok=True)
                extra.write_bytes(b'not admitted\n')
                with self.subTest(path=path), self.assertRaises(ValueError):
                    m.loader_expectation(root)
                extra.unlink()
            target = root/'crates/bpf-sys/src/lib.rs'
            target.chmod(0o755)
            with self.assertRaises(ValueError):
                m.loader_expectation(root)

    def test_fix1_i4_host_executable_type_and_raw_absolute_target(self):
        m = load()
        _, _, host, _ = layout_fixture(m)
        for executable in ['/usr/bin/python3.11', '/usr/bin/bwrap']:
            bad = copy.deepcopy(host)
            next(row for row in bad['files'] if row['path'] == executable)['path'] += '/child'
            bad['files'].sort(key=lambda row: row['path'])
            with self.subTest(executable=executable), self.assertRaises(ValueError):
                m.host_manifest(bad)
        for target in ['/usr/bin/../bin/python3.11', '/usr//bin/python3.11', '/usr/bin/./python3.11']:
            bad = copy.deepcopy(host)
            bad['links'] = [dict(path='/usr/bin/python3', target=target)]
            with self.subTest(target=target), self.assertRaises(ValueError):
                m.host_manifest(bad)

    def test_fix1_i5_exact_git_origin_and_query_bytes(self):
        m = load()
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            (root/'crates/ebpf').mkdir(parents=True)
            raw, _ = tree_archive([('Cargo.toml', 'file', b'[package]\nname="tiny"\nversion="1.0.0"\n')])
            (root/'tiny.tar').write_bytes(raw)
            archive = dict(path='tiny.tar', bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            for suffix in ['', '-other', '?branch=reviewed']:
                declared = 'https://example.invalid/tiny'
                locked = declared+suffix
                lock = ('version=4\n[[package]]\nname="tiny"\nversion="1.0.0"\nsource="git+'+locked+'#'+'1'*40+'"\n').encode()
                (root/'Cargo.lock').write_bytes(lock)
                (root/'crates/ebpf/Cargo.lock').write_bytes(b'version=4\npackage=[]\n')
                component = dict(id='tiny', name='tiny', version='1.0.0', dependencies=[], source=dict(kind='git', repository=declared, revision='1'*40, archive=archive))
                admitted = SimpleNamespace(source=root, inputs=root, request=dict(dependencies=dict(components=[component], host=['tiny'], bpf=[], build_std=[])))
                with mock.patch.dict(m.os.environ, {'HOME': str(root), 'CARGO_HOME': str(root)}):
                    if suffix:
                        with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                            m._vendor_plan_in(admitted, m._ArchiveAdmission())
                    else:
                        plan = m._vendor_plan_in(admitted, m._ArchiveAdmission())
                        self.assertIn(b'git = "https://example.invalid/tiny"', plan.config)
            component['source']['repository'] = locked
            with mock.patch.dict(m.os.environ, {'HOME': str(root), 'CARGO_HOME': str(root)}):
                plan = m._vendor_plan_in(admitted, m._ArchiveAdmission())
                self.assertIn(b'git = "https://example.invalid/tiny?branch=reviewed"', plan.config)
    def test_build_std_fixed_retained_lock_git_and_declared_closure(self):
        m = load()
        repository = 'https://example.invalid/tiny'
        revision = '1'*40
        source_id = 'git+'+repository+'#'+revision
        literal = ('version = 4\n[[package]]\nname = "tiny"\nversion = "1.0.0"\nsource = "'+source_id+'"\n'
                   '[[package]]\nname = "optional"\nversion = "9.0.0"\nsource = "registry+https://example.invalid/index"\nchecksum = "'+'f'*64+'"\n').encode()
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            (root/'crates/ebpf').mkdir(parents=True)
            for path in ['Cargo.lock', 'crates/ebpf/Cargo.lock']:
                (root/path).write_bytes(b'version = 4\npackage = []\n')
            cargo = b'[package]\nname="tiny"\nversion="1.0.0"\n'
            raw, _ = tree_archive([('Cargo.toml', 'file', cargo)])
            (root/'tiny.tar').write_bytes(raw)
            archive = dict(path='tiny.tar', sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
            component = dict(id='tiny', name='tiny', version='1.0.0', dependencies=[], source=dict(kind='git', repository=repository, revision=revision, archive=archive))
            deps = dict(components=[component], host=[], bpf=[], build_std=['tiny'])
            for target in [GNU, MUSL]:
                rec, layout, host, assets = layout_fixture(m, target, literal)
                roots, files, usage = m._admit_documents(rec, layout, host, lambda e: assets[canonical(e)], canonical(layout))
                admitted = m.AdmittedLayout(rec, dict(dependencies=deps), roots, files, assets, root, root, usage)
                with mock.patch.dict(m.os.environ, {'HOME': str(root), 'CARGO_HOME': str(root)}):
                    plan = m._vendor_plan_in(admitted, m._ArchiveAdmission())
                    self.assertEqual(set(plan.mappings), {source_id})
                    self.assertEqual(json.loads(next(v for k, v in plan.files.items() if k.endswith('/.cargo-checksum.json')).data),
                                     dict(files={'Cargo.toml': hashlib.sha256(cargo).hexdigest()}, package=None))
                    for mutation in ['missing-member', 'substituted', 'source', 'version', 'closure']:
                        bad_files = dict(files)
                        bad_deps = copy.deepcopy(deps)
                        if mutation == 'missing-member':
                            del bad_files[('bpf', 'lib/rustlib/src/rust/library/Cargo.lock')]
                        elif mutation == 'substituted':
                            bad_files[('bpf', 'lib/rustlib/src/rust/library/Cargo.lock')] = literal+b'\n'
                        elif mutation == 'source':
                            bad_deps['components'][0]['source']['repository'] += '/other'
                        elif mutation == 'version':
                            bad_deps['components'][0]['version'] = '2.0.0'
                        else:
                            bad_deps['components'][0]['dependencies'] = ['missing']
                        bad = m.dataclasses.replace(admitted, files=bad_files, request=dict(dependencies=bad_deps))
                        with self.subTest(target=target, mutation=mutation), self.assertRaises(ValueError):
                            m._vendor_plan_in(bad, m._ArchiveAdmission())
            for changed in [literal.replace(b'tiny', b'other'), literal.replace(b'1.0.0', b'2.0.0'), literal+literal,
                            literal.replace(b'[[package]]', b'checksum = "bad"\n[[package]]', 1)]:
                # The last mutation is top-level metadata and is not source
                # corroboration; unsupported lock top-level fields refuse.
                with self.assertRaises(ValueError):
                    m._corroborate_std_lock(changed, [component], {})
    def test_distinct_acquisition_ledger_exact_boundary_and_decode_once(self):
        m = load()
        rec, layout, host, assets = layout_fixture(m)
        args = (rec, layout, host, lambda e: assets[canonical(e)], canonical(layout))
        with mock.patch.object(m, '_archive_members_in', wraps=m._archive_members_in) as decoder:
            _, _, usage = m._admit_documents(*args)
            self.assertEqual(decoder.call_count, 10)
        limits = m.BudgetLimits()
        exact = m.dataclasses.replace(limits, decoded=usage.decoded_bytes, entries=usage.entries)
        with mock.patch.object(m, 'BudgetLimits', return_value=exact):
            self.assertEqual(m._admit_documents(*args)[2], usage)
        for limits in [m.dataclasses.replace(exact, decoded=exact.decoded-1),
                       m.dataclasses.replace(exact, entries=exact.entries-1)]:
            with mock.patch.object(m, 'BudgetLimits', return_value=limits), self.assertRaises(ValueError):
                m._admit_documents(*args)

    def test_ustar_named_refusal_table(self):
        m = load()
        raw, tree = tree_archive([('bin', 'directory', None), ('bin/tool', 'file', b'abc')])
        def header(offset, value, at=512):
            bad = bytearray(raw)
            bad[at+offset:at+offset+len(value)] = value
            bad[at+148:at+156] = b'        '
            bad[at+148:at+156] = ('%06o\0 ' % sum(bad[at:at+512])).encode()
            return bytes(bad)
        cases = {
            'hardlink': header(156, b'1'), 'device': header(156, b'3'), 'fifo': header(156, b'6'),
            'pax-xattr': header(156, b'x'), 'gnu-longname': header(156, b'L'),
            'setid': header(100, b'0004755\0'), 'writable-mode': header(100, b'0000777\0'),
            'uid': header(108, b'0000001\0'), 'gid': header(116, b'0000001\0'),
            'timestamp': header(136, b'00000000001\0'), 'uname': header(265, b'private'),
            'gname': header(297, b'private'), 'device-number': header(329, b'0000001\0'),
            'absolute': header(0, b'/in/tool'), 'traversal': header(0, b'../tool\0'),
            'empty-component': header(0, b'a//tool\0'), 'backslash': header(0, b'a\\/tool\0'),
            'link-on-file': header(157, b'bin/tool'), 'base256-size': header(124, b'\x80'),
            'unsupported-magic': header(257, b'gnu  \0'), 'header-padding': header(500, b'x'),
            'nonzero-string-padding': header(20, b'x')}
        for name, bad in cases.items():
            with self.subTest(refusal=name), self.assertRaises(ValueError):
                m.validate_tool_archive(bad, tree, m.BudgetLimits())
        zipdata = gzip.compress(raw, mtime=0)
        for flag in [4, 8, 16, 32, 64, 128]:
            bad = bytearray(zipdata)
            bad[3] = flag
            with self.subTest(gzip_flag=flag), self.assertRaises(ValueError):
                m.validate_tool_archive(bytes(bad), tree, m.BudgetLimits())
        bad = bytearray(zipdata)
        bad[-8] ^= 1
        with self.assertRaises((ValueError, m.zlib.error)):
            m.validate_tool_archive(bytes(bad), tree, m.BudgetLimits())

    def test_materialized_identical_copies_are_separately_charged(self):
        m = load()
        rec, layout, host, assets = layout_fixture(m)
        roots, files, usage = m._admit_documents(rec, layout, host, lambda e: assets[canonical(e)], canonical(layout))
        with tempfile.TemporaryDirectory() as name:
            parent = pathlib.Path(name)
            original_lstat = pathlib.Path.lstat
            def observed_lstat(path, *args, **kwargs):
                value = original_lstat(path, *args, **kwargs)
                # Literal externally admitted ancestor observations, no host
                # ownership/permission changes and no filesystem admission claim.
                return SimpleNamespace(st_mode=(value.st_mode & ~0o022), st_uid=m.os.getuid())
            device = parent.stat().st_dev
            mount = (42, str(m.os.major(device))+':'+str(m.os.minor(device)), '/', str(parent), 'ext4', '/dev/owned')
            volume = SimpleNamespace(f_blocks=16, f_frsize=4096, f_bfree=12, f_bavail=10)
            admitted = m.AdmittedLayout(rec, {}, roots, files, assets, parent, parent, usage)
            with mock.patch.object(pathlib.Path, 'lstat', observed_lstat), mock.patch.object(m, '_mounts', return_value=[mount]), mock.patch.object(m.os, 'fstatvfs', return_value=volume):
                owned = m._materialize_trees(admitted, dict(work_root=parent/'work', output_root=parent/'output'))
                self.assertEqual(owned.materialized_bytes, sum(len(data) for data in files.values()))
                self.assertEqual((owned.roots['native']/'bin/cc').read_bytes(), b'cc')
                self.assertEqual((owned.roots['build']/'bin/cc').read_bytes(), b'cc')
                self.assertGreater(owned.materialized_bytes, sum(len(data) for data in set(files.values())))
                owned.close()
                self.assertTrue(owned.storage.closed)
                self.assertEqual(owned.root_fds, {})

    def test_storage_drift_and_flush_failure_poison_and_close(self):
        m = load()
        rec, layout, host, assets = layout_fixture(m)
        roots, files, usage = m._admit_documents(rec, layout, host, lambda e: assets[canonical(e)], canonical(layout))
        with tempfile.TemporaryDirectory() as name:
            parent = pathlib.Path(name)
            original_lstat = pathlib.Path.lstat
            def lstat(path, *args, **kwargs):
                value = original_lstat(path, *args, **kwargs)
                return SimpleNamespace(st_mode=value.st_mode & ~0o022, st_uid=m.os.getuid())
            device = parent.stat().st_dev
            mount = (42, str(m.os.major(device))+':'+str(m.os.minor(device)), '/', str(parent), 'ext4', '/dev/owned')
            volume = SimpleNamespace(f_blocks=16, f_frsize=4096, f_bfree=12, f_bavail=10)
            paths = dict(work_root=parent/'work', output_root=parent/'output')
            with mock.patch.object(pathlib.Path, 'lstat', lstat), mock.patch.object(m, '_mounts', return_value=[mount]), mock.patch.object(m.os, 'fstatvfs', return_value=volume):
                admission = m.admit_storage(paths, m.dataclasses.replace(m.BudgetLimits(), storage=65536))
                m.check_storage(admission)
                changed = SimpleNamespace(f_blocks=17, f_frsize=4096, f_bfree=12, f_bavail=10)
                with mock.patch.object(m.os, 'fstatvfs', return_value=changed), self.assertRaises(ValueError):
                    m.check_storage(admission)
                self.assertTrue(admission.poisoned)
                with self.assertRaises(ValueError):
                    m.check_storage(admission)
                admission.close()
                self.assertFalse(paths['work_root'].exists())
                admitted = m.AdmittedLayout(rec, {}, roots, files, assets, parent, parent, usage)
                before = set(m.os.listdir('/proc/self/fd'))
                with mock.patch.object(m.os, 'fsync', side_effect=OSError(errno.ENOSPC, 'synthetic flush exhaustion')), self.assertRaises(OSError):
                    m._materialize_trees(admitted, paths)
                self.assertEqual(set(m.os.listdir('/proc/self/fd')), before)
                self.assertTrue(paths['work_root'].exists())
                self.assertFalse((paths['work_root']/'build-receipt.json').exists())

    def test_separate_storage_mounts_refuse_before_writes(self):
        m = load()
        with tempfile.TemporaryDirectory() as name:
            parent = pathlib.Path(name)
            left, right = parent/'left', parent/'right'
            left.mkdir()
            right.mkdir()
            original_lstat, original_fstat = pathlib.Path.lstat, m.os.fstat
            def lstat(path, *args, **kwargs):
                value = original_lstat(path, *args, **kwargs)
                return SimpleNamespace(st_mode=value.st_mode & ~0o022, st_uid=m.os.getuid())
            def fstat(fd):
                value = original_fstat(fd)
                device = 2049 if m.os.readlink('/proc/self/fd/'+str(fd)) == str(left) else 2050
                return SimpleNamespace(st_dev=device, st_ino=value.st_ino, st_uid=m.os.getuid(), st_mode=0o40755)
            mounts = [(42, '8:1', '/', str(left), 'ext4', '/dev/one'), (43, '8:2', '/', str(right), 'ext4', '/dev/two')]
            volume = SimpleNamespace(f_blocks=16, f_frsize=4096, f_bfree=12, f_bavail=10)
            with mock.patch.object(pathlib.Path, 'lstat', lstat), mock.patch.object(m.os, 'fstat', fstat), mock.patch.object(m, '_mounts', return_value=mounts), mock.patch.object(m.os, 'fstatvfs', return_value=volume), mock.patch.object(m.os, 'mkdir', wraps=m.os.mkdir) as writes:
                with self.assertRaises(ValueError):
                    m.admit_storage(dict(work_root=left/'work', output_root=right/'output'), m.BudgetLimits())
                self.assertEqual(writes.call_count, 0)
    def test_all_eight_roots_and_role_members(self):
        m = load()
        for target in [GNU, MUSL]:
            rec, layout, host, assets = layout_fixture(m, target)
            roots, files, usage = m._admit_documents(rec, layout, host, lambda e: assets[canonical(e)], canonical(layout))
            self.assertEqual(set(roots), {'rootfs', 'host', 'bpf', 'linker', 'llvm', 'native', 'build', 'package'})
            self.assertEqual(files[('host', 'bin/cargo')], b'cargo')
            self.assertEqual(usage.entries, sum(len(t) for t in roots.values())+5)
            for mutation in ['missing-root', 'missing-binding', 'extra-binding', 'wrong-member', 'order', 'backedge']:
                bad = copy.deepcopy(layout)
                if mutation == 'missing-root':
                    bad['archives'].pop()
                elif mutation == 'missing-binding':
                    bad['bindings'].pop()
                elif mutation == 'extra-binding':
                    bad['bindings'].append(bad['bindings'][0])
                elif mutation == 'wrong-member':
                    next(r for r in bad['bindings'] if r['role'] == 'host')['member'] = 'bin/cargo'
                elif mutation == 'order':
                    bad['archives'].reverse()
                else:
                    bad['commands'] = []
                with self.subTest(target=target, mutation=mutation), self.assertRaises(ValueError):
                    m._admit_documents(rec, bad, host, lambda e: assets[canonical(e)], canonical(bad))

    def test_host_runtime_manifest_closed(self):
        m = load()
        _, _, host, _ = layout_fixture(m)
        self.assertEqual(len(m.host_manifest(host)['entries']), 4)
        absolute = copy.deepcopy(host)
        absolute['links'] = [dict(path='/usr/bin/python3', target='/usr/bin/python3.11')]
        self.assertEqual(next(n for n in m.host_manifest(absolute)['entries'] if n['path'] == 'usr/bin/python3')['target'], 'python3.11')
        for mutation in ['field', 'mode', 'order', 'private', 'missing', 'link-loop']:
            bad = copy.deepcopy(host)
            if mutation == 'field':
                bad['commands'] = []
            elif mutation == 'mode':
                bad['files'][0]['mode'] = 0o4755
            elif mutation == 'order':
                bad['files'].reverse()
            elif mutation == 'private':
                bad['files'][0]['path'] = '/home/customer/secret'
            elif mutation == 'missing':
                bad['files'].pop()
            else:
                bad['links'] = [dict(path='/usr/lib/one', target='two'), dict(path='/usr/lib/two', target='one')]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                m.host_manifest(bad)

    def test_vendor_exact_locked_sources_and_checksums(self):
        m = load()
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            (root/'crates/ebpf').mkdir(parents=True)
            source_id = 'registry+https://github.com/rust-lang/crates.io-index'
            cargo = b'[package]\nname="tiny"\nversion="1.0.0"\n'
            original_tar, _ = tree_archive([('tiny-1.0.0/Cargo.toml', 'file', cargo)])
            original = gzip.compress(original_tar, mtime=0)
            original_sha = hashlib.sha256(original).hexdigest()
            original_entry = dict(path='tiny.crate', bytes=len(original), sha256=original_sha)
            (root/'tiny.crate').write_bytes(original)
            lock = ('version = 4\n[[package]]\nname = "tiny"\nversion = "1.0.0"\nsource = "'+source_id+'"\nchecksum = "'+original_sha+'"\n').encode()
            (root/'Cargo.lock').write_bytes(lock)
            (root/'crates/ebpf/Cargo.lock').write_bytes(b'version = 4\npackage = []\n')
            raw, _ = tree_archive([('Cargo.toml', 'file', b'[package]\nname="tiny"\nversion="1.0.0"\n')])
            archive = dict(path='tiny.tar', bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            (root/'tiny.tar').write_bytes(raw)
            component = dict(id='tiny', name='tiny', version='1.0.0', source=dict(kind='registry', location=source_id, checksum=original_sha, archive=original_entry, corresponding_source=archive))
            deps = dict(components=[component], host=['tiny'], bpf=[], build_std=[])
            admitted = SimpleNamespace(source=root, inputs=root, request=dict(dependencies=deps))
            with mock.patch.dict(m.os.environ, {'HOME': str(root), 'CARGO_HOME': str(root)}):
                plan = m._vendor_plan_in(admitted, m._ArchiveAdmission())
            base = '/build/vendor/'+hashlib.sha256(source_id.encode()).hexdigest()
            self.assertEqual(plan.mappings, {source_id: base})
            checksum = json.loads(plan.files[base+'/tiny-1.0.0/.cargo-checksum.json'].data)
            self.assertEqual(checksum, dict(files={'Cargo.toml': hashlib.sha256(cargo).hexdigest()}, package=original_sha))
            self.assertEqual(plan.config, ('[net]\noffline = true\n\n[source."crates-io"]\nreplace-with = "vendor-0"\n[source.vendor-0]\ndirectory = "'+base+'"\n').encode())

    def test_storage_literal_observations(self):
        m = load()
        mount = (42, '8:1', '/', '/dedicated', 'ext4', '/dev/owned')
        s = SimpleNamespace(st_dev=2049, st_ino=10, st_uid=m.os.getuid(), st_mode=0o40755)
        v = SimpleNamespace(f_blocks=16, f_frsize=4096, f_bfree=12, f_bavail=10)
        limits = m.dataclasses.replace(m.BudgetLimits(), storage=65536)
        with mock.patch.object(m.os, 'fstat', return_value=s), mock.patch.object(m.os, 'fstatvfs', return_value=v), mock.patch.object(m, '_mounts', return_value=[mount]):
            self.assertEqual(m._storage_observation(8, '/dedicated/work', limits)[5], 65536)
            for bad in [dict(f_blocks=17), dict(f_frsize=0)]:
                changed = copy.copy(v)
                changed.__dict__.update(bad)
                with mock.patch.object(m.os, 'fstatvfs', return_value=changed), self.assertRaises(ValueError):
                    m._storage_observation(8, '/dedicated/work', limits)

            for mounts in [[(42, '8:1', '/', '/dedicated', 'xfs', '/dev/owned')],
                           [mount, (43, '8:1', '/', '/alias', 'ext4', '/dev/owned')],
                           [mount, (43, '8:2', '/', '/dedicated/work/child', 'ext4', '/dev/other')], []]:
                with mock.patch.object(m, '_mounts', return_value=mounts), self.assertRaises(ValueError):
                    m._storage_observation(8, '/dedicated/work', limits)

    def test_budget_streams_and_deadline_equality_poison(self):
        m = load()
        limits = m.dataclasses.replace(m.BudgetLimits(), stdout=4, stderr=3, whole=2, cargo=10)
        state = m.BudgetState(limits, 0)
        m.charge_stream(state, 'stdout', 2)
        m.charge_stream(state, 'stdout', 2)
        m.charge_stream(state, 'stderr', 3)
        with self.assertRaises(ValueError):
            m.charge_stream(state, 'stdout', 1)
        with self.assertRaises(ValueError):
            m.check_deadline(state, m.Phase.Host, 0)
        state = m.BudgetState(limits, 0)
        m.check_deadline(state, m.Phase.Bootstrap, 0)
        m.check_deadline(state, m.Phase.Host, 1999999999)
        with self.assertRaises(ValueError):
            m.check_deadline(state, m.Phase.Host, 2000000000)
    def test_musl_bootstrap_exact_gnu_vector(self):
        m = load()
        actual = m.phase_spec(recipe(MUSL), m.Phase.Bootstrap)
        self.assertEqual(actual.executable, '/build/tools/host/bin/cargo')
        self.assertEqual(actual.argv, ['build', '--release', '--frozen', '--offline', '--target', GNU,
                                     '--jobs', '2', '--bin', 'osslscope-package', '--message-format=json-render-diagnostics'])
        self.assertNotIn('OSSL_PACKAGE_RECORD_DIR', dict(actual.environment))

    def test_all_five_literal_descriptors(self):
        m = load()
        for target in [GNU, MUSL]:
            for phase in m.Phase:
                actual = m.phase_spec(recipe(target), phase)
                name = phase.value
                env = COMMON.copy()
                if name in ['bootstrap', 'bpf', 'host']:
                    tc = 'bpf' if name == 'bpf' else 'host'
                    env += [('CARGO_TARGET_DIR', '/build/target/' + name),
                            ('CARGO_HOME', '/build/cache/' + name + '/cargo'),
                            ('HOME', '/build/home/' + name), ('TMPDIR', '/build/tmp/' + name),
                            ('PATH', '/build/tools/build/bin'), ('RUSTC', '/build/tools/' + tc + '/bin/rustc'),
                            ('CC', '/build/tools/build/bin/cc'), ('AR', '/build/tools/build/bin/ar'),
                            ('LD_LIBRARY_PATH', '/build/tools/llvm/lib:/build/tools/native/lib'),
                            ('CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER', '/build/tools/build/bin/cc')]
                    if name == 'host' and target == MUSL:
                        env += [('CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER', '/build/tools/native/bin/cc'),
                                ('CC_x86_64_unknown_linux_musl', '/build/tools/native/bin/cc'),
                                ('AR_x86_64_unknown_linux_musl', '/build/tools/native/bin/ar')]
                    if name == 'bpf':
                        env += [('CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER', '/build/tools/bpf-linker/bin/bpf-linker')]
                    if name == 'host':
                        env += [('OSSL_PACKAGE_RECORD_DIR', '/build/records')]
                    argv = (BPF if name == 'bpf' else HOST).copy()[1:]
                    if name == 'host':
                        argv[5] = target
                    if name == 'bootstrap':
                        argv[9] = 'osslscope-package'
                    executable = '/build/tools/' + tc + '/bin/cargo'
                    cwd = '/build/source/crates/ebpf' if name == 'bpf' else '/build/source'
                else:
                    env += [('HOME', '/build/home/bootstrap'), ('TMPDIR', '/build/tmp/bootstrap')]
                    executable = '/build/target/bootstrap/x86_64-unknown-linux-gnu/release/osslscope-package'
                    argv = (['build-bundle', '--root', '/build/source', '--inputs', '/build/inputs',
                             '--request', '/build/request.json', '--output', '/build/output']
                            if name == 'native' else ['verify-payload', '--root', '/build/output'])
                    cwd = '/build/source'
                self.assertEqual((actual.executable, actual.argv, actual.environment, actual.cwd),
                                 (executable, argv, env, cwd))
                expected = dict(executable=executable, argv=argv,
                                environment=[dict(name=n, value=v) for n, v in env], cwd=cwd)
                self.assertEqual(m.descriptor_sha256(actual), hashlib.sha256(canonical(expected)).hexdigest())

    def test_descriptor_mutations_refuse(self):
        m = load()
        for mutate in [lambda r: r['argv'].reverse(), lambda r: r['bpf_argv'].append('--bin'),
                       lambda r: r['environment'].reverse(), lambda r: r.update(jobs=3),
                       lambda r: r.update(schema='osslscope-build-recipe-v1'),
                       lambda r: r.update(config={'linker': 'ambient'}),
                       lambda r: r['determinism'].update(path_remap='ambient')]:
            r = recipe()
            mutate(r)
            with self.assertRaises(ValueError):
                m.phase_spec(r, m.Phase.Host)

    def test_ustar_tree_exact_and_stream_bounded(self):
        m = load()
        data, tree = tree_archive([('bin', 'directory', None), ('bin/tool', 'file', b'abc')])
        limits = m.BudgetLimits()
        for archive in [data, gzip.compress(data, mtime=0)]:
            usage = m.validate_tool_archive(archive, tree, limits)
            self.assertEqual((usage.decoded_bytes, usage.entries), (len(data), 2))
        for field, value in [('decoded', len(data)-1), ('entries', 1), ('member', 2), ('archive_input', 1)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                m.validate_tool_archive(data, tree, m.dataclasses.replace(limits, **{field: value}))
        for offset in [0, 148, 257, 511, 1024+3]:
            bad = bytearray(data)
            bad[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                m.validate_tool_archive(bytes(bad), tree, limits)
        for bad in [data[:-1], data+b'x', gzip.compress(data, mtime=1),
                    gzip.compress(data, mtime=0)*2, gzip.compress(data, mtime=0)[:-1]]:
            with self.assertRaises(ValueError):
                m.validate_tool_archive(bad, tree, limits)

    def test_archive_alias_link_overlap_refusal(self):
        m = load()
        for entries in [[('a', 'file', b'a'), ('a', 'file', b'a')],
                        [('a', 'symlink', '../escape')], [('a', 'symlink', 'b'), ('b', 'symlink', 'a')],
                        [('a', 'symlink', 'missing')], [('a', 'file', b'x'), ('a/b', 'file', b'x')]]:
            data, tree = tree_archive(entries)
            with self.assertRaises(ValueError):
                m.validate_tool_archive(data, tree, m.BudgetLimits())

    def test_cumulative_distinct_archives_boundary_and_poison(self):
        m = load()
        state = m.BudgetState(m.dataclasses.replace(m.BudgetLimits(), decoded=20, entries=3), 0)
        m.charge_archive(state, 10, 1)
        m.charge_archive(state, 10, 2)
        self.assertEqual((state.decoded, state.entries), (20, 3))
        with self.assertRaises(ValueError):
            m.charge_archive(state, 1, 0)
        with self.assertRaises(ValueError):
            m.charge_archive(state, 0, 0)
        state = m.BudgetState(m.BudgetLimits(), 0)
        with self.assertRaises(ValueError):
            m.charge_archive(state, 2**64, 0)

    def test_loader_literal_and_selected_source_drift_zero_spawn(self):
        m = load()
        self.assertIn('src/package/records.rs', m.POLICY_FILES)
        self.assertEqual(hashlib.sha256(canonical(m.POLICY_INVENTORY)).hexdigest(), '62d35545bf9b93389f9690c52c7fbfce5307acf832e0612ae126279aceb1e029')
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            for path in m.POLICY_FILES:
                (root/path).parent.mkdir(parents=True, exist_ok=True)
                (root/path).write_bytes((PRODUCT/path).read_bytes())
            manifest = dict(inventory=dict(files=[dict(path=p, mode=0o100644, bytes=(root/p).stat().st_size, sha256=hashlib.sha256((root/p).read_bytes()).hexdigest(), node=dict(kind='file')) for p in m.POLICY_FILES]))
            (root/'osslscope-source.json').write_bytes(canonical(manifest))
            self.assertEqual(m.loader_expectation(root), (2, '62d35545bf9b93389f9690c52c7fbfce5307acf832e0612ae126279aceb1e029'))
            for mutation in ['missing', 'additional', 'count-extra']:
                bad = copy.deepcopy(manifest)
                if mutation == 'missing':
                    bad['inventory']['files'].pop()
                if mutation == 'additional':
                    bad['inventory']['files'].append(dict(path='crates/ebpf-common/src/additional.rs'))
                (root/'osslscope-source.json').write_bytes(canonical(bad))
                if mutation == 'count-extra':
                    bad_policy = copy.deepcopy(m.POLICY_INVENTORY)
                    bad_policy['roles'][1]['extra']['map_count'] = 6
                    with mock.patch.object(m, 'POLICY_INVENTORY', bad_policy), self.assertRaises(ValueError):
                        m.loader_expectation(root)
                else:
                    with self.assertRaises(ValueError):
                        m.loader_expectation(root)
            (root/'osslscope-source.json').write_bytes(canonical(manifest))
            path = root/'src/package/records.rs'
            original = path.read_bytes()
            changed = original.replace(b'osslscope-harvest', b'osslscope-harvesX')
            self.assertNotEqual(original, changed)
            path.write_bytes(changed)
            with self.assertRaises(ValueError):
                m.loader_expectation(root)
            for selected, expected in m.POLICY_FILES.items():
                if selected != 'src/package/records.rs':
                    self.assertEqual(hashlib.sha256((root/selected).read_bytes()).hexdigest(), expected)
            with mock.patch.object(m, 'phase_spec', wraps=m.phase_spec) as descriptors:
                with self.assertRaises(ValueError):
                    m.admit_layout(dict(config={}, dependencies={}, tools={}), root, root)
                self.assertEqual(descriptors.call_count, 0)
            path.write_bytes(original)
            missing = root/'crates/bpf-sys/Cargo.toml'
            missing.unlink()
            with self.assertRaises((ValueError, OSError)):
                m.loader_expectation(root)
        self.assertNotIn('subprocess', m.__dict__)


if __name__ == '__main__':
    unittest.main()
