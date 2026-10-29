#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Construct matched five-role development packages from a clean pinned build.

No compilation, installation, acquisition or privilege changes. Output must be
fresh. Source payloads and dependency/runtime notices accompany each set.
Publication and final source/license/platform qualification are separate gates.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import tomllib

NAMES = ('osslscope', 'osslscope-harvest', 'osslscope-count', 'osslscope-members',
         'osslscope-provider-observation', 'osslscope-focused-count')
ROOT = Path(__file__).resolve().parents[1]


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON member')
        result[key] = value
    return result


def read_manifest(path):
    with path.open('rb') as stream:
        data = stream.read((1 << 20) + 1)
    if len(data) > 1 << 20:
        raise ValueError('build manifest exceeds 1 MiB')
    return json.loads(data, object_pairs_hook=no_duplicates)


def artifact_bytes(entry, name):
    path = Path(entry['path'])
    # The normal builder records real files; never silently follow aliases.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        maximum = 256 << 20 if name == 'osslscope' else 16 << 20
        if not stat.S_ISREG(before.st_mode) or not 64 < before.st_size <= maximum:
            raise ValueError('missing, empty, symlinked or oversized artifact: ' + name)
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError('artifact changed during read: ' + name)
    if type(entry.get('bytes')) is not int or len(data) != entry['bytes'] or sha(data) != entry.get('sha256'):
        raise ValueError('stale artifact length/hash: ' + name)
    if data[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('not ELF64 little endian: ' + name)
    kind, machine = struct.unpack_from('<HH', data, 16)
    if (name == 'osslscope' and (kind not in (2, 3) or machine != 62)) or (name != 'osslscope' and (kind != 1 or machine != 247)):
        raise ValueError('wrong ELF role: ' + name)
    return data


def select_artifacts(manifest, revision, tree):
    expected = {'schema': 'osslscope-dev-build-manifest-v1', 'product_ref': revision,
                'product_tree': tree, 'product_dirty': False, 'host_toolchain': '1.88.0',
                'bpf_toolchain': 'nightly-2026-05-20', 'bpf_linker': 'bpf-linker 0.10.4',
                'bpf_target': 'bpfel-unknown-none', 'host_profile': 'release', 'mode': 'both'}
    for key, value in expected.items():
        if type(manifest.get(key)) is not type(value) or manifest[key] != value:
            raise ValueError('full clean pinned release build required: ' + key)
    if not re.fullmatch('[0-9a-f]{40}', revision) or not re.fullmatch('[0-9a-f]{40}', tree):
        raise ValueError('source revision/tree required')
    arts = manifest.get('artifacts')
    if not isinstance(arts, list) or len(arts) != 6:
        raise ValueError('exact six artifacts (CLI and five BPF roles) required')
    selected = {}
    for entry in arts:
        if entry.get('role') == 'host-binary' and 'bin' not in entry:
            name = 'osslscope'
        elif entry.get('role') == 'bpf-object':
            name = entry.get('bin')
        else:
            raise ValueError('unknown artifact role')
        if name not in NAMES or name in selected:
            raise ValueError('unknown or duplicate role')
        if entry.get('product_ref') != revision or entry.get('product_tree') != tree:
            raise ValueError('mixed source artifact: ' + name)
        try:
            artifact_bytes(entry, name)
        except OSError as error:
            raise ValueError('unreadable artifact: ' + name) from error
        selected[name] = entry
    if set(selected) != set(NAMES):
        raise ValueError('five BPF roles and CLI required')
    return selected


def relative(name):
    return Path('bin/osslscope') if name == 'osslscope' else Path('lib/osslscope') / name


def stage_artifacts(stage, prefix, manifest, artifacts):
    stage.mkdir(mode=0o755)  # refuse overwrite, including existing symlinks
    entries = []
    for name in NAMES:
        entry = artifacts[name]
        data = artifact_bytes(entry, name)  # verify retained bytes, not an earlier read
        dest = stage / relative(name)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        dest.chmod(0o755 if name == 'osslscope' else 0o644)
        record = {'role': entry['role'], 'bytes': len(data), 'sha256': sha(data),
                  'dest': str(Path(prefix) / relative(name)), 'product_ref': manifest['product_ref']}
        if name != 'osslscope':
            record['bin'] = name
        entries.append(record)
    receipt = {'schema': 'osslscope-install-manifest-v2', 'prefix': prefix,
               'product_ref': manifest['product_ref'], 'product_dirty': False, 'artifacts': entries}
    dest = stage / 'share/osslscope/install-manifest.json'
    dest.parent.mkdir(parents=True)
    dest.write_bytes(canonical(receipt))
    dest.chmod(0o644)
    # Caller umask cannot strand installed ordinary users.
    for directory in stage.rglob('*'):
        if directory.is_dir():
            directory.chmod(0o755)
    stage.chmod(0o755)
    return receipt


def run(argv, **kwargs):
    return subprocess.check_output(argv, **kwargs)


def source_identity():
    if run(['git', '-C', str(ROOT), 'rev-parse', '--show-toplevel']).decode().strip() != str(ROOT):
        raise ValueError('source must be the product repository')
    if run(['git', '-C', str(ROOT), 'status', '--porcelain']):
        raise ValueError('source tree must be clean; commit reviewed changes and rebuild first')
    revision = run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD']).decode().strip()
    tree = run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD^{tree}']).decode().strip()
    return revision, tree


def restored_notices(name, version, checksum, vcs):
    index = json.loads((ROOT/'packaging/notices/restored.json').read_bytes(), object_pairs_hook=no_duplicates)
    entries = [p for p in index['packages'] if (p['name'],p['version'],p['crate_sha256'],p['vcs_revision']) == (name,version,checksum,vcs)]
    if index['schema'] != 'osslscope-restored-notices-v1' or len(entries) != 1:
        raise ValueError('dependency needs exact-source notice review: ' + name)
    entry = dict(entries[0])
    entry['texts'] = []
    for source in entries[0]['texts']:
        path = ROOT/'packaging/notices'/source['file']
        if path.name != source['file'] or path.is_symlink():
            raise ValueError('invalid restored notice path')
        data = path.read_bytes()
        if sha(data) != source['sha256'] or len(data) != source['bytes']:
            raise ValueError('restored notice text changed')
        entry['texts'].append(dict(source, data=data))
    return entry


def dependency_notices():
    """Inventory both locked resolved graphs and preserve actual crate notices.

    Links/checksums identify corresponding upstream source, not an offline
    source closure. Compiler/sysroot/native-runtime closure is a release gate.
    """
    graphs, texts = [], {}
    for label, manifest, toolchain in [('host', ROOT/'Cargo.toml', '1.88.0'), ('bpf', ROOT/'crates/ebpf/Cargo.toml', 'nightly-2026-05-20')]:
        metadata = json.loads(run(['cargo', '+'+toolchain, 'metadata', '--locked', '--offline', '--format-version', '1', '--manifest-path', str(manifest)], cwd=manifest.parent))
        lock = tomllib.loads((manifest.parent/'Cargo.lock').read_text())
        checksums = {(p['name'], p['version']): p.get('checksum') for p in lock['package']}
        identifiers = {p['id']: p['name']+'@'+p['version'] for p in metadata['packages']}
        packages = []
        for package in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'])):
            name, version, source = package['name'], package['version'], package['source']
            record = {'id': identifiers[package['id']], 'name': name, 'version': version,
                      'license': package['license'], 'source': source,
                      'source_url': f'https://static.crates.io/crates/{name}/{name}-{version}.crate' if source and source.startswith('registry+') else None,
                      'source_sha256': checksums.get((name, version)), 'notices': []}
            directory = Path(package['manifest_path']).parent
            if source:
                if source != 'registry+https://github.com/rust-lang/crates.io-index' or not record['source_sha256']:
                    raise ValueError('unsupported external dependency source: ' + name)
                candidates = [p for p in directory.iterdir() if p.is_file() and p.name.lower().startswith(('license', 'licence', 'notice', 'copying', 'copyright'))]
                if package.get('license_file'):
                    candidates.append(directory/package['license_file'])
                for path in sorted(set(candidates)):
                    resolved = path.resolve()
                    if not resolved.is_relative_to(directory.resolve()) or not path.is_file():
                        raise ValueError('dependency notice escapes source: ' + name)
                    text = path.read_bytes()
                    key = f'{name}-{version}/{path.name}'
                    texts[key] = text
                    record['notices'].append({'path': 'dependency-notices/'+key, 'sha256': sha(text), 'bytes': len(text)})
                if not record['notices']:
                    vcs = json.loads((directory/'.cargo_vcs_info.json').read_bytes())['git']['sha1']
                    restored = restored_notices(name, version, record['source_sha256'], vcs)
                    if record['license'] != restored['declared_license']:
                        raise ValueError('restored license declaration changed: ' + name)
                    record['selected_license'] = restored['selected_license']
                    record['vcs_revision'] = vcs
                    for text in restored['texts']:
                        key = f"{name}-{version}/{text['file']}"
                        texts[key] = text['data']
                        record['notices'].append({'path':'dependency-notices/'+key, 'sha256':text['sha256'], 'bytes':text['bytes'], 'upstream_url':text['upstream_url']})
                if not record['license']:
                    raise ValueError('dependency needs license review: ' + name)
            packages.append(record)
        nodes = [{'id': identifiers[n['id']], 'dependencies': sorted(identifiers[d] for d in n['dependencies'])} for n in metadata['resolve']['nodes']]
        graphs.append({'graph': label, 'lock_sha256': sha((manifest.parent/'Cargo.lock').read_bytes()),
                       'packages': packages, 'nodes': sorted(nodes, key=lambda n:n['id'])})
    return {'schema': 'osslscope-dependency-notices-v1', 'scope': 'locked resolved host/BPF graphs; not compiler/sysroot/native-runtime closure', 'graphs': graphs}, texts


def archive_tree(root, output, epoch, base=''):
    with output.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=epoch) as compressed, tarfile.open(fileobj=compressed, mode='w') as archive:
        for path in sorted(root.rglob('*')):
            info = archive.gettarinfo(str(path), arcname=str(Path(base)/path.relative_to(root)))
            if not (info.isfile() or info.isdir()):
                raise ValueError('only regular files and directories allowed in package tree')
            info.uid = info.gid = 0
            info.uname = info.gname = 'root'
            info.mtime = epoch
            with path.open('rb') if info.isfile() else io.BytesIO() as stream:
                archive.addfile(info, stream if info.isfile() else None)


def package_deb(stage, output, version, revision, epoch):
    control = stage/'DEBIAN'
    control.mkdir(mode=0o755)
    control.chmod(0o755)
    (stage/'usr').chmod(0o755)
    template = (ROOT/'packaging/deb/DEBIAN/control.in').read_text()
    (control/'control').write_text(template.replace('@VERSION@', version).replace('@REVISION@', revision))
    (control/'control').chmod(0o644)
    for name in ('postinst', 'prerm'):
        shutil.copyfile(ROOT/'packaging/deb/DEBIAN'/name, control/name)
        (control/name).chmod(0o755)
    env = dict(os.environ, SOURCE_DATE_EPOCH=str(epoch))
    run(['dpkg-deb', '--build', '--root-owner-group', str(stage), str(output)], env=env)


def package_rpm(stage, output, version, release, epoch, work):
    top = work/'rpmbuild'
    for name in ('BUILD', 'RPMS', 'SOURCES', 'SPECS', 'SRPMS', 'BUILDROOT'):
        (top/name).mkdir(parents=True)
    archive_tree(stage, top/'SOURCES'/f'osslscope-{version}.tar.gz', epoch, f'osslscope-{version}')
    run(['rpmbuild', '-bb', '--define', f'pkg_version {version}', '--define', f'pkg_release {release}',
         '--define', f'_topdir {top}', '--define', 'dist %{nil}', '--define', '_build_id_links none',
         '--define', '__os_install_post %{nil}', str(ROOT/'packaging/rpm/osslscope.spec')],
        env=dict(os.environ, SOURCE_DATE_EPOCH=str(epoch)))
    matches = list((top/'RPMS/x86_64').glob(f'osslscope-{version}-{release}.x86_64.rpm'))
    if len(matches) != 1:
        raise ValueError('expected one exact current RPM')
    shutil.copyfile(matches[0], output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=ROOT/'target/dev-build-manifest.json')
    parser.add_argument('--output', type=Path, required=True, help='fresh directory; never overwritten')
    parser.add_argument('--source-archives', type=Path, required=True, help='directory of original locked .crate and pinned rust-src archives; no downloads')
    parser.add_argument('--formats', default='tar,deb,rpm')
    parser.add_argument('--prefix', default='/usr', help='receipt binds this final absolute prefix; DEB/RPM require /usr')
    parser.add_argument('--revision', default='1', help='DEB revision/RPM release for lifecycle controls')
    args = parser.parse_args()
    formats = args.formats.split(',')
    try:
        if not formats or len(set(formats)) != len(formats) or set(formats)-{'tar','deb','rpm'}:
            raise ValueError('formats must be tar,deb,rpm or a nonempty subset')
        if not re.fullmatch('[1-9][0-9]*', args.revision):
            raise ValueError('positive numeric package revision required')
        if not re.fullmatch(r'/[A-Za-z0-9_/-]+', args.prefix) or any(p in ('.','..') for p in args.prefix.split('/')) or '//' in args.prefix or args.prefix.endswith('/'):
            raise ValueError('absolute normalized prefix required')
        if set(formats)&{'deb','rpm'} and args.prefix != '/usr':
            raise ValueError('DEB/RPM require /usr prefix')
        if args.output.exists() or args.output.is_symlink():
            raise FileExistsError('output already exists')
        args.output = args.output.absolute()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        revision, tree = source_identity()
        manifest = read_manifest(args.manifest)
        artifacts = select_artifacts(manifest, revision, tree)
        version = tomllib.loads((ROOT/'Cargo.toml').read_text())['package']['version']
        if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
            raise ValueError('unsupported package version')
        epoch = int(run(['git','-C',str(ROOT),'show','-s','--format=%ct',revision]))
        notices, notice_texts = dependency_notices()
        from source_payload import stage_payload
        runtime_pins = json.loads((ROOT/'packaging/runtime-sources.json').read_bytes(), object_pairs_hook=no_duplicates)
        for component in runtime_pins['components']:
            compiler_version = run(['rustc', '+'+component['toolchain'], '-vV']).decode()
            if 'commit-hash: '+component['rust_revision']+'\n' not in compiler_version:
                raise ValueError('runtime compiler revision needs source review')
        with tempfile.TemporaryDirectory(prefix='.osslscope-package-', dir=args.output.parent) as tmp:
            work = Path(tmp)
            result = work/'result'
            result.mkdir()
            source = result/f'osslscope-{version}-source.tar'
            run(['git','-C',str(ROOT),'archive','--format=tar',f'--output={source}',revision])
            payload = work/'accompanying-source'
            payload_manifest = stage_payload(ROOT, args.source_archives, payload, source, revision, tree,
                                             [artifacts[name] for name in NAMES], notices, notice_texts)
            accompanying = result/f'osslscope-{version}-accompanying-source.tar.gz'
            archive_tree(payload, accompanying, epoch)
            accompanying_info = {'archive':accompanying.name,'bytes':accompanying.stat().st_size,
                                 'sha256':sha(accompanying.read_bytes()),
                                 'manifest_sha256':sha(canonical(payload_manifest))}
            stage = work/'prefix'
            receipt = stage_artifacts(stage, args.prefix, manifest, artifacts)
            docs = stage/'share/doc/osslscope'
            docs.mkdir(parents=True)
            for name in ('docs/install.md', 'docs/licensing.md', 'NOTICE.md', 'LICENSE', 'LICENSES/GPL-2.0-only.txt'):
                shutil.copyfile(ROOT/name, docs/Path(name).name)
            (docs/'dependency-notices.json').write_bytes(canonical(notices))
            shutil.copytree(payload/'runtime-notices', docs/'runtime-notices')
            (docs/'accompanying-source-manifest.json').write_bytes(canonical(payload_manifest))
            shutil.copyfile(ROOT/'packaging/SOURCE-README.md', docs/'SOURCE-README.md')
            for name, data in notice_texts.items():
                path = docs/'dependency-notices'/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            source_info = {'schema':'osslscope-source-availability-v1', 'product_ref': revision, 'product_tree': tree,
                           'archive':source.name, 'sha256':sha(source.read_bytes()),
                           'dependency_sources':'dependency-notices.json',
                           'accompanying_source':accompanying_info,
                           'qualification':'development construction with accompanying source payload; final rights, reproducibility and installed platform qualification pending'}
            (docs/'source-availability.json').write_bytes(canonical(source_info))
            # Normalize all package content independent of caller umask.
            for path in stage.rglob('*'):
                path.chmod(0o755 if path.is_dir() or path == stage/'bin/osslscope' else 0o644)
                os.utime(path, (epoch,epoch))
            if 'tar' in formats:
                archive_tree(stage, result/f'osslscope-{version}-prefix.tar.gz', epoch)
            if 'rpm' in formats:
                package_rpm(stage, result/f'osslscope-{version}-{args.revision}.x86_64.rpm', version, args.revision, epoch, work)
            if 'deb' in formats:
                deb_stage = work/'deb'
                (deb_stage/'usr').mkdir(parents=True)
                shutil.copytree(stage, deb_stage/'usr', dirs_exist_ok=True)
                package_deb(deb_stage, result/f'osslscope_{version}-{args.revision}_amd64.deb', version, args.revision, epoch)
            if source_identity() != (revision,tree):
                raise ValueError('source changed during packaging')
            package_manifest = {'schema':'osslscope-current-package-v1', 'product_version':version, 'source':source_info,
                                'install_receipt':receipt, 'formats':sorted(formats),
                                'artifacts':[{'file':p.name,'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in sorted(result.iterdir())]}
            (result/'package-manifest.json').write_bytes(canonical(package_manifest))
            # Never replace an existing result, including concurrent writers.
            args.output.mkdir()
            try:
                for path in result.iterdir():
                    path.rename(args.output/path.name)
            except BaseException:
                # Keep partial outputs for diagnosis; never publish a success.
                raise
        print(args.output)
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, tarfile.TarError) as error:
        parser.exit(1, f'package construction refused: {error}\n')


if __name__ == '__main__':
    raise SystemExit(main())
