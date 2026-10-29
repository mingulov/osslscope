#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Assemble and prepare the accompanying sources used by build-package.py.

After extracting the published bundle: python3 source_payload.py --output NEW_DIR
No downloads, compilers, installation or privilege changes occur here.
"""
import argparse
import hashlib
import io
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import tomllib

REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
BUILTINS_TERMS = 'MIT AND Apache-2.0 WITH LLVM-exception AND (MIT OR Apache-2.0)'


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(name):
    path = PurePosixPath(name)
    if not path.parts or path.is_absolute() or '..' in path.parts or str(path) != name:
        raise ValueError('unsafe source payload path')
    return path


def checked_bytes(path, checksum=None, size=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 128 << 20:
            raise ValueError('source input must be a bounded nonempty regular file: '+path.name)
        data = stream.read((128 << 20)+1)
        after = os.fstat(stream.fileno())
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) != (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
        raise ValueError('source input changed during read: '+path.name)
    if len(data) != before.st_size or (size is not None and len(data) != size) or (checksum is not None and sha(data) != checksum):
        raise ValueError('missing, stale or mutated source input: '+path.name)
    return data


def archive_files(data, modes=None, source_links=False):
    """Reject traversal/special files; optionally materialize internal source links."""
    result, seen, links, total = {}, set(), {}, 0
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive:
            name = member.name.rstrip('/') if member.isdir() else member.name
            safe_path(name)
            if name in seen or len(seen) >= 20000:
                raise ValueError('duplicate or excessive source archive members')
            seen.add(name)
            if member.isdir():
                continue
            if member.issym() and source_links:
                if PurePosixPath(member.linkname).is_absolute():
                    raise ValueError('absolute first-party source link')
                target = posixpath.normpath(str(PurePosixPath(name).parent/member.linkname))
                safe_path(target)
                links[name] = target
                continue
            total += member.size
            if not member.isfile() or member.size < 0 or total > 256 << 20:
                raise ValueError('source archive contains aliases or excessive data')
            result[name] = archive.extractfile(member).read()
            if modes is not None:
                modes[name] = 0o755 if member.mode & 0o111 else 0o644
    for name,target in links.items():
        if target not in result or target in links:
            raise ValueError('first-party source link must target a regular source file')
        total += len(result[target])
        if total > 256 << 20:
            raise ValueError('excessive source link data')
        result[name] = result[target]
        if modes is not None:
            modes[name] = modes[target]
    return result


def stage_payload(root, archives, destination, source, revision, tree, artifacts, notices, notice_texts):
    """Inputs are the live locked graphs and reviewed runtime pins, never a frozen graph."""
    pins = json.loads((root/'packaging/runtime-sources.json').read_bytes())
    if pins['schema'] != 'osslscope-runtime-sources-v1':
        raise ValueError('unreviewed runtime source pins')
    destination.mkdir()
    records = []

    def put(payload_path, data, role, **metadata):
        safe_path(payload_path)
        path = destination/payload_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            raise ValueError('duplicate source payload path')
        path.write_bytes(data)
        records.append(dict(path=payload_path, bytes=len(data), sha256=sha(data), role=role, **metadata))

    first_party = checked_bytes(source)
    source_files = archive_files(first_party, source_links=True)
    for graph in notices['graphs']:
        lock = 'Cargo.lock' if graph['graph']=='host' else 'crates/ebpf/Cargo.lock'
        if sha(source_files[lock]) != graph['lock_sha256']:
            raise ValueError('source archive and current dependency graph disagree')
    put('product-source.tar', first_party, 'product-source')
    put('SOURCE-README.md', checked_bytes(root/'packaging/SOURCE-README.md'), 'recipe')
    put('source_payload.py', checked_bytes(root/'packaging/source_payload.py'), 'recipe')
    put('notices/dependency-notices.json', canonical(notices), 'dependency-inventory')
    for name, data in sorted(notice_texts.items()):
        put('notices/dependency-notices/'+name, data, 'dependency-notice')

    crates = {}
    for graph in notices['graphs']:
        for package in graph['packages']:
            if not package['source']:
                continue
            key = (package['name'],package['version'])
            if package['source'] != REGISTRY or not package['source_sha256']:
                raise ValueError('unsupported source dependency')
            if key in crates:
                prior = crates[key]
                if (prior['sha256'],prior['license']) != (package['source_sha256'],package['license']):
                    raise ValueError('inconsistent locked source graphs')
                prior['graphs'].append(graph['graph'])
            else:
                crates[key] = {'sha256':package['source_sha256'], 'license':package['license'], 'graphs':[graph['graph']], 'role':'project-cargo-crate', 'notices':package['notices'], 'vcs_revision':package.get('vcs_revision')}

    runtime_files = {}
    for component in pins['components']:
        name = component['archive']
        if Path(name).name != name:
            raise ValueError('invalid runtime archive name')
        data = checked_bytes(archives/name, component['sha256'], component['bytes'])
        files = archive_files(data)
        prefix = component['root']+'/'
        if any(not name.startswith(prefix) for name in files):
            raise ValueError('runtime source component root mismatch')
        if files[prefix+'git-commit-hash'].decode().strip() != component['rust_revision']:
            raise ValueError('runtime source revision mismatch')
        library = prefix+'rust-src/lib/rustlib/src/rust/library/'
        runtime_files[component['toolchain']] = files
        metadata = {key:component[key] for key in ('toolchain','rust_revision','url')}
        put('rust-runtime/'+component['archive'], data, 'rust-runtime-source-component', **metadata)
        # Make the principal runtime notices available with installed binaries too.
        for name, text in files.items():
            relative = name[len(prefix):]
            if relative in ('LICENSE-MIT','LICENSE-APACHE','COPYRIGHT') or relative == 'rust-src/lib/rustlib/src/rust/library/compiler-builtins/LICENSE.txt':
                put('runtime-notices/'+component['toolchain']+'/'+Path(name).name, text, 'runtime-notice')
        if component['toolchain']=='nightly-2026-05-20':
            manifest_path = library+'compiler-builtins/compiler-builtins/Cargo.toml'
            if manifest_path in files:
                terms = tomllib.loads(files[manifest_path].decode())['package']['license']
                if terms != BUILTINS_TERMS:
                    raise ValueError('nightly compiler_builtins terms need review')

    host_component = next(c for c in pins['components'] if c['toolchain']=='1.88.0')
    host_lock = host_component['root']+'/rust-src/lib/rustlib/src/rust/library/Cargo.lock'
    locked = tomllib.loads(runtime_files['1.88.0'][host_lock].decode())
    checksums = {(p['name'],p['version']):p.get('checksum') for p in locked['package']}
    for package in pins['host_std_crates']:
        key = (package['name'],package['version'])
        if checksums.get(key) != package['sha256']:
            raise ValueError('host std source and runtime lock disagree')
        if key in crates:
            if crates[key]['sha256'] != package['sha256']:
                raise ValueError('host std source conflicts with project lock')
            crates[key]['graphs'].append('host-stdlib')
        else:
            crates[key] = {'sha256':package['sha256'], 'bytes':package['bytes'], 'graphs':['host-stdlib'], 'role':'host-stdlib-cargo-crate'}

    for (name,version), package in sorted(crates.items()):
        filename = name+'-'+version+'.crate'
        if Path(filename).name != filename:
            raise ValueError('invalid source crate name')
        data = checked_bytes(archives/filename,package['sha256'],package.get('bytes'))
        files = archive_files(data)
        prefix = name+'-'+version+'/'
        if any(not path.startswith(prefix) for path in files):
            raise ValueError('crate source root mismatch')
        cargo = tomllib.loads(files[prefix+'Cargo.toml'].decode())['package']
        if (cargo['name'],cargo['version']) != (name,version) or not cargo.get('license'):
            raise ValueError('crate identity or license missing')
        terms = cargo['license']
        if package.get('license',terms) != terms or (name=='compiler_builtins' and terms != BUILTINS_TERMS):
            raise ValueError('crate license declaration needs review')
        for notice in package.get('notices',[]):
            key = notice['path'].removeprefix('dependency-notices/')
            original = files.get(prefix+Path(key).name)
            if original is None:
                vcs = json.loads(files[prefix+'.cargo_vcs_info.json'])['git']['sha1']
                if not package.get('vcs_revision') or vcs != package['vcs_revision']:
                    raise ValueError('notice supplement must bind original crate VCS source')
            elif notice_texts.get(key) != original:
                raise ValueError('cached notice differs from original locked source')
        put('cargo-crates/'+filename,data,package['role'],name=name,version=version,license=terms,
            graphs=sorted(set(package['graphs'])),url=f'https://static.crates.io/crates/{name}/{filename}')
        if package['role']=='host-stdlib-cargo-crate':
            for path, text in files.items():
                relative = path[len(prefix):]
                if '/' not in relative and relative.lower().startswith(('license','licence','copyright','notice','copying')):
                    put('runtime-notices/host-stdlib/'+name+'-'+version+'/'+relative,text,'runtime-notice')

    for notice in pins['notices']:
        data = checked_bytes(root/'packaging/notices'/notice['file'], notice['sha256'], notice['bytes'])
        put('runtime-notices/'+notice['file'],data,'runtime-notice',**{k:notice[k] for k in ('url','origin') if k in notice})
    public_artifacts = [{key:entry[key] for key in ('role','bin','bytes','sha256') if key in entry} for entry in artifacts]
    manifest = {'schema':'osslscope-accompanying-source-v1','product_ref':revision,'product_tree':tree,
                'artifacts':public_artifacts,'files':sorted(records,key=lambda r:r['path']),
                'runtime_scope':'pinned Rust library source components and bounded host std crate superset; ordinary compiler/linker/system runtimes remain prerequisites',
                'compiler_builtins_terms':BUILTINS_TERMS,
                'qualification':'source payload construction; no offline-build, reproducibility, installed-runtime or final rights qualification inferred'}
    (destination/'source-manifest.json').write_bytes(canonical(manifest))
    return manifest


def prepare(bundle, output):
    """Verify the full payload before producing a fresh ordinary Cargo source tree."""
    manifest = json.loads((bundle/'source-manifest.json').read_bytes())
    if manifest['schema'] != 'osslscope-accompanying-source-v1':
        raise ValueError('unsupported source manifest')
    files, records = {}, {}
    for record in manifest['files']:
        name = record['path']
        safe_path(name)
        if name in records:
            raise ValueError('duplicate source manifest path')
        records[name] = record
        files[name] = checked_bytes(bundle/name,record['sha256'],record['bytes'])
    paths = list(bundle.rglob('*'))
    if any(path.is_symlink() for path in paths):
        raise ValueError('source payload contains an alias')
    actual = {str(path.relative_to(bundle)) for path in paths if not path.is_dir()}
    if actual != set(files)|{'source-manifest.json'}:
        raise ValueError('missing or unlisted source payload')
    # Validate every archive before creating output. No archive extraction API
    # follows links or special files; all output files are ordinary new files.
    extracted, modes = {}, {}
    for name,data in files.items():
        if name=='product-source.tar' or records[name]['role'] in ('project-cargo-crate','host-stdlib-cargo-crate','rust-runtime-source-component'):
            modes[name] = {}
            extracted[name] = archive_files(data,modes[name],source_links=name=='product-source.tar')
    output.mkdir()
    product = output/'product'
    product.mkdir()

    def write_tree(base, content, permissions):
        for name,data in content.items():
            dest = base/name
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(data)
            dest.chmod(permissions[name])

    write_tree(product,extracted['product-source.tar'],modes['product-source.tar'])
    vendor = product/'vendor'
    vendor.mkdir()
    for name,content in extracted.items():
        record = records[name]
        if record['role'] in ('project-cargo-crate','host-stdlib-cargo-crate'):
            prefix = record['name']+'-'+record['version']
            write_tree(vendor,content,modes[name])
            checksums = {path[len(prefix)+1:]:sha(data) for path,data in content.items()}
            (vendor/prefix/'.cargo-checksum.json').write_bytes(canonical({'files':checksums,'package':record['sha256']}))
        elif record['role']=='rust-runtime-source-component':
            write_tree(output/'rust-runtime'/record['toolchain'],content,modes[name])
    # Cargo's build-std resolver visits the sysroot workspace, including
    # dependencies outside core. They already accompany the official nightly
    # component. Merge that ordinary vendor tree without acquiring more crates.
    for name,content in extracted.items():
        record = records[name]
        if record['role'] != 'rust-runtime-source-component' or record['toolchain'] != 'nightly-2026-05-20':
            continue
        markers = [path.removesuffix('.cargo-checksum.json') for path in content if '/library/vendor/' in path and path.endswith('/.cargo-checksum.json')]
        for prefix in markers:
            directory = PurePosixPath(prefix.rstrip('/')).name
            checksum = json.loads(content[prefix+'.cargo-checksum.json'])
            existing = vendor/directory/'.cargo-checksum.json'
            if existing.exists():
                if json.loads(existing.read_bytes())['package'] != checksum['package']:
                    raise ValueError('runtime vendor and crate source checksums disagree')
                continue
            subset = {directory+'/'+path[len(prefix):]:data for path,data in content.items() if path.startswith(prefix)}
            permissions = {directory+'/'+path[len(prefix):]:modes[name][path] for path in content if path.startswith(prefix)}
            write_tree(vendor,subset,permissions)
    config = product/'.cargo/config.toml'
    config.parent.mkdir(exist_ok=True)
    if config.exists():
        raise ValueError('product already configures Cargo; review directory-source merge')
    config.write_text('[source.crates-io]\nreplace-with = "accompanying-sources"\n\n[source.accompanying-sources]\ndirectory = "vendor"\n')
    shutil.copytree(bundle/'runtime-notices',output/'runtime-notices',dirs_exist_ok=True)
    print(output)


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True,help='fresh source directory')
    args = parser.parse_args()
    try:
        prepare(Path(__file__).resolve().parent,args.output)
    except (OSError,ValueError,KeyError,TypeError,tarfile.TarError) as error:
        parser.exit(1,'source preparation refused: '+str(error)+'\n')
