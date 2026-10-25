# SPDX-License-Identifier: GPL-3.0-or-later
"""Pure admission for the finite matched-package executor (Python 3.11).

No command line or launch backend exists here. Metadata consistency is not
initial-interpreter, source-rights, storage-exclusivity or worker admission.
"""
import dataclasses
import enum
import hashlib
import json
import os
import pathlib
import stat
import time
import tomllib
import zlib
from types import MappingProxyType


def fail(message):
    raise ValueError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def closed(value, keys):
    if type(value) is not dict or set(value) != set(keys.split()):
        fail('closed record fields')


def parse(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                fail('duplicate JSON key')
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=unique, parse_constant=lambda _: fail('JSON constant'))
    if canonical(value) != data:
        fail('noncanonical JSON')
    return value


def relative(path, empty=False):
    if type(path) is not str or (not path and not empty) or path.startswith('/') or '\\' in path or any(ord(c) < 32 or ord(c) == 127 for c in path):
        fail('unsafe relative path')
    if path and any(p in ['', '.', '..'] for p in path.split('/')):
        fail('unnormalized relative path')
    return path


def uint(value):
    if type(value) is not int or not 0 <= value <= 2**64-1:
        fail('unsigned integer overflow')
    return value


def add(a, b, maximum):
    result = uint(a) + uint(b)
    if result > min(maximum, 2**64-1):
        fail('budget exceeded')
    return result


@dataclasses.dataclass(frozen=True)
class BudgetLimits:
    whole: int = 14400
    native: int = 14400
    cargo: int = 7200
    readback: int = 7200
    stdout: int = 16777216
    stderr: int = 16777216
    cargo_line: int = 1048576
    storage: int = 68719476736
    archive_input: int = 536870912
    member: int = 536870912
    decoded: int = 34359738368
    entries: int = 500000


@dataclasses.dataclass
class BudgetState:
    limits: BudgetLimits
    start_ns: int
    decoded: int = 0
    entries: int = 0
    stdout: int = 0
    stderr: int = 0
    poisoned: bool = False
    phase_deadlines: dict = dataclasses.field(default_factory=dict)


def charge_archive(state, decoded_delta, entry_delta):
    if state.poisoned:
        fail('attempt poisoned')
    try:
        decoded = add(state.decoded, decoded_delta, state.limits.decoded)
        entries = add(state.entries, entry_delta, state.limits.entries)
    except ValueError:
        state.poisoned = True
        raise
    state.decoded, state.entries = decoded, entries


def charge_stream(state, stream, n):
    if stream not in ['stdout', 'stderr'] or state.poisoned:
        fail('invalid/poisoned stream')
    try:
        setattr(state, stream, add(getattr(state, stream), n, getattr(state.limits, stream)))
    except ValueError:
        state.poisoned = True
        raise


def check_deadline(state, phase, now_ns):
    if state.poisoned:
        fail('attempt poisoned')
    name = phase.value
    seconds = state.limits.native if name == 'native' else state.limits.readback if name == 'readback' else state.limits.cargo
    deadline = state.phase_deadlines.setdefault(name, min(state.start_ns + state.limits.whole * 10**9, now_ns + seconds * 10**9))
    if now_ns >= deadline:
        state.poisoned = True
        fail('attempt deadline')


class Phase(enum.Enum):
    Bootstrap = 'bootstrap'
    Native = 'native'
    Bpf = 'bpf'
    Host = 'host'
    Readback = 'readback'


@dataclasses.dataclass(frozen=True)
class CommandSpec:
    executable: str
    argv: list
    environment: list
    cwd: str


GNU = 'x86_64-unknown-linux-gnu'
MUSL = 'x86_64-unknown-linux-musl'
COMMON = [('LC_ALL', 'C'), ('TZ', 'UTC'), ('SOURCE_DATE_EPOCH', '1792799804'),
          ('CARGO_NET_OFFLINE', 'true'), ('CARGO_BUILD_JOBS', '2'),
          ('RUSTFLAGS', '--remap-path-prefix=/build=.')]


def host_argv(target):
    return ['cargo', 'build', '--release', '--frozen', '--offline', '--target', target,
            '--jobs', '2', '--bin', 'osslscope', '--message-format=json-render-diagnostics']


def bpf_argv():
    return ['cargo', 'build', '--release', '--frozen', '--offline', '-Z', 'build-std=core',
            '--target', 'bpfel-unknown-none', '--jobs', '2', '--bin', 'osslscope-harvest',
            '--bin', 'osslscope-count', '--bin', 'osslscope-members', '--message-format=json-render-diagnostics']


def phase_spec(recipe, phase):
    if not set(recipe) <= set('schema profile host_profile tools resources abi_evidence required_cells argv bpf_argv environment formats jobs determinism'.split()):
        fail('unknown recipe/descriptor configuration')
    target = recipe['host_profile']['target']
    if (recipe['schema'] != 'osslscope-build-recipe-v2' or type(recipe['jobs']) is not int or recipe['jobs'] != 2
            or target not in [GNU, MUSL] or recipe['argv'] != host_argv(target) or recipe['bpf_argv'] != bpf_argv()
            or recipe['environment'] != [dict(name=n, value=v) for n, v in COMMON]
            or recipe['determinism']['path_remap'] != '--remap-path-prefix=/build=.'):
        fail('recipe descriptor policy')
    if type(phase) is not Phase:
        fail('phase')
    name = phase.value
    env = COMMON.copy()
    if phase in [Phase.Native, Phase.Readback]:
        env += [('HOME', '/build/home/bootstrap'), ('TMPDIR', '/build/tmp/bootstrap')]
        argv = (['build-bundle', '--root', '/build/source', '--inputs', '/build/inputs', '--request', '/build/request.json', '--output', '/build/output']
                if phase is Phase.Native else ['verify-payload', '--root', '/build/output'])
        return CommandSpec('/build/target/bootstrap/' + GNU + '/release/osslscope-package', argv, env, '/build/source')
    tc = 'bpf' if phase is Phase.Bpf else 'host'
    argv = bpf_argv() if phase is Phase.Bpf else host_argv(target if phase is Phase.Host else GNU)
    if phase is Phase.Bootstrap:
        argv[10] = 'osslscope-package'
    env += [('CARGO_TARGET_DIR', '/build/target/' + name), ('CARGO_HOME', '/build/cache/' + name + '/cargo'),
            ('HOME', '/build/home/' + name), ('TMPDIR', '/build/tmp/' + name), ('PATH', '/build/tools/build/bin'),
            ('RUSTC', '/build/tools/' + tc + '/bin/rustc'), ('CC', '/build/tools/build/bin/cc'), ('AR', '/build/tools/build/bin/ar'),
            ('LD_LIBRARY_PATH', '/build/tools/llvm/lib:/build/tools/native/lib'),
            ('CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER', '/build/tools/build/bin/cc')]
    if phase is Phase.Host and target == MUSL:
        env += [('CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER', '/build/tools/native/bin/cc'),
                ('CC_x86_64_unknown_linux_musl', '/build/tools/native/bin/cc'), ('AR_x86_64_unknown_linux_musl', '/build/tools/native/bin/ar')]
    if phase is Phase.Bpf:
        env += [('CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER', '/build/tools/bpf-linker/bin/bpf-linker')]
    if phase is Phase.Host:
        env += [('OSSL_PACKAGE_RECORD_DIR', '/build/records')]
    return CommandSpec('/build/tools/' + tc + '/bin/cargo', argv[1:], env,
                       '/build/source/crates/ebpf' if phase is Phase.Bpf else '/build/source')


def descriptor_sha256(spec):
    return digest(canonical(dict(executable=spec.executable, argv=spec.argv,
                                 environment=[dict(name=n, value=v) for n, v in spec.environment], cwd=spec.cwd)))


def link_target(path, target):
    if type(target) is not str or not target or target.startswith('/') or '\\' in target or any(ord(c) < 32 for c in target):
        fail('invalid link target')
    parts = path.split('/')[:-1]
    for part in target.split('/'):
        if part in ['', '.']:
            fail('unnormalized link target')
        if part == '..':
            if not parts:
                fail('escaping link')
            parts.pop()
        else:
            parts.append(part)
    return '/'.join(parts)


def validate_tree(tree, implicit=False):
    closed(tree, 'schema entries')
    if tree['schema'] != 'osslscope-tool-tree-v1' or type(tree['entries']) is not list:
        fail('tree schema')
    nodes = {}
    last = ''
    for row in tree['entries']:
        kind = row.get('kind')
        closed(row, {'file': 'path kind mode bytes sha256', 'directory': 'path kind mode', 'symlink': 'path kind mode target'}.get(kind, ''))
        path = relative(row['path'])
        if path <= last:
            fail('unsorted/duplicate tree paths')
        last = path
        if type(row['mode']) is not int or row['mode'] not in ({'file': [0o644, 0o755], 'directory': [0o755], 'symlink': [0o777]}[kind]):
            fail('tree node mode')
        if kind == 'file':
            uint(row['bytes'])
            if row['bytes'] > BudgetLimits().member or type(row['sha256']) is not str or len(row['sha256']) != 64 or any(c not in '0123456789abcdef' for c in row['sha256']):
                fail('file size/digest')
        nodes[path] = row
    for path, row in nodes.items():
        parts = path.split('/')
        for i in range(1, len(parts)):
            ancestor = '/'.join(parts[:i])
            if (ancestor not in nodes and not implicit) or (ancestor in nodes and nodes[ancestor]['kind'] != 'directory'):
                fail('missing/non-directory extraction ancestor')
        if not implicit:
            resolve_node(nodes, path)
    return nodes


def resolve_node(nodes, path):
    seen = set()
    while True:
        if path in seen or path not in nodes:
            fail('unresolved/looped link graph')
        seen.add(path)
        parts = path.split('/')
        for i in range(1, len(parts)+1):
            prefix = '/'.join(parts[:i])
            row = nodes.get(prefix)
            if row is None:
                fail('unresolved link ancestor')
            if row['kind'] == 'symlink':
                target = link_target(prefix, row['target'])
                path = '/'.join([target] + parts[i:])
                break
        else:
            return nodes[path]


@dataclasses.dataclass(frozen=True)
class ArchiveUsage:
    decoded_bytes: int
    entries: int



@dataclasses.dataclass(frozen=True)
class _RawNode:
    header: bytes
    path: str
    mode: int
    kind: str
    link: str
    uid: int
    gid: int
    mtime: int
    uname: str
    gname: str
    major: int
    minor: int
    posix: bool
    strict: bool
    data: bytes


@dataclasses.dataclass(frozen=True)
class _DecodedArchive:
    raw: bytes
    nodes: tuple
    decoded: int
    gzip: bool
    normalized_gzip: bool


def _tar_text(field):
    end = field.find(b'\0')
    if end >= 0:
        if any(field[end:]):
            fail('tar text padding')
        field = field[:end]
    return field.decode('utf-8')


def _tar_octal(field):
    raw = field.strip(b' \0')
    if not raw:
        return 0
    if any(c not in b'01234567' for c in raw):
        fail('tar octal')
    return uint(int(raw, 8))


class _ArchiveAdmission:
    def __init__(self):
        self.state = BudgetState(BudgetLimits(), time.monotonic_ns())
        self.cache = {}
        self.binding = None
        self.decode_count = 0
        self.retained_rows = 0

    def ensure(self):
        if self.state.poisoned:
            fail('archive owner poisoned')

    def bind(self, binding):
        self.ensure()
        if self.binding is not None and self.binding != binding:
            self.state.poisoned = True
            fail('archive owner source/input/recipe binding drift')
        self.binding = binding

    def decode(self, data, profile):
        try:
            self.ensure()
            if profile not in ['tool', 'source', 'registry']:
                fail('archive policy')
            limit = self.state.limits
            input_limit = min(limit.archive_input, 67108864 if profile == 'registry' else 536870912)
            decoded_limit = min(limit.decoded, 536870912 if profile != 'tool' else 34359738368)
            member_limit = min(limit.member, 67108864 if profile == 'registry' else 536870912)
            entry_limit = min(limit.entries, 10000 if profile != 'tool' else 500000)
            if not data or len(data) > input_limit:
                fail('archive input bound')
            key = (digest(data), len(data))
            if key in self.cache:
                value = self.cache[key]
                if value.raw != data:
                    fail('archive digest collision')
            else:
                value = self._read(data, profile, decoded_limit, member_limit, entry_limit)
                self.cache[key] = value
                self.decode_count += 1
            if (value.decoded > decoded_limit or len(value.nodes) > entry_limit
                    or any(len(n.data) > member_limit for n in value.nodes)
                    or profile == 'source' and value.gzip or profile == 'registry' and not value.gzip
                    or profile == 'tool' and value.gzip and not value.normalized_gzip):
                fail('cached archive policy/limit mismatch')
            return value
        except BaseException:
            self.state.poisoned = True
            raise

    def _read(self, data, profile, decoded_limit, member_limit, entry_limit):
        zipped = data.startswith(b'\x1f\x8b')
        normalized = len(data) >= 18 and data[2:8] == b'\x08\x00\x00\x00\x00\x00'
        if profile == 'source' and zipped or profile == 'registry' and not zipped or profile == 'tool' and zipped and not normalized:
            fail('archive compression metadata')
        def chunks():
            if not zipped:
                for offset in range(0, len(data), 65536):
                    yield data[offset:offset+65536]
                return
            decoder = zlib.decompressobj(31)
            for offset in range(0, len(data), 65536):
                pending = data[offset:offset+65536]
                while pending:
                    chunk = decoder.decompress(pending, 65536)
                    pending = decoder.unconsumed_tail
                    if chunk:
                        yield chunk
                    if decoder.unused_data:
                        fail('multiple gzip members/trailing bytes')
            if not decoder.eof:
                fail('gzip trailer/truncation')
        iterator, pending, decoded, consumed = iter(chunks()), b'', 0, 0
        def read(n):
            nonlocal pending, decoded, consumed
            consumed = add(consumed, n, decoded_limit)
            while len(pending) < n:
                chunk = next(iterator, b'')
                if not chunk:
                    fail('truncated archive')
                decoded = add(decoded, len(chunk), decoded_limit)
                charge_archive(self.state, len(chunk), 0)
                pending += chunk
            result, pending = pending[:n], pending[n:]
            return result
        nodes = []
        while True:
            h = read(512)
            if not any(h):
                if any(read(512)) or any(pending):
                    fail('tar end/hidden bytes')
                for chunk in iterator:
                    decoded = add(decoded, len(chunk), decoded_limit)
                    charge_archive(self.state, len(chunk), 0)
                    if any(chunk):
                        fail('hidden tar payload')
                if decoded % 512:
                    fail('tar alignment')
                return _DecodedArchive(data, tuple(nodes), decoded, zipped, normalized)
            if len(nodes) >= entry_limit:
                fail('per-archive entry bound before retention')
            charge_archive(self.state, 0, 1)
            if _tar_octal(h[148:156]) != sum(h[:148])+256+sum(h[156:]):
                fail('tar checksum')
            posix = h[257:265] == b'ustar\x0000'
            gnu = h[257:265] == b'ustar  \0'
            if not (posix or gnu) or posix and any(h[500:]) or gnu and any(h[345:]):
                fail('tar header/extension')
            name, prefix = _tar_text(h[:100]), _tar_text(h[345:500]) if posix else ''
            path = prefix+'/'+name if prefix else name
            size, mode = _tar_octal(h[124:136]), _tar_octal(h[100:108])
            if size > member_limit or h[156] not in [48, 50, 53]:
                fail('archive member size/type')
            # decoded includes prefetched pending bytes; only future bytes need
            # remaining-ledger admission, while consumed covers the full member.
            end = add(consumed, size+(-size) % 512, decoded_limit)
            add(self.state.decoded, max(0, end-decoded), self.state.limits.decoded)
            strict = all(field.strip(b' \0') and all(c in b'01234567' for c in field.strip(b' \0'))
                         for field in [h[100:108], h[108:116], h[116:124], h[124:136], h[136:148]])
            kept = bytearray()
            remaining = size
            while remaining:
                chunk = read(min(remaining, 65536))
                kept.extend(chunk)
                remaining -= len(chunk)
            if any(read((-size) % 512)):
                fail('tar member padding')
            node = _RawNode(h, path, mode, chr(h[156]), _tar_text(h[157:257]), _tar_octal(h[108:116]),
                            _tar_octal(h[116:124]), _tar_octal(h[136:148]), _tar_text(h[265:297]),
                            _tar_text(h[297:329]), _tar_octal(h[329:337]), _tar_octal(h[337:345]), posix, bool(strict), bytes(kept))
            self.retained_rows += 1
            nodes.append(node)


def _archive_members_in(owner, data, tree, retain=False, implicit=False):
    try:
        nodes = validate_tree(tree, implicit)
        parsed = owner.decode(data, 'tool')
        seen, files = set(), {}
        for item in parsed.nodes:
            path = item.path[:-1] if item.kind == '5' and item.path.endswith('/') else item.path
            relative(path)
            kind = {'0': 'file', '2': 'symlink', '5': 'directory'}[item.kind]
            if path in seen or path not in nodes:
                fail('extra/duplicate tar node')
            row = nodes[path]
            # Preserve the tool parser's asymmetric NUL/space trimming and
            # the all-NUL device-pair exception on fresh and cached records.
            fields = [item.header[100:108], item.header[108:116], item.header[116:124],
                      item.header[124:136], item.header[136:148], item.header[148:156]]
            if any(item.header[329:345]):
                fields.extend([item.header[329:337], item.header[337:345]])
            tool_numbers = all(value and all(c in b'01234567' for c in value)
                               for value in (field.rstrip(b' \0').lstrip(b' ') for field in fields))
            if (not item.posix or not item.strict or not tool_numbers or item.uid or item.gid or item.mtime not in [0, 1792799804]
                    or item.uname or item.gname or item.major or item.minor or kind != row['kind'] or item.mode != row['mode']
                    or len(item.data) != (row['bytes'] if kind == 'file' else 0)
                    or item.link != (row['target'] if kind == 'symlink' else '')):
                fail('tool member metadata/shape')
            if kind == 'file' and digest(item.data) != row['sha256']:
                fail('tool member digest')
            if kind == 'file' and retain:
                files[path] = item.data
            seen.add(path)
        if seen != set(nodes):
            fail('missing tar member')
        return ArchiveUsage(parsed.decoded, len(parsed.nodes)), files
    except BaseException:
        owner.state.poisoned = True
        raise


def archive_members(data, tree, limits, retain=False, implicit=False):
    owner = _ArchiveAdmission()
    owner.state.limits = limits
    return _archive_members_in(owner, data, tree, retain, implicit)


def validate_tool_archive(data, tree, limits):
    return archive_members(data, tree, limits)[0]


ROOTS = ('rootfs', 'host', 'bpf', 'linker', 'llvm', 'native', 'build', 'package')
FIXED = {'host': ('host', 'bin/rustc', 'file'), 'host-cargo': ('host', 'bin/cargo', 'file'),
         'bpf': ('bpf', 'bin/rustc', 'file'), 'bpf-cargo': ('bpf', 'bin/cargo', 'file'),
         'linker': ('linker', 'bin/bpf-linker', 'file'), 'native-compiler': ('native', 'bin/cc', 'file'),
         'native-linker': ('native', 'bin/ld', 'file'), 'archive': ('native', 'bin/ar', 'file'),
         'build-compiler': ('build', 'bin/cc', 'file'), 'build-linker': ('build', 'bin/ld', 'file'),
         'build-archive': ('build', 'bin/ar', 'file'), 'host-sysroot': ('host', 'lib/rustlib', 'tree'),
         'bpf-sysroot': ('bpf', 'lib/rustlib', 'tree'), 'rust-src': ('bpf', 'lib/rustlib/src/rust', 'tree'),
         'sysroot': ('native', 'sysroot', 'tree'), 'build-sysroot': ('build', 'sysroot', 'tree'),
         'llvm': ('llvm', 'lib', 'tree'), 'package': ('package', '', 'tree'), 'builder': ('rootfs', '', 'tree')}


def content_entry(row):
    closed(row, 'path sha256 bytes')
    relative(row['path'])
    uint(row['bytes'])
    if row['bytes'] > BudgetLimits().archive_input or type(row['sha256']) is not str or len(row['sha256']) != 64 or any(c not in '0123456789abcdef' for c in row['sha256']):
        fail('content entry')


def retained(root, entry):
    content_entry(entry)
    data = read_nofollow(root, entry['path'], entry['bytes'])
    if len(data) != entry['bytes'] or digest(data) != entry['sha256']:
        fail('retained asset content drift')
    return data


def read_nofollow(root, path, maximum):
    parts = relative(path).split('/')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            previous, fd = fd, next_fd
            os.close(previous)
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
                fail('nonregular/linked/oversized input')
            out = bytearray()
            while True:
                chunk = os.read(file_fd, min(65536, maximum+1-len(out)))
                if not chunk:
                    break
                if len(out)+len(chunk) > maximum:
                    fail('input grew')
                out.extend(chunk)
            after = os.fstat(file_fd)
            if (before.st_dev, before.st_ino, before.st_mode, before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mode, after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                fail('input changed')
            return bytes(out)
        finally:
            os.close(file_fd)
    finally:
        os.close(fd)


def host_manifest(document):
    closed(document, 'schema files links')
    if document['schema'] != 'osslscope-executor-host-v1':
        fail('host schema')
    nodes = []
    for kind in ['files', 'links']:
        last = ''
        for row in document[kind]:
            closed(row, 'path sha256 bytes mode' if kind == 'files' else 'path target')
            path = row['path']
            if not path.startswith('/') or path <= last:
                fail('host path order')
            relative(path[1:])
            if path.startswith(('/build/', '/home/', '/root/', '/tmp/', '/work/')):
                fail('private host path')
            last = path
            if kind == 'files':
                content_entry(dict(path=path[1:], bytes=row['bytes'], sha256=row['sha256']))
                if row['bytes'] == 0 or row['mode'] not in [0o644, 0o755] or type(row['mode']) is not int:
                    fail('host file mode/length')
                nodes.append(dict(row, path=path[1:], kind='file'))
            else:
                target = row['target']
                if target.startswith('/'):
                    relative(target[1:])
                    if target.startswith(('/build/', '/home/', '/root/', '/tmp/', '/work/')):
                        fail('private absolute host target')
                    target = os.path.relpath(target, str(pathlib.PurePosixPath(path).parent))
                nodes.append(dict(path=path[1:], kind='symlink', mode=0o777, target=target))
    paths = {n['path'] for n in nodes}
    for node in nodes.copy():
        for parent in pathlib.PurePosixPath(node['path']).parents:
            if str(parent) != '.' and str(parent) not in paths:
                nodes.append(dict(path=str(parent), kind='directory', mode=0o755))
                paths.add(str(parent))
    tree = dict(schema='osslscope-tool-tree-v1', entries=sorted(nodes, key=lambda n: n['path']))
    parsed = validate_tree(tree)
    for path in ['usr/bin/python3.11', 'usr/bin/bwrap']:
        node = resolve_node(parsed, path)
        if node['kind'] != 'file' or node['mode'] != 0o755:
            fail('host executable binding')
    return tree


def subtree(tree, member):
    relative(member, empty=True)
    nodes = validate_tree(tree)
    if not member:
        return tree
    if member not in nodes or nodes[member]['kind'] != 'directory':
        fail('subtree root')
    rows = [dict(row, path=path[len(member)+1:]) for path, row in nodes.items() if path.startswith(member+'/')]
    result = dict(schema='osslscope-tool-tree-v1', entries=rows)
    validate_tree(result)
    return result


@dataclasses.dataclass(frozen=True)
class AdmittedLayout:
    recipe: dict
    request: dict
    roots: dict
    files: dict
    identities: dict
    source: pathlib.Path
    inputs: pathlib.Path
    usage: ArchiveUsage
    _archives: object = None


def _admit_documents(recipe, layout, host, asset, source_layout, closure_entries=()):
    return _admit_documents_in(_ArchiveAdmission(), recipe, layout, host, asset, source_layout, closure_entries)


def _admit_documents_in(owner, recipe, layout, host, asset, source_layout, closure_entries=()):
    try:
        owner.ensure()
        return _admit_documents_data(owner, recipe, layout, host, asset, source_layout, closure_entries)
    except BaseException:
        owner.state.poisoned = True
        raise


def _admit_documents_data(owner, recipe, layout, host, asset, source_layout, closure_entries=()):
    closed(layout, 'schema archives bindings')
    if layout['schema'] != 'osslscope-executor-layout-v1' or canonical(layout) != source_layout:
        fail('layout/source equality')
    resources = recipe['resources']
    roles = {r['role']: r for r in resources}
    if len(roles) != len(resources) or not set(FIXED).union({'llvm-library', 'executor-host', 'executor-layout'}) <= set(roles):
        fail('resource roles')
    roots, files, by_hash, usage = {}, {}, {}, owner.state
    last = None
    acquisitions = {canonical(r['acquisition']) for r in resources if r['role'] not in ['executor-host', 'executor-layout']}
    actual = set()
    retained_entries = {canonical(r['content']) for r in resources}
    retained_entries.update(canonical(entry) for entry in closure_entries)
    for row in layout['archives']:
        closed(row, 'acquisition tree root')
        key = (row['root'], row['acquisition']['path'])
        if row['root'] not in ROOTS or (last is not None and key <= last):
            fail('archive order/root')
        last = key
        identity = canonical(row['acquisition'])
        if identity not in acquisitions or identity in actual or canonical(row['tree']) not in retained_entries:
            fail('acquisition/tree closure')
        actual.add(identity)
        data = asset(row['acquisition'])
        tree = parse(asset(row['tree']))
        use, contents = _archive_members_in(owner, data, tree, retain=True)
        sha = row['acquisition']['sha256']
        if sha in by_hash:
            fail('archive content alias')
        by_hash[sha] = (row['root'], tree, contents)
        merged = roots.setdefault(row['root'], {})
        for path, node in validate_tree(tree).items():
            if path in merged and merged[path] != node:
                fail('conflicting overlay')
            merged[path] = node
            if node['kind'] == 'file':
                key = (row['root'], path)
                if key in files and files[key] != contents[path]:
                    fail('conflicting overlay bytes')
                files.setdefault(key, contents[path])
    if actual != acquisitions or set(roots) != set(ROOTS):
        fail('missing acquisition/eight roots')
    for root, nodes in roots.items():
        validate_tree(dict(schema='osslscope-tool-tree-v1', entries=sorted(nodes.values(), key=lambda n: n['path'])))
    for anchor in ['build', 'proc', 'dev']:
        if roots['rootfs'].get(anchor) != dict(path=anchor, kind='directory', mode=0o755) or any(p.startswith(anchor+'/') for p in roots['rootfs']):
            fail('rootfs empty anchors')
    for root, nodes in roots.items():
        if any(p.rsplit('/', 1)[-1] in ['config', 'config.toml'] and '.cargo' in p.split('/') for p in nodes):
            fail('ambient Cargo configuration')
    expected_roles = set(roles)-{'executor-host', 'executor-layout'}
    bound, last = set(), ''
    for row in layout['bindings']:
        closed(row, 'role archive_sha256 member kind')
        role, member = row['role'], relative(row['member'], empty=row['kind'] == 'tree')
        if role <= last or role not in expected_roles or row['kind'] not in ['file', 'tree'] or row['archive_sha256'] not in by_hash:
            fail('binding order/closure')
        last = role
        bound.add(role)
        root, tree, contents = by_hash[row['archive_sha256']]
        if role in FIXED and (root, member, row['kind']) != FIXED[role]:
            fail('fixed destination binding')
        if role == 'llvm-library' and (root != 'llvm' or row['kind'] != 'file' or not member.startswith('lib/')):
            fail('actual LLVM member')
        if row['kind'] == 'tree':
            data = canonical(subtree(tree, member))
        else:
            node = resolve_node(validate_tree(tree), member)
            if node['kind'] != 'file' or (role in FIXED and node['mode'] != 0o755):
                fail('executable binding')
            data = contents[node['path']]
        if data != asset(roles[role]['content']) or roles[role]['acquisition']['sha256'] != row['archive_sha256']:
            fail('role member/content/acquisition mismatch')
    if bound != expected_roles:
        fail('incomplete runtime bindings')
    host_tree = host_manifest(host)
    host_resource = roles['executor-host']
    host_use, _ = _archive_members_in(owner, asset(host_resource['acquisition']), host_tree)
    layout_bytes = canonical(layout)
    layout_tree = dict(schema='osslscope-tool-tree-v1', entries=[dict(path='layout.json', kind='file', mode=0o644, bytes=len(layout_bytes), sha256=digest(layout_bytes))])
    layout_use, _ = _archive_members_in(owner, asset(roles['executor-layout']['acquisition']), layout_tree)
    if recipe['host_profile']['target'] == GNU:
        for a, b in [('native-compiler', 'build-compiler'), ('archive', 'build-archive'), ('sysroot', 'build-sysroot')]:
            if asset(roles[a]['content']) != asset(roles[b]['content']):
                fail('GNU selected/build equality')
    return roots, files, ArchiveUsage(usage.decoded, usage.entries)


def reject_cargo_configs(root):
    for ancestor in [root]+list(root.parents):
        if any((ancestor/'.cargo'/name).exists() or (ancestor/'.cargo'/name).is_symlink() for name in ['config', 'config.toml']):
            fail('source/ancestor Cargo config')
    for directory in [pathlib.Path.home()/'.cargo', pathlib.Path(os.environ.get('CARGO_HOME', str(pathlib.Path.home()/'.cargo')))]:
        if any((directory/name).exists() or (directory/name).is_symlink() for name in ['config', 'config.toml']):
            fail('user Cargo config')


def _same(left, right):
    return canonical(left) == canonical(right)


def _verify_source_files(root, manifest):
    expected = {}
    for row in manifest['inventory']['files']:
        closed(row, 'path mode sha256 bytes node')
        path = relative(row['path'])
        uint(row['bytes'])
        if path in expected:
            fail('duplicate source inventory path')
        expected[path] = row
    seen, visited = set(), 0
    def visit(fd, prefix):
        nonlocal visited
        for name in os.listdir(fd):
            visited += 1
            if visited > 20000:
                fail('source traversal bound')
            path = prefix+name
            relative(path)
            metadata = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                try:
                    visit(child, path+'/')
                finally:
                    os.close(child)
            elif path == 'osslscope-source.json':
                if not stat.S_ISREG(metadata.st_mode):
                    fail('nonregular source manifest')
            else:
                row = expected.get(path)
                if row is None:
                    fail('unlisted source file: '+path)
                if '.cargo' in path.split('/') and name in ['config', 'config.toml']:
                    fail('nested source Cargo configuration')
                seen.add(path)
                if stat.S_ISREG(metadata.st_mode) and row['node'] == dict(kind='file'):
                    mode = 0o100755 if metadata.st_mode & 0o111 else 0o100644
                    if row['mode'] != mode:
                        fail('source executable-mode drift')
                    data = read_nofollow(root, path, row['bytes'])
                elif stat.S_ISLNK(metadata.st_mode) and row['node'].get('kind') == 'symlink':
                    target = os.readlink(name, dir_fd=fd)
                    if row['mode'] != 0o120000 or target != row['node']['target']:
                        fail('source symlink mode/target drift')
                    link_target(path, target)
                    data = target.encode()
                else:
                    fail('source node type drift')
                if len(data) != row['bytes'] or digest(data) != row['sha256']:
                    fail('source file identity drift')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        visit(fd, '')
    finally:
        os.close(fd)
    if seen != set(expected):
        fail('missing source inventory file')


def _admission_records(request, root, inputs, recipe, recipe_bytes):
    """Repeat the source-bound record equalities before deriving any descriptor.

    This checks metadata/content, not acquisition authenticity or source rights.
    The later native source closure route remains mandatory.
    """
    config, deps, tools = request['config'], request['dependencies'], request['tools']
    closed(config, 'schema product_version cargo_toml_sha256 release_toml_sha256 package_epoch package_revision source_epoch jobs selected_profile profiles artifacts')
    closed(recipe, 'schema profile host_profile tools resources abi_evidence required_cells argv bpf_argv environment formats jobs determinism')
    closed(tools, 'host bpf linker llvm builder components')
    closed(deps, 'schema locks components host bpf tool_sources build_std linker_build runtime')
    profile = config['selected_profile']
    if profile not in ['gnu', 'musl'] or recipe['profile'] != profile:
        fail('profile policy')
    target = GNU if profile == 'gnu' else MUSL
    formats = ['deb', 'rpm', 'prefix'] if profile == 'gnu' else ['prefix']
    closed(recipe['host_profile'], 'target abi_profile abi_floor')
    if (recipe['host_profile']['target'] != target or recipe['host_profile']['abi_profile'] != 'linux-x86_64-'+profile
            or type(recipe['host_profile']['abi_floor']) is not str or not recipe['host_profile']['abi_floor'] or recipe['formats'] != formats):
        fail('host profile policy')
    determinism = dict(locale='C', timezone='UTC', umask=18, uid=0, gid=0, file_mode=420,
                       executable_mode=493, symlink_mode=511, mtime=1792799804,
                       archive_order='lexical', compression='none', path_remap='--remap-path-prefix=/build=.')
    if not _same(recipe['determinism'], determinism) or not _same(recipe['tools'], tools):
        fail('determinism/tools policy')
    for name, value in [('package_epoch', 1), ('package_revision', 1), ('source_epoch', 1792799804), ('jobs', 2)]:
        if type(config[name]) is not int or config[name] != value:
            fail('fixed release policy')
    if config['schema'] != 'osslscope-release-config-v1' or deps['schema'] != 'osslscope-dependency-inventory-v1':
        fail('request schema')
    selected = [p for p in config['profiles'] if p['id'] == profile]
    if len(selected) != 1 or selected[0] != dict(id=profile, target=target, abi_profile='linux-x86_64-'+profile,
                                               builder='packaging/builders/'+profile+'.json', formats=formats):
        fail('selected builder policy')
    identities = [tools[n] for n in ['host', 'bpf', 'linker', 'llvm', 'builder']]+tools['components']
    if len(identities) != len(recipe['resources']):
        fail('tool resource closure')
    names, roles = set(), set()
    for identity, resource in zip(identities, recipe['resources']):
        closed(identity, 'name version sha256')
        closed(resource, 'role identity content acquisition source_component')
        if (not _same(identity, resource['identity']) or identity['sha256'] != resource['content']['sha256']
                or not identity['name'] or identity['name'] in names or not identity['version']
                or identity['version'] in ['latest', 'main', 'master'] or resource['role'] in roles
                or resource['source_component'] not in deps['tool_sources']):
            fail('tool identity/source closure')
        if (type(identity['name']) is not str or type(identity['version']) is not str
                or '/' in identity['name'] or '\\' in identity['name']
                or identity['version'].startswith(('/', '\\'))
                or any(ord(c) < 32 for c in identity['name']+identity['version'])):
            fail('tool identity atom')
        names.add(identity['name'])
        roles.add(resource['role'])
        content_entry(resource['content'])
        content_entry(resource['acquisition'])
    required = set(FIXED).union({'llvm-library', 'executor-host', 'executor-layout'})
    if not required <= roles or [r['role'] for r in recipe['resources'][:5]] != ['host', 'bpf', 'linker', 'llvm', 'builder']:
        fail('mandatory tool roles/order')
    by_role = {r['role']: r for r in recipe['resources']}
    for role, version in [('host', '1.88.0'), ('host-cargo', '1.88.0'), ('host-sysroot', '1.88.0'),
                          ('bpf', 'nightly-2026-05-20'), ('bpf-cargo', 'nightly-2026-05-20'),
                          ('bpf-sysroot', 'nightly-2026-05-20'), ('rust-src', 'nightly-2026-05-20'), ('linker', '0.10.4')]:
        if by_role[role]['identity']['version'] != version:
            fail('pinned tool version')
    for special in ['executor-host', 'executor-layout']:
        resource = by_role[special]
        if any(r['role'] != special and (r['acquisition']['path'] == resource['acquisition']['path']
                    or r['source_component'] == resource['source_component']) for r in recipe['resources']):
            fail('executor acquisition/source alias')
    manifest = parse(read_nofollow(root, 'osslscope-source.json', 1048576))
    closed(manifest, 'schema source inventory')
    closed(manifest['source'], 'revision inventory_sha256')
    closed(manifest['inventory'], 'schema files')
    _verify_source_files(root, manifest)
    if (manifest['schema'] != 'osslscope-source-manifest-v1'
            or manifest['inventory']['schema'] != 'osslscope-original-source-v1'
            or digest(canonical(manifest['inventory'])) != manifest['source']['inventory_sha256']):
        fail('original source inventory identity')
    revision = manifest['source']['revision']
    if type(revision) is not str or len(revision) != 40 or any(c not in '0123456789abcdef' for c in revision):
        fail('source revision')
    last = ''
    for row in manifest['inventory']['files']:
        closed(row, 'path mode sha256 bytes node')
        path = relative(row['path'])
        if path <= last:
            fail('source inventory ordering')
        last = path
        if row['node'] == dict(kind='file'):
            if type(row['mode']) is not int or row['mode'] not in [0o100644, 0o100755]:
                fail('source file mode')
            data = read_nofollow(root, path, row['bytes'])
        else:
            closed(row['node'], 'kind target')
            if row['node']['kind'] != 'symlink':
                fail('source node kind')
            if row['mode'] != 0o120000 or type(row['mode']) is not int:
                fail('source link mode')
            link_target(path, row['node']['target'])
            if os.readlink(root/path) != row['node']['target']:
                fail('source symlink changed')
            data = row['node']['target'].encode()
        if len(data) != row['bytes'] or digest(data) != row['sha256']:
            fail('source file content drift')
        if '.cargo' in path.split('/') and path.rsplit('/', 1)[-1] in ['config', 'config.toml']:
            fail('source Cargo config')
    record = parse(read_nofollow(inputs, 'build-inputs.json', 1048576))
    closed(record, 'schema source product_version package_epoch package_revision source_epoch host_profile locks recipe tools jobs argv environment offline_inventory_sha256')
    if record['schema'] != 'osslscope-build-inputs-v1':
        fail('build inputs schema')
    for field in ['product_version', 'package_epoch', 'package_revision', 'source_epoch', 'jobs']:
        if not _same(record[field], config[field]):
            fail('release/build inputs duplicate')
    for field in ['host_profile', 'tools', 'argv', 'environment']:
        if not _same(record[field], recipe[field]):
            fail('recipe/build inputs duplicate')
    closed(record['recipe'], 'recipe_sha256 config_sha256')
    closed(record['locks'], 'host_sha256 bpf_sha256')
    if (not _same(record['source'], manifest['source']) or not _same(record['locks'], deps['locks'])
            or record['recipe']['recipe_sha256'] != digest(recipe_bytes)
            or record['recipe']['config_sha256'] != config['release_toml_sha256']):
        fail('source/recipe/config/locks binding')
    for path, field in [('Cargo.lock', 'host_sha256'), ('crates/ebpf/Cargo.lock', 'bpf_sha256')]:
        if digest(read_nofollow(root, path, 1048576)) != record['locks'][field]:
            fail('original lock drift')
    cargo = read_nofollow(root, 'Cargo.toml', 1048576)
    if digest(cargo) != config['cargo_toml_sha256'] or tomllib.loads(cargo.decode())['package']['version'] != config['product_version']:
        fail('root Cargo version/config binding')
    if digest(read_nofollow(root, 'packaging/release.toml', 1048576)) != config['release_toml_sha256']:
        fail('release TOML binding')
    offline_bytes = read_nofollow(inputs, config['artifacts']['offline_inventory'], 536870912)
    offline = parse(offline_bytes)
    closed(offline, 'schema source locks dependencies recipe_sha256 config_sha256 tools source_assets assets')
    if (digest(offline_bytes) != record['offline_inventory_sha256'] or offline['schema'] != 'osslscope-offline-inventory-v1'
            or not _same(offline['source'], record['source']) or not _same(offline['locks'], record['locks'])
            or not _same(offline['dependencies'], deps) or not _same(offline['tools'], tools)
            or offline['recipe_sha256'] != digest(recipe_bytes) or offline['config_sha256'] != config['release_toml_sha256']):
        fail('offline inventory duplicates')
    last, retained_identities = '', set()
    for entry in offline['assets']:
        if entry['path'] <= last:
            fail('offline asset ordering/alias')
        last = entry['path']
        retained(inputs, entry)
        retained_identities.add(canonical(entry))
    closed(offline['source_assets'], 'source_archive dependency_archives tool_source_archives tool_archives notices license_index license_texts sbom source_availability')
    if offline['source_assets']['sbom']['path'] != 'source.spdx.json':
        fail('immutable source SPDX identity')
    def require_entries(value):
        if type(value) is dict:
            if set(value) == {'path', 'sha256', 'bytes'}:
                content_entry(value)
                if canonical(value) not in retained_identities:
                    fail('missing retained closure entry')
            else:
                for child in value.values():
                    require_entries(child)
        elif type(value) is list:
            for child in value:
                require_entries(child)
    require_entries(offline['source_assets'])
    require_entries(deps)
    require_entries(recipe['resources'])
    content_entry(recipe['abi_evidence'])
    if recipe['abi_evidence']['bytes'] > 1048576:
        fail('ABI document bound')
    retained(inputs, recipe['abi_evidence'])


def admit_layout(request, root, inputs):
    owner = _ArchiveAdmission()
    try:
        return _admit_layout_in(owner, request, root, inputs)
    except BaseException:
        owner.state.poisoned = True
        raise


def _admit_layout_in(owner, request, root, inputs):
    closed(request, 'config dependencies tools')
    root, inputs = pathlib.Path(root), pathlib.Path(inputs)
    loader_expectation(root)
    reject_cargo_configs(root)
    config = request['config']
    profiles = [p for p in config['profiles'] if p['id'] == config['selected_profile']]
    if len(profiles) != 1:
        fail('selected profile')
    recipe_bytes = read_nofollow(root, profiles[0]['builder'], 1048576)
    recipe = parse(recipe_bytes)
    _admission_records(request, root, inputs, recipe, recipe_bytes)
    owner.bind(canonical(request)+read_nofollow(root, 'osslscope-source.json', 1048576)+read_nofollow(inputs, 'build-inputs.json', 1048576)+recipe_bytes)
    for phase in Phase:
        phase_spec(recipe, phase)
    if recipe['tools'] != request['tools'] or recipe['profile'] != config['selected_profile']:
        fail('request/recipe mismatch')
    assets = {}
    def asset(entry):
        identity = canonical(entry)
        if identity not in assets:
            assets[identity] = retained(inputs, entry)
        return assets[identity]
    roles = {r['role']: r for r in recipe['resources']}
    layout = parse(asset(roles['executor-layout']['content']))
    host = parse(asset(roles['executor-host']['content']))
    entries = []
    def collect(value):
        if type(value) is dict:
            if set(value) == {'path', 'sha256', 'bytes'}:
                entries.append(value)
            else:
                for child in value.values():
                    collect(child)
        elif type(value) is list:
            for child in value:
                collect(child)
    collect(request['dependencies'])
    roots, files, usage = _admit_documents_in(owner, recipe, layout, host, asset,
        read_nofollow(root, 'packaging/builders/'+recipe['profile']+'.layout.json', 1048576), entries)
    admitted = AdmittedLayout(recipe, request, roots, files, assets, root, inputs, usage, owner)
    _check_layout_owner(admitted)
    return admitted


@dataclasses.dataclass(frozen=True)
class VendorFile:
    data: bytes
    mode: int


@dataclasses.dataclass(frozen=True)
class VendorPlan:
    mappings: dict
    config: bytes
    files: dict


def _check_layout_owner(layout):
    owner = layout._archives
    if owner is None:
        fail("missing bound archive owner")
    try:
        owner.ensure()
        recipe_bytes = read_nofollow(layout.source, "packaging/builders/"+layout.recipe["profile"]+".json", 1048576)
        owner.bind(canonical(layout.request)+read_nofollow(layout.source, "osslscope-source.json", 1048576)+read_nofollow(layout.inputs, "build-inputs.json", 1048576)+recipe_bytes)
        loader_expectation(layout.source)
        reject_cargo_configs(layout.source)
        _admission_records(layout.request, layout.source, layout.inputs, parse(recipe_bytes), recipe_bytes)
        return owner
    except BaseException:
        owner.state.poisoned = True
        raise


def vendor_plan(layout):
    owner = _check_layout_owner(layout)
    try:
        return _vendor_plan_in(layout, owner)
    except BaseException:
        owner.state.poisoned = True
        raise


def _vendor_plan_in(layout, owner):
    try:
        owner.ensure()
        return _vendor_plan_data(layout, owner)
    except BaseException:
        owner.state.poisoned = True
        raise


def _vendor_plan_data(layout, owner):
    owner.ensure()
    reject_cargo_configs(layout.source)
    deps = layout.request['dependencies']
    components = {c['id']: c for c in deps['components']}
    selected = set(deps['host']+deps['bpf']+deps['build_std'])
    if len(components) != len(deps['components']) or not selected <= set(components):
        fail('selected vendor component closure')
    if any(not set(components[c].get('dependencies', [])) <= selected for c in selected):
        fail('missing declared vendor dependency closure')
    locks = [tomllib.loads(read_nofollow(layout.source, p, 1048576).decode()) for p in ['Cargo.lock', 'crates/ebpf/Cargo.lock']]
    locked = {}
    for lock in locks:
        for row in lock['package']:
            if 'source' in row:
                key = (row['source'], row['name'], row['version'])
                if key in locked and locked[key] != row.get('checksum'):
                    fail('mixed locked package')
                locked[key] = row.get('checksum')
    std_components = [components[c] for c in deps['build_std'] if components[c]['source']['kind'] in ['registry', 'git']]
    if std_components:
        path = 'lib/rustlib/src/rust/library/Cargo.lock'
        if not hasattr(layout, 'roots') or not hasattr(layout, 'files'):
            fail('missing validated rust-src layout')
        node = layout.roots.get('bpf', {}).get(path)
        data = layout.files.get(('bpf', path))
        if (not node or node['kind'] != 'file' or data is None or len(data) > 1048576
                or len(data) != node['bytes'] or digest(data) != node['sha256']):
            fail('missing/substituted retained build-std lock')
        _corroborate_std_lock(data, std_components, locked)
    mappings, files, admitted = {}, {}, set()
    for identifier in sorted(selected):
        c = components[identifier]
        source = c['source']
        if source['kind'] not in ['registry', 'git']:
            if source['kind'] == 'path' or (source['kind'] == 'native' and identifier in deps['build_std']):
                continue
            fail('build-std source needs locked Cargo identity')
        candidates = [key for key in locked if key[1:] == (c['name'], c['version']) and
                      (key[0] == source.get('location') if source['kind'] == 'registry' else key[0] == 'git+'+source['repository']+'#'+source['revision'])]
        if len(candidates) != 1:
            fail('missing/mixed locked source')
        key = candidates[0]
        if key in admitted:
            fail('vendor package collision')
        admitted.add(key)
        source_id = key[0]
        if source['kind'] == 'registry' and (source['checksum'] != locked[key] or source['archive']['sha256'] != locked[key]):
            fail('registry original checksum/lock mismatch')
        base = '/build/vendor/'+digest(source_id.encode())
        mappings[source_id] = base
        # Exact retained normalized members become Cargo's directory checksum
        # set. The registry package checksum remains its original lock pin.
        raw = retained(layout.inputs, source.get('corresponding_source', source['archive']))
        members, modes = _source_members_in(owner, raw)
        if source['kind'] == 'registry':
            original = retained(layout.inputs, source['archive'])
            _registry_correspondence_in(owner, original, members, modes, c['name'], c['version'])
        if not members or '.cargo-checksum.json' in members:
            fail('vendor empty/checksum collision')
        package = c['name']+'-'+c['version']
        relative(package)
        members['.cargo-checksum.json'] = canonical(dict(files={p: digest(data) for p, data in members.items()}, package=locked[key]))
        for path, data in members.items():
            destination = base+'/'+package+'/'+path
            if destination in files:
                fail('vendor destination collision')
            files[destination] = VendorFile(data, 0o644 if path == ".cargo-checksum.json" else modes[path])
    if admitted != set(locked):
        fail('missing locked vendor source')
    rows = ['[net]', 'offline = true', '']
    for index, (source_id, directory) in enumerate(sorted(mappings.items())):
        key = 'crates-io' if source_id == 'registry+https://github.com/rust-lang/crates.io-index' else source_id
        rows += ['[source.'+json.dumps(key, ensure_ascii=False)+']']
        if source_id.startswith('git+'):
            repository, revision = source_id[4:].rsplit('#', 1)
            rows += ['git = '+json.dumps(repository, ensure_ascii=False), 'rev = '+json.dumps(revision, ensure_ascii=False)]
        rows += ['replace-with = "vendor-'+str(index)+'"', '[source.vendor-'+str(index)+']', 'directory = '+json.dumps(directory, ensure_ascii=False), '']
    return VendorPlan(MappingProxyType(mappings), ('\n'.join(rows)).encode(), MappingProxyType(files))


def _corroborate_std_lock(data, components, locked):
    if not data or len(data) > 1048576:
        fail('build-std lock size')
    workspace = {}
    value = tomllib.loads(data.decode())
    if not set(value) <= {'version', 'package'} or value.get('version') not in [3, 4]:
        fail('build-std lock version/fields')
    if type(value.get('package')) is not list:
        fail('build-std lock package rows')
    for row in value['package']:
        if type(row) is not dict or not set(row) <= {'name', 'version', 'source', 'checksum', 'dependencies'}:
            fail('build-std lock package fields')
        if type(row.get('name')) is not str or type(row.get('version')) is not str:
            fail('build-std lock package identity')
        if 'source' not in row:
            continue
        if type(row['source']) is not str or ('checksum' in row and type(row['checksum']) is not str):
            fail('build-std lock source/checksum type')
        key = (row['source'], row['name'], row['version'])
        checksum = row.get('checksum')
        if key in workspace:
            fail('ambiguous build-std lock package')
        workspace[key] = checksum
    for c in components:
        source = c['source']
        if source['kind'] == 'registry':
            source_id, checksum = source['location'], source['checksum']
            if source['archive']['sha256'] != checksum:
                fail('build-std original archive checksum')
        else:
            source_id, checksum = 'git+'+source['repository']+'#'+source['revision'], None
        key = (source_id, c['name'], c['version'])
        if key not in workspace or workspace[key] != checksum or (key in locked and locked[key] != checksum):
            fail('build-std declared closure/locked source mismatch')
        locked[key] = checksum


def _source_members_in(owner, data):
    try:
        parsed = owner.decode(data, 'source')
        result, modes = {}, {}
        for n in parsed.nodes:
            path = relative(n.path)
            if (not n.posix or not n.strict or n.kind != '0' or n.mode not in [0o644, 0o755] or n.link
                    or n.uid or n.gid or n.mtime not in [0, 1792799804] or n.uname or n.gname or n.major or n.minor or path in result):
                fail('normalized vendor source metadata')
            result[path], modes[path] = n.data, n.mode
        tree = dict(schema='osslscope-tool-tree-v1', entries=[dict(path=p, kind='file', mode=modes[p], bytes=len(v), sha256=digest(v)) for p, v in sorted(result.items())])
        validate_tree(tree, implicit=True)
        return result, modes
    except BaseException:
        owner.state.poisoned = True
        raise


def _registry_correspondence_in(owner, original, normalized, modes, name, version):
    try:
        parsed = owner.decode(original, 'registry')
        prefix = name+'-'+version+'/'
        relative(prefix[:-1])
        observed = {}
        for n in parsed.nodes:
            relative(n.path)
            if (not n.path.startswith(prefix) or n.kind != '0' or n.link or n.mode not in [0o644, 0o755]
                    or n.major or n.minor):
                fail('original registry member metadata')
            path = relative(n.path[len(prefix):])
            if path in observed:
                fail('original duplicate registry member')
            observed[path] = (n.mode, n.data)
        if not observed or observed != {p: (modes[p], data) for p, data in normalized.items()}:
            fail('registry original/normalized correspondence')
    except BaseException:
        owner.state.poisoned = True
        raise


@dataclasses.dataclass
class StorageAdmission:
    parent_fds: tuple
    observations: tuple
    limits: BudgetLimits
    closed: bool = False
    poisoned: bool = False

    def close(self):
        if not self.closed:
            self.closed = True
            for fd in self.parent_fds:
                os.close(fd)


def _mounts():
    rows = []
    for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines():
        left, right = line.split(' - ', 1)
        f, tail = left.split(), right.split()
        def unescape(p):
            for code, char in [('040', ' '), ('011', '\t'), ('012', '\n'), ('134', '\\')]:
                p = p.replace('\\'+code, char)
            return p
        rows.append((int(f[0]), f[2], unescape(f[3]), unescape(f[4]), tail[0], tail[1]))
    return rows


def _storage_observation(fd, path, limits):
    s, v = os.fstat(fd), os.fstatvfs(fd)
    mounts = _mounts()
    matches = [r for r in mounts if path == r[3] or path.startswith(r[3].rstrip('/')+'/')]
    if not matches:
        fail('unknown storage mount')
    selected = max(matches, key=lambda r: len(r[3]))
    if selected[4] != 'ext4' or selected[2] != '/' or sum(r[3] == selected[3] for r in mounts) != 1:
        fail('unsupported/aliased storage')
    capacity = uint(v.f_blocks)*uint(v.f_frsize)
    if (not 0 < capacity <= limits.storage or s.st_uid != os.getuid() or s.st_mode & 0o022
            or selected[1] != str(os.major(s.st_dev))+':'+str(os.minor(s.st_dev))
            or not 0 <= v.f_bavail <= v.f_bfree <= v.f_blocks):
        fail('capacity/ownership storage admission')
    if any(r[0] != selected[0] and (r[3].startswith(path.rstrip('/')+'/') or r[1] == selected[1]) for r in mounts):
        fail('storage submount/alias')
    return (selected, s.st_dev, s.st_ino, v.f_blocks, v.f_frsize, capacity, v.f_bfree, v.f_bavail)


def _new_path(path):
    path = pathlib.Path(path)
    if not path.is_absolute() or any(p in ['.', '..'] for p in path.parts) or path.exists() or path.is_symlink():
        fail('new absolute path required')
    current = pathlib.Path('/')
    for part in path.parts[1:-1]:
        current /= part
        s = current.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid not in [0, os.getuid()] or s.st_mode & 0o022:
            fail('protected no-follow ancestry')
    return path


def admit_storage(paths, limits):
    # External exclusive assignment, no-resize/no-mount rights and actual
    # kernel/headroom admission are mandatory prerequisites before invocation.
    work, output = _new_path(paths['work_root']), _new_path(paths['output_root'])
    if work == output or work in output.parents or output in work.parents:
        fail('overlapping storage roots')
    fds = []
    try:
        for path in [work, output]:
            fds.append(os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC))
        observations = tuple(_storage_observation(fd, str(path.parent), limits) for fd, path in zip(fds, [work, output]))
        if observations[0][0] != observations[1][0] or observations[0][1] != observations[1][1]:
            fail('separate storage filesystems')
        return StorageAdmission(tuple(fds), observations, limits)
    except BaseException:
        for fd in fds:
            os.close(fd)
        raise


def check_storage(admission):
    if admission.closed or admission.poisoned:
        fail('closed/poisoned storage admission')
    try:
        for fd, old in zip(admission.parent_fds, admission.observations):
            path = os.readlink('/proc/self/fd/'+str(fd))
            new = _storage_observation(fd, path, admission.limits)
            if old[:6] != new[:6]:
                fail('storage identity/capacity drift')
    except BaseException:
        admission.poisoned = True
        raise


@dataclasses.dataclass
class OwnedTrees:
    storage: StorageAdmission
    roots: dict
    materialized_bytes: int
    root_fds: dict

    def close(self):
        for fd in self.root_fds.values():
            os.close(fd)
        self.root_fds.clear()
        self.storage.close()


def _directory(parent, name):
    os.mkdir(name, mode=0o755, dir_fd=parent)
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        os.fchmod(fd, 0o755)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _parent_fd(root, path):
    parts = relative(path).split('/')
    fd = os.dup(root)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            previous, fd = fd, child
            os.close(previous)
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def materialize(layout, paths):
    owner = _check_layout_owner(layout)
    try:
        return _materialize_trees(layout, paths)
    except BaseException:
        if layout._archives is not None:
            layout._archives.state.poisoned = True
        raise


def _materialize_trees(layout, paths):
    admission = admit_storage(paths, BudgetLimits())
    total, roots, root_fds = 0, {}, {}
    work_fd = output_fd = tools_fd = None
    try:
        check_storage(admission)
        work, output = pathlib.Path(paths['work_root']), pathlib.Path(paths['output_root'])
        work_fd = _directory(admission.parent_fds[0], work.name)
        output_fd = _directory(admission.parent_fds[1], output.name)
        tools_fd = _directory(work_fd, 'tools')
        for root, nodes in layout.roots.items():
            check_storage(admission)
            destination = work/'rootfs' if root == 'rootfs' else work/'tools'/root
            root_fd = _directory(work_fd if root == 'rootfs' else tools_fd, 'rootfs' if root == 'rootfs' else root)
            root_fds[root] = root_fd
            roots[root] = destination
            for path, row in sorted(nodes.items()):
                check_storage(admission)
                if row['kind'] == 'symlink':
                    continue
                parent, name = _parent_fd(root_fd, path)
                try:
                    if row['kind'] == 'directory':
                        child = _directory(parent, name)
                        os.close(child)
                    else:
                        data = layout.files[(root, path)]
                        total = add(total, len(data), BudgetLimits().storage)
                        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, row['mode'], dir_fd=parent)
                        try:
                            out = os.fdopen(fd, 'wb')
                        except BaseException:
                            os.close(fd)
                            raise
                        with out:
                            for start in range(0, len(data), 65536):
                                check_storage(admission)
                                chunk = data[start:start+65536]
                                if out.write(chunk) != len(chunk):
                                    fail('short materialization write')
                            out.flush()
                            os.fsync(out.fileno())
                            os.fchmod(out.fileno(), row['mode'])
                finally:
                    os.close(parent)
            for path, row in sorted(nodes.items()):
                if row['kind'] == 'symlink':
                    check_storage(admission)
                    parent, name = _parent_fd(root_fd, path)
                    try:
                        os.symlink(row['target'], name, dir_fd=parent)
                    finally:
                        os.close(parent)
        check_storage(admission)
        return OwnedTrees(admission, roots, total, root_fds)
    except BaseException:
        admission.poisoned = True
        for fd in root_fds.values():
            os.close(fd)
        admission.close()
        # No deletion/reuse claim: the external owner retains failed domains.
        raise
    finally:
        for fd in [work_fd, output_fd, tools_fd]:
            if fd is not None:
                os.close(fd)


# Reviewed dependency table; excludes this executor and build.rs to avoid self-hash.
POLICY_FILES = {'Cargo.lock': '393fc4de79dca5539bcea186b366f0cd7504f0433445fe0578ea5cfe2ca5901e',
 'Cargo.toml': '0d49f8a78295b50ea0e4a9580b8bdae4eada6aaa43cc046b253456447f7ebfef',
 'crates/bpf-sys/Cargo.toml': 'f2e45e2dfd773fab81debbed211b0f42d04bf77d6a6af41b074f3cdefa9c88b3',
 'crates/bpf-sys/src/lib.rs': 'ac0c0c7e0bc2075b8ef5f4f3a1709c3688ae452312240870143bfa3550d63929',
 'crates/ebpf-common/Cargo.toml': 'beefa805493aa752192150ee6722f13228f675b8f18434bdd7f4a35d5776ae1e',
 'crates/ebpf-common/src/lib.rs': '44b82ca1234457e9301f4855197170a309b4de8974a0054fe0eced4d6beb799c',
 'src/loader.rs': '58ca90950d9fa29d98085de00ea69becfc3d9b0fb66ce21c7a0baa57502c9577',
 'src/package/records.rs': 'd5a86556f9cffe5a8c124ec92b31819ec70e4a66f4b6e6b21a287d02dae44a06',
 'src/package/resolve.rs': '2639c8b58329268e6cc7819e45e6bf56c3bd3d19af70fe1641e82263f36afc19'}
POLICY_SHA256 = '62d35545bf9b93389f9690c52c7fbfce5307acf832e0612ae126279aceb1e029'
# Literal canonical policy independently transcribed from the reviewed contract.
POLICY_INVENTORY = json.loads('{"generic":{"elf":{"endianness":"little","forbidden_sections":[".BTF",".BTF.ext"],"machine":247},"license":{"absent_default":"GPL","accepted":["GPL","GPL v2","GPL and additional rights","Dual BSD/GPL","Dual MIT/GPL","Dual MPL/GPL"],"encoding":"UTF8","section":".license","trim_trailing_NUL":true},"maps":{"checked_fields":["map_type","key_size","value_size","max_entries","flags"],"definition_bytes":28,"required_dimensions":"EXACT_TABLE","section":"maps","symbol_kind":"OBJECT","unknown_map_symbols":"REJECT"},"programs":{"alignment_bytes":8,"body_min_bytes":8,"output":"SELECTED_ROOT_PLUS_REACHABLE_TEXT","selected_sections":["uprobe","uretprobe"],"selection":"REQUIRED_TABLE_SYMBOLS"},"relocations":{"entry_bytes":16,"rules":["OWNED_OR_REJECT","FULL_SITE_WITHIN_OWNER","MAP_TARGET_KNOWN_OBJECT_AND_LD_IMM64","CALL_TARGET_TEXT_ENTRY","FUNCTION_POINTER_FUNC_TEXT_ENTRY_NAME_VALUE_MATCH","ALL_PSEUDO_CALL_AND_FUNCTION_POINTER_REWRITES_ACCOUNTED"],"section_prefix":".rel","selected_types":[1,10],"site_bytes":[16,8]},"text":{"callbacks":"REFERENCED_FUNCTION_POINTER_TARGETS_MARKED","closure":"TRANSITIVE_CALL_AND_FUNCTION_POINTER_ROOTS","functions":"NONEMPTY_ALIGNED_UNIQUE_NAMES","layout":"ROOT_THEN_REACHABLE_TEXT_ELF_ORDER","section":".text"}},"roles":[{"extra":{},"file":"osslscope-harvest","maps":[{"flags":0,"key_size":0,"map_type":27,"max_entries":2097152,"name":"EVENTS","value_size":0},{"flags":0,"key_size":8,"map_type":1,"max_entries":1024,"name":"PENDING_INIT","value_size":8},{"flags":0,"key_size":8,"map_type":1,"max_entries":1024,"name":"PENDING_QUERY","value_size":16},{"flags":0,"key_size":8,"map_type":1,"max_entries":1024,"name":"TERMD","value_size":8},{"flags":0,"key_size":8,"map_type":1,"max_entries":1024,"name":"GEN","value_size":8},{"flags":0,"key_size":4,"map_type":5,"max_entries":32,"name":"LOSS","value_size":8},{"flags":0,"key_size":16,"map_type":1,"max_entries":4096,"name":"QUERY_NEXT","value_size":8},{"flags":0,"key_size":4,"map_type":5,"max_entries":64,"name":"TRUNC","value_size":8},{"flags":0,"key_size":4,"map_type":5,"max_entries":64,"name":"CALLS","value_size":8},{"flags":0,"key_size":8,"map_type":5,"max_entries":128,"name":"TRIP","value_size":8},{"flags":0,"key_size":4,"map_type":5,"max_entries":64,"name":"LGCALLS","value_size":8},{"flags":0,"key_size":8,"map_type":1,"max_entries":1024,"name":"ALG_CLASS","value_size":42},{"flags":0,"key_size":8,"map_type":1,"max_entries":64,"name":"TRIP_CLASS","value_size":22},{"flags":0,"key_size":4,"map_type":3,"max_entries":8,"name":"JUMPS","value_size":4}],"program_type":2,"programs":[{"name":"init_entry","section":"uprobe"},{"name":"init_return","section":"uretprobe"},{"name":"query_entry","section":"uprobe"},{"name":"query_return","section":"uretprobe"},{"name":"trip_count","section":"uprobe"},{"name":"trip_str0","section":"uprobe"},{"name":"trip_str1","section":"uprobe"},{"name":"c0","section":"uretprobe"},{"name":"c1","section":"uretprobe"},{"name":"c2","section":"uretprobe"},{"name":"c3","section":"uretprobe"},{"name":"c4","section":"uretprobe"},{"name":"c5","section":"uretprobe"},{"name":"c6","section":"uretprobe"},{"name":"c7","section":"uretprobe"}],"role":"harvest"},{"extra":{"callback_subprograms":"FORBIDDEN","executable_sections":[".text","uprobe"],"first_subprogram":{"insn_off":0,"name":"count_entry"},"helper12_tail_calls":"FORBIDDEN","is_return":false,"map_count":7,"map_fixups":"EXACT_LD_IMM64_SITE_AND_COUNT_MAP_MEMBER","program_count":1,"pseudo_func":"FORBIDDEN","root":{"exact_count":1,"name":"count_entry","nonempty":true,"section":"uprobe"}},"file":"osslscope-count","maps":[{"flags":0,"key_size":8,"map_type":5,"max_entries":8192,"name":"COUNTS","value_size":24},{"flags":0,"key_size":4,"map_type":6,"max_entries":1,"name":"ADMITTED","value_size":8},{"flags":0,"key_size":4,"map_type":6,"max_entries":16,"name":"LATC","value_size":8},{"flags":0,"key_size":4,"map_type":2,"max_entries":1,"name":"GEN","value_size":4},{"flags":0,"key_size":4,"map_type":2,"max_entries":1,"name":"TARGET","value_size":8},{"flags":0,"key_size":4,"map_type":2,"max_entries":2,"name":"WINDOW","value_size":8},{"flags":0,"key_size":4,"map_type":6,"max_entries":1,"name":"DROPFAIL","value_size":8}],"program_type":2,"programs":[{"name":"count_entry","section":"uprobe"}],"role":"count"},{"extra":{},"file":"osslscope-members","maps":[{"flags":0,"key_size":0,"map_type":27,"max_entries":16777216,"name":"EVENTS","value_size":0},{"flags":0,"key_size":4,"map_type":1,"max_entries":4096,"name":"BUCKET","value_size":8},{"flags":0,"key_size":8,"map_type":1,"max_entries":1024,"name":"GEN","value_size":8},{"flags":0,"key_size":4,"map_type":5,"max_entries":32,"name":"LOSS","value_size":8},{"flags":0,"key_size":4,"map_type":5,"max_entries":64,"name":"TRUNC","value_size":8},{"flags":0,"key_size":4,"map_type":5,"max_entries":64,"name":"CALLS","value_size":8},{"flags":0,"key_size":8,"map_type":1,"max_entries":1024,"name":"ALG_CLASS","value_size":42},{"flags":0,"key_size":4,"map_type":9,"max_entries":1024,"name":"SCAN","value_size":40},{"flags":0,"key_size":4,"map_type":1,"max_entries":4096,"name":"SEQ","value_size":8},{"flags":0,"key_size":4,"map_type":1,"max_entries":4096,"name":"BIRTH","value_size":2},{"flags":0,"key_size":4,"map_type":1,"max_entries":4096,"name":"RCOUNT","value_size":8},{"flags":0,"key_size":8,"map_type":1,"max_entries":1024,"name":"T_CACHE","value_size":16},{"flags":0,"key_size":4,"map_type":2,"max_entries":1,"name":"CTRL","value_size":24},{"flags":0,"key_size":4,"map_type":6,"max_entries":1,"name":"ATTEMPT","value_size":8},{"flags":0,"key_size":4,"map_type":5,"max_entries":64,"name":"TRUNC_SEQ","value_size":8}],"program_type":2,"programs":[{"name":"member_entry","section":"uprobe"},{"name":"member_000","section":"uretprobe"},{"name":"member_001","section":"uretprobe"},{"name":"member_002","section":"uretprobe"},{"name":"member_003","section":"uretprobe"},{"name":"member_004","section":"uretprobe"},{"name":"member_005","section":"uretprobe"},{"name":"member_006","section":"uretprobe"},{"name":"member_007","section":"uretprobe"},{"name":"member_008","section":"uretprobe"},{"name":"member_009","section":"uretprobe"},{"name":"member_010","section":"uretprobe"},{"name":"member_011","section":"uretprobe"},{"name":"member_012","section":"uretprobe"},{"name":"member_013","section":"uretprobe"},{"name":"member_014","section":"uretprobe"},{"name":"member_015","section":"uretprobe"},{"name":"member_016","section":"uretprobe"},{"name":"member_017","section":"uretprobe"},{"name":"member_018","section":"uretprobe"},{"name":"member_019","section":"uretprobe"},{"name":"member_020","section":"uretprobe"},{"name":"member_021","section":"uretprobe"},{"name":"member_022","section":"uretprobe"},{"name":"member_023","section":"uretprobe"},{"name":"member_024","section":"uretprobe"},{"name":"member_025","section":"uretprobe"},{"name":"member_026","section":"uretprobe"},{"name":"member_027","section":"uretprobe"},{"name":"member_028","section":"uretprobe"},{"name":"member_029","section":"uretprobe"},{"name":"member_030","section":"uretprobe"},{"name":"member_031","section":"uretprobe"},{"name":"member_032","section":"uretprobe"},{"name":"member_033","section":"uretprobe"},{"name":"member_034","section":"uretprobe"},{"name":"member_035","section":"uretprobe"},{"name":"member_036","section":"uretprobe"},{"name":"member_037","section":"uretprobe"},{"name":"member_038","section":"uretprobe"},{"name":"member_039","section":"uretprobe"},{"name":"member_040","section":"uretprobe"},{"name":"member_041","section":"uretprobe"},{"name":"member_042","section":"uretprobe"},{"name":"member_043","section":"uretprobe"},{"name":"member_044","section":"uretprobe"},{"name":"member_045","section":"uretprobe"},{"name":"member_046","section":"uretprobe"},{"name":"member_047","section":"uretprobe"},{"name":"member_048","section":"uretprobe"},{"name":"member_049","section":"uretprobe"},{"name":"member_050","section":"uretprobe"},{"name":"member_051","section":"uretprobe"},{"name":"member_052","section":"uretprobe"},{"name":"member_053","section":"uretprobe"},{"name":"member_054","section":"uretprobe"},{"name":"member_055","section":"uretprobe"},{"name":"member_056","section":"uretprobe"},{"name":"member_057","section":"uretprobe"},{"name":"member_058","section":"uretprobe"},{"name":"member_059","section":"uretprobe"},{"name":"member_060","section":"uretprobe"},{"name":"member_061","section":"uretprobe"},{"name":"member_062","section":"uretprobe"},{"name":"member_063","section":"uretprobe"},{"name":"member_064","section":"uretprobe"},{"name":"member_065","section":"uretprobe"},{"name":"member_066","section":"uretprobe"},{"name":"member_067","section":"uretprobe"},{"name":"member_068","section":"uretprobe"},{"name":"member_069","section":"uretprobe"},{"name":"member_070","section":"uretprobe"},{"name":"member_071","section":"uretprobe"},{"name":"member_072","section":"uretprobe"},{"name":"member_073","section":"uretprobe"},{"name":"member_074","section":"uretprobe"},{"name":"member_075","section":"uretprobe"},{"name":"member_076","section":"uretprobe"},{"name":"member_077","section":"uretprobe"},{"name":"member_078","section":"uretprobe"},{"name":"member_079","section":"uretprobe"},{"name":"member_080","section":"uretprobe"},{"name":"member_081","section":"uretprobe"},{"name":"member_082","section":"uretprobe"},{"name":"member_083","section":"uretprobe"},{"name":"member_084","section":"uretprobe"},{"name":"member_085","section":"uretprobe"},{"name":"member_086","section":"uretprobe"},{"name":"member_087","section":"uretprobe"},{"name":"member_088","section":"uretprobe"},{"name":"member_089","section":"uretprobe"},{"name":"member_090","section":"uretprobe"},{"name":"member_091","section":"uretprobe"},{"name":"member_092","section":"uretprobe"},{"name":"member_093","section":"uretprobe"},{"name":"member_094","section":"uretprobe"},{"name":"member_095","section":"uretprobe"},{"name":"member_096","section":"uretprobe"},{"name":"member_097","section":"uretprobe"},{"name":"member_098","section":"uretprobe"},{"name":"member_099","section":"uretprobe"},{"name":"member_100","section":"uretprobe"},{"name":"member_101","section":"uretprobe"},{"name":"member_102","section":"uretprobe"},{"name":"member_103","section":"uretprobe"},{"name":"member_104","section":"uretprobe"},{"name":"member_105","section":"uretprobe"},{"name":"member_106","section":"uretprobe"},{"name":"member_107","section":"uretprobe"},{"name":"member_108","section":"uretprobe"},{"name":"member_109","section":"uretprobe"},{"name":"member_110","section":"uretprobe"},{"name":"member_111","section":"uretprobe"},{"name":"member_112","section":"uretprobe"},{"name":"member_113","section":"uretprobe"},{"name":"member_114","section":"uretprobe"},{"name":"member_115","section":"uretprobe"},{"name":"member_116","section":"uretprobe"},{"name":"member_117","section":"uretprobe"},{"name":"member_118","section":"uretprobe"},{"name":"member_119","section":"uretprobe"},{"name":"member_120","section":"uretprobe"},{"name":"member_121","section":"uretprobe"},{"name":"member_122","section":"uretprobe"},{"name":"member_123","section":"uretprobe"},{"name":"member_124","section":"uretprobe"},{"name":"member_125","section":"uretprobe"},{"name":"member_126","section":"uretprobe"},{"name":"member_127","section":"uretprobe"},{"name":"member_128","section":"uretprobe"},{"name":"member_129","section":"uretprobe"},{"name":"member_130","section":"uretprobe"},{"name":"member_131","section":"uretprobe"},{"name":"member_132","section":"uretprobe"},{"name":"member_133","section":"uretprobe"},{"name":"member_134","section":"uretprobe"},{"name":"member_135","section":"uretprobe"},{"name":"member_136","section":"uretprobe"},{"name":"member_137","section":"uretprobe"},{"name":"member_138","section":"uretprobe"},{"name":"member_139","section":"uretprobe"},{"name":"member_140","section":"uretprobe"},{"name":"member_141","section":"uretprobe"},{"name":"member_142","section":"uretprobe"},{"name":"member_143","section":"uretprobe"},{"name":"member_144","section":"uretprobe"},{"name":"member_145","section":"uretprobe"},{"name":"member_146","section":"uretprobe"},{"name":"member_147","section":"uretprobe"},{"name":"member_148","section":"uretprobe"},{"name":"member_149","section":"uretprobe"},{"name":"member_150","section":"uretprobe"},{"name":"member_151","section":"uretprobe"},{"name":"member_152","section":"uretprobe"},{"name":"member_153","section":"uretprobe"},{"name":"member_154","section":"uretprobe"},{"name":"member_155","section":"uretprobe"},{"name":"member_156","section":"uretprobe"},{"name":"member_157","section":"uretprobe"},{"name":"member_158","section":"uretprobe"},{"name":"member_159","section":"uretprobe"},{"name":"member_160","section":"uretprobe"},{"name":"member_161","section":"uretprobe"},{"name":"member_162","section":"uretprobe"},{"name":"member_163","section":"uretprobe"},{"name":"member_164","section":"uretprobe"},{"name":"member_165","section":"uretprobe"},{"name":"member_166","section":"uretprobe"},{"name":"member_167","section":"uretprobe"},{"name":"member_168","section":"uretprobe"},{"name":"member_169","section":"uretprobe"},{"name":"member_170","section":"uretprobe"},{"name":"member_171","section":"uretprobe"},{"name":"member_172","section":"uretprobe"},{"name":"member_173","section":"uretprobe"},{"name":"member_174","section":"uretprobe"},{"name":"member_175","section":"uretprobe"},{"name":"member_176","section":"uretprobe"},{"name":"member_177","section":"uretprobe"},{"name":"member_178","section":"uretprobe"},{"name":"member_179","section":"uretprobe"},{"name":"member_180","section":"uretprobe"},{"name":"member_181","section":"uretprobe"},{"name":"member_182","section":"uretprobe"},{"name":"member_183","section":"uretprobe"},{"name":"member_184","section":"uretprobe"},{"name":"member_185","section":"uretprobe"},{"name":"member_186","section":"uretprobe"},{"name":"member_187","section":"uretprobe"},{"name":"member_188","section":"uretprobe"},{"name":"member_189","section":"uretprobe"},{"name":"member_190","section":"uretprobe"},{"name":"member_191","section":"uretprobe"},{"name":"member_192","section":"uretprobe"},{"name":"member_193","section":"uretprobe"},{"name":"member_194","section":"uretprobe"},{"name":"member_195","section":"uretprobe"},{"name":"member_196","section":"uretprobe"},{"name":"member_197","section":"uretprobe"},{"name":"member_198","section":"uretprobe"},{"name":"member_199","section":"uretprobe"},{"name":"member_200","section":"uretprobe"},{"name":"member_201","section":"uretprobe"},{"name":"member_202","section":"uretprobe"},{"name":"member_203","section":"uretprobe"},{"name":"member_204","section":"uretprobe"},{"name":"member_205","section":"uretprobe"},{"name":"member_206","section":"uretprobe"},{"name":"member_207","section":"uretprobe"},{"name":"member_208","section":"uretprobe"},{"name":"member_209","section":"uretprobe"},{"name":"member_210","section":"uretprobe"},{"name":"member_211","section":"uretprobe"},{"name":"member_212","section":"uretprobe"},{"name":"member_213","section":"uretprobe"},{"name":"member_214","section":"uretprobe"},{"name":"member_215","section":"uretprobe"},{"name":"member_216","section":"uretprobe"},{"name":"member_217","section":"uretprobe"},{"name":"member_218","section":"uretprobe"},{"name":"member_219","section":"uretprobe"},{"name":"member_220","section":"uretprobe"},{"name":"member_221","section":"uretprobe"},{"name":"member_222","section":"uretprobe"},{"name":"member_223","section":"uretprobe"},{"name":"member_224","section":"uretprobe"},{"name":"member_225","section":"uretprobe"},{"name":"member_226","section":"uretprobe"},{"name":"member_227","section":"uretprobe"},{"name":"member_228","section":"uretprobe"},{"name":"member_229","section":"uretprobe"},{"name":"member_230","section":"uretprobe"},{"name":"member_231","section":"uretprobe"},{"name":"member_232","section":"uretprobe"},{"name":"member_233","section":"uretprobe"},{"name":"member_234","section":"uretprobe"},{"name":"member_235","section":"uretprobe"},{"name":"member_236","section":"uretprobe"},{"name":"member_237","section":"uretprobe"},{"name":"member_238","section":"uretprobe"},{"name":"member_239","section":"uretprobe"},{"name":"member_240","section":"uretprobe"},{"name":"member_241","section":"uretprobe"},{"name":"member_242","section":"uretprobe"},{"name":"member_243","section":"uretprobe"},{"name":"member_244","section":"uretprobe"},{"name":"member_245","section":"uretprobe"},{"name":"member_246","section":"uretprobe"},{"name":"member_247","section":"uretprobe"},{"name":"member_248","section":"uretprobe"},{"name":"member_249","section":"uretprobe"},{"name":"member_250","section":"uretprobe"},{"name":"member_251","section":"uretprobe"},{"name":"member_252","section":"uretprobe"},{"name":"member_253","section":"uretprobe"},{"name":"member_254","section":"uretprobe"},{"name":"member_255","section":"uretprobe"},{"name":"member_256","section":"uretprobe"},{"name":"member_257","section":"uretprobe"},{"name":"member_258","section":"uretprobe"},{"name":"member_259","section":"uretprobe"},{"name":"member_260","section":"uretprobe"},{"name":"member_261","section":"uretprobe"},{"name":"member_262","section":"uretprobe"},{"name":"member_263","section":"uretprobe"},{"name":"member_264","section":"uretprobe"},{"name":"member_265","section":"uretprobe"},{"name":"member_266","section":"uretprobe"},{"name":"member_267","section":"uretprobe"},{"name":"member_268","section":"uretprobe"},{"name":"member_269","section":"uretprobe"},{"name":"member_270","section":"uretprobe"},{"name":"member_271","section":"uretprobe"},{"name":"member_272","section":"uretprobe"},{"name":"member_273","section":"uretprobe"},{"name":"member_274","section":"uretprobe"},{"name":"member_275","section":"uretprobe"},{"name":"member_276","section":"uretprobe"},{"name":"member_277","section":"uretprobe"},{"name":"member_278","section":"uretprobe"},{"name":"member_279","section":"uretprobe"},{"name":"member_280","section":"uretprobe"},{"name":"member_281","section":"uretprobe"},{"name":"member_282","section":"uretprobe"},{"name":"member_283","section":"uretprobe"},{"name":"member_284","section":"uretprobe"},{"name":"member_285","section":"uretprobe"},{"name":"member_286","section":"uretprobe"},{"name":"member_287","section":"uretprobe"},{"name":"member_288","section":"uretprobe"},{"name":"member_289","section":"uretprobe"},{"name":"member_290","section":"uretprobe"},{"name":"member_291","section":"uretprobe"},{"name":"member_292","section":"uretprobe"},{"name":"member_293","section":"uretprobe"},{"name":"member_294","section":"uretprobe"},{"name":"member_295","section":"uretprobe"},{"name":"member_296","section":"uretprobe"},{"name":"member_297","section":"uretprobe"},{"name":"member_298","section":"uretprobe"},{"name":"member_299","section":"uretprobe"},{"name":"member_300","section":"uretprobe"},{"name":"member_301","section":"uretprobe"},{"name":"member_302","section":"uretprobe"},{"name":"member_303","section":"uretprobe"},{"name":"member_304","section":"uretprobe"},{"name":"member_305","section":"uretprobe"},{"name":"member_306","section":"uretprobe"},{"name":"member_307","section":"uretprobe"},{"name":"member_308","section":"uretprobe"},{"name":"member_309","section":"uretprobe"},{"name":"member_310","section":"uretprobe"},{"name":"member_311","section":"uretprobe"},{"name":"member_312","section":"uretprobe"},{"name":"member_313","section":"uretprobe"},{"name":"member_314","section":"uretprobe"},{"name":"member_315","section":"uretprobe"},{"name":"member_316","section":"uretprobe"},{"name":"member_317","section":"uretprobe"},{"name":"member_318","section":"uretprobe"},{"name":"member_319","section":"uretprobe"},{"name":"member_320","section":"uretprobe"},{"name":"member_321","section":"uretprobe"},{"name":"member_322","section":"uretprobe"},{"name":"member_323","section":"uretprobe"},{"name":"member_324","section":"uretprobe"},{"name":"member_325","section":"uretprobe"},{"name":"member_326","section":"uretprobe"},{"name":"member_327","section":"uretprobe"},{"name":"member_328","section":"uretprobe"},{"name":"member_329","section":"uretprobe"},{"name":"member_330","section":"uretprobe"},{"name":"member_331","section":"uretprobe"},{"name":"member_332","section":"uretprobe"},{"name":"member_333","section":"uretprobe"},{"name":"member_334","section":"uretprobe"},{"name":"member_335","section":"uretprobe"},{"name":"member_336","section":"uretprobe"},{"name":"member_337","section":"uretprobe"},{"name":"member_338","section":"uretprobe"},{"name":"member_339","section":"uretprobe"},{"name":"member_340","section":"uretprobe"},{"name":"member_341","section":"uretprobe"},{"name":"member_342","section":"uretprobe"},{"name":"member_343","section":"uretprobe"},{"name":"member_344","section":"uretprobe"},{"name":"member_345","section":"uretprobe"},{"name":"member_346","section":"uretprobe"},{"name":"member_347","section":"uretprobe"},{"name":"member_348","section":"uretprobe"},{"name":"member_349","section":"uretprobe"},{"name":"member_350","section":"uretprobe"},{"name":"member_351","section":"uretprobe"},{"name":"member_352","section":"uretprobe"},{"name":"member_353","section":"uretprobe"},{"name":"member_354","section":"uretprobe"},{"name":"member_355","section":"uretprobe"},{"name":"member_356","section":"uretprobe"},{"name":"member_357","section":"uretprobe"},{"name":"member_358","section":"uretprobe"},{"name":"member_359","section":"uretprobe"},{"name":"member_360","section":"uretprobe"},{"name":"member_361","section":"uretprobe"},{"name":"member_362","section":"uretprobe"},{"name":"member_363","section":"uretprobe"},{"name":"member_364","section":"uretprobe"},{"name":"member_365","section":"uretprobe"},{"name":"member_366","section":"uretprobe"},{"name":"member_367","section":"uretprobe"},{"name":"member_368","section":"uretprobe"},{"name":"member_369","section":"uretprobe"},{"name":"member_370","section":"uretprobe"},{"name":"member_371","section":"uretprobe"},{"name":"member_372","section":"uretprobe"},{"name":"member_373","section":"uretprobe"},{"name":"member_374","section":"uretprobe"},{"name":"member_375","section":"uretprobe"},{"name":"member_376","section":"uretprobe"},{"name":"member_377","section":"uretprobe"},{"name":"member_378","section":"uretprobe"},{"name":"member_379","section":"uretprobe"},{"name":"member_380","section":"uretprobe"},{"name":"member_381","section":"uretprobe"},{"name":"member_382","section":"uretprobe"},{"name":"member_383","section":"uretprobe"},{"name":"member_384","section":"uretprobe"},{"name":"member_385","section":"uretprobe"},{"name":"member_386","section":"uretprobe"},{"name":"member_387","section":"uretprobe"},{"name":"member_388","section":"uretprobe"},{"name":"member_389","section":"uretprobe"},{"name":"member_390","section":"uretprobe"},{"name":"member_391","section":"uretprobe"},{"name":"member_392","section":"uretprobe"},{"name":"member_393","section":"uretprobe"},{"name":"member_394","section":"uretprobe"},{"name":"member_395","section":"uretprobe"},{"name":"member_396","section":"uretprobe"},{"name":"member_397","section":"uretprobe"},{"name":"member_398","section":"uretprobe"},{"name":"member_399","section":"uretprobe"},{"name":"member_400","section":"uretprobe"},{"name":"member_401","section":"uretprobe"},{"name":"member_402","section":"uretprobe"},{"name":"member_403","section":"uretprobe"},{"name":"member_404","section":"uretprobe"},{"name":"member_405","section":"uretprobe"},{"name":"member_406","section":"uretprobe"},{"name":"member_407","section":"uretprobe"},{"name":"member_408","section":"uretprobe"},{"name":"member_409","section":"uretprobe"},{"name":"member_410","section":"uretprobe"},{"name":"member_411","section":"uretprobe"},{"name":"member_412","section":"uretprobe"},{"name":"member_413","section":"uretprobe"},{"name":"member_414","section":"uretprobe"},{"name":"member_415","section":"uretprobe"},{"name":"member_416","section":"uretprobe"},{"name":"member_417","section":"uretprobe"},{"name":"member_418","section":"uretprobe"},{"name":"member_419","section":"uretprobe"},{"name":"member_420","section":"uretprobe"},{"name":"member_421","section":"uretprobe"},{"name":"member_422","section":"uretprobe"},{"name":"member_423","section":"uretprobe"},{"name":"member_424","section":"uretprobe"},{"name":"member_425","section":"uretprobe"},{"name":"member_426","section":"uretprobe"},{"name":"member_427","section":"uretprobe"},{"name":"member_428","section":"uretprobe"},{"name":"member_429","section":"uretprobe"},{"name":"member_430","section":"uretprobe"},{"name":"member_431","section":"uretprobe"},{"name":"member_432","section":"uretprobe"},{"name":"member_433","section":"uretprobe"},{"name":"member_434","section":"uretprobe"},{"name":"member_435","section":"uretprobe"},{"name":"member_436","section":"uretprobe"},{"name":"member_437","section":"uretprobe"},{"name":"member_438","section":"uretprobe"},{"name":"member_439","section":"uretprobe"},{"name":"member_440","section":"uretprobe"},{"name":"member_441","section":"uretprobe"},{"name":"member_442","section":"uretprobe"},{"name":"member_443","section":"uretprobe"},{"name":"member_444","section":"uretprobe"},{"name":"member_445","section":"uretprobe"},{"name":"member_446","section":"uretprobe"},{"name":"member_447","section":"uretprobe"},{"name":"member_448","section":"uretprobe"},{"name":"member_449","section":"uretprobe"},{"name":"member_450","section":"uretprobe"},{"name":"member_451","section":"uretprobe"},{"name":"member_452","section":"uretprobe"},{"name":"member_453","section":"uretprobe"},{"name":"member_454","section":"uretprobe"},{"name":"member_455","section":"uretprobe"},{"name":"member_456","section":"uretprobe"},{"name":"member_457","section":"uretprobe"},{"name":"member_458","section":"uretprobe"},{"name":"member_459","section":"uretprobe"},{"name":"member_460","section":"uretprobe"},{"name":"member_461","section":"uretprobe"},{"name":"member_462","section":"uretprobe"},{"name":"member_463","section":"uretprobe"},{"name":"member_464","section":"uretprobe"},{"name":"member_465","section":"uretprobe"},{"name":"member_466","section":"uretprobe"},{"name":"member_467","section":"uretprobe"},{"name":"member_468","section":"uretprobe"},{"name":"member_469","section":"uretprobe"},{"name":"member_470","section":"uretprobe"},{"name":"member_471","section":"uretprobe"},{"name":"member_472","section":"uretprobe"},{"name":"member_473","section":"uretprobe"},{"name":"member_474","section":"uretprobe"},{"name":"member_475","section":"uretprobe"},{"name":"member_476","section":"uretprobe"},{"name":"member_477","section":"uretprobe"},{"name":"member_478","section":"uretprobe"},{"name":"member_479","section":"uretprobe"},{"name":"member_480","section":"uretprobe"},{"name":"member_481","section":"uretprobe"},{"name":"member_482","section":"uretprobe"},{"name":"member_483","section":"uretprobe"},{"name":"member_484","section":"uretprobe"},{"name":"member_485","section":"uretprobe"},{"name":"member_486","section":"uretprobe"},{"name":"member_487","section":"uretprobe"},{"name":"member_488","section":"uretprobe"},{"name":"member_489","section":"uretprobe"},{"name":"member_490","section":"uretprobe"},{"name":"member_491","section":"uretprobe"},{"name":"member_492","section":"uretprobe"},{"name":"member_493","section":"uretprobe"},{"name":"member_494","section":"uretprobe"},{"name":"member_495","section":"uretprobe"},{"name":"member_496","section":"uretprobe"},{"name":"member_497","section":"uretprobe"},{"name":"member_498","section":"uretprobe"},{"name":"member_499","section":"uretprobe"},{"name":"member_500","section":"uretprobe"},{"name":"member_501","section":"uretprobe"},{"name":"member_502","section":"uretprobe"},{"name":"member_503","section":"uretprobe"},{"name":"member_504","section":"uretprobe"},{"name":"member_505","section":"uretprobe"},{"name":"member_506","section":"uretprobe"},{"name":"member_507","section":"uretprobe"},{"name":"member_508","section":"uretprobe"},{"name":"member_509","section":"uretprobe"},{"name":"member_510","section":"uretprobe"},{"name":"member_511","section":"uretprobe"}],"role":"members"}],"schema":"osslscope-loader-policy-v1","wire_abi":2,"wire_components":{"count":2,"discovery":2}}\n')


def loader_expectation(root):
    root = pathlib.Path(root)
    manifest = parse(read_nofollow(root, 'osslscope-source.json', 1048576))
    _verify_source_files(root, manifest)
    selected = {row['path'] for row in manifest['inventory']['files']
                if row['path'] in POLICY_FILES or row['path'].startswith(('crates/ebpf-common/', 'crates/bpf-sys/'))}
    if selected != set(POLICY_FILES):
        fail('selected source inventory mismatch')
    for path, expected in POLICY_FILES.items():
        if digest(read_nofollow(root, path, 536870912)) != expected:
            fail('loader policy source drift: '+path)
    if digest(canonical(POLICY_INVENTORY)) != POLICY_SHA256:
        fail('loader policy literal drift')
    return 2, POLICY_SHA256
