#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Finite source/dependency boundary check; never an authorship certificate."""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

BASE = 'baabe2c9af67b395749c14586eb48b8b89c3a060'
OLD = 'osslscope_ebpf_common'
NEW = 'osslscope_bpf_contract'
BINS = ('count', 'harvest', 'members')
OLD_COUNT_COMMENT = ('//! Wire format (key/value structs + `WINDOW` cells) is owned by\n'
                     '//! `osslscope-ebpf-common` — shared with userspace, drift-proof.')
NEW_COUNT_COMMENT = ('//! BPF wire records and `WINDOW` cells use `osslscope-bpf-contract`.\n'
                     '//! Userspace retains separate ABI-compatible common types.')
INPUT_PATHS = (
    'crates/ebpf/Cargo.toml', 'crates/ebpf/Cargo.lock',
    'crates/ebpf-common/src/lib.rs',
    'crates/bpf-contract/Cargo.toml', 'crates/bpf-contract/src/lib.rs',
    'crates/bpf-contract/src/classify.rs', 'crates/bpf-contract/src/records.rs',
    'crates/bpf-contract/src/scalars.rs',
    *(f'crates/ebpf/src/bin/{name}.rs' for name in BINS),
)
EXPECTED_COMMON_SHA256 = '44b82ca1234457e9301f4855197170a309b4de8974a0054fe0eced4d6beb799c'
SOURCE_ROOT = Path(__file__).resolve().parents[2]


def base_text(rel):
    try:
        return subprocess.check_output(['git', '-C', str(SOURCE_ROOT), 'show', f'{BASE}:{rel}'],
                                       text=True, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return ''  # The later exact-base comparisons fail closed.


def imports(src, crate):
    match = re.search(r'\buse\s+' + re.escape(crate) + r'::\{([^}]*)\};', src, re.S)
    return set(re.findall(r'\b[A-Za-z_][A-Za-z_0-9]*\b', match.group(1))) if match else set()


def inspect(product):
    product = Path(product)
    errors = []
    def read(rel):
        try:
            return (product / rel).read_text()
        except (OSError, UnicodeError) as e:
            errors.append(f'{rel}: missing/unreadable: {e}')
            return ''
    manifest = read('crates/ebpf/Cargo.toml')
    lock_text = read('crates/ebpf/Cargo.lock')
    try:
        deps = tomllib.loads(manifest)['dependencies']
        packages = {p['name']: p for p in tomllib.loads(lock_text)['package']}
        old_packages = {p['name']: p for p in tomllib.loads(base_text('crates/ebpf/Cargo.lock'))['package']}
        for name, old_package in old_packages.items():
            if name != 'osslscope-ebpf-common' and name != 'osslscope-ebpf':
                if packages.get(name) != old_package:
                    errors.append(f'external lock entry drift: {name}')
        if set(packages) != (set(old_packages) - {'osslscope-ebpf-common'} | {'osslscope-bpf-contract'}):
            errors.append('detached lock package set drift')
        pkg = packages['osslscope-ebpf']
        if 'osslscope-ebpf-common' in deps or 'osslscope-ebpf-common' in pkg['dependencies']:
            errors.append('forbidden common dependency in detached BPF closure')
        if deps.get('osslscope-bpf-contract') != {'path': '../bpf-contract'}:
            errors.append('detached BPF dependency must be explicit path to contract')
        if 'osslscope-bpf-contract' not in pkg['dependencies']:
            errors.append('BPF lock omits contract dependency')
        if 'osslscope-ebpf-common' in packages:
            errors.append('forbidden common dependency in detached BPF lock')
        contract = tomllib.loads(read('crates/bpf-contract/Cargo.toml'))
        p = contract['package']
        if p.get('name') != 'osslscope-bpf-contract' or p.get('license') != 'GPL-2.0-or-later' or p.get('publish') is not False or p.get('edition') != '2021' or p.get('rust-version') != '1.88':
            errors.append('contract package identity/terms drift')
        if any(k in contract for k in ('dependencies','build-dependencies','dev-dependencies','features')):
            errors.append('contract production dependencies/features forbidden')
        if 'build' in p:
            errors.append('build script forbidden')
        if (product / 'crates/bpf-contract/build.rs').exists():
            errors.append('build script forbidden')
        if packages.get('osslscope-bpf-contract', {}).get('dependencies'):
            errors.append('contract lock dependency forbidden')
    except (ValueError, KeyError, TypeError) as e:
        errors.append(f'malformed dependency manifest/lock: {e}')
    common = (product / 'crates/ebpf-common/src/lib.rs')
    if common.exists() and hashlib.sha256(common.read_bytes()).hexdigest() != EXPECTED_COMMON_SHA256:
        errors.append('host common changed')
    lib_sources = '\n'.join(read(f'crates/bpf-contract/src/{name}.rs') for name in ('lib','classify','records','scalars'))
    if '#![no_std]' not in lib_sources:
        errors.append('contract lacks no_std')
    if re.search(r'\b(include|include_str|include_bytes)!|#\s*\[\s*path\s*=|\benv!\s*\(\s*"OUT_DIR"', lib_sources):
        errors.append('include or generated source forbidden')
    if OLD in lib_sources or 'ebpf-common' in lib_sources:
        errors.append('common source reference in contract')
    names_by_bin = {}
    for name in BINS:
        rel = f'crates/ebpf/src/bin/{name}.rs'
        actual = read(rel)
        old = base_text(rel)
        expected = old.replace(OLD, NEW)
        if name == 'count':
            expected = expected.replace(OLD_COUNT_COMMENT, NEW_COUNT_COMMENT)
        if actual != expected:
            errors.append(f'{name}: import/source delta beyond exact crate replacement')
        wanted = imports(old, OLD)
        got = imports(actual, NEW)
        names_by_bin[name] = sorted(got)
        if got != wanted:
            errors.append(f'{name}: named surface import drift (wanted {len(wanted)}, got {len(got)})')
        if OLD in actual:
            errors.append(f'{name}: forbidden common source reference')
    counts = {name: len(names_by_bin[name]) for name in BINS}
    union = set().union(*(names_by_bin[name] for name in BINS))
    if counts != {'count': 6, 'harvest': 44, 'members': 71} or len(union | {'AlgVerdict'}) != 106:
        errors.append(f'named surface count drift: {counts}, union_plus_qualified_AlgVerdict={len(union | {'AlgVerdict'})}')
    for name in union:
        if not re.search(r'\b' + re.escape(name) + r'\b', read('crates/bpf-contract/src/lib.rs')):
            errors.append(f'named surface missing export: {name}')
    for name in ('harvest', 'members'):
        actual = read(f'crates/ebpf/src/bin/{name}.rs')
        if f'{NEW}::AlgVerdict' not in actual:
            errors.append(f'{name}: qualified AlgVerdict missing')
    if 'TripVerdict' not in read('crates/bpf-contract/src/lib.rs'):
        errors.append('TripVerdict missing')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--product', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    failures = inspect(args.product)
    result = {'schema': 1, 'product': str(args.product.resolve()), 'base': BASE,
              'status': 'fail' if failures else 'pass', 'failures': failures,
              'note': 'Source/dependency structure only; no authorship or rights clearance.'}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return bool(failures)


if __name__ == '__main__':
    sys.exit(main())
