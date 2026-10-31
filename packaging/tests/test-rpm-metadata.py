#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check an actual built RPM's intended CLI-only file-capability metadata.

Usage: python3 packaging/tests/test-rpm-metadata.py PATH_TO_RPM
No installation or application execution. Installed rpm -V remains a separate
qualified-host check; a correct header alone does not prove filecap application.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rpm', type=Path)
    args = parser.parse_args()
    # An owned query database avoids consulting/initializing system RPM state.
    with tempfile.TemporaryDirectory(prefix='osslscope-rpm-metadata-') as database:
        result = subprocess.run(['rpm', '--dbpath', database, '-qp', '--qf',
                                 '[%{FILENAMES}\t%{FILECAPS}\n]', str(args.rpm.resolve())],
                                capture_output=True, text=True)
        version_result = subprocess.run(['rpm', '--dbpath', database, '-qp', '--qf',
                                         '%{VERSION}', str(args.rpm.resolve())],
                                        capture_output=True, text=True)
        changelog_result = subprocess.run(['rpm', '--dbpath', database, '-qp', '--changelog',
                                           str(args.rpm.resolve())],
                                          capture_output=True, text=True)
    if result.returncode:
        parser.exit(1, result.stderr)
    rows = [line.split('\t') for line in result.stdout.splitlines()]
    cli = [fields for fields in rows if fields[0] == '/usr/bin/osslscope']
    if len(cli) != 1 or len(cli[0]) != 2:
        parser.exit(1, 'FAIL: expected one CLI file-capability record\n')
    capabilities, separator, flags = cli[0][1].partition('=')
    if (separator != '=' or flags != 'ep'
            or set(capabilities.split(',')) != {'cap_bpf', 'cap_perfmon'}):
        parser.exit(1, f'FAIL: CLI header capabilities {cli[0][1]!r}; expected cap_bpf,cap_perfmon=ep\n')
    if any(len(fields) != 2 or fields[1] not in ('', '(none)')
           for fields in rows if fields[0] != '/usr/bin/osslscope'):
        parser.exit(1, 'FAIL: unexpected file capabilities outside the CLI\n')
    if version_result.returncode or changelog_result.returncode:
        parser.exit(1, 'FAIL: cannot query RPM version/changelog\n')
    # The top changelog entry must describe this package version. Only the
    # version matches: lifecycle-test revisions share the version entry.
    version = version_result.stdout.strip()
    first = changelog_result.stdout.splitlines()[0] if changelog_result.stdout.splitlines() else ''
    entry = first.rsplit(' - ', 1)[-1] if ' - ' in first else ''
    entry_version = entry.rsplit('-', 1)[0] if '-' in entry else ''
    if entry_version != version:
        parser.exit(1, f'FAIL: top changelog entry {entry!r} does not match package version {version!r}\n')
    print('PASS: actual RPM header declares only CLI cap_bpf,cap_perfmon=ep')
    print(f'PASS: top changelog entry {entry!r} matches package version {version!r}')


if __name__ == '__main__':
    main()
