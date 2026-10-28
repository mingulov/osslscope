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
    print('PASS: actual RPM header declares only CLI cap_bpf,cap_perfmon=ep')


if __name__ == '__main__':
    main()
