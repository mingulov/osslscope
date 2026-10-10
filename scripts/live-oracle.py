#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Ledger-vs-observer oracle for the live-known-n workflow.

Compares the ordinary_ops_driver LEDGER stdout (independent count oracle)
against the observer's observed-crypto-v2.0 JSON: the ledgered operation
must be visible as at least one executed site (calls >= 1) carrying a
candidate with the mode's op id. Per the fixture contract, exact
provider-internal callback counts are implementation-defined: they are
printed for the calibration record, never asserted.

Usage: live-oracle.py DRIVER_LOG REPORT_JSON MODE
Exits 0 on ORACLE PASS or ORACLE SKIP (version-gated fixture), 1 on
ORACLE FAIL, 2 on usage error.
"""

import json
import re
import sys

# Fixture mode -> expected OSSL op ids (src/kinds.rs OPS table: DIGEST=1,
# KDF=4, KEYEXCH=11, SIGNATURE=12, KEM=14).
MODE_OPS = {
    "ecdsa": {12},
    "keyexch": {11},
    "kdf": {4},
    "kem": {14},
    "md4": {1},
    "mixed": {1},
}


def fail(msg):
    print("ORACLE FAIL: " + msg)
    return 1


def main(argv):
    if len(argv) != 4:
        print("usage: live-oracle.py DRIVER_LOG REPORT_JSON MODE")
        return 2
    driver_log_path, report_path, mode = argv[1], argv[2], argv[3]
    if mode not in MODE_OPS:
        print("unknown mode %r (want one of %s)" % (mode, sorted(MODE_OPS)))
        return 2
    try:
        with open(driver_log_path) as f:
            log = f.read()
    except OSError as e:
        return fail("cannot read driver log %s: %s" % (driver_log_path, e))
    ledgers = re.findall(r"^LEDGER (.*)$", log, re.M)
    if not ledgers:
        return fail("no LEDGER line in driver output")
    if not re.search(r"^ORDDONE mode=%s rc=0$" % re.escape(mode), log, re.M):
        return fail("driver did not complete rc=0 for mode %s" % mode)
    parsed = []
    for line in ledgers:
        try:
            parsed.append(dict(tok.split("=", 1) for tok in line.split()))
        except ValueError:
            return fail("unparsable LEDGER line: %r" % line)
    print("ledger: %s" % parsed)
    if any("skipped" in d for d in parsed):
        print("ORACLE SKIP: version-gated fixture, no observation asserted")
        return 0
    try:
        with open(report_path) as f:
            rep = json.load(f)
    except (OSError, ValueError) as e:
        return fail("cannot parse report %s: %s" % (report_path, e))
    if rep.get("schema_version") != "observed-crypto-v2.0":
        return fail("schema_version is %r, want observed-crypto-v2.0"
                     % rep.get("schema_version"))
    sites = rep.get("sites", [])
    total = sum(s.get("calls", 0) for s in sites)
    print("observed sites: %d total_calls: %d completeness: %s" % (
        len(sites), total, rep.get("completeness", {}).get("status")))
    want = MODE_OPS[mode]
    hit = False
    for s in sites:
        ops = sorted({c.get("op") for c in s.get("candidates", [])})
        print("  site calls=%d ops=%s" % (s.get("calls"), ops))
        if s.get("calls", 0) >= 1 and (want & set(ops)):
            hit = True
    if not hit:
        return fail("no executed site carries op %s for mode %s "
                     "(total %d calls over %d sites)"
                     % (sorted(want), mode, total, len(sites)))
    print("ORACLE PASS: ledgered op %s execution is visible in observer JSON"
          % sorted(want))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
