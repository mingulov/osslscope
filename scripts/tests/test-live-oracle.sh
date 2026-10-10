#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# test-live-oracle.sh — host-runnable unit tests for scripts/live-oracle.py.
#
# The oracle compares the ordinary_ops_driver LEDGER (independent count
# oracle) against the observer's v2 JSON: the ledgered operation must be
# visible as >=1 executed site with a matching candidate op id (op ids from
# src/kinds.rs OPS table). Exact provider-internal counts are recorded,
# never asserted.
#
# Usage: ./scripts/tests/test-live-oracle.sh
# Exit: 0 all pass; 1 any failure.
set -eu

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
ORACLE="$REPO/scripts/live-oracle.py"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT INT TERM

if [ ! -f "$ORACLE" ]; then
    bad "scripts/live-oracle.py exists"
    echo "---"; echo "pass=$PASS fail=$FAIL"; exit 1
fi

mk_report() {
    # $1 = outfile, $2 = JSON sites array
    printf '{"schema_version": "observed-crypto-v2.0", "completeness": {"status": "COMPLETE"}, "sites": %s}' "$2" >"$1"
}
SITE12='[{"calls": 5, "candidates": [{"op": 12, "algorithm_classes": ["ECDSA"]}]}]'
SITE12_DSA='[{"calls": 5, "candidates": [{"op": 12, "algorithm_classes": ["DSA"]}]}]'
SITE12_3='[{"calls": 3, "candidates": [{"op": 12, "algorithm_classes": ["ECDSA"]}]}]'
SITE12_25='[{"calls": 25, "candidates": [{"op": 12, "algorithm_classes": ["ECDSA"]}]}]'
SITE1='[{"calls": 3, "candidates": [{"op": 1, "algorithm_classes": ["SHA2-256"]}]}]'
SITE12_ZERO='[{"calls": 0, "candidates": [{"op": 12}]}, {"calls": 3, "candidates": [{"op": 1}]}]'

printf 'LEDGER mode=ecdsa fetches=1 signs=1 verifies=1\nORDDONE mode=ecdsa rc=0\n' >"$T/ecdsa.log"
printf 'LEDGER mode=kem skipped=old-openssl\nORDDONE mode=kem rc=0\n' >"$T/kem-skip.log"
printf 'LEDGER mode=md4 legacy_loads=1\nLEDGER digest=MD4 fetches=1 digests=1\nORDDONE mode=md4 rc=0\n' >"$T/md4.log"
printf 'nothing here\nORDDONE mode=ecdsa rc=0\n' >"$T/no-ledger.log"
printf 'LEDGER mode=ecdsa fetches=1 signs=1 verifies=1\nLEDGER mINSPECT stage=legacy trips=2\nLEDGER mode=ecdsa fetches=34 signs=1 verifies=1\nORDDONE mode=ecdsa rc=0\n' >"$T/interleave.log"
printf 'LEDGER mINSPECT stage=legacy trips=2\nORDDONE mode=ecdsa rc=0\n' >"$T/all-corrupt.log"
printf 'LEDGER mode=ecdsa fetches=1 signs=1 verifies=1\nLEDGER mode=ecdsa loop_secs=10 ops=10 fetches=20\nORDDONE mode=ecdsa rc=0\n' >"$T/loop.log"
python3 -c "print(''.join('LEDGER mode=ecdsa fetches=%d signs=1 verifies=1\n' % i for i in range(1, 101)) + 'ORDDONE mode=ecdsa rc=0\n')" >"$T/spam.log"
printf 'LEDGER mode=ecdsa fetches=1 signs=0 verifies=0\nORDDONE mode=ecdsa rc=2\n' >"$T/rc2.log"
mk_report "$T/rep12.json" "$SITE12"
mk_report "$T/rep12dsa.json" "$SITE12_DSA"
mk_report "$T/rep12_3.json" "$SITE12_3"
mk_report "$T/rep12_25.json" "$SITE12_25"
mk_report "$T/rep1.json" "$SITE1"
mk_report "$T/rep12zero.json" "$SITE12_ZERO"
printf '{"schema_version": "observed-crypto-v1", "sites": %s}' "$SITE12" >"$T/repv1.json"

# 1. PASS: ledgered SIGNATURE execution visible.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12.json" ecdsa >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "ecdsa ledger + op-12 site passes" \
        || bad "ecdsa ledger + op-12 site passes"
else
    bad "ecdsa ledger + op-12 site passes (rc=$?)"
fi

# 2. FAIL: digest-only report does not satisfy an ECDSA ledger.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep1.json" ecdsa >"$T/out" 2>&1; then
    bad "ecdsa ledger + digest-only report fails (got exit 0)"
else
    grep -q 'FAIL' "$T/out" \
        && ok "ecdsa ledger + digest-only report fails" \
        || bad "ecdsa ledger + digest-only report fails"
fi

# 3. FAIL: zero-call matching site does not satisfy.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12zero.json" ecdsa >"$T/out" 2>&1; then
    bad "zero-call op-12 site fails (got exit 0)"
else
    ok "zero-call op-12 site fails"
fi

# 4. FAIL: no LEDGER line.
if python3 "$ORACLE" "$T/no-ledger.log" "$T/rep12.json" ecdsa >"$T/out" 2>&1; then
    bad "missing LEDGER fails (got exit 0)"
else
    ok "missing LEDGER fails"
fi

# 5. FAIL: driver rc != 0.
if python3 "$ORACLE" "$T/rc2.log" "$T/rep12.json" ecdsa >"$T/out" 2>&1; then
    bad "driver rc=2 fails (got exit 0)"
else
    ok "driver rc=2 fails"
fi

# 6. SKIP: version-gated fixture (report never opened).
if python3 "$ORACLE" "$T/kem-skip.log" "$T/does-not-exist.json" kem >"$T/out" 2>&1; then
    grep -q 'ORACLE SKIP' "$T/out" \
        && ok "skipped ledger skips without opening report" \
        || bad "skipped ledger skips without opening report"
else
    bad "skipped ledger skips without opening report (rc=$?)"
fi

# 7. PASS: multi-LEDGER md4 mode against DIGEST site.
if python3 "$ORACLE" "$T/md4.log" "$T/rep1.json" md4 >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "md4 multi-LEDGER + op-1 site passes" \
        || bad "md4 multi-LEDGER + op-1 site passes"
else
    bad "md4 multi-LEDGER + op-1 site passes (rc=$?)"
fi

# 8. FAIL: wrong schema version.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/repv1.json" ecdsa >"$T/out" 2>&1; then
    bad "v1 report fails (got exit 0)"
else
    ok "v1 report fails"
fi

# 9. Usage: unknown mode exits 2.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12.json" bogus >"$T/out" 2>&1; then
    bad "unknown mode exits 2 (got exit 0)"
else
    [ "$?" -eq 2 ] && ok "unknown mode exits 2" || bad "unknown mode exits 2 (rc=$?)"
fi

# 10. PASS: one interleaved-corrupt LEDGER line is skipped, not fatal.
if python3 "$ORACLE" "$T/interleave.log" "$T/rep12.json" ecdsa >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" && grep -q 'skipped 1 corrupt' "$T/out" \
        && ok "interleaved corrupt line skipped, verdict stands" \
        || bad "interleaved corrupt line skipped, verdict stands"
else
    bad "interleaved corrupt line skipped, verdict stands (rc=$?)"
fi

# 11. FAIL: all-corrupt ledger stays vacuous (skip is not a blank pass).
if python3 "$ORACLE" "$T/all-corrupt.log" "$T/rep12.json" ecdsa >"$T/out" 2>&1; then
    bad "all-corrupt ledger fails (got exit 0)"
else
    grep -q 'no parsable LEDGER' "$T/out" \
        && ok "all-corrupt ledger fails" \
        || bad "all-corrupt ledger fails"
fi

# 12. PASS: 100-LEDGER spam prints bounded (first/last, not megabytes).
if python3 "$ORACLE" "$T/spam.log" "$T/rep12.json" ecdsa >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" && grep -q '100 lines, first=' "$T/out" \
        && [ "$(wc -c <"$T/out")" -lt 2000 ] \
        && ok "spam ledger bounded first/last" \
        || bad "spam ledger bounded first/last"
else
    bad "spam ledger bounded first/last (rc=$?)"
fi

# 13. FAIL: DSA op-12 for an ECDSA ledger (wrong algorithm).
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12dsa.json" ecdsa >"$T/out" 2>&1; then
    bad "DSA for ECDSA fails (got exit 0)"
else
    grep -q 'wrong algorithm' "$T/out" \
        && ok "DSA for ECDSA fails" \
        || bad "DSA for ECDSA fails"
fi

# 14. FAIL: loop op calls below ledgered iterations (3 < 10).
if python3 "$ORACLE" "$T/loop.log" "$T/rep12_3.json" ecdsa >"$T/out" 2>&1; then
    bad "calls below ledgered fails (got exit 0)"
else
    grep -q 'below ledgered' "$T/out" \
        && ok "calls below ledgered fails" \
        || bad "calls below ledgered fails"
fi

# 15. PASS: loop op calls cover ledgered iterations (25 >= 10).
if python3 "$ORACLE" "$T/loop.log" "$T/rep12_25.json" ecdsa >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" && grep -q '25 op calls over 10' "$T/out" \
        && ok "calls cover ledgered passes" \
        || bad "calls cover ledgered passes"
else
    bad "calls cover ledgered passes (rc=$?)"
fi

echo "---"
echo "pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
