#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# test-live-oracle.sh — host-runnable unit tests for scripts/live-oracle.py.
#
# The oracle compares the ordinary_ops_driver LEDGER (independent count
# oracle) against the observer's v2 JSON across current + fenced
# generations: the ledgered operation must be visible as executed
# sites carrying the mode's op, algorithm class(es), provider class
# and operation funcids (pins in live-oracle.py MODE_* tables, grounded
# in live runs — see docs/2026-10-12-p3-oracle-design.md). Exact
# provider-internal counts are recorded, never asserted; the ledger
# lower-bounds observation (mode-op calls >= loop iterations).
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
    # $1 = outfile, $2 = JSON sites array (no fenced key: old shape)
    printf '{"schema_version": "observed-crypto-v2.0", "completeness": {"status": "PARTIAL"}, "sites": %s}' "$2" >"$1"
}
mk_report_f() {
    # $1 = outfile, $2 = sites, $3 = fenced buckets
    printf '{"schema_version": "observed-crypto-v2.0", "completeness": {"status": "PARTIAL"}, "sites": %s, "fenced": %s}' "$2" "$3" >"$1"
}
site() {
    # $1 = calls, $2 = inode, $3 = candidates JSON, $4 = generation (opt)
    # Declares candidates_coverage complete explicitly: definite
    # operation evidence requires it (missing fails closed).
    printf '{"calls": %s, "candidates": [%s], "object": "lib", "device": 1, "inode": %s, "offset": 4096, "generation": %s, "candidates_coverage": "complete"}' "$1" "$3" "$2" "${4:-0}"
}

# Candidates (full v2 shape: op + funcid + provider_class + classes).
C11='{"op": 12, "funcid": 11, "provider_class": "default", "algorithm_classes": ["ECDSA"]}'
C15='{"op": 12, "funcid": 15, "provider_class": "default", "algorithm_classes": ["ECDSA"]}'
C9='{"op": 12, "funcid": 9, "provider_class": "default", "algorithm_classes": ["ECDSA"]}'
C10='{"op": 12, "funcid": 10, "provider_class": "default", "algorithm_classes": ["ECDSA"]}'
C13='{"op": 12, "funcid": 13, "provider_class": "default", "algorithm_classes": ["ECDSA"]}'
C14='{"op": 12, "funcid": 14, "provider_class": "default", "algorithm_classes": ["ECDSA"]}'
C8='{"op": 12, "funcid": 8, "provider_class": "default", "algorithm_classes": ["ECDSA"]}'
C12='{"op": 12, "funcid": 12, "provider_class": "default", "algorithm_classes": ["ECDSA"]}'
C3SIG='{"op": 12, "funcid": 3, "provider_class": "default", "algorithm_classes": ["ECDSA"]}'
C5SIG='{"op": 12, "funcid": 5, "provider_class": "default", "algorithm_classes": ["ECDSA"]}'
C16='{"op": 12, "funcid": 16, "provider_class": "default", "algorithm_classes": ["ECDSA"]}'
CDSA='{"op": 12, "funcid": 11, "provider_class": "default", "algorithm_classes": ["DSA"]}'
CDSA15='{"op": 12, "funcid": 15, "provider_class": "default", "algorithm_classes": ["DSA"]}'
CLEG='{"op": 12, "funcid": 11, "provider_class": "legacy", "algorithm_classes": ["ECDSA"]}'
CX3='{"op": 11, "funcid": 3, "provider_class": "default", "algorithm_classes": ["X25519"]}'
CX2='{"op": 11, "funcid": 2, "provider_class": "default", "algorithm_classes": ["X25519"]}'
CXRSA='{"op": 11, "funcid": 3, "provider_class": "default", "algorithm_classes": ["RSA"]}'
CK5='{"op": 4, "funcid": 5, "provider_class": "default", "algorithm_classes": ["HKDF"]}'
CK1='{"op": 4, "funcid": 1, "provider_class": "default", "algorithm_classes": ["HKDF"]}'
CE3='{"op": 14, "funcid": 3, "provider_class": "default", "algorithm_classes": ["2.16.840.1.101.3.4.4.2"]}'
CE5='{"op": 14, "funcid": 5, "provider_class": "default", "algorithm_classes": ["2.16.840.1.101.3.4.4.2"]}'
CEF='{"op": 14, "funcid": 3, "provider_class": "default", "algorithm_classes": ["ML-KEM-768"]}'
CE512='{"op": 14, "funcid": 3, "provider_class": "default", "algorithm_classes": ["2.16.840.1.101.3.4.4.1"]}'
CE512B='{"op": 14, "funcid": 5, "provider_class": "default", "algorithm_classes": ["2.16.840.1.101.3.4.4.1"]}'
CE2='{"op": 14, "funcid": 2, "provider_class": "default", "algorithm_classes": ["2.16.840.1.101.3.4.4.2"]}'
CMD4U='{"op": 1, "funcid": 3, "provider_class": "unknown", "algorithm_classes": ["MD4"]}'
CMD4U4='{"op": 1, "funcid": 4, "provider_class": "unknown", "algorithm_classes": ["MD4"]}'
CMD4L='{"op": 1, "funcid": 4, "provider_class": "legacy", "algorithm_classes": ["MD4"]}'
CMD4D='{"op": 1, "funcid": 3, "provider_class": "default", "algorithm_classes": ["MD4"]}'
CSHA='{"op": 1, "funcid": 4, "provider_class": "default", "algorithm_classes": ["2.16.840.1.101.3.4.2.1"]}'
CSHAF='{"op": 1, "funcid": 3, "provider_class": "default", "algorithm_classes": ["SHA2-256"]}'
C1='{"op": 1, "funcid": 4, "provider_class": "default", "algorithm_classes": ["SHA2-256"]}'

printf 'LEDGER mode=ecdsa fetches=1 signs=1 verifies=1\nORDDONE mode=ecdsa rc=0\n' >"$T/ecdsa.log"
printf 'LEDGER mode=kem skipped=old-openssl\nORDDONE mode=kem rc=0\n' >"$T/kem-skip.log"
printf 'LEDGER mode=md4 legacy_loads=1\nLEDGER digest=MD4 fetches=1 digests=1\nORDDONE mode=md4 rc=0\n' >"$T/md4.log"
printf 'LEDGER mode=keyexch fetches=1 derives=1\nORDDONE mode=keyexch rc=0\n' >"$T/keyexch.log"
printf 'LEDGER mode=kdf fetches=1 derives=1\nORDDONE mode=kdf rc=0\n' >"$T/kdf.log"
printf 'LEDGER mode=kem fetches=1 encaps=1 decaps=1\nORDDONE mode=kem rc=0\n' >"$T/kem.log"
printf 'LEDGER digest=SHA2-256 fetches=1 digests=1\nLEDGER digest=MD4 fetches=2 digests=1\nLEDGER mode=mixed legacy_loads=1\nORDDONE mode=mixed rc=0\n' >"$T/mixed.log"
printf 'nothing here\nORDDONE mode=ecdsa rc=0\n' >"$T/no-ledger.log"
printf 'LEDGER mode=ecdsa fetches=1 signs=1 verifies=1\nLEDGER mINSPECT stage=legacy trips=2\nLEDGER mode=ecdsa fetches=34 signs=1 verifies=1\nORDDONE mode=ecdsa rc=0\n' >"$T/interleave.log"
printf 'LEDGER mINSPECT stage=legacy trips=2\nORDDONE mode=ecdsa rc=0\n' >"$T/all-corrupt.log"
printf 'LEDGER mode=ecdsa fetches=1 signs=1 verifies=1\nLEDGER mode=ecdsa loop_secs=10 ops=10 fetches=20\nORDDONE mode=ecdsa rc=0\n' >"$T/loop.log"
python3 -c "print(''.join('LEDGER mode=ecdsa fetches=%d signs=1 verifies=1\n' % i for i in range(1, 101)) + 'ORDDONE mode=ecdsa rc=0\n')" >"$T/spam.log"
printf 'LEDGER mode=ecdsa fetches=1 signs=0 verifies=0\nORDDONE mode=ecdsa rc=2\n' >"$T/rc2.log"

S11=$(site 3 101 "$C11"); S15=$(site 2 102 "$C15")
mk_report "$T/rep12.json" "[$S11, $S15]"
SDSA=$(site 5 103 "$CDSA"); SDSA15=$(site 2 131 "$CDSA15")
mk_report "$T/rep12dsa.json" "[$SDSA, $SDSA15]"
S3=$(site 2 104 "$C11"); S3B=$(site 1 105 "$C15")
mk_report "$T/rep12_3.json" "[$S3, $S3B]"
S25=$(site 15 106 "$C11"); S25B=$(site 10 107 "$C15")
mk_report "$T/rep12_25.json" "[$S25, $S25B]"
S1=$(site 3 108 "$C1")
mk_report "$T/rep1.json" "[$S1]"
S0=$(site 0 109 "$C11")
mk_report "$T/rep12zero.json" "[$S0, $S1]"
printf '{"schema_version": "observed-crypto-v1", "sites": [%s]}' "$S11" >"$T/repv1.json"

SX3=$(site 4 110 "$CX3")
mk_report "$T/repx.json" "[$SX3]"
SXRSA=$(site 4 111 "$CXRSA")
mk_report "$T/repxrsa.json" "[$SXRSA]"
SX2=$(site 4 112 "$CX2")
mk_report "$T/repx2.json" "[$SX2]"
SK5=$(site 4 113 "$CK5")
mk_report "$T/repk.json" "[$SK5]"
SK1=$(site 4 114 "$CK1")
mk_report "$T/repk1.json" "[$SK1]"
SE3=$(site 2 115 "$CE3"); SE5=$(site 2 116 "$CE5")
mk_report "$T/repe.json" "[$SE3, $SE5]"
SEF=$(site 4 117 "$CEF"); SEF5=$(site 2 118 "$CE5")
mk_report "$T/repef.json" "[$SEF, $SEF5]"
SE512=$(site 2 119 "$CE512"); SE512B=$(site 2 132 "$CE512B")
mk_report "$T/repe512.json" "[$SE512, $SE512B]"
SE2=$(site 2 120 "$CE2")
mk_report "$T/repe2.json" "[$SE2, $SE5]"
SMD4=$(site 3 121 "$CMD4U"); SMD4B=$(site 2 122 "$CMD4U4")
mk_report "$T/repmd4.json" "[$SMD4, $SMD4B]"
SMD4L=$(site 5 123 "$CMD4L")
mk_report "$T/repmd4leg.json" "[$SMD4L]"
SMD4D=$(site 5 124 "$CMD4D")
mk_report "$T/repmd4def.json" "[$SMD4D]"
SSHA=$(site 3 125 "$CSHA")
mk_report "$T/repmix.json" "[$SSHA, $SMD4]"
SSHAF=$(site 3 126 "$CSHAF")
mk_report "$T/repmixf.json" "[$SSHAF, $SMD4L]"
mk_report "$T/repmixsha.json" "[$SSHA]"
mk_report "$T/repmixd.json" "[$SSHA, $SMD4D]"

SLEG=$(site 5 127 "$CLEG")
mk_report "$T/rep12leg.json" "[$SLEG, $S15]"
S3SIG=$(site 3 128 "$C3SIG")
mk_report "$T/rep12s3.json" "[$S3SIG, $S15]"
S5SIG=$(site 2 129 "$C5SIG")
mk_report "$T/rep12s5.json" "[$S11, $S5SIG]"
S16=$(site 5 130 "$C16")
mk_report "$T/rep12life.json" "[$S16]"
S9=$(site 3 401 "$C9"); S13=$(site 2 402 "$C13")
mk_report "$T/rep12stream9.json" "[$S9, $S13]"
S10=$(site 3 403 "$C10"); S14=$(site 2 404 "$C14")
mk_report "$T/rep12stream10.json" "[$S10, $S14]"
S8=$(site 4 405 "$C8"); S12=$(site 4 406 "$C12")
mk_report "$T/rep12init.json" "[$S8, $S12]"
mk_report "$T/rep12liveshape.json" "[$S8, $S9, $S10, $S12, $S13, $S14]"

F11=$(site 3 201 "$C11"); F15=$(site 2 202 "$C15")
mk_report_f "$T/rep12fence.json" "[]" \
    '[{"generation": 0, "sites": ['"$F11"', '"$F15"']}]'
C2=$(site 2 203 "$C11"); F9=$(site 9 204 "$C15")
mk_report_f "$T/rep12split.json" "[$C2]" \
    '[{"generation": 0, "sites": ['"$F9"']}]'
C1A=$(site 1 205 "$C11"); F1=$(site 1 206 "$C15")
mk_report_f "$T/rep12split3.json" "[$C1A]" \
    '[{"generation": 0, "sites": ['"$F1"']}]'
D1=$(site 2 207 "$C11"); D2=$(site 3 207 "$C11")
mk_report "$T/repdup.json" "[$D1, $D2]"
G0=$(site 2 208 "$C11" 0); G1=$(site 3 208 "$C15" 1)
mk_report "$T/repregen.json" "[$G0, $G1]"

# 1. PASS: ledgered SIGNATURE execution visible (op + class + provider + funcids).
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
    grep -q 'no executed site carries op' "$T/out" \
        && ok "ecdsa ledger + digest-only report fails" \
        || bad "ecdsa ledger + digest-only report fails"
fi

# 3. FAIL: zero-call matching site does not satisfy (the op-12
# candidate never executed, so no executed site carries op 12 —
# pinned to the specific reason, like leg 2: a bare exit-code
# check would also pass on a missing LEDGER or driver-rc
# failure).
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12zero.json" ecdsa >"$T/out" 2>&1; then
    bad "zero-call op-12 site fails (got exit 0)"
else
    grep -q 'no executed site carries op \[12\] for mode ecdsa' "$T/out" \
        && ok "zero-call op-12 site fails" \
        || bad "zero-call op-12 site fails"
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

# 6. SKIP: version-gated fixture exits 3 (report never opened).
if python3 "$ORACLE" "$T/kem-skip.log" "$T/does-not-exist.json" kem >"$T/out" 2>&1; then
    bad "skipped ledger exits 3 (got exit 0)"
else
    [ "$?" -eq 3 ] && grep -q 'ORACLE SKIP' "$T/out" \
        && ok "skipped ledger skips without opening report (exit 3)" \
        || bad "skipped ledger skips without opening report (rc=$?)"
fi

# 7. PASS: md4 ledger against MD4/legacy DIGEST site.
if python3 "$ORACLE" "$T/md4.log" "$T/repmd4leg.json" md4 >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "md4 ledger + MD4 site passes" \
        || bad "md4 ledger + MD4 site passes"
else
    bad "md4 ledger + MD4 site passes (rc=$?)"
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

# 10. FAIL: a corrupt LEDGER line is a fixture bug (streams are separate).
if python3 "$ORACLE" "$T/interleave.log" "$T/rep12.json" ecdsa >"$T/out" 2>&1; then
    bad "corrupt LEDGER line fails (got exit 0)"
else
    grep -q 'corrupt' "$T/out" \
        && ok "corrupt LEDGER line fails" \
        || bad "corrupt LEDGER line fails"
fi

# 11. FAIL: all-corrupt ledger stays vacuous.
if python3 "$ORACLE" "$T/all-corrupt.log" "$T/rep12.json" ecdsa >"$T/out" 2>&1; then
    bad "all-corrupt ledger fails (got exit 0)"
else
    grep -q 'corrupt' "$T/out" \
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

# 16. PASS: md4 ledger against MD4/unresolved-provider site (live honest state).
if python3 "$ORACLE" "$T/md4.log" "$T/repmd4.json" md4 >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "md4 ledger + unresolved-provider MD4 passes" \
        || bad "md4 ledger + unresolved-provider MD4 passes"
else
    bad "md4 ledger + unresolved-provider MD4 passes (rc=$?)"
fi

# 17. PASS: keyexch ledger against X25519/default/derive site.
if python3 "$ORACLE" "$T/keyexch.log" "$T/repx.json" keyexch >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "keyexch ledger + X25519 site passes" \
        || bad "keyexch ledger + X25519 site passes"
else
    bad "keyexch ledger + X25519 site passes (rc=$?)"
fi

# 18. FAIL: RSA op-11 for a keyexch ledger (wrong algorithm).
if python3 "$ORACLE" "$T/keyexch.log" "$T/repxrsa.json" keyexch >"$T/out" 2>&1; then
    bad "RSA for keyexch fails (got exit 0)"
else
    grep -q 'wrong algorithm' "$T/out" \
        && ok "RSA for keyexch fails" \
        || bad "RSA for keyexch fails"
fi

# 19. FAIL: derives ledgered but only INIT executed (wrong function).
if python3 "$ORACLE" "$T/keyexch.log" "$T/repx2.json" keyexch >"$T/out" 2>&1; then
    bad "keyexch INIT-only fails (got exit 0)"
else
    grep -q 'function' "$T/out" \
        && ok "keyexch INIT-only fails" \
        || bad "keyexch INIT-only fails"
fi

# 20. PASS: kdf ledger against HKDF/default/derive site.
if python3 "$ORACLE" "$T/kdf.log" "$T/repk.json" kdf >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "kdf ledger + HKDF site passes" \
        || bad "kdf ledger + HKDF site passes"
else
    bad "kdf ledger + HKDF site passes (rc=$?)"
fi

# 21. FAIL: derives ledgered but only NEWCTX executed (wrong function).
if python3 "$ORACLE" "$T/kdf.log" "$T/repk1.json" kdf >"$T/out" 2>&1; then
    bad "kdf NEWCTX-only fails (got exit 0)"
else
    grep -q 'function' "$T/out" \
        && ok "kdf NEWCTX-only fails" \
        || bad "kdf NEWCTX-only fails"
fi

# 22. PASS: kem ledger against ML-KEM-768-OID/default sites.
if python3 "$ORACLE" "$T/kem.log" "$T/repe.json" kem >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "kem ledger + KEM-OID sites pass" \
        || bad "kem ledger + KEM-OID sites pass"
else
    bad "kem ledger + KEM-OID sites pass (rc=$?)"
fi

# 23. PASS: kem friendly-name alias accepted.
if python3 "$ORACLE" "$T/kem.log" "$T/repef.json" kem >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "kem friendly alias passes" \
        || bad "kem friendly alias passes"
else
    bad "kem friendly alias passes (rc=$?)"
fi

# 24. FAIL: ML-KEM-512 OID for a 768 ledger (wrong variant).
if python3 "$ORACLE" "$T/kem.log" "$T/repe512.json" kem >"$T/out" 2>&1; then
    bad "KEM-512 for 768 fails (got exit 0)"
else
    grep -q 'wrong algorithm' "$T/out" \
        && ok "KEM-512 for 768 fails" \
        || bad "KEM-512 for 768 fails"
fi

# 25. FAIL: encaps ledgered but only INIT executed (wrong function).
if python3 "$ORACLE" "$T/kem.log" "$T/repe2.json" kem >"$T/out" 2>&1; then
    bad "kem encaps INIT-only fails (got exit 0)"
else
    grep -q 'function' "$T/out" \
        && ok "kem encaps INIT-only fails" \
        || bad "kem encaps INIT-only fails"
fi

# 26. PASS: mixed ledger against SHA-OID/default + MD4/unresolved.
if python3 "$ORACLE" "$T/mixed.log" "$T/repmix.json" mixed >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "mixed ledger + both providers passes" \
        || bad "mixed ledger + both providers passes"
else
    bad "mixed ledger + both providers passes (rc=$?)"
fi

# 27. PASS: mixed friendly + legacy spellings accepted.
if python3 "$ORACLE" "$T/mixed.log" "$T/repmixf.json" mixed >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "mixed alias spellings pass" \
        || bad "mixed alias spellings pass"
else
    bad "mixed alias spellings pass (rc=$?)"
fi

# 28. FAIL: mixed ledger with SHA but no MD4 (missing provider leg).
if python3 "$ORACLE" "$T/mixed.log" "$T/repmixsha.json" mixed >"$T/out" 2>&1; then
    bad "mixed without MD4 fails (got exit 0)"
else
    grep -q 'MD4' "$T/out" \
        && ok "mixed without MD4 fails" \
        || bad "mixed without MD4 fails"
fi

# 29. FAIL: mixed MD4 attributed to default (wrong provider).
if python3 "$ORACLE" "$T/mixed.log" "$T/repmixd.json" mixed >"$T/out" 2>&1; then
    bad "mixed MD4-on-default fails (got exit 0)"
else
    grep -q 'provider' "$T/out" \
        && ok "mixed MD4-on-default fails" \
        || bad "mixed MD4-on-default fails"
fi

# 30. FAIL: md4 MD4 attributed to default (wrong provider).
if python3 "$ORACLE" "$T/md4.log" "$T/repmd4def.json" md4 >"$T/out" 2>&1; then
    bad "md4 on default fails (got exit 0)"
else
    grep -q 'provider' "$T/out" \
        && ok "md4 on default fails" \
        || bad "md4 on default fails"
fi

# 31. FAIL: SHA site for an md4 ledger (wrong algorithm).
if python3 "$ORACLE" "$T/md4.log" "$T/rep1.json" md4 >"$T/out" 2>&1; then
    bad "SHA for md4 fails (got exit 0)"
else
    grep -q 'wrong algorithm' "$T/out" \
        && ok "SHA for md4 fails" \
        || bad "SHA for md4 fails"
fi

# 32. FAIL: ecdsa execution on legacy (wrong provider, ALL-default rule).
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12leg.json" ecdsa >"$T/out" 2>&1; then
    bad "ecdsa on legacy fails (got exit 0)"
else
    grep -q 'provider' "$T/out" \
        && ok "ecdsa on legacy fails" \
        || bad "ecdsa on legacy fails"
fi

# 33. FAIL: signs ledgered but only plain SIGN executed (want DIGEST_SIGN).
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12s3.json" ecdsa >"$T/out" 2>&1; then
    bad "ecdsa plain-SIGN fails (got exit 0)"
else
    grep -q 'function' "$T/out" \
        && ok "ecdsa plain-SIGN fails" \
        || bad "ecdsa plain-SIGN fails"
fi

# 34. FAIL: verifies ledgered but only plain VERIFY executed.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12s5.json" ecdsa >"$T/out" 2>&1; then
    bad "ecdsa plain-VERIFY fails (got exit 0)"
else
    grep -q 'function' "$T/out" \
        && ok "ecdsa plain-VERIFY fails" \
        || bad "ecdsa plain-VERIFY fails"
fi

# 35. FAIL: only lifecycle funcids executed (no operation function).
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12life.json" ecdsa >"$T/out" 2>&1; then
    bad "ecdsa lifecycle-only fails (got exit 0)"
else
    grep -q 'function' "$T/out" \
        && ok "ecdsa lifecycle-only fails" \
        || bad "ecdsa lifecycle-only fails"
fi

# 36. PASS: mode-op hit lives in a fenced generation (current empty).
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12fence.json" ecdsa >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "fenced hit passes" \
        || bad "fenced hit passes"
else
    bad "fenced hit passes (rc=$?)"
fi

# 37. PASS: lower bound sums current + fenced (2 + 9 >= 10).
if python3 "$ORACLE" "$T/loop.log" "$T/rep12split.json" ecdsa >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" && grep -q '11 op calls over 10' "$T/out" \
        && ok "split bound passes" \
        || bad "split bound passes"
else
    bad "split bound passes (rc=$?)"
fi

# 38. FAIL: split total below ledgered (1 + 1 < 10).
if python3 "$ORACLE" "$T/loop.log" "$T/rep12split3.json" ecdsa >"$T/out" 2>&1; then
    bad "split shortfall fails (got exit 0)"
else
    grep -q 'below ledgered' "$T/out" \
        && ok "split shortfall fails" \
        || bad "split shortfall fails"
fi

# 39. FAIL: same site counted twice in one generation (duplicate join).
if python3 "$ORACLE" "$T/ecdsa.log" "$T/repdup.json" ecdsa >"$T/out" 2>&1; then
    bad "duplicate site fails (got exit 0)"
else
    grep -q 'duplicate' "$T/out" \
        && ok "duplicate site fails" \
        || bad "duplicate site fails"
fi

# 40. PASS: same identity in different generations is reincarnation, not a dup.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/repregen.json" ecdsa >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "cross-generation reincarnation passes" \
        || bad "cross-generation reincarnation passes"
else
    bad "cross-generation reincarnation passes (rc=$?)"
fi

# v2.1 fixtures: versioned reports plus installed_at-carrying sites
# (current + fenced). mk_report/mk_report_f above keep stamping v2.0
# (stored-evidence compatibility); these stamp the version under test.
mk_report_v() {
    # $1 = outfile, $2 = schema_version, $3 = JSON sites array
    printf '{"schema_version": "%s", "completeness": {"status": "PARTIAL"}, "sites": %s}' "$2" "$3" >"$1"
}
mk_report_vf() {
    # $1 = outfile, $2 = schema_version, $3 = sites, $4 = fenced buckets
    printf '{"schema_version": "%s", "completeness": {"status": "PARTIAL"}, "sites": %s, "fenced": %s}' "$2" "$3" "$4" >"$1"
}
site_i() {
    # $1 = calls, $2 = inode, $3 = candidates JSON, $4 = installed_at, $5 = generation (opt)
    # Declares candidates_coverage complete explicitly (see site()).
    printf '{"calls": %s, "candidates": [%s], "object": "lib", "device": 1, "inode": %s, "offset": 4096, "generation": %s, "installed_at": %s, "candidates_coverage": "complete"}' "$1" "$3" "$2" "${5:-0}" "$4"
}

S11I=$(site_i 3 101 "$C11" 5); S15I=$(site_i 2 102 "$C15" 6)
mk_report_v "$T/rep12_v21.json" "observed-crypto-v2.1" "[$S11I, $S15I]"
F11I=$(site_i 3 201 "$C11" 7); F15I=$(site_i 2 202 "$C15" 8)
mk_report_vf "$T/rep12fence_v21.json" "observed-crypto-v2.1" "[]" \
    '[{"generation": 0, "sites": ['"$F11I"', '"$F15I"']}]'
mk_report_v "$T/rep12_bare.json" "observed-crypto-v2" "[$S11, $S15]"
mk_report_v "$T/rep12_v29.json" "observed-crypto-v2.9" "[$S11, $S15]"
mk_report_v "$T/rep12_v3.json" "observed-crypto-v3.0" "[$S11, $S15]"
mk_report_v "$T/rep12_v2x.json" "observed-crypto-v2.x" "[$S11, $S15]"
mk_report_v "$T/rep12_v2dot.json" "observed-crypto-v2." "[$S11, $S15]"

# 41. PASS: v2.1 current sites with installed_at pass (reader gate).
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12_v21.json" ecdsa >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "v2.1 current sites with installed_at pass" \
        || bad "v2.1 current sites with installed_at pass"
else
    bad "v2.1 current sites with installed_at pass (rc=$?)"
fi

# 42. PASS: v2.1 fenced sites with installed_at pass (reader gate).
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12fence_v21.json" ecdsa >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "v2.1 fenced sites with installed_at pass" \
        || bad "v2.1 fenced sites with installed_at pass"
else
    bad "v2.1 fenced sites with installed_at pass (rc=$?)"
fi

# 43. PASS: bare observed-crypto-v2 accepted (implicit .0).
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12_bare.json" ecdsa >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "bare v2 accepted" \
        || bad "bare v2 accepted"
else
    bad "bare v2 accepted (rc=$?)"
fi

# 44. PASS: future digit minor v2.9 accepted (reader gate).
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12_v29.json" ecdsa >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "v2.9 accepted" \
        || bad "v2.9 accepted"
else
    bad "v2.9 accepted (rc=$?)"
fi

# 45. FAIL: other major v3.0 rejected.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12_v3.json" ecdsa >"$T/out" 2>&1; then
    bad "v3.0 rejected (got exit 0)"
else
    grep -q 'schema_version' "$T/out" \
        && ok "v3.0 rejected" \
        || bad "v3.0 rejected"
fi

# 46. FAIL: non-digit minor v2.x rejected.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12_v2x.json" ecdsa >"$T/out" 2>&1; then
    bad "v2.x rejected (got exit 0)"
else
    grep -q 'schema_version' "$T/out" \
        && ok "v2.x rejected" \
        || bad "v2.x rejected"
fi

# 47. FAIL: empty minor v2. rejected.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12_v2dot.json" ecdsa >"$T/out" 2>&1; then
    bad "v2. rejected (got exit 0)"
else
    grep -q 'schema_version' "$T/out" \
        && ok "v2. rejected" \
        || bad "v2. rejected"
fi

# R09 fixtures: split-attribution negatives (class/provider/function on
# different candidates must not witness an operation), combined
# positives, and the aggregate-bound quantitative pin. SIGNATURE
# NEWCTX=1 and DIGEST INIT=2 are setup-only funcids (src/kinds.rs);
# they never satisfy an operation counter.
CSETUP='{"op": 12, "funcid": 1, "provider_class": "default", "algorithm_classes": ["ECDSA"]}'
CMD4SETUP='{"op": 1, "funcid": 2, "provider_class": "legacy", "algorithm_classes": ["MD4"]}'
printf 'LEDGER mode=ecdsa fetches=102 signs=1 verifies=1\nLEDGER mode=ecdsa loop_secs=30 ops=100 fetches=102\nORDDONE mode=ecdsa rc=0\n' >"$T/loop100.log"

S48A=$(site 5 301 "$CSETUP"); S48B=$(site 3 302 "$CDSA"); S48C=$(site 2 303 "$CDSA15")
mk_report "$T/rep48split.json" "[$S48A, $S48B, $S48C]"
S49A=$(site 4 304 "$CLEG, $CDSA"); S49B=$(site 2 305 "$C15")
mk_report "$T/rep49split.json" "[$S49A, $S49B]"
S50A=$(site 3 306 "$CMD4SETUP"); S50B=$(site 4 307 "$CSHAF")
mk_report "$T/rep50split.json" "[$S50A, $S50B]"
S51A=$(site 7 308 "$CSETUP"); S51B=$(site 3 309 "$C11"); S51C=$(site 2 310 "$C15")
mk_report "$T/rep51combo.json" "[$S51A, $S51B, $S51C]"
S52A=$(site 4 311 "$CMD4SETUP"); S52B=$(site 3 312 "$CMD4L")
mk_report "$T/rep52combo.json" "[$S52A, $S52B]"
S53A=$(site 100 313 "$CSETUP"); S53B=$(site 1 314 "$C11"); S53C=$(site 1 315 "$C15")
mk_report "$T/rep53agg.json" "[$S53A, $S53B, $S53C]"
S54A=$(site 97 316 "$CSETUP"); S54B=$(site 1 317 "$C11"); S54C=$(site 1 318 "$C15")
mk_report "$T/rep54agg.json" "[$S54A, $S54B, $S54C]"
D55A=$(site 2 319 "$CLEG, $CDSA"); D55B=$(site 3 319 "$CLEG, $CDSA")
mk_report "$T/rep55dup.json" "[$D55A, $D55B]"

# 48. FAIL: ECDSA setup + DSA sign/verify split across candidates.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep48split.json" ecdsa >"$T/out" 2>&1; then
    bad "ecdsa setup+DSA split fails (got exit 0)"
else
    grep -q 'no single candidate' "$T/out" \
        && ok "ecdsa setup+DSA split fails" \
        || bad "ecdsa setup+DSA split fails"
fi

# 49. FAIL: ECDSA/legacy + DSA/default alternatives in one site.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep49split.json" ecdsa >"$T/out" 2>&1; then
    bad "ecdsa legacy/DSA split fails (got exit 0)"
else
    grep -q 'no single candidate' "$T/out" \
        && ok "ecdsa legacy/DSA split fails" \
        || bad "ecdsa legacy/DSA split fails"
fi

# 50. FAIL: MD4 setup + SHA operation split across candidates.
if python3 "$ORACLE" "$T/md4.log" "$T/rep50split.json" md4 >"$T/out" 2>&1; then
    bad "md4 setup+SHA split fails (got exit 0)"
else
    grep -q 'no single candidate' "$T/out" \
        && ok "md4 setup+SHA split fails" \
        || bad "md4 setup+SHA split fails"
fi

# 51. PASS: ECDSA setup + sign + verify combined tuples pass.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep51combo.json" ecdsa >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "ecdsa combined tuples pass" \
        || bad "ecdsa combined tuples pass"
else
    bad "ecdsa combined tuples pass (rc=$?)"
fi

# 52. PASS: MD4 setup + MD4 operation combined tuples pass.
if python3 "$ORACLE" "$T/md4.log" "$T/rep52combo.json" md4 >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "md4 combined tuples pass" \
        || bad "md4 combined tuples pass"
else
    bad "md4 combined tuples pass (rc=$?)"
fi

# 53. PASS: setup 100 + sign 1 + verify 1 at ledger 100 meets the
# adopted aggregate lower bound (102 >= 100). The guarantee is
# aggregate presence, never per-function exactness.
if python3 "$ORACLE" "$T/loop100.log" "$T/rep53agg.json" ecdsa >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" && grep -q '102 op calls over 100' "$T/out" \
        && grep -q 'aggregate lower bound' "$T/out" \
        && ok "aggregate bound 102-over-100 passes" \
        || bad "aggregate bound 102-over-100 passes"
else
    bad "aggregate bound 102-over-100 passes (rc=$?)"
fi

# 54. FAIL: fewer than 100 aggregate calls at ledger 100 (99 < 100).
if python3 "$ORACLE" "$T/loop100.log" "$T/rep54agg.json" ecdsa >"$T/out" 2>&1; then
    bad "aggregate shortfall 99-under-100 fails (got exit 0)"
else
    grep -q 'below ledgered' "$T/out" \
        && ok "aggregate shortfall 99-under-100 fails" \
        || bad "aggregate shortfall 99-under-100 fails"
fi

# 55. FAIL: duplicate physical join on a multi-candidate site.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep55dup.json" ecdsa >"$T/out" 2>&1; then
    bad "multi-candidate duplicate fails (got exit 0)"
else
    grep -q 'duplicate' "$T/out" \
        && ok "multi-candidate duplicate fails" \
        || bad "multi-candidate duplicate fails"
fi

# R09 fix-round-1: full-schema fixtures with coherent object references
# and conservation fields, plus conflicting/incomplete certainty controls.
# Abbreviated builders above declare candidates_coverage complete
# explicitly but still omit first_ns/last_ns and provider/weak_alias;
# these builders emit structurally complete v2.1 documents. Definite
# operation evidence requires an explicitly complete candidate set
# with every alternative agreeing on the full tuple (evidence model);
# conflicting alternatives, unknown coverage, or a missing coverage
# key are possible attribution, never definite (fail closed).
full_cand() {
    # $1=provider $2=provider_class $3=op $4=funcid $5=classes JSON $6=weak_alias
    printf '{"provider": "%s", "provider_class": "%s", "op": %s, "funcid": %s, "algorithm_classes": %s, "weak_alias": %s}' "$1" "$2" "$3" "$4" "$5" "$6"
}
full_site() {
    # $1=calls $2=object $3=device $4=inode $5=offset $6=generation $7=candidates $8=coverage $9=first_ns $10=last_ns
    printf '{"calls": %s, "candidates": [%s], "object": "%s", "device": %s, "inode": %s, "offset": %s, "generation": %s, "candidates_coverage": "%s", "first_ns": %s, "last_ns": %s}' "$1" "$7" "$2" "$3" "$4" "$5" "$6" "$8" "$9" "${10}"
}
mk_full_report() {
    # $1=outfile $2=sites JSON $3=total $4=leg $5=nonleg $6=shared $7=tail
    python3 - "$1" "$2" "$3" "$4" "$5" "$6" "$7" <<'PYEOF'
import sys, json
outfile, sites_json, total, leg, nonleg, shared, tail = sys.argv[1:8]
sites = json.loads(sites_json)
total = int(total); leg = int(leg); nonleg = int(nonleg)
shared = int(shared); tail = int(tail)
assert leg + nonleg + shared + tail == total, "partition must sum to total"
assert sum(s["calls"] for s in sites) == total, "sites must sum to total"
objs = {("obj-default", 8, 100), ("obj-legacy", 8, 200)}
prov_ids = {"obj-default", "obj-legacy"}
for s in sites:
    assert (s["object"], s["device"], s["inode"]) in objs, \
        "dangling site object %r" % ((s["object"], s["device"], s["inode"]),)
    for c in s["candidates"]:
        assert c["provider"] in prov_ids, \
            "dangling candidate provider %r" % (c["provider"],)
    assert s["first_ns"] <= s["last_ns"], "ordered timestamps"
doc = {
    "schema_version": "observed-crypto-v2.1",
    "target": {"pid": 42, "comm": "test", "container_id": "",
               "image_digest": "", "argv_redacted": True},
    "openssl": {"state": "verified", "version": "3.5.8"},
    "window": {"requested_start_ns": 0, "requested_end_ns": 30000000000,
               "effective_start_ns": 0, "effective_end_ns": 30000000000,
               "signal_cut": False},
    "completeness": {"status": "PARTIAL", "fatal_kind": None,
                     "reasons": [{"kind": "loss",
                                  "counter": "lifecycle.polling_fallback",
                                  "source": "lifecycle", "value": 1}],
                     "counters": [{"name": "lifecycle.polling_fallback",
                                   "kind": "loss", "units": "events",
                                   "source": "lifecycle", "value": 1}]},
    "sites": sites,
    "fenced": [],
    "objects": [
        {"id": "obj-default", "device": 8, "inode": 100,
         "display_locator": "/usr/lib/ossl-modules/default.so"},
        {"id": "obj-legacy", "device": 8, "inode": 200,
         "display_locator": "/usr/lib/ossl-modules/legacy.so"}],
    "coverage": [{"scope": "provider/default",
                  "expected": {"state": "applicable", "sites": len(sites)},
                  "discovered": len(sites), "attached": len(sites)}],
    "legacy_partition": {"legacy_exclusive_calls": leg,
                         "non_legacy_exclusive_calls": nonleg,
                         "shared_ambiguous_calls": shared,
                         "unfenced_tail_calls": tail},
}
with open(outfile, "w") as f:
    json.dump(doc, f)
PYEOF
}

F11=$(full_cand "obj-default" "default" 12 11 '["ECDSA"]' false)
F15=$(full_cand "obj-default" "default" 12 15 '["ECDSA"]' false)
FDSA11=$(full_cand "obj-default" "default" 12 11 '["DSA"]' false)
FDSA15=$(full_cand "obj-default" "default" 12 15 '["DSA"]' false)
FLEG11=$(full_cand "obj-legacy" "legacy" 12 11 '["ECDSA"]' false)
FSETUP=$(full_cand "obj-default" "default" 12 1 '["ECDSA"]' false)
FMD4SETUP=$(full_cand "obj-legacy" "legacy" 1 2 '["MD4"]' false)
FMD4OP=$(full_cand "obj-legacy" "legacy" 1 4 '["MD4"]' false)
FSHA=$(full_cand "obj-default" "default" 1 3 '["SHA2-256"]' false)

# 56: conflicting class alternatives (ECDSA vs DSA) in complete sets.
S56A=$(full_site 5 "obj-default" 8 100 4096 0 "$F11, $FDSA11" "complete" 10 90)
S56B=$(full_site 5 "obj-default" 8 100 8192 0 "$F15, $FDSA15" "complete" 10 90)
mk_full_report "$T/rep56conf.json" "[$S56A, $S56B]" 10 0 10 0 0
# 57: incomplete sets (unknown coverage) with matching single candidates.
S57A=$(full_site 5 "obj-default" 8 100 12288 0 "$F11" "unknown" 10 90)
S57B=$(full_site 5 "obj-default" 8 100 16384 0 "$F15" "unknown" 10 90)
mk_full_report "$T/rep57unk.json" "[$S57A, $S57B]" 10 0 10 0 0
# 58: conflicting provider alternatives (default vs legacy) in complete sets.
FLEG15=$(full_cand "obj-legacy" "legacy" 12 15 '["ECDSA"]' false)
S58A=$(full_site 5 "obj-default" 8 100 20480 0 "$F11, $FLEG11" "complete" 10 90)
S58B=$(full_site 5 "obj-default" 8 100 24576 0 "$F15, $FLEG15" "complete" 10 90)
mk_full_report "$T/rep58prov.json" "[$S58A, $S58B]" 10 0 0 10 0
# 59: empty candidate sets prove nothing (unattributed).
S59A=$(full_site 5 "obj-default" 8 100 28672 0 "" "complete" 10 90)
S59B=$(full_site 5 "obj-default" 8 100 32768 0 "" "complete" 10 90)
mk_full_report "$T/rep59empty.json" "[$S59A, $S59B]" 10 0 0 0 10
# 60: full-schema ECDSA setup + DSA sign/verify split.
S60A=$(full_site 5 "obj-default" 8 100 36864 0 "$FSETUP" "complete" 10 90)
S60B=$(full_site 3 "obj-default" 8 100 40960 0 "$FDSA11" "complete" 10 90)
S60C=$(full_site 2 "obj-default" 8 100 45056 0 "$FDSA15" "complete" 10 90)
mk_full_report "$T/rep60split.json" "[$S60A, $S60B, $S60C]" 10 0 10 0 0
# 61: full-schema ECDSA/legacy + DSA/default split.
S61A=$(full_site 4 "obj-default" 8 100 49152 0 "$FLEG11, $FDSA11" "complete" 10 90)
S61B=$(full_site 2 "obj-default" 8 100 53248 0 "$F15" "complete" 10 90)
mk_full_report "$T/rep61split.json" "[$S61A, $S61B]" 6 0 2 4 0
# 62: full-schema MD4 setup + SHA operation split.
S62A=$(full_site 3 "obj-legacy" 8 200 4096 0 "$FMD4SETUP" "complete" 10 90)
S62B=$(full_site 4 "obj-default" 8 100 57344 0 "$FSHA" "complete" 10 90)
mk_full_report "$T/rep62split.json" "[$S62A, $S62B]" 7 3 4 0 0
# 63: full-schema ECDSA combined tuples pass (definite).
S63A=$(full_site 7 "obj-default" 8 100 61440 0 "$FSETUP" "complete" 10 90)
S63B=$(full_site 3 "obj-default" 8 100 65536 0 "$F11" "complete" 10 90)
S63C=$(full_site 2 "obj-default" 8 100 69632 0 "$F15" "complete" 10 90)
mk_full_report "$T/rep63combo.json" "[$S63A, $S63B, $S63C]" 12 0 12 0 0
# 64: full-schema MD4 combined tuples pass (definite).
S64A=$(full_site 4 "obj-legacy" 8 200 8192 0 "$FMD4SETUP" "complete" 10 90)
S64B=$(full_site 3 "obj-legacy" 8 200 12288 0 "$FMD4OP" "complete" 10 90)
mk_full_report "$T/rep64combo.json" "[$S64A, $S64B]" 7 7 0 0 0
# 65: missing-key control (fail closed): fixture-57 singletons with NO
# candidates_coverage key must not establish definite attribution.
full_site_nocov() {
    # same shape as full_site minus the coverage key: $1=calls $2=object
    # $3=device $4=inode $5=offset $6=generation $7=candidates $8=first $9=last
    printf '{"calls": %s, "candidates": [%s], "object": "%s", "device": %s, "inode": %s, "offset": %s, "generation": %s, "first_ns": %s, "last_ns": %s}' "$1" "$7" "$2" "$3" "$4" "$5" "$6" "$8" "$9"
}
S65A=$(full_site_nocov 5 "obj-default" 8 100 12288 0 "$F11" 10 90)
S65B=$(full_site_nocov 5 "obj-default" 8 100 16384 0 "$F15" 10 90)
mk_full_report "$T/rep65nocov.json" "[$S65A, $S65B]" 10 0 10 0 0

# 56. FAIL: conflicting ECDSA/DSA alternatives are possible, not definite.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep56conf.json" ecdsa >"$T/out" 2>&1; then
    bad "full-schema conflicting class fails (got exit 0)"
else
    grep -q 'ambiguous' "$T/out" \
        && ok "full-schema conflicting class fails" \
        || bad "full-schema conflicting class fails"
fi

# 57. FAIL: unknown candidate sets cannot establish certainty.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep57unk.json" ecdsa >"$T/out" 2>&1; then
    bad "full-schema unknown coverage fails (got exit 0)"
else
    grep -q 'ambiguous' "$T/out" \
        && ok "full-schema unknown coverage fails" \
        || bad "full-schema unknown coverage fails"
fi

# 58. FAIL: conflicting default/legacy alternatives are not definite.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep58prov.json" ecdsa >"$T/out" 2>&1; then
    bad "full-schema conflicting provider fails (got exit 0)"
else
    grep -q 'ambiguous' "$T/out" \
        && ok "full-schema conflicting provider fails" \
        || bad "full-schema conflicting provider fails"
fi

# 59. FAIL: empty candidate sets prove nothing.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep59empty.json" ecdsa >"$T/out" 2>&1; then
    bad "full-schema empty candidates fail (got exit 0)"
else
    grep -q 'no executed site carries op' "$T/out" \
        && ok "full-schema empty candidates fail" \
        || bad "full-schema empty candidates fail"
fi

# 60. FAIL: full-schema ECDSA setup + DSA sign/verify split.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep60split.json" ecdsa >"$T/out" 2>&1; then
    bad "full-schema ecdsa setup+DSA split fails (got exit 0)"
else
    grep -q 'no single candidate' "$T/out" \
        && ok "full-schema ecdsa setup+DSA split fails" \
        || bad "full-schema ecdsa setup+DSA split fails"
fi

# 61. FAIL: full-schema ECDSA/legacy + DSA/default split.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep61split.json" ecdsa >"$T/out" 2>&1; then
    bad "full-schema legacy/DSA split fails (got exit 0)"
else
    grep -q 'no single candidate' "$T/out" \
        && ok "full-schema legacy/DSA split fails" \
        || bad "full-schema legacy/DSA split fails"
fi

# 62. FAIL: full-schema MD4 setup + SHA operation split.
if python3 "$ORACLE" "$T/md4.log" "$T/rep62split.json" md4 >"$T/out" 2>&1; then
    bad "full-schema md4 setup+SHA split fails (got exit 0)"
else
    grep -q 'no single candidate' "$T/out" \
        && ok "full-schema md4 setup+SHA split fails" \
        || bad "full-schema md4 setup+SHA split fails"
fi

# 63. PASS: full-schema ECDSA combined tuples pass (definite).
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep63combo.json" ecdsa >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "full-schema ecdsa combined passes" \
        || bad "full-schema ecdsa combined passes"
else
    bad "full-schema ecdsa combined passes (rc=$?)"
fi

# 64. PASS: full-schema MD4 combined tuples pass (definite).
if python3 "$ORACLE" "$T/md4.log" "$T/rep64combo.json" md4 >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "full-schema md4 combined passes" \
        || bad "full-schema md4 combined passes"
else
    bad "full-schema md4 combined passes (rc=$?)"
fi

# 65. FAIL: missing candidates_coverage cannot establish certainty.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep65nocov.json" ecdsa >"$T/out" 2>&1; then
    bad "missing coverage fails closed (got exit 0)"
else
    grep -q 'ambiguous' "$T/out" \
        && ok "missing coverage fails closed" \
        || bad "missing coverage fails closed"
fi

# R21 finding 3: default-provider ECDSA has no one-shot
# digest_sign/verify (ecdsa_sig.c "shouldn't do digest_sign";
# EVP falls through to init/update/final). The legs accept the
# streaming UPDATE/FINAL funcids; the INIT funcids stay
# setup-only and never satisfy a counter.
# 66. PASS: signs/verifies satisfied by streaming UPDATE (9/13).
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12stream9.json" ecdsa >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "ecdsa streaming UPDATE satisfies legs" \
        || bad "ecdsa streaming UPDATE satisfies legs"
else
    bad "ecdsa streaming UPDATE satisfies legs (rc=$?)"
fi

# 67. PASS: signs/verifies satisfied by streaming FINAL (10/14).
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12stream10.json" ecdsa >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "ecdsa streaming FINAL satisfies legs" \
        || bad "ecdsa streaming FINAL satisfies legs"
else
    bad "ecdsa streaming FINAL satisfies legs (rc=$?)"
fi

# 68. PASS: the R21 live shape (INIT + UPDATE + FINAL executed)
# passes — INIT sites are present but UPDATE/FINAL satisfy.
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12liveshape.json" ecdsa >"$T/out" 2>&1; then
    grep -q 'ORACLE PASS' "$T/out" \
        && ok "ecdsa INIT+UPDATE+FINAL live shape passes" \
        || bad "ecdsa INIT+UPDATE+FINAL live shape passes"
else
    bad "ecdsa INIT+UPDATE+FINAL live shape passes (rc=$?)"
fi

# 69. FAIL: signs/verifies ledgered but only INIT executed (8/12
# are setup-only — wrong function).
if python3 "$ORACLE" "$T/ecdsa.log" "$T/rep12init.json" ecdsa >"$T/out" 2>&1; then
    bad "ecdsa INIT-only fails (got exit 0)"
else
    grep -q 'function' "$T/out" \
        && ok "ecdsa INIT-only fails" \
        || bad "ecdsa INIT-only fails"
fi

echo "---"
echo "pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
