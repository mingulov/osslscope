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
    printf '{"calls": %s, "candidates": [%s], "object": "lib", "device": 1, "inode": %s, "offset": 4096, "generation": %s}' "$1" "$3" "$2" "${4:-0}"
}

# Candidates (full v2 shape: op + funcid + provider_class + classes).
C11='{"op": 12, "funcid": 11, "provider_class": "default", "algorithm_classes": ["ECDSA"]}'
C15='{"op": 12, "funcid": 15, "provider_class": "default", "algorithm_classes": ["ECDSA"]}'
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

echo "---"
echo "pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
