#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# test-scriptlets.sh — host-runnable deb/rpm scriptlet tests (no root, no rpm/dpkg).
#
# Simulates the package install/upgrade/erase scriptlet argument matrix with a
# stub setcap, so the file-capability lifecycle is tested on any host:
#
#   deb: postinst configure | prerm remove | prerm upgrade
#   rpm: %post | %preun $1=0 (erase) | %preun $1=1 (upgrade) | %posttrans
#
# The key regression: upgrading FROM the audited 1.0.0 RPM runs the OLD
# unguarded %preun AFTER the new %post, stripping freshly applied caps.
# The new spec must therefore (a) guard %preun with $1 -eq 0 (erase-only)
# and (b) restore caps in %posttrans (runs at end of transaction).
#
# Usage: ./packaging/tests/test-scriptlets.sh
# Exit: 0 all pass; 1 any failure. Each assertion prints PASS/FAIL.
set -eu

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SPEC="$REPO/packaging/rpm/osslscope.spec"
POSTINST="$REPO/packaging/deb/DEBIAN/postinst"
PRERM="$REPO/packaging/deb/DEBIAN/prerm"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }

# Absolute shell path: PATH-prefixed runs (missing-setcap simulation) must
# still resolve the interpreter itself.
SH_BIN="$(command -v sh)"

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT INT TERM

# --- stub setcap: logs argv, exit code controlled by STUB_SETCAP_EXIT ---
mkdir -p "$T/stubbin"
cat >"$T/stubbin/setcap" <<'EOF'
#!/bin/sh
echo "$*" >>"$SETCAP_LOG"
exit "${STUB_SETCAP_EXIT:-0}"
EOF
chmod +x "$T/stubbin/setcap"
export SETCAP_LOG="$T/setcap.log"

# Extract one %section body from the spec into a runnable sh file.
extract_spec_section() {
    # $1 = section name (post|preun|posttrans), $2 = output file
    awk -v want="$1" '
        /^%posttrans/ { sec=($0=="%posttrans")?"posttrans":""; next }
        /^%post$/     { sec=(want=="post")?"post":""; next }
        /^%preun/     { sec=(want=="preun")?"preun":""; next }
        /^%/          { sec=""; next }
        sec==want     { print }
    ' want="$1" "$SPEC" >"$2"
    [ -s "$2" ] || { echo "spec section %$1 missing or empty" >&2; rm -f "$2"; return 1; }
}

run_with_stub() {
    # $1.. = command; runs with stub setcap first on PATH
    : >"$SETCAP_LOG"
    STUB_SETCAP_EXIT="${STUB_SETCAP_EXIT:-0}" PATH="$T/stubbin:$PATH" "$@"
}

# ============ static spec checks ============
if grep -q '^%posttrans' "$SPEC"; then
    ok "spec has %posttrans (final-transaction cap restoration)"
else
    bad "spec has %posttrans (final-transaction cap restoration)"
fi

if awk '/^%preun/{f=1} f&&/\$1.*-eq 0/{g=1} /^(%files|%changelog|%posttrans)/{f=0} END{exit !g}' "$SPEC"; then
    ok "spec %preun is guarded by \$1 -eq 0 (erase-only)"
else
    bad "spec %preun is guarded by \$1 -eq 0 (erase-only)"
fi

if grep -q '^Release:.*pkg_release' "$SPEC"; then
    ok "spec Release honors pkg_release override (upgrade-path testing)"
else
    bad "spec Release honors pkg_release override (upgrade-path testing)"
fi

# ============ build script static checks (no rpmbuild/dpkg-deb needed) ============
for s in "$REPO/packaging/build-deb.sh" "$REPO/packaging/build-rpm.sh" \
         "$REPO/packaging/deb/DEBIAN/postinst" "$REPO/packaging/deb/DEBIAN/prerm"; do
    if sh -n "$s" 2>"$T/err"; then
        ok "sh -n passes: ${s#$REPO/}"
    else
        bad "sh -n passes: ${s#$REPO/} ($(cat "$T/err"))"
    fi
done

if grep -q 'pkg_release' "$REPO/packaging/build-rpm.sh" \
   && grep -q 'RPM_RELEASE' "$REPO/packaging/build-rpm.sh"; then
    ok "build-rpm.sh threads RPM_RELEASE into pkg_release define"
else
    bad "build-rpm.sh threads RPM_RELEASE into pkg_release define"
fi

# The result glob must pin the built release: a shared RPMS dir holding an
# older release would otherwise make a first-match `-*` glob return the
# stale rpm and turn an upgrade witness into a no-op.
if grep -q 'osslscope-"\$ver"-"\$release"\.' "$REPO/packaging/build-rpm.sh"; then
    ok "build-rpm.sh result glob pins the built release"
else
    bad "build-rpm.sh result glob pins the built release"
fi

# Simulate the control.in substitution build-deb.sh performs.
if sed -e "s/@VERSION@/9.9.9/" -e "s/@REVISION@/2/" \
        "$REPO/packaging/deb/DEBIAN/control.in" >"$T/control" \
   && grep -q '^Version: 9.9.9-2$' "$T/control" \
   && ! grep -q '@VERSION@\|@REVISION@' "$T/control"; then
    ok "deb control.in substitutes version+revision with no leftover placeholders"
else
    bad "deb control.in substitutes version+revision with no leftover placeholders"
fi

# ============ deb matrix ============
: >"$SETCAP_LOG"
if run_with_stub sh "$POSTINST" configure 2>"$T/err"; then
    grep -q 'cap_bpf,cap_perfmon+ep /usr/bin/osslscope' "$SETCAP_LOG" \
        && ok "deb postinst configure applies caps" \
        || bad "deb postinst configure applies caps"
else
    bad "deb postinst configure exits 0 (got nonzero)"
fi

mkdir -p "$T/empty"
if PATH="$T/empty" "$SH_BIN" "$POSTINST" configure 2>"$T/err"; then
    if grep -q 'libcap2-bin' "$T/err" && grep -q 'labeled sudo' "$T/err"; then
        ok "deb postinst without setcap warns with libcap2-bin + labeled-sudo fallback, exit 0"
    else
        bad "deb postinst without setcap warns with libcap2-bin + labeled-sudo fallback, exit 0"
    fi
else
    bad "deb postinst without setcap still exits 0 (got nonzero)"
fi

: >"$SETCAP_LOG"
if run_with_stub sh "$PRERM" remove 2>"$T/err"; then
    grep -q 'setcap -r' "$SETCAP_LOG" 2>/dev/null || grep -q -- '-r /usr/bin/osslscope' "$SETCAP_LOG" \
        && ok "deb prerm remove clears caps" \
        || bad "deb prerm remove clears caps"
else
    bad "deb prerm remove exits 0 (got nonzero)"
fi

: >"$SETCAP_LOG"
if run_with_stub sh "$PRERM" upgrade 2>"$T/err"; then
    if [ ! -s "$SETCAP_LOG" ]; then
        ok "deb prerm upgrade leaves caps alone (no setcap call)"
    else
        bad "deb prerm upgrade leaves caps alone (saw: $(cat "$SETCAP_LOG"))"
    fi
else
    bad "deb prerm upgrade exits 0 (got nonzero)"
fi

# ============ rpm matrix (bodies extracted from spec) ============
extract_spec_section post "$T/rpm-post.sh" \
    && ok "spec %post extracts" || bad "spec %post extracts"
extract_spec_section preun "$T/rpm-preun.sh" \
    && ok "spec %preun extracts" || bad "spec %preun extracts"
if extract_spec_section posttrans "$T/rpm-posttrans.sh" 2>/dev/null; then
    ok "spec %posttrans extracts"
else
    bad "spec %posttrans extracts"
fi

if [ -f "$T/rpm-post.sh" ]; then
    : >"$SETCAP_LOG"
    if run_with_stub sh "$T/rpm-post.sh" 2>"$T/err"; then
        grep -q 'cap_bpf,cap_perfmon+ep /usr/bin/osslscope' "$SETCAP_LOG" \
            && ok "rpm %post applies caps" \
            || bad "rpm %post applies caps"
    else
        bad "rpm %post exits 0 (got nonzero)"
    fi
    if PATH="$T/empty" "$SH_BIN" "$T/rpm-post.sh" 2>"$T/err"; then
        if grep -q 'install libcap' "$T/err" && grep -q 'labeled sudo' "$T/err"; then
            ok "rpm %post without setcap warns with libcap + labeled-sudo fallback, exit 0"
        else
            bad "rpm %post without setcap warns with libcap + labeled-sudo fallback, exit 0"
        fi
    else
        bad "rpm %post without setcap still exits 0 (got nonzero)"
    fi
    if STUB_SETCAP_EXIT=1 run_with_stub sh "$T/rpm-post.sh" 2>"$T/err"; then
        grep -q 'setcap failed' "$T/err" \
            && ok "rpm %post with failing setcap warns, exit 0" \
            || bad "rpm %post with failing setcap warns, exit 0"
    else
        bad "rpm %post with failing setcap still exits 0 (got nonzero)"
    fi
fi

if [ -f "$T/rpm-preun.sh" ]; then
    : >"$SETCAP_LOG"
    if run_with_stub sh "$T/rpm-preun.sh" 0 2>"$T/err"; then
        grep -q -- '-r /usr/bin/osslscope' "$SETCAP_LOG" \
            && ok "rpm %preun \$1=0 (erase) clears caps" \
            || bad "rpm %preun \$1=0 (erase) clears caps"
    else
        bad "rpm %preun \$1=0 exits 0 (got nonzero)"
    fi
    : >"$SETCAP_LOG"
    if run_with_stub sh "$T/rpm-preun.sh" 1 2>"$T/err"; then
        if [ ! -s "$SETCAP_LOG" ]; then
            ok "rpm %preun \$1=1 (upgrade) leaves caps alone (no setcap call)"
        else
            bad "rpm %preun \$1=1 (upgrade) leaves caps alone (saw: $(cat "$SETCAP_LOG"))"
        fi
    else
        bad "rpm %preun \$1=1 exits 0 (got nonzero)"
    fi
fi

if [ -f "$T/rpm-posttrans.sh" ]; then
    touch "$T/fake-bin"
    : >"$SETCAP_LOG"
    if OSSLSCOPE_BIN="$T/fake-bin" run_with_stub sh "$T/rpm-posttrans.sh" 2>"$T/err"; then
        grep -q "cap_bpf,cap_perfmon+ep $T/fake-bin" "$SETCAP_LOG" \
            && ok "rpm %posttrans restores caps (upgrade-from-1.0.0 migration)" \
            || bad "rpm %posttrans restores caps (upgrade-from-1.0.0 migration)"
    else
        bad "rpm %posttrans exits 0 (got nonzero)"
    fi
    : >"$SETCAP_LOG"
    if OSSLSCOPE_BIN="$T/fake-bin" PATH="$T/empty" "$SH_BIN" "$T/rpm-posttrans.sh" 2>"$T/err"; then
        if grep -q 'labeled sudo' "$T/err"; then
            ok "rpm %posttrans without setcap warns with labeled-sudo fallback, exit 0"
        else
            bad "rpm %posttrans without setcap warns with labeled-sudo fallback, exit 0"
        fi
    else
        bad "rpm %posttrans without setcap still exits 0 (got nonzero)"
    fi
    : >"$SETCAP_LOG"
    if OSSLSCOPE_BIN="$T/does-not-exist" run_with_stub sh "$T/rpm-posttrans.sh" 2>"$T/err"; then
        if [ ! -s "$SETCAP_LOG" ]; then
            ok "rpm %posttrans with missing binary calls no setcap, exit 0"
        else
            bad "rpm %posttrans with missing binary calls no setcap (saw: $(cat "$SETCAP_LOG"))"
        fi
    else
        bad "rpm %posttrans with missing binary exits 0 (got nonzero)"
    fi
fi

echo "---"
echo "pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
