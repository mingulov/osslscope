#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# test-lifecycle-assert.sh — host-runnable tests for lifecycle-assert.sh
# (no root, no rpm/dpkg): stubs the package-query commands and exercises
# EVR parsing, absence detection, the initial-state gate, binary
# identity, and old-scriptlet presence.
#
# Usage: ./packaging/tests/test-lifecycle-assert.sh
# Exit: 0 all pass; 1 any failure. Each assertion prints PASS/FAIL.
set -eu

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
LIB="$REPO/packaging/tests/lifecycle-assert.sh"
WITNESS="$REPO/packaging/tests/guest-lifecycle.sh"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT INT TERM
export LOG="$T/lib.log"

command -v sha256sum >/dev/null 2>&1 || { echo "test prereq missing: sha256sum" >&2; exit 1; }

if sh -n "$LIB" 2>"$T/err" && sh -n "$WITNESS" 2>>"$T/err"; then
    ok "sh -n passes: lifecycle-assert.sh + guest-lifecycle.sh"
else
    bad "sh -n passes ($(cat "$T/err"))"
fi

# --- stub query farm (real sha256sum/grep/tee flow through PATH) ---
mkdir -p "$T/stubbin"
cat >"$T/stubbin/rpm" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "-q" ]; then
    if [ -n "${STUB_RPM_INSTALLED:-}" ]; then printf '%s\n' "$STUB_RPM_INSTALLED"; exit 0; else exit 1; fi
fi
if [ "${1:-}" = "-qp" ]; then
    case "$*" in *--scripts*)
        if [ -f "${STUB_RPM_SCRIPTS_FILE:-/nonexistent}" ]; then cat "$STUB_RPM_SCRIPTS_FILE"; exit 0; else exit 1; fi ;;
    esac
    if [ -n "${STUB_RPM_FILEVER:-}" ]; then printf '%s\n' "$STUB_RPM_FILEVER"; exit 0; else exit 1; fi
fi
exit 1
EOF
cat >"$T/stubbin/dpkg-query" <<'EOF'
#!/bin/sh
if [ -n "${STUB_DEB_INSTALLED:-}" ]; then printf '%s\n' "$STUB_DEB_INSTALLED"; exit 0; else exit 1; fi
EOF
cat >"$T/stubbin/dpkg-deb" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "-f" ]; then
    if [ -n "${STUB_DEB_FILEVER:-}" ]; then printf '%s\n' "$STUB_DEB_FILEVER"; exit 0; else exit 1; fi
fi
if [ "${1:-}" = "--ctrl-tarfile" ]; then
    if [ -f "${STUB_CTRL_LIST_FILE:-/nonexistent}" ]; then cat "$STUB_CTRL_LIST_FILE"; exit 0; else exit 1; fi
fi
exit 1
EOF
# tar stands in for `tar -t` listing control members: the stub dpkg-deb
# above already emits member names, so passthrough is the faithful shape.
cat >"$T/stubbin/tar" <<'EOF'
#!/bin/sh
cat
EOF
chmod +x "$T/stubbin/rpm" "$T/stubbin/dpkg-query" "$T/stubbin/dpkg-deb" "$T/stubbin/tar"
export PATH="$T/stubbin:$PATH"

# shellcheck source=./lifecycle-assert.sh
. "$LIB"

# --- EVR queries ---
if [ "$(STUB_RPM_INSTALLED="1.0.0-2" pkg_installed_evr rpm)" = "1.0.0-2" ]; then
    ok "rpm installed EVR parsed"
else
    bad "rpm installed EVR parsed"
fi
if pkg_installed_evr rpm >/dev/null 2>&1; then
    bad "rpm absent reports rc 1 (got EVR)"
else
    ok "rpm absent reports rc 1"
fi
if [ "$(STUB_DEB_INSTALLED="1.0.0-1" pkg_installed_evr deb)" = "1.0.0-1" ]; then
    ok "deb installed EVR parsed"
else
    bad "deb installed EVR parsed"
fi
if [ "$(STUB_RPM_FILEVER="1.0.0-1" pkg_file_evr rpm "$T/old.rpm")" = "1.0.0-1" ]; then
    ok "rpm file EVR parsed"
else
    bad "rpm file EVR parsed"
fi
if pkg_file_evr rpm "$T/old.rpm" >/dev/null 2>&1; then
    bad "rpm file query failure reports rc 1 (got EVR)"
else
    ok "rpm file query failure reports rc 1"
fi
if [ "$(STUB_DEB_FILEVER="2.1.0-3" pkg_file_evr deb "$T/new.deb")" = "2.1.0-3" ]; then
    ok "deb file EVR parsed"
else
    bad "deb file EVR parsed"
fi

# --- installed-EVR gate ---
if ( STUB_RPM_INSTALLED="1.0.0-1" assert_installed_evr "install-old" rpm "1.0.0-1" ) >/dev/null 2>&1; then
    ok "matching installed EVR accepted"
else
    bad "matching installed EVR accepted"
fi
if ( STUB_RPM_INSTALLED="1.0.0-9" assert_installed_evr "upgrade-new" rpm "1.0.0-2" ) >/dev/null 2>&1; then
    bad "mismatched installed EVR rejected (got rc 0)"
else
    ok "mismatched installed EVR rejected"
fi
if ( assert_installed_evr "upgrade-new" deb "1.0.0-2" ) >/dev/null 2>&1; then
    bad "absent package vs expected EVR rejected (got rc 0)"
else
    ok "absent package vs expected EVR rejected"
fi

# --- initial-state gate ---
if ( OSSLSCOPE_BIN="$T/no-such-binary" assert_initial_absent deb ) >/dev/null 2>&1; then
    ok "clean initial state accepted"
else
    bad "clean initial state accepted"
fi
if ( STUB_DEB_INSTALLED="1.0.0-1" OSSLSCOPE_BIN="$T/no-such-binary" assert_initial_absent deb ) >/dev/null 2>&1; then
    bad "already-installed initial state rejected (got rc 0)"
else
    ok "already-installed initial state rejected"
fi
touch "$T/stray-bin"
if ( OSSLSCOPE_BIN="$T/stray-bin" assert_initial_absent rpm ) >/dev/null 2>&1; then
    bad "stray-binary initial state rejected (got rc 0)"
else
    ok "stray-binary initial state rejected"
fi

# --- binary identity ---
printf 'fake-binary-bytes' >"$T/fake-bin"
_want="$(sha256sum "$T/fake-bin")"; _want="${_want%% *}"
if [ "$(OSSLSCOPE_BIN="$T/fake-bin" bin_identity)" = "$_want" ]; then
    ok "binary identity is the sha256 of the installed path"
else
    bad "binary identity is the sha256 of the installed path"
fi
if OSSLSCOPE_BIN="$T/no-such-binary" bin_identity >/dev/null 2>&1; then
    bad "missing binary reports rc 1 (got hash)"
else
    ok "missing binary reports rc 1"
fi

# --- old scriptlet presence ---
cat >"$T/scripts-guarded.txt" <<'EOF'
preuninstall scriptlet (using /bin/sh):
if [ "$1" -eq 0 ]; then
  setcap -r /usr/bin/osslscope 2>/dev/null || true
fi
posttrans scriptlet (using /bin/sh):
setcap cap_bpf,cap_perfmon+ep /usr/bin/osslscope
EOF
cat >"$T/scripts-unguarded.txt" <<'EOF'
preuninstall scriptlet (using /bin/sh):
setcap -r /usr/bin/osslscope 2>/dev/null || true
EOF
: >"$T/lib.log"
if ( STUB_RPM_SCRIPTS_FILE="$T/scripts-guarded.txt" assert_old_scriptlet rpm "$T/old.rpm" ) >/dev/null 2>&1 \
   && grep -q "guarded" "$T/lib.log"; then
    ok "old rpm %preun presence asserted, guarded variant logged"
else
    bad "old rpm %preun presence asserted, guarded variant logged"
fi
: >"$T/lib.log"
if ( STUB_RPM_SCRIPTS_FILE="$T/scripts-unguarded.txt" assert_old_scriptlet rpm "$T/old.rpm" ) >/dev/null 2>&1 \
   && grep -q "unguarded" "$T/lib.log"; then
    ok "old rpm %preun presence asserted, unguarded variant logged"
else
    bad "old rpm %preun presence asserted, unguarded variant logged"
fi
printf 'posttrans scriptlet (using /bin/sh):\nsetcap x\n' >"$T/scripts-no-preun.txt"
if ( STUB_RPM_SCRIPTS_FILE="$T/scripts-no-preun.txt" assert_old_scriptlet rpm "$T/old.rpm" ) >/dev/null 2>&1; then
    bad "old rpm without %preun rejected (got rc 0)"
else
    ok "old rpm without %preun rejected"
fi
if ( assert_old_scriptlet rpm "$T/old.rpm" ) >/dev/null 2>&1; then
    bad "old rpm scriptlet query failure rejected (got rc 0)"
else
    ok "old rpm scriptlet query failure rejected"
fi
printf 'control\n./prerm\n./postinst\n' >"$T/ctrl-with-prerm.txt"
if ( STUB_CTRL_LIST_FILE="$T/ctrl-with-prerm.txt" assert_old_scriptlet deb "$T/old.deb" ) >/dev/null 2>&1; then
    ok "old deb prerm presence asserted (./-prefixed members)"
else
    bad "old deb prerm presence asserted (./-prefixed members)"
fi
printf 'control\n./postinst\n' >"$T/ctrl-no-prerm.txt"
if ( STUB_CTRL_LIST_FILE="$T/ctrl-no-prerm.txt" assert_old_scriptlet deb "$T/old.deb" ) >/dev/null 2>&1; then
    bad "old deb without prerm rejected (got rc 0)"
else
    ok "old deb without prerm rejected"
fi

echo "---"
echo "pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
