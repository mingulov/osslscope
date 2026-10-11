#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# lifecycle-assert.sh — install/upgrade identity assertions for the package
# lifecycle witness (F-G/Bm3). Function library: safe to source (no
# top-level side effects beyond defining functions). guest-lifecycle.sh
# sources it; packaging/tests/test-lifecycle-assert.sh exercises it with
# stubbed query commands. Failing assertions print a diagnosis and exit 1
# (callers run them in subshells when probing failure paths).
#
# Shared conventions: LOG is the main log (defaults to /dev/null when
# unset); OSSLSCOPE_BIN overrides the installed binary path (default
# /usr/bin/osslscope, same convention as the rpm spec).

# Installed package EVR or nothing: prints e.g. "1.0.0-2"; returns 1
# when the package is not installed. $1 = rpm|deb.
pkg_installed_evr() {
    if [ "$1" = "rpm" ]; then
        _evr="$(rpm -q --queryformat '%{VERSION}-%{RELEASE}\n' osslscope 2>/dev/null)" \
            || return 1
    else
        _evr="$(dpkg-query -W -f='${Version}\n' osslscope 2>/dev/null)" || return 1
    fi
    [ -n "$_evr" ] || return 1
    printf '%s\n' "$_evr"
}

# EVR of a package FILE (proves what was built, not what the tree
# claims): prints e.g. "1.0.0-2"; returns 1 on query failure.
# $1 = rpm|deb, $2 = package file.
pkg_file_evr() {
    if [ "$1" = "rpm" ]; then
        _evr="$(rpm -qp --queryformat '%{VERSION}-%{RELEASE}\n' "$2" 2>/dev/null)" \
            || return 1
    else
        _evr="$(dpkg-deb -f "$2" Version 2>/dev/null)" || return 1
    fi
    [ -n "$_evr" ] || return 1
    printf '%s\n' "$_evr"
}

# sha256 of the installed binary (pure shell field split, no awk).
bin_identity() {
    _h="$(sha256sum "${OSSLSCOPE_BIN:-/usr/bin/osslscope}" 2>/dev/null)" || return 1
    [ -n "$_h" ] || return 1
    printf '%s\n' "${_h%% *}"
}

# Precondition: nothing installed and no binary present. An already
# installed package (or stray binary) would turn install-old into a
# no-op that "passes" — refuse loudly instead of witnessing theater.
assert_initial_absent() {
    _bin="${OSSLSCOPE_BIN:-/usr/bin/osslscope}"
    if pkg_installed_evr "$1" >/dev/null 2>&1; then
        echo "lifecycle precondition FAILED: package osslscope already installed ($(pkg_installed_evr "$1")) — refusing a no-op witness" \
            | tee -a "${LOG:-/dev/null}" >&2
        exit 1
    fi
    if [ -e "$_bin" ]; then
        echo "lifecycle precondition FAILED: stray binary $_bin exists with no package — refusing" \
            | tee -a "${LOG:-/dev/null}" >&2
        exit 1
    fi
    echo "precondition: osslscope not installed, $_bin absent" | tee -a "${LOG:-/dev/null}" >&2
}

# Exact installed identity after a stage: $1 = stage label, $2 = pkg,
# $3 = expected EVR (taken from the built package file, never assumed).
assert_installed_evr() {
    _got="$(pkg_installed_evr "$2" || true)"
    if [ "$_got" != "$3" ]; then
        echo "[$1] installed EVR '${_got:-(none)}' != expected '$3' — lifecycle FAILED" \
            | tee -a "${LOG:-/dev/null}" >&2
        exit 1
    fi
    echo "[$1] installed EVR $_got" | tee -a "${LOG:-/dev/null}" >&2
}

# The OLD package must carry the removal scriptlet whose ordering is
# under test (rpm old %preun after new %post; deb old prerm). Without
# it the "upgrade" never exercises the intended path. $1 = pkg,
# $2 = old package file. Presence is asserted; guarded-vs-unguarded
# is recorded as evidence only (it depends on the old ref: the
# audited 1.0.0 line is unguarded by design, current trees guarded).
assert_old_scriptlet() {
    if [ "$1" = "rpm" ]; then
        _scripts="$(rpm -qp --scripts "$2" 2>/dev/null)" \
            || { echo "cannot read scriptlets from old package $2 — lifecycle FAILED" \
                | tee -a "${LOG:-/dev/null}" >&2; exit 1; }
        echo "$_scripts" | grep -q "preun" \
            || { echo "old package $2 has no %preun scriptlet — upgrade would not exercise the intended path — lifecycle FAILED" \
                | tee -a "${LOG:-/dev/null}" >&2; exit 1; }
        if echo "$_scripts" | grep -q 'eq 0'; then
            _kind="guarded (erase-only)"
        else
            _kind="unguarded (1.0.0-line, %posttrans must restore caps)"
        fi
        echo "old package %preun present: $_kind" | tee -a "${LOG:-/dev/null}" >&2
    else
        _members="$(dpkg-deb --ctrl-tarfile "$2" 2>/dev/null | tar -t 2>/dev/null)" \
            || { echo "cannot list control members of old package $2 — lifecycle FAILED" \
                | tee -a "${LOG:-/dev/null}" >&2; exit 1; }
        echo "$_members" | grep -q "prerm" \
            || { echo "old package $2 has no prerm script — upgrade would not exercise the intended path — lifecycle FAILED" \
                | tee -a "${LOG:-/dev/null}" >&2; exit 1; }
        echo "old package prerm present" | tee -a "${LOG:-/dev/null}" >&2
    fi
}
