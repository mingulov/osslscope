#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# guest-lifecycle.sh — privileged package lifecycle witness (PREPARED, NOT-RUN).
#
# Real install → reinstall → upgrade → removal lifecycle for the rpm or deb
# package on an approved guest, asserting ordinary-user file capabilities
# survive every step — in particular upgrade FROM a 1.0.0-line package whose
# old %preun runs unguarded (the %posttrans migration path).
#
# This script is NOT run on unprivileged hosts: without --execute it only
# prints the plan (dry run). Execution needs an approved guest with sudo,
# rpmbuild or dpkg-deb, the pinned Rust toolchain, and setcap/getcap.
# It is wired for the C4 `installed` suite / RPM-upgrade guest witness lane.
#
# Usage:
#   ./packaging/tests/guest-lifecycle.sh --pkg rpm|deb \
#       --old-ref REF --new-ref REF [--execute] [--workdir DIR]
#
# Exit codes: 0 all assertions held; 1 any failure; 2 usage; 3 missing
# prerequisite. Dry run always exits 0 after printing the plan.
set -eu

PKG=""
OLD_REF=""
NEW_REF=""
EXECUTE=0
WORKDIR=""

usage() {
    sed -n '2,20p' "$0"
    echo "Exit codes: 0 lifecycle held; 2 usage; 3 missing prerequisite; 1 assertion failure."
}

while [ $# -gt 0 ]; do
    case "$1" in
        --pkg) [ $# -ge 2 ] || { echo "error: --pkg needs rpm|deb" >&2; exit 2; }; PKG="$2"; shift 2 ;;
        --pkg=*) PKG="${1#--pkg=}"; shift ;;
        --old-ref) [ $# -ge 2 ] || { echo "error: --old-ref needs a ref" >&2; exit 2; }; OLD_REF="$2"; shift 2 ;;
        --old-ref=*) OLD_REF="${1#--old-ref=}"; shift ;;
        --new-ref) [ $# -ge 2 ] || { echo "error: --new-ref needs a ref" >&2; exit 2; }; NEW_REF="$2"; shift 2 ;;
        --new-ref=*) NEW_REF="${1#--new-ref=}"; shift ;;
        --workdir) [ $# -ge 2 ] || { echo "error: --workdir needs a dir" >&2; exit 2; }; WORKDIR="$2"; shift 2 ;;
        --workdir=*) WORKDIR="${1#--workdir=}"; shift ;;
        --execute) EXECUTE=1; shift ;;
        --dry-run) EXECUTE=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

case "$PKG" in
    rpm|deb) ;;
    *) echo "error: --pkg must be rpm or deb" >&2; exit 2 ;;
esac
[ -n "$OLD_REF" ] || { echo "error: --old-ref is required (e.g. the audited 1.0.0 ref)" >&2; exit 2; }
[ -n "$NEW_REF" ] || { echo "error: --new-ref is required (a clean committed revision)" >&2; exit 2; }
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
if [ -z "$WORKDIR" ]; then WORKDIR="$REPO/target/lifecycle-$PKG-$$"; fi

plan() {
    echo "lifecycle plan ($PKG): old=$OLD_REF new=$NEW_REF workdir=$WORKDIR"
    echo "  1. export both refs to isolated dirs; build a release binary in each"
    echo "  2. build old package (release/revision 1) and new package (release/revision 2)"
    echo "  3. install old; assert getcap shows cap_bpf+cap_perfmon; run doctor"
    echo "  4. upgrade old->new; assert caps SURVIVED (posttrans migration); run doctor"
    echo "  5. reinstall new; assert caps still present"
    echo "  6. remove; assert /usr/bin/osslscope is gone"
    echo "NOT-RUN without --execute on an approved guest."
}

if [ "$EXECUTE" -eq 0 ]; then
    plan
    echo "dry-run: no changes made."
    exit 0
fi

echo "EXECUTING privileged lifecycle on $(hostname) (kernel $(uname -r))"

fail_prereq() { echo "prerequisite missing: $1 ($2)" >&2; exit 3; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || fail_prereq "$1" "$2"; }
need_cmd git "a product checkout with both refs resolvable"
need_cmd cargo "pinned Rust 1.88.0 toolchain"
need_cmd setcap "libcap2-bin (deb) or libcap (rpm)"
need_cmd getcap "libcap2-bin (deb) or libcap (rpm)"
need_cmd sudo "passwordless or interactive sudo on the approved guest"
if [ "$PKG" = "rpm" ]; then
    need_cmd rpmbuild "rpm-build package"
    need_cmd dnf "dnf (or adapt install/upgrade/remove lines to yum/zypper)"
else
    need_cmd dpkg-deb "dpkg-dev package"
    need_cmd dpkg "dpkg"
    need_cmd apt-get "apt (dependency fix-up)"
fi
git -C "$REPO" rev-parse --verify "$OLD_REF^{commit}" >/dev/null 2>&1 \
    || { echo "error: old ref does not resolve: $OLD_REF" >&2; exit 2; }
git -C "$REPO" rev-parse --verify "$NEW_REF^{commit}" >/dev/null 2>&1 \
    || { echo "error: new ref does not resolve: $NEW_REF" >&2; exit 2; }

LOG="$WORKDIR/lifecycle.log"
mkdir -p "$WORKDIR"
echo "old=$OLD_REF new=$NEW_REF pkg=$PKG host=$(hostname) kernel=$(uname -r)" | tee "$LOG"

assert_caps() {
    # $1 = step label
    _caps="$(getcap /usr/bin/osslscope 2>/dev/null || true)"
    echo "[$1] getcap: ${_caps:-(none)}" | tee -a "$LOG"
    case "$_caps" in
        *cap_bpf*cap_perfmon*|*cap_perfmon*cap_bpf*) echo "[$1] caps PRESENT" | tee -a "$LOG" ;;
        *) echo "[$1] CAPS MISSING — lifecycle FAILED" | tee -a "$LOG"; exit 1 ;;
    esac
}

build_one() {
    # $1 = ref, $2 = tag (old|new), $3 = release/revision number; echoes pkg path
    _ref="$1"; _tag="$2"; _rel="$3"
    _dir="$WORKDIR/$_tag"
    mkdir -p "$_dir"
    git -C "$REPO" archive "$_ref" | tar -x -C "$_dir"
    (cd "$_dir" && CARGO_BUILD_JOBS=2 cargo +1.88.0 build --locked --release) 2>&1 | tail -2 | tee -a "$LOG"
    if [ "$PKG" = "rpm" ]; then
        (cd "$_dir" && RPM_RELEASE="$_rel" ./packaging/build-rpm.sh) 2>&1 | tee -a "$LOG" | tail -1
    else
        (cd "$_dir" && DEB_REVISION="$_rel" ./packaging/build-deb.sh) 2>&1 | tee -a "$LOG" | tail -1
    fi
}

echo "--- building old package (release 1) ---" | tee -a "$LOG"
OLD_PKG="$(build_one "$OLD_REF" old 1 | sed -n 's/^built //p' | tail -1)"
echo "old package: $OLD_PKG" | tee -a "$LOG"
[ -f "$OLD_PKG" ] || { echo "old package build produced no file" | tee -a "$LOG"; exit 1; }

echo "--- building new package (release 2) ---" | tee -a "$LOG"
NEW_PKG="$(build_one "$NEW_REF" new 2 | sed -n 's/^built //p' | tail -1)"
echo "new package: $NEW_PKG" | tee -a "$LOG"
[ -f "$NEW_PKG" ] || { echo "new package build produced no file" | tee -a "$LOG"; exit 1; }

if [ "$PKG" = "rpm" ]; then
    echo "--- install old ---" | tee -a "$LOG"
    sudo dnf install -y "$OLD_PKG" 2>&1 | tail -3 | tee -a "$LOG"
    assert_caps "install-old"
    osslscope doctor 2>&1 | tee -a "$LOG" | head -20 || true
    echo "--- upgrade old -> new ---" | tee -a "$LOG"
    sudo dnf upgrade -y "$NEW_PKG" 2>&1 | tail -3 | tee -a "$LOG"
    assert_caps "upgrade-new"
    osslscope doctor 2>&1 | tee -a "$LOG" | head -20 || true
    echo "--- reinstall new ---" | tee -a "$LOG"
    sudo dnf reinstall -y "$NEW_PKG" 2>&1 | tail -3 | tee -a "$LOG"
    assert_caps "reinstall-new"
    echo "--- remove ---" | tee -a "$LOG"
    sudo dnf remove -y osslscope 2>&1 | tail -3 | tee -a "$LOG"
else
    echo "--- install old ---" | tee -a "$LOG"
    sudo dpkg -i "$OLD_PKG" 2>&1 | tail -3 | tee -a "$LOG" || sudo apt-get install -f -y 2>&1 | tail -3 | tee -a "$LOG"
    assert_caps "install-old"
    osslscope doctor 2>&1 | tee -a "$LOG" | head -20 || true
    echo "--- upgrade old -> new ---" | tee -a "$LOG"
    sudo dpkg -i "$NEW_PKG" 2>&1 | tail -3 | tee -a "$LOG" || sudo apt-get install -f -y 2>&1 | tail -3 | tee -a "$LOG"
    assert_caps "upgrade-new"
    osslscope doctor 2>&1 | tee -a "$LOG" | head -20 || true
    echo "--- reinstall new ---" | tee -a "$LOG"
    sudo dpkg -i "$NEW_PKG" 2>&1 | tail -3 | tee -a "$LOG" || true
    assert_caps "reinstall-new"
    echo "--- remove ---" | tee -a "$LOG"
    sudo dpkg -P osslscope 2>&1 | tail -3 | tee -a "$LOG"
fi

if [ -e /usr/bin/osslscope ]; then
    echo "removal FAILED: /usr/bin/osslscope still exists" | tee -a "$LOG"; exit 1
fi
echo "lifecycle HELD: install/upgrade/reinstall kept caps; removal cleaned up." | tee -a "$LOG"
echo "log: $LOG"
