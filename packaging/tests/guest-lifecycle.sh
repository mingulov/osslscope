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
# shellcheck source=./lifecycle-assert.sh
. "$(dirname "$0")/lifecycle-assert.sh"

plan() {
    echo "lifecycle plan ($PKG): old=$OLD_REF new=$NEW_REF workdir=$WORKDIR"
    echo "  0. precondition: osslscope NOT installed and no stray binary (no-op witnesses refused)"
    echo "  1. export both refs to isolated dirs; build a release binary in each"
    echo "  2. build old package (release/revision 1) and new package (release/revision 2);"
    echo "     assert distinct package EVRs and old removal-scriptlet presence"
    echo "  3. install old; assert exact old EVR + binary identity; caps; doctor"
    echo "  4. upgrade old->new; assert exact new EVR + changed binary identity (bytes transitioned); caps; doctor"
    echo "  5. reinstall new; assert EVR + binary identity stable; caps"
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
need_cmd sha256sum "coreutils (binary identity assertions)"
need_cmd tar "tar (control-member listing)"
if [ "$PKG" = "rpm" ]; then
    need_cmd rpmbuild "rpm-build package"
    need_cmd rpm "rpm (installed-version assertions)"
    need_cmd dnf "dnf (or adapt install/upgrade/remove lines to yum/zypper)"
else
    need_cmd dpkg-deb "dpkg-dev package"
    need_cmd dpkg "dpkg"
    need_cmd dpkg-query "dpkg (installed-version assertions)"
    need_cmd apt-get "apt (dependency fix-up)"
fi
git -C "$REPO" rev-parse --verify "$OLD_REF^{commit}" >/dev/null 2>&1 \
    || { echo "error: old ref does not resolve: $OLD_REF" >&2; exit 2; }
git -C "$REPO" rev-parse --verify "$NEW_REF^{commit}" >/dev/null 2>&1 \
    || { echo "error: new ref does not resolve: $NEW_REF" >&2; exit 2; }

LOG="$WORKDIR/lifecycle.log"
mkdir -p "$WORKDIR"
echo "old=$OLD_REF new=$NEW_REF pkg=$PKG host=$(hostname) kernel=$(uname -r)" | tee "$LOG"

run_step() {
    # $1 = tag, $@ = command. Runs without pipelines so no exit code is
    # masked (dash has no pipefail); step output lands in its own log plus
    # the main log. Any failure aborts the lifecycle: a HELD verdict must
    # never follow a failed step.
    _tag="$1"; shift
    _sl="$WORKDIR/step-$_tag.log"
    # Progress goes to stderr: build_one runs inside $(...) where stdout is
    # the captured package path.
    echo "--- step $_tag: $*" | tee -a "$LOG" >&2
    if "$@" >"$_sl" 2>&1; then
        tail -3 "$_sl" | tee -a "$LOG" >&2
    else
        _rc=$?
        cat "$_sl" | tee -a "$LOG" >&2
        echo "step $_tag FAILED (exit $_rc) — lifecycle FAILED" | tee -a "$LOG" >&2
        exit 1
    fi
}

run_doctor() {
    # $1 = tag. Records doctor output; a doctor crash fails the
    # lifecycle. Exit 4 is the orderly FAIL-CLOSED verdict (expected
    # here: packages never ship BPF objects, so objects rows fail) and
    # is recorded for the lane reviewer, not treated as a crash.
    _tag="$1"
    _rc=0
    osslscope doctor >"$WORKDIR/doctor-$_tag.log" 2>&1 || _rc=$?
    case "$_rc" in
        0|4) ;;
        *) echo "doctor crashed after $_tag (exit $_rc) — lifecycle FAILED" | tee -a "$LOG" >&2
           cat "$WORKDIR/doctor-$_tag.log" | tee -a "$LOG" >&2
           exit 1 ;;
    esac
    grep -h "verdict:" "$WORKDIR/doctor-$_tag.log" | tee -a "$LOG" >&2
    head -20 "$WORKDIR/doctor-$_tag.log" | tee -a "$LOG" >&2
}

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
    # $1 = ref, $2 = tag (old|new), $3 = release/revision number; echoes the
    # ABSOLUTE package path. No pipelines on decisive commands: each stage
    # writes its own log file and its exit code is checked directly.
    _ref="$1"; _tag="$2"; _rel="$3"
    _dir="$WORKDIR/$_tag"
    mkdir -p "$_dir"
    git -C "$REPO" archive "$_ref" >"$WORKDIR/archive-$_tag.tar" || exit 1
    tar -x -f "$WORKDIR/archive-$_tag.tar" -C "$_dir" || exit 1
    (cd "$_dir" && CARGO_BUILD_JOBS=2 run_step "cargo-$_tag" cargo +1.88.0 build --locked --release) || exit 1
    if [ "$PKG" = "rpm" ]; then
        (cd "$_dir" && RPM_RELEASE="$_rel" run_step "pkg-$_tag" ./packaging/build-rpm.sh) || exit 1
        _built="$(sed -n 's/^built //p' "$WORKDIR/step-pkg-$_tag.log" | tail -1)"
        printf '%s\n' "$_built"
    else
        (cd "$_dir" && DEB_REVISION="$_rel" run_step "pkg-$_tag" ./packaging/build-deb.sh) || exit 1
        _built="$(sed -n 's/^built //p' "$WORKDIR/step-pkg-$_tag.log" | tail -1)"
        # build-deb.sh reports a path relative to the export dir; absolutize
        # before returning (callers check from the original directory).
        case "$_built" in
            /*) printf '%s\n' "$_built" ;;
            *) printf '%s\n' "$_dir/$_built" ;;
        esac
    fi
}

deb_install() {
    # $1 = tag, $2 = pkg. dpkg install with dependency fix-up; fails closed
    # when the package is not installed afterwards.
    _tag="$1"; _pkg="$2"
    # shellcheck disable=SC2024 # log dir is user-owned by design; only dpkg runs privileged
    if sudo dpkg -i "$_pkg" >"$WORKDIR/step-$_tag.log" 2>&1; then
        tail -3 "$WORKDIR/step-$_tag.log" | tee -a "$LOG" >&2
    else
        tail -5 "$WORKDIR/step-$_tag.log" | tee -a "$LOG" >&2
        echo "dpkg failed; attempting dependency fix-up" | tee -a "$LOG" >&2
        run_step "$_tag-deps" sudo apt-get install -f -y
    fi
    dpkg -s osslscope >/dev/null 2>&1 \
        || { echo "package osslscope not installed after $_tag — lifecycle FAILED" | tee -a "$LOG" >&2; exit 1; }
}

assert_initial_absent "$PKG"

echo "--- building old package (release 1) ---" | tee -a "$LOG"
OLD_PKG="$(build_one "$OLD_REF" old 1)"
echo "old package: $OLD_PKG" | tee -a "$LOG"
[ -f "$OLD_PKG" ] || { echo "old package build produced no file" | tee -a "$LOG"; exit 1; }

echo "--- building new package (release 2) ---" | tee -a "$LOG"
NEW_PKG="$(build_one "$NEW_REF" new 2)"
echo "new package: $NEW_PKG" | tee -a "$LOG"
[ -f "$NEW_PKG" ] || { echo "new package build produced no file" | tee -a "$LOG"; exit 1; }

# F-G/Bm3: identities come from the built files, never assumed. An
# old==new EVR would make the "upgrade" theater — refuse it here.
OLD_EVR="$(pkg_file_evr "$PKG" "$OLD_PKG")" \
    || { echo "cannot read old package EVR — lifecycle FAILED" | tee -a "$LOG" >&2; exit 1; }
NEW_EVR="$(pkg_file_evr "$PKG" "$NEW_PKG")" \
    || { echo "cannot read new package EVR — lifecycle FAILED" | tee -a "$LOG" >&2; exit 1; }
echo "old EVR: $OLD_EVR; new EVR: $NEW_EVR" | tee -a "$LOG"
[ "$OLD_EVR" != "$NEW_EVR" ] \
    || { echo "old and new packages share EVR $OLD_EVR — upgrade would be a no-op — lifecycle FAILED" | tee -a "$LOG" >&2; exit 1; }
assert_old_scriptlet "$PKG" "$OLD_PKG"

if [ "$PKG" = "rpm" ]; then
    run_step "install-old" sudo dnf install -y "$OLD_PKG"
    assert_installed_evr "install-old" "$PKG" "$OLD_EVR"
    HASH_OLD="$(bin_identity)" \
        || { echo "cannot hash installed binary after install-old — lifecycle FAILED" | tee -a "$LOG" >&2; exit 1; }
    echo "[install-old] binary sha256 $HASH_OLD" | tee -a "$LOG"
    assert_caps "install-old"
    run_doctor "install-old"
    run_step "upgrade-new" sudo dnf upgrade -y "$NEW_PKG"
    assert_installed_evr "upgrade-new" "$PKG" "$NEW_EVR"
    HASH_NEW="$(bin_identity)" \
        || { echo "cannot hash installed binary after upgrade-new — lifecycle FAILED" | tee -a "$LOG" >&2; exit 1; }
    echo "[upgrade-new] binary sha256 $HASH_NEW" | tee -a "$LOG"
    [ "$HASH_OLD" != "$HASH_NEW" ] \
        || { echo "installed bytes never transitioned old->new (identical sha256) — lifecycle FAILED" | tee -a "$LOG" >&2; exit 1; }
    assert_caps "upgrade-new"
    run_doctor "upgrade-new"
    run_step "reinstall-new" sudo dnf reinstall -y "$NEW_PKG"
    assert_installed_evr "reinstall-new" "$PKG" "$NEW_EVR"
    HASH_RE="$(bin_identity)" \
        || { echo "cannot hash installed binary after reinstall-new — lifecycle FAILED" | tee -a "$LOG" >&2; exit 1; }
    [ "$HASH_RE" = "$HASH_NEW" ] \
        || { echo "binary identity changed across reinstall ($HASH_NEW -> $HASH_RE) — lifecycle FAILED" | tee -a "$LOG" >&2; exit 1; }
    assert_caps "reinstall-new"
    run_step "remove" sudo dnf remove -y osslscope
else
    deb_install "install-old" "$OLD_PKG"
    assert_installed_evr "install-old" "$PKG" "$OLD_EVR"
    HASH_OLD="$(bin_identity)" \
        || { echo "cannot hash installed binary after install-old — lifecycle FAILED" | tee -a "$LOG" >&2; exit 1; }
    echo "[install-old] binary sha256 $HASH_OLD" | tee -a "$LOG"
    assert_caps "install-old"
    run_doctor "install-old"
    deb_install "upgrade-new" "$NEW_PKG"
    assert_installed_evr "upgrade-new" "$PKG" "$NEW_EVR"
    HASH_NEW="$(bin_identity)" \
        || { echo "cannot hash installed binary after upgrade-new — lifecycle FAILED" | tee -a "$LOG" >&2; exit 1; }
    echo "[upgrade-new] binary sha256 $HASH_NEW" | tee -a "$LOG"
    [ "$HASH_OLD" != "$HASH_NEW" ] \
        || { echo "installed bytes never transitioned old->new (identical sha256) — lifecycle FAILED" | tee -a "$LOG" >&2; exit 1; }
    assert_caps "upgrade-new"
    run_doctor "upgrade-new"
    deb_install "reinstall-new" "$NEW_PKG"
    assert_installed_evr "reinstall-new" "$PKG" "$NEW_EVR"
    HASH_RE="$(bin_identity)" \
        || { echo "cannot hash installed binary after reinstall-new — lifecycle FAILED" | tee -a "$LOG" >&2; exit 1; }
    [ "$HASH_RE" = "$HASH_NEW" ] \
        || { echo "binary identity changed across reinstall ($HASH_NEW -> $HASH_RE) — lifecycle FAILED" | tee -a "$LOG" >&2; exit 1; }
    assert_caps "reinstall-new"
    run_step "remove" sudo dpkg -P osslscope
fi

if [ -e /usr/bin/osslscope ]; then
    echo "removal FAILED: /usr/bin/osslscope still exists" | tee -a "$LOG"; exit 1
fi
echo "lifecycle HELD: exact old->new EVR + binary transition with caps kept; removal cleaned up." | tee -a "$LOG"
echo "log: $LOG"
