#!/bin/sh
# build-dev.sh — reproducible host + BPF development build entrypoint (R09/T05).
#
# Builds the host workspace with the pinned stable toolchain and the BPF
# objects (harvest, count, members, provider observation) with the pinned nightly toolchain,
# then writes a JSON manifest carrying toolchain versions and artifact
# (version/object) identity.
#
# Rules, not suggestions:
#   - No auto-install: a missing prerequisite fails with a diagnosis and a
#     manual install hint. This script never runs apt/dnf/rustup/cargo-install.
#   - No upgrades: pinned toolchains only. Warnings (including the known
#     bpf-linker/LLVM dlopen fallback warning) are diagnosed and recorded,
#     never "fixed" by moving the toolchain.
#   - Default pinned sysroots: ambient Rust flags and unstable host-source
#     configuration are normalized; compatible Cargo cache wrappers remain.
#   - Locked dependencies only: every cargo invocation passes --locked.
#   - Bounded jobs: CARGO_BUILD_JOBS defaults to 2; an explicit setting is
#     honored and recorded in the manifest.
#   - Per-invocation capture dirs: cargo logs live under
#     target/.cargo-log-<utc>-<pid>/ (kept for diagnosis; target/ stays
#     ignored and routinely cleaned, so no explicit rotation).
#
# Usage:
#   scripts/build-dev.sh [--host-only|--bpf-only] [--offline|--online]
#                        [--identity-v2-inputs FILE --identity-v2-dir DIR]
#                        [--release] [--manifest PATH] [--jobs N] [--check-only]
#
# Exit codes: 0 ok; 2 usage error; 3 missing prerequisite (environment);
# 1 build failure. A prerequisite failure is an environment condition,
# not a product regression.
#
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

HOST_TOOLCHAIN="1.88.0"
BPF_TOOLCHAIN="nightly-2026-05-20"
BPF_LINKER_PIN="0.10.4"
BPF_BINS="osslscope-harvest osslscope-count osslscope-members osslscope-provider-observation osslscope-focused-count"
BPF_TARGET="bpfel-unknown-none"

MODE="both"        # both | host | bpf
NET="auto"         # auto | offline | online
PROFILE="dev"      # dev (host) — BPF always builds --release
MANIFEST=""        # default: <repo>/target/dev-build-manifest.json
JOBS="${CARGO_BUILD_JOBS:-2}"
CHECK_ONLY=0
IDENTITY_INPUTS=""
IDENTITY_DIR=""

usage() {
    sed -n '2,20p' "$0"
    echo "Exit codes: 0 ok; 2 usage; 3 missing prerequisite; 1 build failure."
}

while [ $# -gt 0 ]; do
    case "$1" in
        --identity-v2-inputs) [ $# -ge 2 ] || { echo "error: --identity-v2-inputs needs FILE" >&2; exit 2; }; IDENTITY_INPUTS="$2"; shift 2 ;;
        --identity-v2-dir) [ $# -ge 2 ] || { echo "error: --identity-v2-dir needs DIR" >&2; exit 2; }; IDENTITY_DIR="$2"; shift 2 ;;
        --host-only) MODE="host"; shift ;;
        --bpf-only) MODE="bpf"; shift ;;
        --offline) NET="offline"; shift ;;
        --online) NET="online"; shift ;;
        --release) PROFILE="release"; shift ;;
        --manifest) [ $# -ge 2 ] || { echo "error: --manifest needs a path" >&2; exit 2; }; MANIFEST="$2"; shift 2 ;;
        --manifest=*) MANIFEST="${1#--manifest=}"; shift ;;
        --jobs) [ $# -ge 2 ] || { echo "error: --jobs needs a number" >&2; exit 2; }; JOBS="$2"; shift 2 ;;
        --jobs=*) JOBS="${1#--jobs=}"; shift ;;
        --check-only) CHECK_ONLY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [ -n "$IDENTITY_INPUTS" ] || [ -n "$IDENTITY_DIR" ]; then
    [ -n "$IDENTITY_INPUTS" ] && [ -n "$IDENTITY_DIR" ] && [ "$MODE" = "both" ] || { echo "error: identity v2 requires both --identity-v2-inputs FILE and --identity-v2-dir DIR in full mode" >&2; exit 2; }
    [ -f "$IDENTITY_INPUTS" ] || { echo "error: identity v2 inputs absent" >&2; exit 2; }
    IDENTITY_INPUTS="$(cd "$(dirname "$IDENTITY_INPUTS")" && pwd)/$(basename "$IDENTITY_INPUTS")"
    mkdir -p "$IDENTITY_DIR"
    IDENTITY_DIR="$(cd "$IDENTITY_DIR" && pwd)"
    [ ! -e "$IDENTITY_DIR/dev-admission.json" ] || { echo "error: use a fresh identity v2 output directory" >&2; exit 2; }
    unset OSSL_PACKAGE_RECORD_DIR
fi

case "$JOBS" in
    ''|*[!0-9]*) echo "error: --jobs must be a positive integer, got: $JOBS" >&2; exit 2 ;;
esac
if [ "$JOBS" -lt 1 ]; then echo "error: --jobs must be >= 1" >&2; exit 2; fi
export CARGO_BUILD_JOBS="$JOBS"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
if [ -z "$MANIFEST" ]; then MANIFEST="$REPO/target/dev-build-manifest.json"; fi

fail_prereq() {
    echo "prerequisite missing: $1" >&2
    echo "hint: $2" >&2
    echo "This script does not install anything; resolve the above and re-run." >&2
    exit 3
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail_prereq "command '$1' not found on PATH" "$2"
}

# Resolve the pinned executable once and use it both for direct source/version
# queries and every Cargo operation. Preserve ordinary Cargo cache wrappers;
# compiler selection itself is owned by this pinned build recipe.
resolve_pinned_rustc() {
    _resolved_rustc="$(rustup which --toolchain "$1" rustc)" || return 1
    case "$_resolved_rustc" in /*) ;; *) return 1 ;; esac
    [ -f "$_resolved_rustc" ] && [ -x "$_resolved_rustc" ] || return 1
    printf '%s\n' "$_resolved_rustc"
}
run_pinned_cargo() {
    _cargo_pin="$1"; shift
    case "$_cargo_pin" in
        "$HOST_TOOLCHAIN") _cargo_rustc="$HOST_RUSTC_PATH" ;;
        "$BPF_TOOLCHAIN") _cargo_rustc="$BPF_RUSTC_PATH" ;;
        *) echo "error: unsupported pinned Cargo toolchain" >&2; return 2 ;;
    esac
    # A fixed default sysroot is part of this recipe. An explicitly present
    # empty encoded flag set overrides ambient build/target flags, while the
    # scalar config overrides disable separate host-table flag selection.
    # The blanking is load-bearing, not hygiene: ambient RUSTFLAGS leak
    # into every cargo invocation, so `-C target-cpu=native` breaks the
    # bpfel link (host CPU features reach bpf-linker) and `--sysroot ALT`
    # silently redirects compilation while the manifest still binds the
    # pinned source identity. Custom Rust flags are outside this pinned
    # recipe; see docs/build.md. Proof:
    # scripts/tests/test-runtime-source-binding.py
    # (test_environment_build_and_target_flags_cannot_redirect_source).
    RUSTC="$_cargo_rustc" CARGO_BUILD_RUSTC="$_cargo_rustc" \
        CARGO_ENCODED_RUSTFLAGS='' RUSTFLAGS='' \
        CARGO_UNSTABLE_HOST_CONFIG=false CARGO_UNSTABLE_TARGET_APPLIES_TO_HOST=false \
        cargo +"$_cargo_pin" --config unstable.host-config=false \
        --config unstable.target-applies-to-host=false "$@"
}

# --- prerequisite checks (diagnose, never install) ---
need_cmd cargo "install the Rust toolchain via rustup (pinned: $HOST_TOOLCHAIN + $BPF_TOOLCHAIN), then re-run"
need_cmd rustc "install the Rust toolchain via rustup, then re-run"
need_cmd rustup "install rustup and the pinned toolchains, then re-run"
need_cmd python3 "install python3 (used for source inventory and JSON manifests), then re-run"
need_cmd sha256sum "install coreutils, then re-run"

HOST_RUSTC_PATH="$(resolve_pinned_rustc "$HOST_TOOLCHAIN")" \
    || fail_prereq "cannot resolve pinned host rustc" "install the pinned $HOST_TOOLCHAIN toolchain"
HOST_CARGO_VER="$(run_pinned_cargo "$HOST_TOOLCHAIN" --version 2>/dev/null)" \
    || fail_prereq "cargo +$HOST_TOOLCHAIN unavailable" "rustup toolchain install $HOST_TOOLCHAIN --profile minimal"
HOST_RUSTC_VER="$("$HOST_RUSTC_PATH" --version 2>/dev/null)" \
    || fail_prereq "rustc +$HOST_TOOLCHAIN unavailable" "rustup toolchain install $HOST_TOOLCHAIN --profile minimal"
case "$HOST_RUSTC_VER" in
    "rustc 1.88.0 "*) ;;
    *) echo "warning: host rustc is not the pinned 1.88.0: $HOST_RUSTC_VER" >&2 ;;
esac

BPF_CARGO_VER=""
BPF_RUSTC_VER=""
BPF_LINKER_VER=""
BPF_RUSTC_PATH=""
if [ "$MODE" != "host" ]; then
    BPF_RUSTC_PATH="$(resolve_pinned_rustc "$BPF_TOOLCHAIN")" \
        || fail_prereq "cannot resolve pinned BPF rustc" "install the pinned $BPF_TOOLCHAIN toolchain"
    BPF_CARGO_VER="$(run_pinned_cargo "$BPF_TOOLCHAIN" --version 2>/dev/null)" \
        || fail_prereq "cargo +$BPF_TOOLCHAIN unavailable" "rustup toolchain install $BPF_TOOLCHAIN --component rust-src"
    BPF_RUSTC_VER="$("$BPF_RUSTC_PATH" --version 2>/dev/null)" \
        || fail_prereq "rustc +$BPF_TOOLCHAIN unavailable" "rustup toolchain install $BPF_TOOLCHAIN --component rust-src"
    rustup component list --toolchain "$BPF_TOOLCHAIN" --installed 2>/dev/null | grep -q '^rust-src' \
        || fail_prereq "rust-src missing on $BPF_TOOLCHAIN (bpfel needs -Z build-std=core)" "rustup component add --toolchain $BPF_TOOLCHAIN rust-src"
    command -v bpf-linker >/dev/null 2>&1 \
        || fail_prereq "bpf-linker not found on PATH" "install bpf-linker $BPF_LINKER_PIN manually (e.g. cargo install --locked bpf-linker --version $BPF_LINKER_PIN)"
    BPF_LINKER_VER="$(bpf-linker --version 2>/dev/null || echo bpf-linker-unknown)"
    # Exact pin: a missing or wrong-version linker miscompiles the
    # BPF objects, so both refuse here (exit 3) in every BPF mode —
    # check-only and build share these prereqs, and there is no
    # silent fallback. Host-only builds need no linker and skip this.
    [ "$BPF_LINKER_VER" = "bpf-linker $BPF_LINKER_PIN" ] \
        || fail_prereq "bpf-linker is '$BPF_LINKER_VER', need exactly 'bpf-linker $BPF_LINKER_PIN'" "install bpf-linker $BPF_LINKER_PIN manually (e.g. cargo install --locked bpf-linker --version $BPF_LINKER_PIN)"
fi

# Cargo build-std reads the separately installed source tree, not compiler
# implementation bytes. Capture all library files before compilation; the
# matching post-build snapshot is required before an artifact receipt is written.
BPF_LIBRARY_IDENTITY=""
BPF_LIBRARY_ROOT=""
if [ "$MODE" != "host" ]; then
    [ -z "${__CARGO_TESTS_ONLY_SRC_ROOT-}" ] || fail_prereq \
        "runtime source override is unsupported by this pinned recipe" \
        "unset __CARGO_TESTS_ONLY_SRC_ROOT; use the pinned installed rust-src"
    BPF_SYSROOT="$("$BPF_RUSTC_PATH" --print sysroot)" \
        || fail_prereq "cannot resolve BPF compiler sysroot" "check the pinned nightly compiler"
    BPF_LIBRARY_ROOT="$BPF_SYSROOT/lib/rustlib/src/rust/library"
    BPF_LIBRARY_IDENTITY="$(python3 "$REPO/packaging/source_payload.py" --library-root "$BPF_LIBRARY_ROOT")" \
        || fail_prereq "runtime library source capture failed" "restore the exact pinned nightly rust-src component"
fi

# Revision is best-effort: a fresh source archive (not a git checkout) must
# still build; the manifest then records a null ref instead of failing.
PRODUCT_REF=""
PRODUCT_TREE=""
PRODUCT_REF_SHORT="unknown"
PRODUCT_DIRTY="unknown"
# A source archive may sit inside another repository. Only this exact tree's
# own checkout can supply product identity; never inherit a containing repo.
PRODUCT_GIT_ROOT="$(git -C "$REPO" rev-parse --show-toplevel 2>/dev/null || true)"
if [ "$PRODUCT_GIT_ROOT" = "$REPO" ] && git -C "$REPO" rev-parse HEAD >/dev/null 2>&1; then
    PRODUCT_REF="$(git -C "$REPO" rev-parse HEAD 2>/dev/null)"
    PRODUCT_TREE="$(git -C "$REPO" rev-parse 'HEAD^{tree}')"
    PRODUCT_REF_SHORT="$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    PRODUCT_DIRTY="false"
    if [ -n "$(git -C "$REPO" status --porcelain 2>/dev/null)" ]; then PRODUCT_DIRTY="true"; fi
fi

# Resolve real target dirs (honors CARGO_TARGET_DIR/build.target-dir) via
# metadata, so validation/manifest hash what cargo actually wrote — never a
# stale default path. Runs in prereqs so --check-only exercises it too.
HOST_TD=""
BPF_TD=""
if [ "$MODE" != "bpf" ]; then
    # From REPO, like the build itself: repo-local config or a relative
    # CARGO_TARGET_DIR must resolve identically for both.
    HOST_TD="$(cd "$REPO" && run_pinned_cargo "$HOST_TOOLCHAIN" metadata \
        --format-version 1 --no-deps \
        --manifest-path "$REPO/Cargo.toml" 2>/dev/null | python3 -c \
        'import json,sys; print(json.load(sys.stdin)["target_directory"])')" \
        || fail_prereq "cannot resolve host target dir (cargo metadata failed)" \
        "check $REPO/Cargo.toml and 'cargo +$HOST_TOOLCHAIN metadata --no-deps'"
    [ -n "$HOST_TD" ] || fail_prereq "empty host target dir" "report this script bug with the manifest"
fi
if [ "$MODE" != "host" ]; then
    BPF_TD="$(cd "$REPO/crates/ebpf" && run_pinned_cargo "$BPF_TOOLCHAIN" metadata \
        --format-version 1 --no-deps --manifest-path "$REPO/crates/ebpf/Cargo.toml" 2>/dev/null | python3 -c \
        'import json,sys; print(json.load(sys.stdin)["target_directory"])')" \
        || fail_prereq "cannot resolve BPF target dir (cargo metadata failed)" \
        "check crates/ebpf/Cargo.toml and the $BPF_TOOLCHAIN toolchain"
    [ -n "$BPF_TD" ] || fail_prereq "empty BPF target dir" "report this script bug with the manifest"
fi

BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "product: $PRODUCT_REF_SHORT (dirty=$PRODUCT_DIRTY)"
echo "host toolchain: $HOST_RUSTC_VER"
if [ "$MODE" != "bpf" ]; then
    echo "host target dir: $HOST_TD"
fi
if [ "$MODE" != "host" ]; then
    echo "bpf toolchain: $BPF_RUSTC_VER"
    echo "linker: $BPF_LINKER_VER"
    echo "bpf target dir: $BPF_TD"
fi
echo "jobs: $CARGO_BUILD_JOBS  net: $NET  mode: $MODE  profile(host): $PROFILE"
if [ "$PRODUCT_DIRTY" = "true" ]; then
    echo "warning: product tree is dirty; manifest records the committed ref, not uncommitted edits" >&2
fi

# --- cargo runner: --locked always; offline when cached, else one locked fetch ---
# Every attempt's stderr is appended to CARGO_LOG (warning triage reads it)
# and echoed to the terminal; nothing is deleted on success. Attempt stdout
# (cargo --message-format JSON) overwrites CARGO_STDOUT so it always holds
# the latest attempt, from which artifact paths are extracted.
# SCRATCH/CARGO_LOG/CARGO_STDOUT are per-invocation (timestamp+pid): two
# concurrent builds in one worktree must not share capture files.
OFFLINE_USED="unknown"
LOGSTAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
SCRATCH="$REPO/target/.cargo-log-$LOGSTAMP"
CARGO_LOG="$SCRATCH/build.log"
CARGO_STDOUT="$SCRATCH/stdout.jsonl"
_log_attempt() {
    # $1 = attempt err file, $2 = attempt out file
    cat "$1" >>"$CARGO_LOG"
    cat "$1" >&2
    cat "$2" >"$CARGO_STDOUT"
    rm -f "$1" "$2"
}
run_cargo_locked() {
    # $1 = toolchain, $@ = cargo args (sans --offline/--locked)
    _tc="$1"; shift
    _att="$SCRATCH/.cargo-attempt.err"
    _ato="$SCRATCH/.cargo-attempt.out"
    _rc=0
    if [ "$NET" = "online" ]; then
        OFFLINE_USED="false"
        run_pinned_cargo "$_tc" "$@" --locked >"$_ato" 2>"$_att" || _rc=$?
        _log_attempt "$_att" "$_ato"
        return $_rc
    fi
    if [ "$NET" = "offline" ]; then
        OFFLINE_USED="true"
        run_pinned_cargo "$_tc" "$@" --locked --offline >"$_ato" 2>"$_att" || _rc=$?
        _log_attempt "$_att" "$_ato"
        return $_rc
    fi
    # auto: try cached first; on a cache miss retry once online (locked set only)
    if run_pinned_cargo "$_tc" "$@" --locked --offline >"$_ato" 2>"$_att"; then
        OFFLINE_USED="true"
        _log_attempt "$_att" "$_ato"
        return 0
    fi
    if grep -Eq 'offline|failed to download|no matching package|not found in cache' "$_att"; then
        echo "note: offline cache incomplete; retrying once online with --locked (locked set only)" >&2
        cat "$_att" >>"$CARGO_LOG"
        cat "$_ato" >"$CARGO_STDOUT"
        rm -f "$_att" "$_ato"
        OFFLINE_USED="false"
        run_pinned_cargo "$_tc" "$@" --locked >"$_ato" 2>"$_att" || _rc=$?
        _log_attempt "$_att" "$_ato"
        return $_rc
    fi
    OFFLINE_USED="true"
    _log_attempt "$_att" "$_ato"
    return 1
}
extract_artifact() {
    # $1 = cargo JSON stdout file, $2 = bin target name; prints the built
    # executable path. Fails closed: never guess <target>/<profile> paths
    # (build.target/CARGO_BUILD_TARGET change the layout).
    python3 -c '
import json, sys
want = sys.argv[2]
try:
    f = open(sys.argv[1])
except OSError:
    sys.exit("no cargo output to extract %r from" % want)
for line in f:
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") != "compiler-artifact":
        continue
    t = m.get("target", {})
    exe = m.get("executable")
    if t.get("name") == want and "bin" in (t.get("kind") or []) and exe:
        print(exe)
        sys.exit(0)
sys.exit("no compiler-artifact with executable for bin %r" % want)
' "$1" "$2"
}

HOST_CMD=""
BPF_CMD=""
DIAGNOSTICS=""
HOST_BIN=""
BPF_BIN_PATHS=""
MSG_FMT="--message-format=json-render-diagnostics"

if [ "$CHECK_ONLY" -eq 1 ]; then
    echo "check-only: prerequisites pass; no build run."
    DIAGNOSTICS="check-only: no build executed; artifact list empty by request."
else
    mkdir -p "$SCRATCH"
    : >"$CARGO_LOG"
    if [ -n "$IDENTITY_INPUTS" ]; then
        # Freeze custody and all four real objects descriptor-free. Missing
        # future bins refuse here; neither placeholder bytes nor stale output
        # become an admitted artifact.
        _cwd="$(pwd)"
        cd "$REPO"
        CARGO_STDOUT="$SCRATCH/custody-stdout.jsonl"
        if ! run_cargo_locked "$HOST_TOOLCHAIN" build --bin osslscope-identity-custodian "$MSG_FMT"; then
            echo "error: identity v2 requires the actual custody producer" >&2; exit 1
        fi
        _custody="$(extract_artifact "$CARGO_STDOUT" osslscope-identity-custodian)"
        cp --remove-destination "$_custody" "$IDENTITY_DIR/osslscope-identity-custodian"
        cd "$REPO/crates/ebpf"
        CARGO_STDOUT="$SCRATCH/identity-bpf-stdout.jsonl"
        if ! run_cargo_locked "$BPF_TOOLCHAIN" build -Z build-std=core --target "$BPF_TARGET" --release --bin osslscope-harvest --bin osslscope-count --bin osslscope-members --bin osslscope-identity "$MSG_FMT"; then
            echo "error: identity v2 requires four real reader/identity objects" >&2; exit 1
        fi
        BPF_BIN_PATHS=""
        for _role in osslscope-harvest osslscope-count osslscope-members osslscope-identity; do
            _object="$(extract_artifact "$CARGO_STDOUT" "$_role")"
            cp --remove-destination "$_object" "$IDENTITY_DIR/$_role"
            BPF_BIN_PATHS="$BPF_BIN_PATHS
$_object"
        done
        cd "$REPO"
        # One Rust canonical serializer and policy, bootstrapped separately.
        _saved_target="${CARGO_TARGET_DIR-}"
        export CARGO_TARGET_DIR="$SCRATCH/admission-target"
        CARGO_STDOUT="$SCRATCH/admission-stdout.jsonl"
        run_cargo_locked "$HOST_TOOLCHAIN" build --bin osslscope-dev-admission "$MSG_FMT" || exit 1
        _admission="$(extract_artifact "$CARGO_STDOUT" osslscope-dev-admission)"
        "$_admission" contract --inputs "$IDENTITY_INPUTS" --root "$IDENTITY_DIR" || exit 1
        if [ -n "$_saved_target" ]; then export CARGO_TARGET_DIR="$_saved_target"; else unset CARGO_TARGET_DIR; fi
        CARGO_STDOUT="$SCRATCH/host-stdout.jsonl"
        export OSSL_PACKAGE_RECORD_DIR="$IDENTITY_DIR"
        if [ "$PROFILE" = "release" ]; then
            run_cargo_locked "$HOST_TOOLCHAIN" build --release --bin osslscope "$MSG_FMT" || exit 1
        else
            run_cargo_locked "$HOST_TOOLCHAIN" build --bin osslscope "$MSG_FMT" || exit 1
        fi
        unset OSSL_PACKAGE_RECORD_DIR
        HOST_BIN="$(extract_artifact "$CARGO_STDOUT" osslscope)"
        cp --remove-destination "$HOST_BIN" "$IDENTITY_DIR/osslscope"
        "$_admission" finalize --root "$IDENTITY_DIR" || exit 1
        HOST_CMD="identity-v2: frozen custody/four roles, descriptor-free helper, observer-only embedded build, atomic dev admission"
        BPF_CMD="four identity-v2 BPF bins --locked"
        cd "$_cwd"
    elif [ "$MODE" != "bpf" ]; then
        if [ "$PROFILE" = "release" ]; then
            HOST_CMD="cargo +$HOST_TOOLCHAIN build --locked --release $MSG_FMT"
            _args="build --release $MSG_FMT"
        else
            HOST_CMD="cargo +$HOST_TOOLCHAIN build --locked $MSG_FMT"
            _args="build $MSG_FMT"
        fi
        # Build from REPO (never the caller's cwd); no subshell so
        # run_cargo_locked propagates OFFLINE_USED to the manifest.
        _cwd="$(pwd)"
        cd "$REPO"
        CARGO_STDOUT="$SCRATCH/host-stdout.jsonl"
        : >"$CARGO_STDOUT"
        # shellcheck disable=SC2086
        if ! run_cargo_locked "$HOST_TOOLCHAIN" $_args; then
            cd "$_cwd"
            exit 1
        fi
        cd "$_cwd"
        HOST_BIN="$(extract_artifact "$CARGO_STDOUT" osslscope)" \
            || { echo "error: built host binary path unknown (see $CARGO_LOG)" >&2; exit 1; }
        [ -x "$HOST_BIN" ] || { echo "error: expected host binary missing: $HOST_BIN" >&2; exit 1; }
    fi
    if [ "$MODE" != "host" ] && [ -z "$IDENTITY_INPUTS" ]; then
        BPF_CMD="cargo +$BPF_TOOLCHAIN build --locked -Z build-std=core --target $BPF_TARGET --release --bin osslscope-harvest --bin osslscope-count --bin osslscope-members --bin osslscope-provider-observation --bin osslscope-focused-count $MSG_FMT (in crates/ebpf)"
        # No subshell: run_cargo_locked must propagate OFFLINE_USED to the manifest.
        _cwd="$(pwd)"
        cd "$REPO/crates/ebpf"
        CARGO_STDOUT="$SCRATCH/bpf-stdout.jsonl"
        : >"$CARGO_STDOUT"
        if ! run_cargo_locked "$BPF_TOOLCHAIN" build \
            -Z build-std=core --target "$BPF_TARGET" --release \
            --bin osslscope-harvest --bin osslscope-count --bin osslscope-members --bin osslscope-provider-observation --bin osslscope-focused-count "$MSG_FMT"; then
            cd "$_cwd"
            exit 1
        fi
        cd "$_cwd"
        BPF_BIN_PATHS=""
        for b in $BPF_BINS; do
            _p="$(extract_artifact "$CARGO_STDOUT" "$b")" \
                || { echo "error: built BPF object path unknown for $b (see $CARGO_LOG)" >&2; exit 1; }
            [ -f "$_p" ] || { echo "error: expected BPF object missing: $_p" >&2; exit 1; }
            BPF_BIN_PATHS="$BPF_BIN_PATHS
$_p"
            if { [ "$b" = "osslscope-provider-observation" ] || [ "$b" = "osslscope-focused-count" ]; } && [ -n "$HOST_BIN" ]; then
                # Cargo's emitted paths also cover custom target directories,
                # target triples and profiles. Never guess a default target/.
                cp --remove-destination "$_p" "$(dirname "$HOST_BIN")/$b"
            fi
        done
        BPF_BIN_PATHS="$(printf '%s' "$BPF_BIN_PATHS" | sed '/^$/d')"
        # Known warning triage (diagnose, do not upgrade): bpf-linker probes a
        # shared LLVM and falls back when dlopen fails; objects still link.
        # CARGO_LOG holds every attempt's stderr, including successful ones.
        if grep -Eq 'dlopen.*failed|failed to load.*[Ll][Ll][Vv][Mm]' "$CARGO_LOG" 2>/dev/null; then
            DIAGNOSTICS="bpf-linker LLVM dlopen fallback warning present (known; objects verified below). Linker selection: $(command -v bpf-linker). Not a toolchain defect; do not upgrade toolchains for it."
            echo "note: $DIAGNOSTICS" >&2
        else
            DIAGNOSTICS="no bpf-linker LLVM fallback warning in this build."
        fi
    fi
fi

if [ "$MODE" != "host" ] && [ "$CHECK_ONLY" -eq 0 ]; then
    _after_sysroot="$("$BPF_RUSTC_PATH" --print sysroot)" || exit 1
    _after_source="$(python3 "$REPO/packaging/source_payload.py" --library-root "$_after_sysroot/lib/rustlib/src/rust/library")" \
        || { echo "error: runtime library source capture failed after build" >&2; exit 1; }
    if [ "$_after_source" != "$BPF_LIBRARY_IDENTITY" ]; then
        echo "error: runtime library source changed during build; no new manifest written" >&2
        exit 1
    fi
fi

# A build crossing source revisions or tracked/untracked edits cannot claim
# clean source provenance, even when it began in a clean checkout.
if [ -n "$PRODUCT_REF" ]; then
    if [ "$(git -C "$REPO" rev-parse HEAD)" != "$PRODUCT_REF" ] || [ -n "$(git -C "$REPO" status --porcelain)" ]; then
        PRODUCT_DIRTY="true"
    fi
fi

# --- manifest: versions + artifact identity ---
export REPO MANIFEST PRODUCT_REF PRODUCT_TREE PRODUCT_REF_SHORT PRODUCT_DIRTY BUILT_AT \
    HOST_CARGO_VER HOST_RUSTC_VER BPF_CARGO_VER BPF_RUSTC_VER BPF_LINKER_VER \
    HOST_TOOLCHAIN BPF_TOOLCHAIN BPF_TARGET BPF_BINS JOBS NET OFFLINE_USED \
    MODE PROFILE HOST_CMD BPF_CMD DIAGNOSTICS HOST_BIN BPF_BIN_PATHS \
    HOST_TD BPF_TD CHECK_ONLY CARGO_TARGET_DIR CARGO_LOG SCRATCH BPF_LIBRARY_IDENTITY HOST_RUSTC_PATH BPF_RUSTC_PATH
python3 - <<'EOF'
import hashlib, json, os, subprocess

def ident(path):
    if not path or not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    try:
        ftype = subprocess.run(["file", "-b", path], capture_output=True,
                               text=True, timeout=30).stdout.strip()
    except Exception:
        ftype = "unknown"
    build_id = None
    try:
        out = subprocess.run(["readelf", "-n", path], capture_output=True,
                             text=True, timeout=30).stdout
        for line in out.splitlines():
            if "Build ID" in line:
                build_id = line.split(":")[-1].strip()
    except Exception:
        pass
    return {"path": path, "sha256": h.hexdigest(),
            "bytes": os.path.getsize(path), "file": ftype,
            "build_id": build_id, "product_ref": os.environ.get("PRODUCT_REF") or None,
            "product_tree": os.environ.get("PRODUCT_TREE") or None}

e = os.environ
artifacts = []
if e.get("CHECK_ONLY") != "1":
    if e.get("HOST_BIN"):
        a = ident(e["HOST_BIN"])
        if a:
            a["role"] = "host-binary"
            artifacts.append(a)
    for p in (e.get("BPF_BIN_PATHS") or "").splitlines():
        p = p.strip()
        a = ident(p) if p and e.get("MODE") != "host" else None
        if a:
            a["role"] = "bpf-object"
            a["bin"] = os.path.basename(p)
            artifacts.append(a)

runtime_source = None
if e.get("MODE") != "host" and e.get("CHECK_ONLY") != "1":
    import sys
    sys.path.insert(0, os.path.join(e["REPO"], "packaging"))
    from source_payload import bpf_artifact_digest
    runtime_source = {"schema": "osslscope-bpf-runtime-source-v3",
                      "source_selection": "pinned-default-sysroot",
                      "compiler_selection": "resolved-pinned-rustc",
                      "toolchain": e["BPF_TOOLCHAIN"],
                      "capture": "before-and-after-build",
                      "library": json.loads(e["BPF_LIBRARY_IDENTITY"]),
                      "artifacts_sha256": bpf_artifact_digest(artifacts)}

manifest = {
    "schema": "osslscope-dev-build-manifest-v1",
    "product_ref": e.get("PRODUCT_REF") or None,
    "product_tree": e.get("PRODUCT_TREE") or None,
    "product_ref_short": (e.get("PRODUCT_REF_SHORT") if e.get("PRODUCT_REF") else None),
    "product_dirty": {"true": True, "false": False}.get(e.get("PRODUCT_DIRTY")),
    "built_at_utc": e.get("BUILT_AT"),
    "host_toolchain": e.get("HOST_TOOLCHAIN"),
    "host_cargo": e.get("HOST_CARGO_VER"),
    "host_rustc": e.get("HOST_RUSTC_VER"),
    "host_rustc_path": e.get("HOST_RUSTC_PATH"),
    "host_profile": e.get("PROFILE"),
    "host_target_dir": e.get("HOST_TD") or None,
    "bpf_target_dir": e.get("BPF_TD") or None,
    "cargo_target_dir_env": e.get("CARGO_TARGET_DIR") or None,
    "cargo_log": e.get("CARGO_LOG") if e.get("CHECK_ONLY") != "1" else None,
    "scratch": e.get("SCRATCH") if e.get("CHECK_ONLY") != "1" else None,
    "bpf_toolchain": e.get("BPF_TOOLCHAIN") or None,
    "bpf_cargo": e.get("BPF_CARGO_VER") or None,
    "bpf_rustc": e.get("BPF_RUSTC_VER") or None,
    "bpf_rustc_path": e.get("BPF_RUSTC_PATH") or None,
    "bpf_linker": e.get("BPF_LINKER_VER") or None,
    "bpf_runtime_source": runtime_source,
    "bpf_target": e.get("BPF_TARGET"),
    "jobs": int(e.get("JOBS", "2")),
    "net_mode": e.get("NET"),
    "offline_used": {"true": True, "false": False}.get(e.get("OFFLINE_USED")),
    "mode": e.get("MODE"),
    "host_cmd": e.get("HOST_CMD") or None,
    "bpf_cmd": e.get("BPF_CMD") or None,
    "diagnostics": e.get("DIAGNOSTICS") or "",
    "artifacts": artifacts,
    # Prefix-install layout contract (consumed by scripts/install-dev.sh;
    # trusted system installs use this layout for default object resolution):
    # install destination per artifact role, relative to the prefix.
    "install_layout": {
        "host-binary": "bin/osslscope",
        "bpf-object:osslscope-harvest": "lib/osslscope/osslscope-harvest",
        "bpf-object:osslscope-count": "lib/osslscope/osslscope-count",
        "bpf-object:osslscope-members": "lib/osslscope/osslscope-members",
        "bpf-object:osslscope-provider-observation": "lib/osslscope/osslscope-provider-observation",
        "bpf-object:osslscope-focused-count": "lib/osslscope/osslscope-focused-count",
    },
}
mpath = e["MANIFEST"]
os.makedirs(os.path.dirname(mpath) or ".", exist_ok=True)
with open(mpath, "w") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
print("manifest: " + mpath)
EOF

echo "done."
