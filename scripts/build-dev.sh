#!/bin/sh
# build-dev.sh — reproducible host + BPF development build entrypoint (R09/T05).
#
# Builds the host workspace with the pinned stable toolchain and the BPF
# objects (harvest, count, members) with the pinned nightly toolchain,
# then writes a JSON manifest carrying toolchain versions and artifact
# (version/object) identity.
#
# Rules, not suggestions:
#   - No auto-install: a missing prerequisite fails with a diagnosis and a
#     manual install hint. This script never runs apt/dnf/rustup/cargo-install.
#   - No upgrades: pinned toolchains only. Warnings (including the known
#     bpf-linker/LLVM dlopen fallback warning) are diagnosed and recorded,
#     never "fixed" by moving the toolchain.
#   - Locked dependencies only: every cargo invocation passes --locked.
#   - Bounded jobs: CARGO_BUILD_JOBS defaults to 2; an explicit setting is
#     honored and recorded in the manifest.
#   - Per-invocation capture dirs: cargo logs live under
#     target/.cargo-log-<utc>-<pid>/ (kept for diagnosis; target/ stays
#     ignored and routinely cleaned, so no explicit rotation).
#
# Usage:
#   scripts/build-dev.sh [--host-only|--bpf-only] [--offline|--online]
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
BPF_BINS="osslscope-harvest osslscope-count osslscope-members"
BPF_TARGET="bpfel-unknown-none"

MODE="both"        # both | host | bpf
NET="auto"         # auto | offline | online
PROFILE="dev"      # dev (host) — BPF always builds --release
MANIFEST=""        # default: <repo>/target/dev-build-manifest.json
JOBS="${CARGO_BUILD_JOBS:-2}"
CHECK_ONLY=0

usage() {
    sed -n '2,20p' "$0"
    echo "Exit codes: 0 ok; 2 usage; 3 missing prerequisite; 1 build failure."
}

while [ $# -gt 0 ]; do
    case "$1" in
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

# --- prerequisite checks (diagnose, never install) ---
need_cmd cargo "install the Rust toolchain via rustup (pinned: $HOST_TOOLCHAIN + $BPF_TOOLCHAIN), then re-run"
need_cmd rustc "install the Rust toolchain via rustup, then re-run"
need_cmd rustup "install rustup and the pinned toolchains, then re-run"
need_cmd python3 "install python3 (used only to write the JSON manifest), then re-run"
need_cmd sha256sum "install coreutils, then re-run"

HOST_CARGO_VER="$(cargo +"$HOST_TOOLCHAIN" --version 2>/dev/null)" \
    || fail_prereq "cargo +$HOST_TOOLCHAIN unavailable" "rustup toolchain install $HOST_TOOLCHAIN --profile minimal"
HOST_RUSTC_VER="$(rustc +"$HOST_TOOLCHAIN" --version 2>/dev/null)" \
    || fail_prereq "rustc +$HOST_TOOLCHAIN unavailable" "rustup toolchain install $HOST_TOOLCHAIN --profile minimal"
case "$HOST_RUSTC_VER" in
    "rustc 1.88.0 "*) ;;
    *) echo "warning: host rustc is not the pinned 1.88.0: $HOST_RUSTC_VER" >&2 ;;
esac

BPF_CARGO_VER=""
BPF_RUSTC_VER=""
BPF_LINKER_VER=""
if [ "$MODE" != "host" ]; then
    BPF_CARGO_VER="$(cargo +"$BPF_TOOLCHAIN" --version 2>/dev/null)" \
        || fail_prereq "cargo +$BPF_TOOLCHAIN unavailable" "rustup toolchain install $BPF_TOOLCHAIN --component rust-src"
    BPF_RUSTC_VER="$(rustc +"$BPF_TOOLCHAIN" --version 2>/dev/null)" \
        || fail_prereq "rustc +$BPF_TOOLCHAIN unavailable" "rustup toolchain install $BPF_TOOLCHAIN --component rust-src"
    rustup component list --toolchain "$BPF_TOOLCHAIN" --installed 2>/dev/null | grep -q '^rust-src' \
        || fail_prereq "rust-src missing on $BPF_TOOLCHAIN (bpfel needs -Z build-std=core)" "rustup component add --toolchain $BPF_TOOLCHAIN rust-src"
    command -v bpf-linker >/dev/null 2>&1 \
        || fail_prereq "bpf-linker not found on PATH" "install bpf-linker 0.10.4 manually (e.g. cargo install --locked bpf-linker --version 0.10.4)"
    BPF_LINKER_VER="$(bpf-linker --version 2>/dev/null || echo bpf-linker-unknown)"
fi

# Revision is best-effort: a fresh source archive (not a git checkout) must
# still build; the manifest then records a null ref instead of failing.
PRODUCT_REF=""
PRODUCT_REF_SHORT="unknown"
PRODUCT_DIRTY="unknown"
if git -C "$REPO" rev-parse HEAD >/dev/null 2>&1; then
    PRODUCT_REF="$(git -C "$REPO" rev-parse HEAD 2>/dev/null)"
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
    HOST_TD="$(cd "$REPO" && cargo +"$HOST_TOOLCHAIN" metadata \
        --format-version 1 --no-deps \
        --manifest-path "$REPO/Cargo.toml" 2>/dev/null | python3 -c \
        'import json,sys; print(json.load(sys.stdin)["target_directory"])')" \
        || fail_prereq "cannot resolve host target dir (cargo metadata failed)" \
        "check $REPO/Cargo.toml and 'cargo +$HOST_TOOLCHAIN metadata --no-deps'"
    [ -n "$HOST_TD" ] || fail_prereq "empty host target dir" "report this script bug with the manifest"
fi
if [ "$MODE" != "host" ]; then
    BPF_TD="$(cd "$REPO/crates/ebpf" && cargo +"$BPF_TOOLCHAIN" metadata \
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
        cargo +"$_tc" "$@" --locked >"$_ato" 2>"$_att" || _rc=$?
        _log_attempt "$_att" "$_ato"
        return $_rc
    fi
    if [ "$NET" = "offline" ]; then
        OFFLINE_USED="true"
        cargo +"$_tc" "$@" --locked --offline >"$_ato" 2>"$_att" || _rc=$?
        _log_attempt "$_att" "$_ato"
        return $_rc
    fi
    # auto: try cached first; on a cache miss retry once online (locked set only)
    if cargo +"$_tc" "$@" --locked --offline >"$_ato" 2>"$_att"; then
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
        cargo +"$_tc" "$@" --locked >"$_ato" 2>"$_att" || _rc=$?
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
    if [ "$MODE" != "bpf" ]; then
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
    if [ "$MODE" != "host" ]; then
        BPF_CMD="cargo +$BPF_TOOLCHAIN build --locked -Z build-std=core --target $BPF_TARGET --release --bin osslscope-harvest --bin osslscope-count --bin osslscope-members $MSG_FMT (in crates/ebpf)"
        # No subshell: run_cargo_locked must propagate OFFLINE_USED to the manifest.
        _cwd="$(pwd)"
        cd "$REPO/crates/ebpf"
        CARGO_STDOUT="$SCRATCH/bpf-stdout.jsonl"
        : >"$CARGO_STDOUT"
        if ! run_cargo_locked "$BPF_TOOLCHAIN" build \
            -Z build-std=core --target "$BPF_TARGET" --release \
            --bin osslscope-harvest --bin osslscope-count --bin osslscope-members "$MSG_FMT"; then
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

# --- manifest: versions + artifact identity ---
export REPO MANIFEST PRODUCT_REF PRODUCT_REF_SHORT PRODUCT_DIRTY BUILT_AT \
    HOST_CARGO_VER HOST_RUSTC_VER BPF_CARGO_VER BPF_RUSTC_VER BPF_LINKER_VER \
    HOST_TOOLCHAIN BPF_TOOLCHAIN BPF_TARGET BPF_BINS JOBS NET OFFLINE_USED \
    MODE PROFILE HOST_CMD BPF_CMD DIAGNOSTICS HOST_BIN BPF_BIN_PATHS \
    HOST_TD BPF_TD CHECK_ONLY CARGO_TARGET_DIR CARGO_LOG SCRATCH
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
            "build_id": build_id}

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

manifest = {
    "schema": "osslscope-dev-build-manifest-v1",
    "product_ref": e.get("PRODUCT_REF") or None,
    "product_ref_short": (e.get("PRODUCT_REF_SHORT") if e.get("PRODUCT_REF") else None),
    "product_dirty": {"true": True, "false": False}.get(e.get("PRODUCT_DIRTY")),
    "built_at_utc": e.get("BUILT_AT"),
    "host_toolchain": e.get("HOST_TOOLCHAIN"),
    "host_cargo": e.get("HOST_CARGO_VER"),
    "host_rustc": e.get("HOST_RUSTC_VER"),
    "host_profile": e.get("PROFILE"),
    "host_target_dir": e.get("HOST_TD") or None,
    "bpf_target_dir": e.get("BPF_TD") or None,
    "cargo_target_dir_env": e.get("CARGO_TARGET_DIR") or None,
    "cargo_log": e.get("CARGO_LOG") if e.get("CHECK_ONLY") != "1" else None,
    "scratch": e.get("SCRATCH") if e.get("CHECK_ONLY") != "1" else None,
    "bpf_toolchain": e.get("BPF_TOOLCHAIN") or None,
    "bpf_cargo": e.get("BPF_CARGO_VER") or None,
    "bpf_rustc": e.get("BPF_RUSTC_VER") or None,
    "bpf_linker": e.get("BPF_LINKER_VER") or None,
    "bpf_target": e.get("BPF_TARGET"),
    "jobs": int(e.get("JOBS", "2")),
    "net_mode": e.get("NET"),
    "offline_used": {"true": True, "false": False}.get(e.get("OFFLINE_USED")),
    "mode": e.get("MODE"),
    "host_cmd": e.get("HOST_CMD") or None,
    "bpf_cmd": e.get("BPF_CMD") or None,
    "diagnostics": e.get("DIAGNOSTICS") or "",
    "artifacts": artifacts,
    # Prefix-install layout contract (consumed by scripts/install-dev.sh
    # and, later, default object resolution): install destination per
    # artifact role, relative to the prefix.
    "install_layout": {
        "host-binary": "bin/osslscope",
        "bpf-object:osslscope-harvest": "lib/osslscope/osslscope-harvest",
        "bpf-object:osslscope-count": "lib/osslscope/osslscope-count",
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
