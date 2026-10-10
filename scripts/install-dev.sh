#!/bin/sh
# install-dev.sh — local prefix install for development builds (R09/T13).
#
# Installs a build-dev.sh host binary plus both BPF objects into a
# user-owned prefix (default: $HOME/.local). This is the developer path to
# a usable install; system packages (deb/rpm) remain the only /usr path and
# are not final distributables during development.
#
# Prefix layout (the contract future default object resolution consumes):
#   $PREFIX/bin/osslscope
#   $PREFIX/lib/osslscope/osslscope-harvest
#   $PREFIX/lib/osslscope/osslscope-count
#   $PREFIX/share/doc/osslscope/install.md
#   $PREFIX/share/osslscope/install-manifest.json
#
# Artifact sources: the build-dev.sh manifest (default
# <repo>/target/dev-build-manifest.json) or explicit operator-built object
# paths (--binary/--harvest/--count), which override the manifest.
#
# Rules, not suggestions:
#   - No auto-install: missing prerequisites fail with a diagnosis.
#   - Fail closed on incompatible objects: the host binary must be an
#     x86-64 ELF executable; BPF objects must be eBPF relocatables.
#   - Never install into system package territory (/ or /usr).
#   - --setcap is explicit and privileged in practice: failure is a
#     deterministic error with a labeled-sudo fallback, never silent.
#
# Usage:
#   scripts/install-dev.sh [--prefix PATH] [--manifest PATH]
#                          [--binary F] [--harvest F] [--count F] [--setcap]
#
# Exit codes: 0 ok; 2 usage error; 3 missing prerequisite (environment);
# 1 install/validation/setup failure. A prerequisite failure is an
# environment condition, not a product regression.
#
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

PREFIX=""
MANIFEST=""
BIN_OVERRIDE=""
HARVEST_OVERRIDE=""
COUNT_OVERRIDE=""
SETCAP=0

usage() {
    sed -n '2,24p' "$0"
    echo "Exit codes: 0 ok; 2 usage; 3 missing prerequisite; 1 install/setup failure."
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) [ $# -ge 2 ] || { echo "error: --prefix needs a path" >&2; exit 2; }; PREFIX="$2"; shift 2 ;;
        --prefix=*) PREFIX="${1#--prefix=}"; shift ;;
        --manifest) [ $# -ge 2 ] || { echo "error: --manifest needs a path" >&2; exit 2; }; MANIFEST="$2"; shift 2 ;;
        --manifest=*) MANIFEST="${1#--manifest=}"; shift ;;
        --binary) [ $# -ge 2 ] || { echo "error: --binary needs a path" >&2; exit 2; }; BIN_OVERRIDE="$2"; shift 2 ;;
        --binary=*) BIN_OVERRIDE="${1#--binary=}"; shift ;;
        --harvest) [ $# -ge 2 ] || { echo "error: --harvest needs a path" >&2; exit 2; }; HARVEST_OVERRIDE="$2"; shift 2 ;;
        --harvest=*) HARVEST_OVERRIDE="${1#--harvest=}"; shift ;;
        --count) [ $# -ge 2 ] || { echo "error: --count needs a path" >&2; exit 2; }; COUNT_OVERRIDE="$2"; shift 2 ;;
        --count=*) COUNT_OVERRIDE="${1#--count=}"; shift ;;
        --setcap) SETCAP=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [ -z "$PREFIX" ]; then
    [ -n "${HOME:-}" ] || { echo "error: HOME is unset and --prefix was not given" >&2; exit 2; }
    PREFIX="$HOME/.local"
fi
# Never spray system package territory: /usr belongs to deb/rpm.
case "$PREFIX" in
    /|//|/usr|/usr/) echo "error: refusing system prefix '$PREFIX': /usr is system package territory (use deb/rpm there); pick a local prefix such as \$HOME/.local" >&2; exit 2 ;;
esac

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

need_cmd python3 "install python3 (used to read the build manifest and write the install manifest), then re-run"
need_cmd file "install file(1), then re-run"
need_cmd readelf "install binutils (readelf validates object identity), then re-run"
need_cmd cp "install coreutils, then re-run"
need_cmd mkdir "install coreutils, then re-run"
need_cmd chmod "install coreutils, then re-run"

# --- resolve artifact sources ---
if [ -z "$BIN_OVERRIDE$HARVEST_OVERRIDE$COUNT_OVERRIDE" ] && [ ! -f "$MANIFEST" ]; then
    echo "error: build manifest not found: $MANIFEST" >&2
    echo "hint: run scripts/build-dev.sh first, or pass explicit --binary/--harvest/--count paths." >&2
    exit 1
fi
if { [ -n "$BIN_OVERRIDE" ] || [ -n "$HARVEST_OVERRIDE" ] || [ -n "$COUNT_OVERRIDE" ]; } \
   && [ ! -f "$MANIFEST" ] \
   && { [ -z "$BIN_OVERRIDE" ] || [ -z "$HARVEST_OVERRIDE" ] || [ -z "$COUNT_OVERRIDE" ]; }; then
    echo "error: partial overrides with no manifest: pass all three of --binary/--harvest/--count, or build first with scripts/build-dev.sh." >&2
    exit 1
fi

MANIFEST_PATHS=""
if [ -f "$MANIFEST" ]; then
    MANIFEST_PATHS="$(python3 - "$MANIFEST" <<'EOF'
import json, sys
try:
    m = json.load(open(sys.argv[1]))
except (OSError, ValueError) as e:
    sys.exit("error: cannot parse build manifest %s: %s" % (sys.argv[1], e))
if m.get("schema") != "osslscope-dev-build-manifest-v1":
    sys.exit("error: unsupported build manifest schema %r in %s (want osslscope-dev-build-manifest-v1; rebuild with scripts/build-dev.sh)" % (m.get("schema"), sys.argv[1]))
arts = {a.get("role"): a for a in m.get("artifacts", [])}
bpf = [a for a in m.get("artifacts", []) if a.get("role") == "bpf-object"]
host = arts.get("host-binary", {}).get("path", "")
harvest = next((a.get("path", "") for a in bpf if a.get("bin") == "osslscope-harvest"), "")
count = next((a.get("path", "") for a in bpf if a.get("bin") == "osslscope-count"), "")
print("%s\t%s\t%s\t%s\t%s" % (host, harvest, count,
      m.get("product_ref", ""), str(m.get("product_dirty", ""))))
EOF
)" || exit 1
fi

HOST_BIN="$BIN_OVERRIDE"
HARVEST_OBJ="$HARVEST_OVERRIDE"
COUNT_OBJ="$COUNT_OVERRIDE"
PRODUCT_REF=""
PRODUCT_DIRTY=""
if [ -n "$MANIFEST_PATHS" ]; then
    IFS='	' read -r _m_host _m_harvest _m_count _m_ref _m_dirty <<EOF2
$MANIFEST_PATHS
EOF2
    [ -n "$HOST_BIN" ] || HOST_BIN="$_m_host"
    [ -n "$HARVEST_OBJ" ] || HARVEST_OBJ="$_m_harvest"
    [ -n "$COUNT_OBJ" ] || COUNT_OBJ="$_m_count"
    PRODUCT_REF="$_m_ref"
    PRODUCT_DIRTY="$_m_dirty"
fi

[ -n "$HOST_BIN" ] || { echo "error: no host binary: manifest lists no host-binary artifact and --binary was not given (build with scripts/build-dev.sh)" >&2; exit 1; }
[ -n "$HARVEST_OBJ" ] || { echo "error: no harvest object: manifest lists no osslscope-harvest artifact and --harvest was not given (build with scripts/build-dev.sh)" >&2; exit 1; }
[ -n "$COUNT_OBJ" ] || { echo "error: no count object: manifest lists no osslscope-count artifact and --count was not given (build with scripts/build-dev.sh)" >&2; exit 1; }
for _a in "$HOST_BIN" "$HARVEST_OBJ" "$COUNT_OBJ"; do
    [ -f "$_a" ] || { echo "error: artifact not found: $_a (stale manifest? rebuild with scripts/build-dev.sh)" >&2; exit 1; }
    [ -s "$_a" ] || { echo "error: artifact is empty: $_a" >&2; exit 1; }
done

# --- fail-closed object validation ---
HOST_FILE="$(file -b "$HOST_BIN")"
case "$HOST_FILE" in
    *ELF*x86-64*)
        [ -x "$HOST_BIN" ] || { echo "error: host binary is not executable: $HOST_BIN" >&2; exit 1; }
        ;;
    *) echo "error: incompatible host binary (want x86-64 ELF executable): $HOST_BIN: $HOST_FILE" >&2; exit 1 ;;
esac

check_bpf() {
    # $1 = path, $2 = which flag (for the hint)
    _f="$(file -b "$1")"
    case "$_f" in
        *ELF*eBPF*) ;;
        *) echo "error: incompatible BPF object (want eBPF relocatable): $1: $_f" >&2
           echo "hint: rebuild with scripts/build-dev.sh, or pass an operator-built $2 object for this machine." >&2
           exit 1 ;;
    esac
    _m="$(readelf -h "$1" 2>/dev/null | grep 'Machine:' || true)"
    case "$_m" in
        *BPF*) ;;
        *) echo "error: incompatible BPF object (readelf Machine is not BPF): $1: ${_m:-unreadable}" >&2; exit 1 ;;
    esac
}
check_bpf "$HARVEST_OBJ" harvest
check_bpf "$COUNT_OBJ" count

# --- install ---
mkdir -p "$PREFIX/bin" "$PREFIX/lib/osslscope" "$PREFIX/share/doc/osslscope" "$PREFIX/share/osslscope"
cp "$HOST_BIN" "$PREFIX/bin/osslscope"
chmod 755 "$PREFIX/bin/osslscope"
cp "$HARVEST_OBJ" "$PREFIX/lib/osslscope/osslscope-harvest"
cp "$COUNT_OBJ" "$PREFIX/lib/osslscope/osslscope-count"
chmod 644 "$PREFIX/lib/osslscope/osslscope-harvest" "$PREFIX/lib/osslscope/osslscope-count"
if [ -f "$REPO/docs/install.md" ]; then
    cp "$REPO/docs/install.md" "$PREFIX/share/doc/osslscope/install.md"
    chmod 644 "$PREFIX/share/doc/osslscope/install.md"
else
    echo "note: $REPO/docs/install.md absent; skipping doc install." >&2
fi

# --- optional file caps (explicit, privileged in practice) ---
SETCAP_STATE="not-requested"
if [ "$SETCAP" -eq 1 ]; then
    if ! command -v setcap >/dev/null 2>&1; then
        echo "error: --setcap requested but setcap not found." >&2
        echo "hint: install libcap2-bin (Debian/Ubuntu) or libcap (Fedora/RHEL), then re-run with --setcap; or run 'sudo setcap cap_bpf,cap_perfmon+ep $PREFIX/bin/osslscope' then '$PREFIX/bin/osslscope doctor'." >&2
        exit 3
    fi
    if setcap cap_bpf,cap_perfmon+ep "$PREFIX/bin/osslscope" 2>/dev/null; then
        SETCAP_STATE="applied"
    else
        echo "error: setcap failed on $PREFIX/bin/osslscope." >&2
        echo "hint: fallback (labeled sudo): run 'sudo setcap cap_bpf,cap_perfmon+ep $PREFIX/bin/osslscope' then '$PREFIX/bin/osslscope doctor'." >&2
        exit 1
    fi
fi

# --- install manifest ---
export PREFIX MANIFEST PRODUCT_REF PRODUCT_DIRTY SETCAP_STATE REPO
export HOST_BIN HARVEST_OBJ COUNT_OBJ
INST_MANIFEST="$PREFIX/share/osslscope/install-manifest.json"
python3 - "$INST_MANIFEST" <<'EOF'
import hashlib, json, os, subprocess, sys, datetime

def ident(path):
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
    return {"sha256": h.hexdigest(), "bytes": os.path.getsize(path),
            "file": ftype, "build_id": build_id}

e = os.environ
pfx = e["PREFIX"]
arts = [
    {"role": "host-binary", "src": e["HOST_BIN"],
     "dest": pfx + "/bin/osslscope"},
    {"role": "bpf-object", "bin": "osslscope-harvest",
     "src": e["HARVEST_OBJ"], "dest": pfx + "/lib/osslscope/osslscope-harvest"},
    {"role": "bpf-object", "bin": "osslscope-count",
     "src": e["COUNT_OBJ"], "dest": pfx + "/lib/osslscope/osslscope-count"},
]
for a in arts:
    a.update(ident(a["dest"]))
manifest = {
    "schema": "osslscope-install-manifest-v1",
    "installed_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "prefix": pfx,
    "build_manifest": e.get("MANIFEST") or None,
    "product_ref": e.get("PRODUCT_REF") or None,
    "product_dirty": e.get("PRODUCT_DIRTY") == "True",
    "setcap": e.get("SETCAP_STATE"),
    "artifacts": arts,
}
with open(sys.argv[1], "w") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
print("install manifest: " + sys.argv[1])
EOF

# --- report ---
echo "installed:"
echo "  binary:  $PREFIX/bin/osslscope"
echo "  harvest: $PREFIX/lib/osslscope/osslscope-harvest"
echo "  count:   $PREFIX/lib/osslscope/osslscope-count"
if [ -r /proc/self/status ]; then
    _nnp="$(grep '^NoNewPrivs:' /proc/self/status | awk '{print $2}')"
    echo "  NoNewPrivs (this shell): ${_nnp:-unknown}"
    if [ "${_nnp:-0}" = "1" ]; then
        echo "warning: NoNewPrivs=1 here: processes exec'd from this environment cannot gain file capabilities; run the installed binary outside it (see docs/install.md)." >&2
    fi
else
    echo "  NoNewPrivs (this shell): unknown (/proc unavailable)"
fi
if [ "$SETCAP" -eq 1 ]; then
    if command -v getcap >/dev/null 2>&1; then
        echo "  caps: $(getcap "$PREFIX/bin/osslscope" 2>/dev/null || echo 'unreadable')"
    fi
else
    echo "next: grant caps once (needs privilege), then verify:"
    echo "  sudo setcap cap_bpf,cap_perfmon+ep $PREFIX/bin/osslscope"
    echo "  $PREFIX/bin/osslscope doctor"
fi
echo "done."
