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
#   - Verify before replacing: manifest-selected artifacts must match the
#     recorded sha256 + byte length; the complete set is staged and
#     screened before any prefix file changes, so a failure leaves an
#     existing install byte-identical.
#   - Fail closed on incompatible objects: the host binary must be an
#     x86-64 ELF executable; BPF objects must be ELF64 little-endian
#     EM_BPF relocatables (role usability stays a loader/doctor gate).
#   - Explicit --binary/--harvest/--count overrides stay supported: they
#     are screened like any object but never hash-checked against the
#     manifest, and the receipt records them as explicit-override.
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
    sed -n '2,34p' "$0"
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
# F-G/B11: canonicalize the FULL ancestry — parent components and
# symlinks — not just trailing slashes: /var/../usr and a symlink
# to /usr must refuse exactly like /usr. realpath resolves the
# nearest existing ancestor physically, then the remainder
# lexically, so not-yet-created prefixes work too. Only exact /
# and /usr are protected (/usr/local and other subdirs stay the
# admin's explicit choice, as before).
command -v realpath >/dev/null 2>&1 || { echo "error: command 'realpath' not found on PATH (install coreutils, then re-run)" >&2; exit 3; }
_NORM="$PREFIX"
case "$_NORM" in
    /*) ;;
    *) _NORM="$(pwd)/$_NORM" ;;
esac
_rest=""
_cur="$_NORM"
while [ ! -e "$_cur" ] && [ "$_cur" != "/" ]; do
    _rest="/${_cur##*/}$_rest"
    _cur="${_cur%/*}"
    [ -n "$_cur" ] || _cur="/"
done
_canon_base="$(realpath "$_cur" 2>/dev/null || echo "$_cur")"
_NORM="$(realpath -m "$_canon_base$_rest" 2>/dev/null || echo "$_canon_base$_rest")"
[ -n "$_NORM" ] || _NORM="/"
case "$_NORM" in
    /|/usr) echo "error: refusing system prefix '$PREFIX' (canonical path '$_NORM'): /usr is system package territory (use deb/rpm there); pick a local prefix such as \$HOME/.local" >&2; exit 2 ;;
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
need_cmd mktemp "install coreutils (staging directory), then re-run"

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
host = arts.get("host-binary", {})
harvest = next((a for a in bpf if a.get("bin") == "osslscope-harvest"), {})
count = next((a for a in bpf if a.get("bin") == "osslscope-count"), {})
def s(v):
    return "" if v is None else str(v)
# One value per line: tab cannot delimit here (tab is IFS whitespace, so
# consecutive tabs collapse and empty fields vanish — a host-only manifest
# would misparse). Paths with newlines are not supported.
print("\n".join([
    host.get("path", "") or "", harvest.get("path", "") or "",
    count.get("path", "") or "",
    m.get("product_ref") or "", str(m.get("product_dirty", "")),
    s(host.get("sha256")), s(host.get("bytes")),
    s(harvest.get("sha256")), s(harvest.get("bytes")),
    s(count.get("sha256")), s(count.get("bytes"))]))
EOF
)" || exit 1
fi

HOST_BIN="$BIN_OVERRIDE"
HARVEST_OBJ="$HARVEST_OVERRIDE"
COUNT_OBJ="$COUNT_OVERRIDE"
PRODUCT_REF=""
PRODUCT_DIRTY=""
HOST_SHA=""; HOST_BYTES=""
HARVEST_SHA=""; HARVEST_BYTES=""
COUNT_SHA=""; COUNT_BYTES=""
SEL_HOST="explicit-override"
SEL_HARVEST="explicit-override"
SEL_COUNT="explicit-override"
if [ -n "$MANIFEST_PATHS" ]; then
    # Pre-initialized: command substitution strips trailing empty lines, so
    # a manifest without revision keys would otherwise make the last read
    # hit EOF and abort under set -e. Missing keys mean empty metadata.
    _m_host=""; _m_harvest=""; _m_count=""; _m_ref=""; _m_dirty=""
    _m_host_sha=""; _m_host_bytes=""
    _m_harvest_sha=""; _m_harvest_bytes=""
    _m_count_sha=""; _m_count_bytes=""
    {
        IFS= read -r _m_host || true
        IFS= read -r _m_harvest || true
        IFS= read -r _m_count || true
        IFS= read -r _m_ref || true
        IFS= read -r _m_dirty || true
        IFS= read -r _m_host_sha || true
        IFS= read -r _m_host_bytes || true
        IFS= read -r _m_harvest_sha || true
        IFS= read -r _m_harvest_bytes || true
        IFS= read -r _m_count_sha || true
        IFS= read -r _m_count_bytes || true
    } <<EOF2
$MANIFEST_PATHS
EOF2
    if [ -z "$HOST_BIN" ]; then HOST_BIN="$_m_host"; SEL_HOST="manifest-verified"; fi
    if [ -z "$HARVEST_OBJ" ]; then HARVEST_OBJ="$_m_harvest"; SEL_HARVEST="manifest-verified"; fi
    if [ -z "$COUNT_OBJ" ]; then COUNT_OBJ="$_m_count"; SEL_COUNT="manifest-verified"; fi
    HOST_SHA="$_m_host_sha"; HOST_BYTES="$_m_host_bytes"
    HARVEST_SHA="$_m_harvest_sha"; HARVEST_BYTES="$_m_harvest_bytes"
    COUNT_SHA="$_m_count_sha"; COUNT_BYTES="$_m_count_bytes"
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

# --- stage: copy the complete artifact set aside, then validate the staged
# bytes before touching the prefix, so any failure leaves an existing
# install byte-identical ---
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/osslscope-install.XXXXXX")" \
    || { echo "error: cannot create staging directory" >&2; exit 1; }
trap 'rm -rf "$STAGE"' EXIT INT TERM
STAGE_HOST="$STAGE/host-binary"
STAGE_HARVEST="$STAGE/bpf-harvest"
STAGE_COUNT="$STAGE/bpf-count"
cp "$HOST_BIN" "$STAGE_HOST" \
    || { echo "error: cannot stage host binary: $HOST_BIN" >&2; exit 1; }
cp "$HARVEST_OBJ" "$STAGE_HARVEST" \
    || { echo "error: cannot stage harvest object: $HARVEST_OBJ" >&2; exit 1; }
cp "$COUNT_OBJ" "$STAGE_COUNT" \
    || { echo "error: cannot stage count object: $COUNT_OBJ" >&2; exit 1; }

# --- manifest integrity: manifest-selected entries must carry a valid
# recorded sha256 + byte length and match the staged bytes that will be
# installed. Explicit overrides are never checked against the manifest. ---
export STAGE_HOST STAGE_HARVEST STAGE_COUNT MANIFEST
export SEL_HOST SEL_HARVEST SEL_COUNT
export HOST_SHA HOST_BYTES HARVEST_SHA HARVEST_BYTES COUNT_SHA COUNT_BYTES
python3 - <<'EOF' || exit 1
import hashlib, os, re, sys
e = os.environ
jobs = [
    ("host binary", e["STAGE_HOST"], e["SEL_HOST"], e["HOST_SHA"], e["HOST_BYTES"]),
    ("harvest object", e["STAGE_HARVEST"], e["SEL_HARVEST"], e["HARVEST_SHA"], e["HARVEST_BYTES"]),
    ("count object", e["STAGE_COUNT"], e["SEL_COUNT"], e["COUNT_SHA"], e["COUNT_BYTES"]),
]
for role, staged, sel, sha, nbytes in jobs:
    if sel != "manifest-verified":
        continue
    where = "build manifest %s" % e.get("MANIFEST")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha or ""):
        sys.exit("error: %s entry in %s records no valid sha256 "
                 "(rebuild with scripts/build-dev.sh to re-record artifact identity)" % (role, where))
    if not re.fullmatch(r"[0-9]+", nbytes or ""):
        sys.exit("error: %s entry in %s records no valid byte length "
                 "(rebuild with scripts/build-dev.sh to re-record artifact identity)" % (role, where))
    actual_len = os.path.getsize(staged)
    if actual_len != int(nbytes):
        sys.exit("error: staged %s does not match %s: byte length %d != recorded %s "
                 "(stale manifest or modified bytes? rebuild with scripts/build-dev.sh)" % (role, where, actual_len, nbytes))
    h = hashlib.sha256()
    with open(staged, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    if h.hexdigest() != sha.lower():
        sys.exit("error: staged %s does not match %s: sha256 %s != recorded %s "
                 "(stale manifest or modified bytes? rebuild with scripts/build-dev.sh)" % (role, where, h.hexdigest(), sha.lower()))
EOF

# --- fail-closed object validation (on staged bytes) ---
HOST_FILE="$(file -b "$STAGE_HOST")"
case "$HOST_FILE" in
    *ELF*x86-64*)
        [ -x "$STAGE_HOST" ] || { echo "error: host binary is not executable: $HOST_BIN" >&2; exit 1; }
        ;;
    *) echo "error: incompatible host binary (want x86-64 ELF executable): $HOST_BIN: $HOST_FILE" >&2; exit 1 ;;
esac

check_bpf() {
    # $1 = staged path, $2 = operator-facing source path, $3 = which flag (for the hint).
    # Screens the ELF header for a relocatable BPF object; whether the
    # object is usable for a role stays a loader/doctor decision, not the
    # installer's.
    _hdr="$(readelf -h "$1" 2>/dev/null || true)"
    _val() { echo "$_hdr" | sed -n "s/^ *$1: *//p"; }
    _class="$(_val Class)"; _data="$(_val Data)"
    _type="$(_val Type)"; _mach="$(_val Machine)"
    _want="want eBPF relocatable (ELF64 little-endian EM_BPF ET_REL)"
    # Positional params inside _bad_elf are its own, so the operator-facing
    # source and flag name travel in (global) shell variables.
    _bpf_src="$2"; _bpf_which="$3"
    _bad_elf() {
        echo "error: incompatible BPF object ($_want): $_bpf_src: $1" >&2
        echo "hint: rebuild with scripts/build-dev.sh, or pass an operator-built $_bpf_which object for this machine." >&2
        exit 1
    }
    case " $_class " in
        *" ELF64 "*) ;;
        *) _bad_elf "Class is ${_class:-unreadable ELF header}" ;;
    esac
    case " $_data " in
        *" little endian "*) ;;
        *) _bad_elf "Data is ${_data:-unreadable ELF header}" ;;
    esac
    case " $_type " in
        *" REL "*) ;;
        *) _bad_elf "Type is ${_type:-unreadable ELF header}" ;;
    esac
    case " $_mach " in
        *" BPF "*) ;;
        *) _bad_elf "Machine is ${_mach:-unreadable ELF header}" ;;
    esac
    _f="$(file -b "$1")"
    case "$_f" in
        *ELF*eBPF*) ;;
        *) _bad_elf "$_f" ;;
    esac
}
check_bpf "$STAGE_HARVEST" "$HARVEST_OBJ" harvest
check_bpf "$STAGE_COUNT" "$COUNT_OBJ" count

# --- install (from staged bytes: everything above already passed) ---
mkdir -p "$PREFIX/bin" "$PREFIX/lib/osslscope" "$PREFIX/share/doc/osslscope" "$PREFIX/share/osslscope"
cp "$STAGE_HOST" "$PREFIX/bin/osslscope"
chmod 755 "$PREFIX/bin/osslscope"
cp "$STAGE_HARVEST" "$PREFIX/lib/osslscope/osslscope-harvest"
cp "$STAGE_COUNT" "$PREFIX/lib/osslscope/osslscope-count"
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
        echo "hint: install libcap2-bin (Debian/Ubuntu) or libcap (Fedora/RHEL), then re-run with --setcap; or run sudo setcap cap_bpf,cap_perfmon+ep '$PREFIX/bin/osslscope' then '$PREFIX/bin/osslscope doctor'." >&2
        exit 3
    fi
    if setcap cap_bpf,cap_perfmon+ep "$PREFIX/bin/osslscope" 2>/dev/null; then
        SETCAP_STATE="applied"
    else
        echo "error: setcap failed on $PREFIX/bin/osslscope." >&2
        echo "hint: fallback (labeled sudo): run sudo setcap cap_bpf,cap_perfmon+ep '$PREFIX/bin/osslscope' then '$PREFIX/bin/osslscope doctor'." >&2
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
# Provenance is per artifact: a manifest-verified artifact keeps the build
# manifest's revision; an explicit override has no recorded revision, so it
# stays unknown (null) rather than asserting the unrelated manifest's.
def ref(sel):
    return (e.get("PRODUCT_REF") or None) if sel == "manifest-verified" else None
def dirty(sel):
    return {"True": True, "False": False}.get(e.get("PRODUCT_DIRTY")) \
        if sel == "manifest-verified" else None
arts = [
    {"role": "host-binary", "src": e["HOST_BIN"],
     "dest": pfx + "/bin/osslscope",
     "selection": e["SEL_HOST"],
     "product_ref": ref(e["SEL_HOST"]), "product_dirty": dirty(e["SEL_HOST"])},
    {"role": "bpf-object", "bin": "osslscope-harvest",
     "src": e["HARVEST_OBJ"], "dest": pfx + "/lib/osslscope/osslscope-harvest",
     "selection": e["SEL_HARVEST"],
     "product_ref": ref(e["SEL_HARVEST"]), "product_dirty": dirty(e["SEL_HARVEST"])},
    {"role": "bpf-object", "bin": "osslscope-count",
     "src": e["COUNT_OBJ"], "dest": pfx + "/lib/osslscope/osslscope-count",
     "selection": e["SEL_COUNT"],
     "product_ref": ref(e["SEL_COUNT"]), "product_dirty": dirty(e["SEL_COUNT"])},
]
for a in arts:
    # Hashes of the installed bytes, which are exactly the staged bytes:
    # staging plus the checks above mean nothing unverified reaches here.
    a.update(ident(a["dest"]))
all_verified = all(a["selection"] == "manifest-verified" for a in arts)
manifest = {
    "schema": "osslscope-install-manifest-v1",
    "installed_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "prefix": pfx,
    "build_manifest": e.get("MANIFEST") or None,
    "product_ref": (e.get("PRODUCT_REF") or None) if all_verified else None,
    "product_dirty": {"True": True, "False": False}.get(e.get("PRODUCT_DIRTY")) if all_verified else None,
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
    echo "  sudo setcap cap_bpf,cap_perfmon+ep '$PREFIX/bin/osslscope'"
    echo "  '$PREFIX/bin/osslscope' doctor"
fi
echo "done."
