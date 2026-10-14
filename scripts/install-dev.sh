#!/bin/sh
# install-dev.sh — local prefix install for development builds (R09/T13).
#
# Installs a build-dev.sh host binary plus the BPF objects into a
# user-owned prefix (default: $HOME/.local). This is the developer path to
# a usable install; system packages (deb/rpm) remain the only /usr path and
# are not final distributables during development.
#
# Prefix layout (the contract future default object resolution consumes):
#   $PREFIX/bin/osslscope
#   $PREFIX/lib/osslscope/osslscope-harvest
#   $PREFIX/lib/osslscope/osslscope-count
#   $PREFIX/lib/osslscope/osslscope-members (traversal runs only; pair-only
#     installs stay valid — the members object installs only when the
#     build manifest lists it or --members names it explicitly)
#   $PREFIX/share/doc/osslscope/install.md
#   $PREFIX/share/osslscope/install-manifest.json
#
# Artifact sources: the build-dev.sh manifest (default
# <repo>/target/dev-build-manifest.json) or explicit operator-built object
# paths (--binary/--harvest/--count/--members), which override the manifest.
#
# Rules, not suggestions:
#   - No auto-install: missing prerequisites fail with a diagnosis.
#   - Fail closed on incompatible objects: the host binary must be an
#     x86-64 ELF executable; BPF objects must be eBPF relocatables.
#   - Staged verification (R08 mechanics, members included): the
#     complete artifact set is copied aside, manifest-selected
#     artifacts are checked against the build manifest's recorded
#     sha256 + byte lengths, and the staged bytes are validated
#     before the prefix is touched — any failure leaves an existing
#     install byte-identical. Receipts publish only still-verified
#     bytes (re-verified immediately before publication).
#   - Never install into system package territory (/ or /usr).
#   - --setcap is explicit and privileged in practice: failure is a
#     deterministic error with a labeled-sudo fallback, never silent.
#
# Usage:
#   scripts/install-dev.sh [--prefix PATH] [--manifest PATH]
#                          [--binary F] [--harvest F] [--count F] [--members F]
#                          [--setcap]
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
MEMBERS_OVERRIDE=""
SETCAP=0

usage() {
    sed -n '2,27p' "$0"
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
        --members) [ $# -ge 2 ] || { echo "error: --members needs a path" >&2; exit 2; }; MEMBERS_OVERRIDE="$2"; shift 2 ;;
        --members=*) MEMBERS_OVERRIDE="${1#--members=}"; shift ;;
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

# POSIX parameter expansion instead of dirname(1): this runs before the
# prerequisite checks, so it cannot depend on any external tool.
_d="${0%/*}"; [ "$_d" = "$0" ] && _d="."
REPO="$(cd "$_d/.." && pwd)"
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
need_cmd cmp "install diffutils (staged/installed byte comparison), then re-run"
need_cmd mv "install coreutils (atomic staged replacement), then re-run"
need_cmd sed "install sed (ELF header screening), then re-run"

# --- resolve artifact sources ---
if [ -z "$BIN_OVERRIDE$HARVEST_OVERRIDE$COUNT_OVERRIDE$MEMBERS_OVERRIDE" ] && [ ! -f "$MANIFEST" ]; then
    echo "error: build manifest not found: $MANIFEST" >&2
    echo "hint: run scripts/build-dev.sh first, or pass explicit --binary/--harvest/--count paths." >&2
    exit 1
fi
if { [ -n "$BIN_OVERRIDE" ] || [ -n "$HARVEST_OVERRIDE" ] || [ -n "$COUNT_OVERRIDE" ] || [ -n "$MEMBERS_OVERRIDE" ]; } \
   && [ ! -f "$MANIFEST" ] \
   && { [ -z "$BIN_OVERRIDE" ] || [ -z "$HARVEST_OVERRIDE" ] || [ -z "$COUNT_OVERRIDE" ]; }; then
    echo "error: partial overrides with no manifest: pass all three of --binary/--harvest/--count, or build first with scripts/build-dev.sh." >&2
    exit 1
fi

# --- snapshot the manifest bytes once per run, before any read: every
# later derivation (paths, revision, hashes, lengths) comes from this
# single snapshot, so a manifest replaced mid-run cannot mix revision A
# metadata with revision B hashes. ---
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/osslscope-install.XXXXXX")" \
    || { echo "error: cannot create staging directory" >&2; exit 1; }
trap 'rm -rf "$STAGE"' EXIT INT TERM
MANIFEST_SNAP=""
if [ -f "$MANIFEST" ]; then
    MANIFEST_SNAP="$STAGE/build-manifest.snapshot.json"
    cp "$MANIFEST" "$MANIFEST_SNAP" \
        || { echo "error: cannot snapshot build manifest: $MANIFEST" >&2; exit 1; }
fi

MANIFEST_PATHS=""
if [ -n "$MANIFEST_SNAP" ]; then
    MANIFEST_PATHS="$(python3 - "$MANIFEST_SNAP" "$MANIFEST" <<'EOF'
import json, sys
try:
    m = json.load(open(sys.argv[1]))
except (OSError, ValueError) as e:
    sys.exit("error: cannot parse build manifest %s: %s" % (sys.argv[2], e))
if m.get("schema") != "osslscope-dev-build-manifest-v1":
    sys.exit("error: unsupported build manifest schema %r in %s (want osslscope-dev-build-manifest-v1; rebuild with scripts/build-dev.sh)" % (m.get("schema"), sys.argv[2]))
arts = {a.get("role"): a for a in m.get("artifacts", [])}
bpf = [a for a in m.get("artifacts", []) if a.get("role") == "bpf-object"]
host = arts.get("host-binary", {})
harvest = next((a for a in bpf if a.get("bin") == "osslscope-harvest"), {})
count = next((a for a in bpf if a.get("bin") == "osslscope-count"), {})
members = next((a for a in bpf if a.get("bin") == "osslscope-members"), {})
def s(v):
    return "" if v is None else str(v)
# One value per line: tab cannot delimit here (tab is IFS whitespace, so
# consecutive tabs collapse and empty fields vanish — a host-only manifest
# would misparse). Recorded sha256/byte lengths are NOT flattened here:
# the verifier below reads them from the manifest itself, so a hostile
# field value cannot shift positional reads and spoof another artifact's
# identity. A newline in any emitted field is refused outright.
vals = [
    s(host.get("path") or ""), s(harvest.get("path") or ""),
    s(count.get("path") or ""), s(members.get("path") or ""),
    s(m.get("product_ref") or ""), s(m.get("product_dirty", ""))]
for v in vals:
    if "\n" in v or "\r" in v:
        sys.exit("error: build manifest %s carries a newline in a field "
                 "value (refusing to parse)" % sys.argv[2])
print("\n".join(vals))
EOF
)" || exit 1
fi

HOST_BIN="$BIN_OVERRIDE"
HARVEST_OBJ="$HARVEST_OVERRIDE"
COUNT_OBJ="$COUNT_OVERRIDE"
MEMBERS_OBJ="$MEMBERS_OVERRIDE"
PRODUCT_REF=""
PRODUCT_DIRTY=""
SEL_HOST="explicit-override"
SEL_HARVEST="explicit-override"
SEL_COUNT="explicit-override"
SEL_MEMBERS="explicit-override"
if [ -n "$MANIFEST_PATHS" ]; then
    # Pre-initialized: command substitution strips trailing empty lines, so
    # a manifest without revision keys would otherwise make the last read
    # hit EOF and abort under set -e. Missing keys mean empty metadata.
    _m_host=""; _m_harvest=""; _m_count=""; _m_members=""; _m_ref=""; _m_dirty=""
    {
        IFS= read -r _m_host || true
        IFS= read -r _m_harvest || true
        IFS= read -r _m_count || true
        IFS= read -r _m_members || true
        IFS= read -r _m_ref || true
        IFS= read -r _m_dirty || true
    } <<EOF2
$MANIFEST_PATHS
EOF2
    if [ -z "$HOST_BIN" ]; then HOST_BIN="$_m_host"; SEL_HOST="manifest-verified"; fi
    if [ -z "$HARVEST_OBJ" ]; then HARVEST_OBJ="$_m_harvest"; SEL_HARVEST="manifest-verified"; fi
    if [ -z "$COUNT_OBJ" ]; then COUNT_OBJ="$_m_count"; SEL_COUNT="manifest-verified"; fi
    # Members is optional (pair-only installs stay valid): an empty
    # manifest entry is not-installed, never verified.
    if [ -z "$MEMBERS_OBJ" ]; then
        MEMBERS_OBJ="$_m_members"
        if [ -n "$MEMBERS_OBJ" ]; then SEL_MEMBERS="manifest-verified"; else SEL_MEMBERS="not-installed"; fi
    fi
    PRODUCT_REF="$_m_ref"
    PRODUCT_DIRTY="$_m_dirty"
fi
if [ -z "$MEMBERS_OBJ" ]; then SEL_MEMBERS="not-installed"; fi

[ -n "$HOST_BIN" ] || { echo "error: no host binary: manifest lists no host-binary artifact and --binary was not given (build with scripts/build-dev.sh)" >&2; exit 1; }
[ -n "$HARVEST_OBJ" ] || { echo "error: no harvest object: manifest lists no osslscope-harvest artifact and --harvest was not given (build with scripts/build-dev.sh)" >&2; exit 1; }
[ -n "$COUNT_OBJ" ] || { echo "error: no count object: manifest lists no osslscope-count artifact and --count was not given (build with scripts/build-dev.sh)" >&2; exit 1; }
# Members is optional (pair-only installs stay valid): required checks
# apply only when a members source resolved (manifest entry or override).
for _a in "$HOST_BIN" "$HARVEST_OBJ" "$COUNT_OBJ"; do
    [ -f "$_a" ] || { echo "error: artifact not found: $_a (stale manifest? rebuild with scripts/build-dev.sh)" >&2; exit 1; }
    [ -s "$_a" ] || { echo "error: artifact is empty: $_a" >&2; exit 1; }
done
if [ -n "$MEMBERS_OBJ" ]; then
    [ -f "$MEMBERS_OBJ" ] || { echo "error: artifact not found: $MEMBERS_OBJ (stale manifest? rebuild with scripts/build-dev.sh)" >&2; exit 1; }
    [ -s "$MEMBERS_OBJ" ] || { echo "error: artifact is empty: $MEMBERS_OBJ" >&2; exit 1; }
fi

# --- stage: copy the complete artifact set aside, then validate the staged
# bytes before touching the prefix, so any failure leaves an existing
# install byte-identical (the staging dir was created beside the manifest
# snapshot above, before any read) ---
STAGE_HOST="$STAGE/host-binary"
STAGE_HARVEST="$STAGE/bpf-harvest"
STAGE_COUNT="$STAGE/bpf-count"
STAGE_MEMBERS="$STAGE/bpf-members"
cp "$HOST_BIN" "$STAGE_HOST" \
    || { echo "error: cannot stage host binary: $HOST_BIN" >&2; exit 1; }
cp "$HARVEST_OBJ" "$STAGE_HARVEST" \
    || { echo "error: cannot stage harvest object: $HARVEST_OBJ" >&2; exit 1; }
cp "$COUNT_OBJ" "$STAGE_COUNT" \
    || { echo "error: cannot stage count object: $COUNT_OBJ" >&2; exit 1; }
if [ -n "$MEMBERS_OBJ" ]; then
    cp "$MEMBERS_OBJ" "$STAGE_MEMBERS" \
        || { echo "error: cannot stage members object: $MEMBERS_OBJ" >&2; exit 1; }
fi

# --- manifest integrity: manifest-selected entries must carry a valid
# recorded sha256 + byte length and match the staged bytes that will be
# installed. Explicit overrides are never checked against the manifest. ---
export STAGE_HOST STAGE_HARVEST STAGE_COUNT STAGE_MEMBERS MANIFEST MANIFEST_SNAP
export SEL_HOST SEL_HARVEST SEL_COUNT SEL_MEMBERS
verify_staged() {
    # Checks staged bytes against the single manifest snapshot; called
    # before replacement and again before the receipt publishes.
    python3 - <<'EOF' || exit 1
import hashlib, json, os, re, sys
e = os.environ
jobs = [
    ("host binary", e["STAGE_HOST"], e["SEL_HOST"]),
    ("harvest object", e["STAGE_HARVEST"], e["SEL_HARVEST"]),
    ("count object", e["STAGE_COUNT"], e["SEL_COUNT"]),
]
if e.get("SEL_MEMBERS") == "manifest-verified":
    jobs.append(("members object", e["STAGE_MEMBERS"], e["SEL_MEMBERS"]))
# Selection and verification together: recorded identities come from the
# single manifest snapshot, never through the flattened shell channel,
# so a newline-bearing JSON value cannot spoof another artifact's
# identity and a mid-run manifest swap cannot mix revisions.
recorded = {}
if any(sel == "manifest-verified" for _, _, sel in jobs):
    try:
        with open(e.get("MANIFEST_SNAP")) as f:
            m = json.load(f)
    except (OSError, ValueError, TypeError) as ex:
        sys.exit("error: cannot re-read build manifest %s: %s" % (e.get("MANIFEST"), ex))
    arts = {a.get("role"): a for a in m.get("artifacts", [])}
    bpf = [a for a in m.get("artifacts", []) if a.get("role") == "bpf-object"]
    recorded = {
        "host binary": arts.get("host-binary", {}),
        "harvest object": next((a for a in bpf if a.get("bin") == "osslscope-harvest"), {}),
        "count object": next((a for a in bpf if a.get("bin") == "osslscope-count"), {}),
        "members object": next((a for a in bpf if a.get("bin") == "osslscope-members"), {}),
    }
for role, staged, sel in jobs:
    if sel != "manifest-verified":
        continue
    where = "build manifest %s" % e.get("MANIFEST")
    rec = recorded.get(role, {})
    sha = rec.get("sha256")
    nbytes = rec.get("bytes")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
        sys.exit("error: %s entry in %s records no valid sha256 "
                 "(rebuild with scripts/build-dev.sh to re-record artifact identity)" % (role, where))
    if isinstance(nbytes, bool) or not (isinstance(nbytes, int)
            or (isinstance(nbytes, str) and re.fullmatch(r"[0-9]+", nbytes))):
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
}
verify_staged

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
if [ -n "$MEMBERS_OBJ" ]; then
    check_bpf "$STAGE_MEMBERS" "$MEMBERS_OBJ" members
fi

# --- install (from staged bytes: everything above already passed) ---
mkdir -p "$PREFIX/bin" "$PREFIX/lib/osslscope" "$PREFIX/share/doc/osslscope" "$PREFIX/share/osslscope"
BIN_DEST="$PREFIX/bin/osslscope"
HARVEST_DEST="$PREFIX/lib/osslscope/osslscope-harvest"
COUNT_DEST="$PREFIX/lib/osslscope/osslscope-count"
MEMBERS_DEST="$PREFIX/lib/osslscope/osslscope-members"
DOC_DEST="$PREFIX/share/doc/osslscope/install.md"
INST_MANIFEST="$PREFIX/share/osslscope/install-manifest.json"
# Each destination is replaced through a FRESH uniquely-owned temporary
# file (mktemp, one per run: copy plus chmod plus rename), so a symlink
# or hardlink alias at an existing destination cannot clobber an already
# installed artifact, and each single-file replacement is atomic. A
# pre-existing "<dest>.install-tmp" path — leftover or alias — refuses
# the install outright instead of being followed or reused, and the
# cleanup trap below only ever removes paths this run created.
for _legacy in "$BIN_DEST.install-tmp" "$HARVEST_DEST.install-tmp" \
        "$COUNT_DEST.install-tmp" "$MEMBERS_DEST.install-tmp" \
        "$DOC_DEST.install-tmp" \
        "$INST_MANIFEST.install-tmp"; do
    if [ -e "$_legacy" ] || [ -L "$_legacy" ]; then
        if [ "$_legacy" = "$INST_MANIFEST.install-tmp" ]; then
            echo "error: refusing to publish install receipt: stale temporary path already exists: $_legacy (remove it and re-run)" >&2
        else
            echo "error: refusing to install: stale temporary path already exists: $_legacy (remove it and re-run)" >&2
        fi
        exit 1
    fi
done
BIN_TMP="$(mktemp "$BIN_DEST.install-tmp.XXXXXX")" \
    || { echo "error: cannot create temporary file for $BIN_DEST" >&2; exit 1; }
HARVEST_TMP="$(mktemp "$HARVEST_DEST.install-tmp.XXXXXX")" \
    || { echo "error: cannot create temporary file for $HARVEST_DEST" >&2; exit 1; }
COUNT_TMP="$(mktemp "$COUNT_DEST.install-tmp.XXXXXX")" \
    || { echo "error: cannot create temporary file for $COUNT_DEST" >&2; exit 1; }
DOC_TMP="$(mktemp "$DOC_DEST.install-tmp.XXXXXX")" \
    || { echo "error: cannot create temporary file for $DOC_DEST" >&2; exit 1; }
RECEIPT_TMP="$(mktemp "$INST_MANIFEST.install-tmp.XXXXXX")" \
    || { echo "error: cannot create temporary file for $INST_MANIFEST" >&2; exit 1; }
if [ -n "$MEMBERS_OBJ" ]; then
    MEMBERS_TMP="$(mktemp "$MEMBERS_DEST.install-tmp.XXXXXX")" \
        || { echo "error: cannot create temporary file for $MEMBERS_DEST" >&2; exit 1; }
else
    MEMBERS_TMP=""
fi
trap 'rm -rf "$STAGE"; rm -f "$BIN_TMP" "$HARVEST_TMP" "$COUNT_TMP" "$DOC_TMP" "$RECEIPT_TMP" "$MEMBERS_TMP"' EXIT INT TERM
install_one() {
    # $1 = staged source, $2 = destination, $3 = temp file, $4 = mode, $5 = role label.
    # The temp file is a fresh mktemp path owned by this run; never write
    # through it if it stopped being a plain file.
    if [ -L "$3" ]; then
        echo "error: refusing to install $5: temporary path is no longer a plain file: $3" >&2
        exit 1
    fi
    cp "$1" "$3" \
        || { echo "error: cannot install $5 to $2" >&2; exit 1; }
    chmod "$4" "$3" \
        || { echo "error: cannot set permissions on $2" >&2; exit 1; }
    mv "$3" "$2" \
        || { echo "error: cannot install $5 to $2" >&2; exit 1; }
}
install_one "$STAGE_HOST" "$BIN_DEST" "$BIN_TMP" 755 "host binary"
install_one "$STAGE_HARVEST" "$HARVEST_DEST" "$HARVEST_TMP" 644 "harvest object"
install_one "$STAGE_COUNT" "$COUNT_DEST" "$COUNT_TMP" 644 "count object"
if [ -n "$MEMBERS_OBJ" ]; then
    install_one "$STAGE_MEMBERS" "$MEMBERS_DEST" "$MEMBERS_TMP" 644 "members object"
fi
# Publication verifies the bytes actually retained: the installed set
# must still match the verified staged set before any receipt is written.
cmp -s "$STAGE_HOST" "$BIN_DEST" \
    || { echo "error: installed binary no longer matches verified staged bytes: $BIN_DEST" >&2; exit 1; }
cmp -s "$STAGE_HARVEST" "$HARVEST_DEST" \
    || { echo "error: installed harvest object no longer matches verified staged bytes: $HARVEST_DEST" >&2; exit 1; }
cmp -s "$STAGE_COUNT" "$COUNT_DEST" \
    || { echo "error: installed count object no longer matches verified staged bytes: $COUNT_DEST" >&2; exit 1; }
if [ -n "$MEMBERS_OBJ" ]; then
    cmp -s "$STAGE_MEMBERS" "$MEMBERS_DEST" \
        || { echo "error: installed members object no longer matches verified staged bytes: $MEMBERS_DEST" >&2; exit 1; }
fi
if [ -f "$REPO/docs/install.md" ]; then
    install_one "$REPO/docs/install.md" "$DOC_DEST" "$DOC_TMP" 644 "install doc"
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

# --- install manifest (published atomically via temp file + rename) ---
# Re-verify the staged bytes against the single manifest snapshot before
# publishing, so the receipt only ever records still-verified bytes.
verify_staged
export PREFIX MANIFEST PRODUCT_REF PRODUCT_DIRTY SETCAP_STATE REPO RECEIPT_TMP
export HOST_BIN HARVEST_OBJ COUNT_OBJ MEMBERS_OBJ
export SEL_HOST SEL_HARVEST SEL_COUNT SEL_MEMBERS
python3 - "$INST_MANIFEST" <<'EOF' || exit 1
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
if e.get("MEMBERS_OBJ"):
    arts.append(
        {"role": "bpf-object", "bin": "osslscope-members",
         "src": e["MEMBERS_OBJ"],
         "dest": pfx + "/lib/osslscope/osslscope-members",
         "selection": e["SEL_MEMBERS"],
         "product_ref": ref(e["SEL_MEMBERS"]), "product_dirty": dirty(e["SEL_MEMBERS"])},
    )
for a in arts:
    # Hashes of the installed bytes, which the retained-identity check
    # above proved still match the verified staged bytes.
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
tmp = e.get("RECEIPT_TMP") or None
if not tmp:
    sys.exit("error: cannot write install receipt %s: no temporary path" % sys.argv[1])
try:
    # The temp file is a fresh mktemp path owned by this run; O_NOFOLLOW
    # refuses to write through it if it stopped being a plain file.
    fd = os.open(tmp, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
    with os.fdopen(fd, "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, sys.argv[1])
except OSError as ex:
    sys.exit("error: cannot write install receipt %s: %s" % (sys.argv[1], ex))
print("install manifest: " + sys.argv[1])
EOF

# --- report ---
echo "installed:"
echo "  binary:  $PREFIX/bin/osslscope"
echo "  harvest: $PREFIX/lib/osslscope/osslscope-harvest"
echo "  count:   $PREFIX/lib/osslscope/osslscope-count"
if [ -n "$MEMBERS_OBJ" ]; then
    echo "  members: $PREFIX/lib/osslscope/osslscope-members"
fi
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
