#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# test-install-dev.sh — host-runnable local-prefix install tests (no root).
#
# Exercises scripts/install-dev.sh against stub artifacts (a real x86-64
# executable + crafted EM_BPF relocatable ELF headers) and asserts:
# layout, manifest consumption, explicit overrides, fail-closed validation
# of incompatible objects, system-prefix refusal, and --setcap/missing-setcap
# diagnostics.
#
# Usage: ./scripts/tests/test-install-dev.sh
# Exit: 0 all pass; 1 any failure.
set -eu

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL="$REPO/scripts/install-dev.sh"
SH_BIN="$(command -v sh)"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT INT TERM

if [ ! -f "$INSTALL" ]; then
    bad "scripts/install-dev.sh exists"
    echo "---"; echo "pass=$PASS fail=$FAIL"; exit 1
fi
if sh -n "$INSTALL" 2>"$T/err"; then
    ok "sh -n passes: scripts/install-dev.sh"
else
    bad "sh -n passes: scripts/install-dev.sh ($(cat "$T/err"))"
fi

# --- fixtures ---
cp "$SH_BIN" "$T/host-bin"
chmod +x "$T/host-bin"
printf '#!/bin/sh\necho hi\n' >"$T/not-elf.sh"
chmod +x "$T/not-elf.sh"
python3 -c "
import struct
e = struct.pack('<16sHHIQQQIHHHHHH',
  b'\x7fELF\x02\x01\x01\x00' + b'\x00'*8, 1, 247, 1, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0)
open('$T/harvest.o','wb').write(e)
open('$T/count.o','wb').write(e)
"
cat >"$T/manifest.json" <<EOF
{"schema": "osslscope-dev-build-manifest-v1",
 "product_ref": "deadbeef-test",
 "product_ref_short": "deadbee",
 "product_dirty": false,
 "artifacts": [
   {"role": "host-binary", "path": "$T/host-bin"},
   {"role": "bpf-object", "bin": "osslscope-harvest", "path": "$T/harvest.o"},
   {"role": "bpf-object", "bin": "osslscope-count", "path": "$T/count.o"}
 ]}
EOF
# A real build-dev.sh manifest records artifact identity (sha256 + byte
# length); fill the fixture in place so manifest-selected installs verify.
python3 - "$T/manifest.json" <<'EOF'
import hashlib, json, os, sys
p = sys.argv[1]
m = json.load(open(p))
for a in m["artifacts"]:
    h = hashlib.sha256()
    with open(a["path"], "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    a["sha256"] = h.hexdigest()
    a["bytes"] = os.path.getsize(a["path"])
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
EOF

# ============ happy path: manifest-driven install ============
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfx" >"$T/out" 2>&1; then
    ok "manifest-driven install exits 0"
else
    bad "manifest-driven install exits 0 (rc=$?; $(tail -3 "$T/out" | tr '\n' '|'))"
fi
for f in bin/osslscope lib/osslscope/osslscope-harvest lib/osslscope/osslscope-count \
         share/doc/osslscope/install.md share/osslscope/install-manifest.json; do
    if [ -f "$T/pfx/$f" ]; then
        ok "layout installs $f"
    else
        bad "layout installs $f"
    fi
done
if [ -x "$T/pfx/bin/osslscope" ]; then
    ok "installed binary keeps exec bit"
else
    bad "installed binary keeps exec bit"
fi
if cmp -s "$T/host-bin" "$T/pfx/bin/osslscope" \
   && cmp -s "$T/harvest.o" "$T/pfx/lib/osslscope/osslscope-harvest" \
   && cmp -s "$T/count.o" "$T/pfx/lib/osslscope/osslscope-count"; then
    ok "installed artifacts are byte-identical"
else
    bad "installed artifacts are byte-identical"
fi
if python3 -c "import json; m=json.load(open('$T/pfx/share/osslscope/install-manifest.json')); assert m['prefix']=='$T/pfx', m; assert len(m['artifacts'])==3, m" 2>"$T/err"; then
    ok "install-manifest.json records prefix + 3 artifacts"
else
    bad "install-manifest.json records prefix + 3 artifacts ($(cat "$T/err"))"
fi
if grep -q 'NoNewPrivs' "$T/out"; then
    ok "install reports NoNewPrivs status"
else
    bad "install reports NoNewPrivs status"
fi

# Reinstall is idempotent.
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfx" >/dev/null 2>&1; then
    ok "reinstall overwrites cleanly (exit 0)"
else
    bad "reinstall overwrites cleanly (rc=$?)"
fi

# ============ explicit overrides (operator-built objects) ============
cp "$T/harvest.o" "$T/op-harvest.o"
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfx2" \
        --harvest "$T/op-harvest.o" --binary "$T/host-bin" --count "$T/count.o" \
        >/dev/null 2>&1 \
   && cmp -s "$T/op-harvest.o" "$T/pfx2/lib/osslscope/osslscope-harvest"; then
    ok "explicit --binary/--harvest/--count override manifest paths"
else
    bad "explicit --binary/--harvest/--count override manifest paths"
fi

# ============ default prefix honors $HOME (never touches real HOME) ============
if HOME="$T/fakehome" "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" >/dev/null 2>&1 \
   && [ -x "$T/fakehome/.local/bin/osslscope" ]; then
    ok "default prefix is \$HOME/.local"
else
    bad "default prefix is \$HOME/.local"
fi

# ============ fail-closed validation ============
if "$SH_BIN" "$INSTALL" --manifest "$T/does-not-exist.json" --prefix "$T/pfx3" >"$T/out" 2>&1; then
    bad "missing manifest fails (got exit 0)"
else
    grep -q 'build-dev.sh' "$T/out" \
        && ok "missing manifest fails with build-dev.sh diagnosis" \
        || bad "missing manifest fails with build-dev.sh diagnosis"
fi

cat >"$T/host-only-manifest.json" <<EOF
{"schema": "osslscope-dev-build-manifest-v1",
 "product_ref": null, "product_dirty": null,
 "artifacts": [{"role": "host-binary", "path": "$T/host-bin"}]}
EOF
if "$SH_BIN" "$INSTALL" --manifest "$T/host-only-manifest.json" --prefix "$T/pfxho" >"$T/out" 2>&1; then
    bad "host-only manifest fails (got exit 0)"
else
    grep -q 'no harvest object' "$T/out" \
        && ok "host-only manifest fails naming the missing harvest object" \
        || bad "host-only manifest fails naming the missing harvest object (saw: $(head -1 "$T/out"))"
fi

if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfx4" \
        --count "$T/host-bin" >"$T/out" 2>&1; then
    bad "x86-64 executable as BPF object fails closed (got exit 0)"
else
    grep -qi 'ebpf' "$T/out" \
        && ok "x86-64 executable as BPF object fails closed with eBPF diagnosis" \
        || bad "x86-64 executable as BPF object fails closed with eBPF diagnosis"
fi

if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfx5" \
        --binary "$T/not-elf.sh" >"$T/out" 2>&1; then
    bad "shell script as host binary fails closed (got exit 0)"
else
    grep -qi 'ELF.*x86-64\|x86-64.*ELF' "$T/out" \
        && ok "shell script as host binary fails closed with arch diagnosis" \
        || bad "shell script as host binary fails closed with arch diagnosis"
fi

echo '{"schema": "something-else-v9", "artifacts": []}' >"$T/bad-schema.json"
if "$SH_BIN" "$INSTALL" --manifest "$T/bad-schema.json" --prefix "$T/pfxs" >"$T/out" 2>&1; then
    bad "wrong-schema manifest fails (got exit 0)"
else
    grep -q 'unsupported build manifest schema' "$T/out" \
        && ok "wrong-schema manifest fails closed with schema diagnosis" \
        || bad "wrong-schema manifest fails closed with schema diagnosis"
fi

if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix /usr >"$T/out" 2>&1; then
    bad "--prefix /usr refused (got exit 0)"
else
    grep -qi 'system package\|refuse' "$T/out" \
        && ok "--prefix /usr refused with system-package diagnosis" \
        || bad "--prefix /usr refused with system-package diagnosis"
fi

if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix / >"$T/out" 2>&1; then
    bad "--prefix / refused (got exit 0)"
else
    ok "--prefix / refused"
fi

for sys in "/usr/." "/usr//" "/usr/./"; do
    if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$sys" >"$T/out" 2>&1; then
        bad "--prefix $sys refused (got exit 0)"
    else
        grep -qi 'system package\|refuse' "$T/out" \
            && ok "--prefix $sys refused as system path" \
            || bad "--prefix $sys refused as system path"
    fi
done

# F-G/B11: canonical aliases of protected destinations must refuse
# with the system-package diagnosis (not a later mkdir/cp error).
for sys in "/var/../usr" "/usr/../usr" "/tmp/../usr" "/usr/bin/.."; do
    if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$sys" >"$T/out" 2>&1; then
        bad "--prefix $sys refused (got exit 0)"
    else
        grep -qi 'system package\|refuse' "$T/out" \
            && ok "--prefix $sys refused as system-path alias" \
            || bad "--prefix $sys refused as system-path alias ($(head -1 "$T/out"))"
    fi
done
ln -s /usr "$T/evil-usr"
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/evil-usr" >"$T/out" 2>&1; then
    bad "symlink-to-/usr prefix refused (got exit 0)"
else
    grep -qi 'system package\|refuse' "$T/out" \
        && ok "symlink-to-/usr prefix refused as system-path alias" \
        || bad "symlink-to-/usr prefix refused as system-path alias ($(head -1 "$T/out"))"
fi
ln -s / "$T/evil-root"
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/evil-root" >"$T/out" 2>&1; then
    bad "symlink-to-/ prefix refused (got exit 0)"
else
    grep -qi 'system package\|refuse' "$T/out" \
        && ok "symlink-to-/ prefix refused as system-path alias" \
        || bad "symlink-to-/ prefix refused as system-path alias ($(head -1 "$T/out"))"
fi
# Positive controls: `..`/symlinks resolving inside allowed space install.
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfx/../pfx-ok" >"$T/out" 2>&1 \
   && [ -x "$T/pfx-ok/bin/osslscope" ]; then
    ok "dotdot prefix resolving to allowed space still installs"
else
    bad "dotdot prefix resolving to allowed space still installs ($(head -1 "$T/out"))"
fi
mkdir -p "$T/real-pfx"
ln -s "$T/real-pfx" "$T/link-pfx"
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/link-pfx" >"$T/out" 2>&1 \
   && [ -x "$T/real-pfx/bin/osslscope" ]; then
    ok "symlink prefix resolving to allowed space still installs"
else
    bad "symlink prefix resolving to allowed space still installs ($(head -1 "$T/out"))"
fi

# Manifest without revision keys must still install (keys are metadata).
python3 -c "
import json
m = json.load(open('$T/manifest.json'))
del m['product_ref']; del m['product_dirty']
json.dump(m, open('$T/norev-manifest.json', 'w'))
"
if "$SH_BIN" "$INSTALL" --manifest "$T/norev-manifest.json" --prefix "$T/pfxnr" >"$T/out" 2>&1 \
   && [ -x "$T/pfxnr/bin/osslscope" ]; then
    ok "manifest without revision keys still installs"
else
    bad "manifest without revision keys still installs (rc=$?; $(head -1 "$T/out"))"
fi

# Printed follow-up commands quote the prefix path.
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/my pfx" >"$T/out" 2>&1; then
    grep -q "setcap cap_bpf,cap_perfmon+ep '$T/my pfx/bin/osslscope'" "$T/out" \
        && ok "follow-up setcap hint quotes spaced prefix path" \
        || bad "follow-up setcap hint quotes spaced prefix path"
else
    bad "spaced prefix installs (rc=$?)"
fi

# ============ install receipt: verified selection + honest provenance ============
# Manifest-driven install records manifest-verified selection with hashes
# matching the staged sources, and keeps the manifest revision.
if python3 -c "
import hashlib, json
m = json.load(open('$T/pfx/share/osslscope/install-manifest.json'))
assert [a['selection'] for a in m['artifacts']] == ['manifest-verified'] * 3, m['artifacts']
for a in m['artifacts']:
    h = hashlib.sha256(open(a['src'], 'rb').read()).hexdigest()
    assert a['sha256'] == h, (a['dest'], a['sha256'], h)
    assert a['product_ref'] == 'deadbeef-test' and a['product_dirty'] is False, a
assert m['product_ref'] == 'deadbeef-test' and m['product_dirty'] is False, m
" 2>"$T/err"; then
    ok "manifest install receipt: all manifest-verified, hashes match sources, revision kept"
else
    bad "manifest install receipt: all manifest-verified, hashes match sources, revision kept ($(cat "$T/err"))"
fi

# Full explicit override beside a manifest: nothing is asserted from the
# unrelated manifest; provenance stays explicit/unknown.
if python3 -c "
import json
m = json.load(open('$T/pfx2/share/osslscope/install-manifest.json'))
assert [a['selection'] for a in m['artifacts']] == ['explicit-override'] * 3, m['artifacts']
for a in m['artifacts']:
    assert a['product_ref'] is None and a['product_dirty'] is None, a
assert m['product_ref'] is None and m['product_dirty'] is None, m
" 2>"$T/err"; then
    ok "full-override receipt: all explicit-override, no revision from unrelated manifest"
else
    bad "full-override receipt: all explicit-override, no revision from unrelated manifest ($(cat "$T/err"))"
fi

# Mixed selection: the overridden harvest is explicit, the rest verified,
# and the installed set claims no single build revision.
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxm" \
        --harvest "$T/op-harvest.o" >/dev/null 2>&1 \
   && python3 -c "
import json
m = json.load(open('$T/pfxm/share/osslscope/install-manifest.json'))
sel = {a.get('bin', a['role']): a['selection'] for a in m['artifacts']}
assert sel == {'host-binary': 'manifest-verified', 'osslscope-harvest': 'explicit-override', 'osslscope-count': 'manifest-verified'}, sel
assert m['product_ref'] is None and m['product_dirty'] is None, m
" 2>"$T/err"; then
    ok "mixed install: per-artifact selection, set revision unknown"
else
    bad "mixed install: per-artifact selection, set revision unknown ($(cat "$T/err" 2>/dev/null))"
fi

# Explicit overrides stay functional when their bytes differ from the
# manifest: the override is screened, not hash-checked against it.
python3 -c "
import struct
e = struct.pack('<16sHHIQQQIHHHHHH',
  b'\x7fELF\x02\x01\x01\x00' + b'\x00'*8, 1, 247, 1, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0)
open('$T/op2-harvest.o','wb').write(e + b'operator-built-padding')
"
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxo" \
        --harvest "$T/op2-harvest.o" >/dev/null 2>&1 \
   && cmp -s "$T/op2-harvest.o" "$T/pfxo/lib/osslscope/osslscope-harvest" \
   && ! cmp -s "$T/harvest.o" "$T/pfxo/lib/osslscope/osslscope-harvest" >/dev/null 2>&1; then
    ok "override with non-manifest bytes installs the override bytes"
else
    bad "override with non-manifest bytes installs the override bytes"
fi

# ============ staged verification: manifest integrity negatives ============
# Byte snapshot of every installed file for failure-atomicity checks.
snapshot_prefix() { (cd "$1" && find . -type f -exec sha256sum {} + | LC_ALL=C sort) >"$2"; }

# Existing prefix under test: install the good set once, then every negative
# below must fail closed and leave it byte-identical.
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxv" >/dev/null 2>&1; then
    ok "setup: good install into prefix-under-test"
else
    bad "setup: good install into prefix-under-test"
fi
snapshot_prefix "$T/pfxv" "$T/pfxv.snap"

# Unchanged-manifest positive control: installing from the unmodified
# manifest verifies every artifact.
if python3 -c "
import json
m = json.load(open('$T/pfxv/share/osslscope/install-manifest.json'))
assert [a['selection'] for a in m['artifacts']] == ['manifest-verified'] * 3, m['artifacts']
assert m['product_ref'] == 'deadbeef-test', m
" 2>"$T/err"; then
    ok "unchanged manifest verifies all artifacts (positive control)"
else
    bad "unchanged manifest verifies all artifacts (positive control) ($(cat "$T/err"))"
fi

# Variant manifests: copies of the fixtures plus a freshly hashed manifest.
mk_variant() {
    mkdir -p "$1"
    cp "$T/host-bin" "$1/host-bin"
    cp "$T/harvest.o" "$1/harvest.o"
    cp "$T/count.o" "$1/count.o"
    python3 - "$1" "${2:-variant-ref}" <<'EOF'
import hashlib, json, os, sys
d, ref = sys.argv[1], sys.argv[2]
def ident(role, path, extra=None):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    a = {"role": role, "path": path, "sha256": h.hexdigest(),
         "bytes": os.path.getsize(path)}
    if extra:
        a.update(extra)
    return a
m = {"schema": "osslscope-dev-build-manifest-v1",
     "product_ref": ref, "product_dirty": False,
     "artifacts": [
        ident("host-binary", d + "/host-bin"),
        ident("bpf-object", d + "/harvest.o", {"bin": "osslscope-harvest"}),
        ident("bpf-object", d + "/count.o", {"bin": "osslscope-count"})]}
json.dump(m, open(d + "/manifest.json", "w"), indent=2, sort_keys=True)
EOF
}

# Mutated bytes, same length: sha256 must mismatch while length still matches.
mk_variant "$T/v-mut"
python3 -c "
p = '$T/v-mut/harvest.o'
b = bytearray(open(p, 'rb').read())
b[40] ^= 0xff
open(p, 'wb').write(bytes(b))
"
if "$SH_BIN" "$INSTALL" --manifest "$T/v-mut/manifest.json" --prefix "$T/pfxv" >"$T/out" 2>&1; then
    bad "mutated-bytes manifest fails (got exit 0)"
else
    grep -q 'sha256' "$T/out" \
        && ok "mutated bytes fail with sha256 diagnosis" \
        || bad "mutated bytes fail with sha256 diagnosis (saw: $(head -1 "$T/out"))"
    snapshot_prefix "$T/pfxv" "$T/pfxv.now"
    cmp -s "$T/pfxv.snap" "$T/pfxv.now" \
        && ok "mutated-bytes failure leaves existing prefix unchanged" \
        || bad "mutated-bytes failure leaves existing prefix unchanged"
fi

# Missing recorded hash: a manifest-selected entry without sha256 fails.
mk_variant "$T/v-nohash"
python3 -c "
import json
p = '$T/v-nohash/manifest.json'
m = json.load(open(p))
for a in m['artifacts']:
    if a.get('bin') == 'osslscope-count':
        del a['sha256']
json.dump(m, open(p, 'w'), indent=2, sort_keys=True)
"
if "$SH_BIN" "$INSTALL" --manifest "$T/v-nohash/manifest.json" --prefix "$T/pfxv" >"$T/out" 2>&1; then
    bad "missing-hash manifest fails (got exit 0)"
else
    grep -q 'sha256' "$T/out" \
        && ok "missing hash fails with sha256 diagnosis" \
        || bad "missing hash fails with sha256 diagnosis (saw: $(head -1 "$T/out"))"
    snapshot_prefix "$T/pfxv" "$T/pfxv.now"
    cmp -s "$T/pfxv.snap" "$T/pfxv.now" \
        && ok "missing-hash failure leaves existing prefix unchanged" \
        || bad "missing-hash failure leaves existing prefix unchanged"
fi

# Wrong recorded length: the bytes field off by one fails even though the
# unmutated file's sha256 would still match.
mk_variant "$T/v-len"
python3 -c "
import json
p = '$T/v-len/manifest.json'
m = json.load(open(p))
for a in m['artifacts']:
    if a.get('role') == 'host-binary':
        a['bytes'] += 1
json.dump(m, open(p, 'w'), indent=2, sort_keys=True)
"
if "$SH_BIN" "$INSTALL" --manifest "$T/v-len/manifest.json" --prefix "$T/pfxv" >"$T/out" 2>&1; then
    bad "wrong-length manifest fails (got exit 0)"
else
    grep -qi 'byte length' "$T/out" \
        && ok "wrong length fails with byte-length diagnosis" \
        || bad "wrong length fails with byte-length diagnosis (saw: $(head -1 "$T/out"))"
    snapshot_prefix "$T/pfxv" "$T/pfxv.now"
    cmp -s "$T/pfxv.snap" "$T/pfxv.now" \
        && ok "wrong-length failure leaves existing prefix unchanged" \
        || bad "wrong-length failure leaves existing prefix unchanged"
fi

# Malformed recorded hash (not 64 hex chars) fails like a missing one.
mk_variant "$T/v-badhash"
python3 -c "
import json
p = '$T/v-badhash/manifest.json'
m = json.load(open(p))
m['artifacts'][0]['sha256'] = 'not-a-hash'
json.dump(m, open(p, 'w'), indent=2, sort_keys=True)
"
if "$SH_BIN" "$INSTALL" --manifest "$T/v-badhash/manifest.json" --prefix "$T/pfxv" >"$T/out" 2>&1; then
    bad "malformed-hash manifest fails (got exit 0)"
else
    grep -q 'sha256' "$T/out" \
        && ok "malformed hash fails with sha256 diagnosis" \
        || bad "malformed hash fails with sha256 diagnosis (saw: $(head -1 "$T/out"))"
    snapshot_prefix "$T/pfxv" "$T/pfxv.now"
    cmp -s "$T/pfxv.snap" "$T/pfxv.now" \
        && ok "malformed-hash failure leaves existing prefix unchanged" \
        || bad "malformed-hash failure leaves existing prefix unchanged"
fi

# ============ staged verification: ELF64 LE EM_BPF ET_REL screen ============
# Each variant passes the historical checks (file(1) says eBPF, readelf
# Machine is BPF) and must be rejected by the new header screen — as explicit
# overrides (screened, not hash-checked) against the existing prefix.
python3 -c "
import struct
def hdr(cls, data, typ):
    e = b'\x7fELF' + bytes([cls, data, 1, 0]) + b'\x00'*8
    bo = '<' if data == 1 else '>'
    if cls == 1:
        return struct.pack(bo + '16sHHIIIIIHHHHHH', e, typ, 247, 1, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0)
    return struct.pack(bo + '16sHHIQQQIHHHHHH', e, typ, 247, 1, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0)
open('$T/bpf-exec.o', 'wb').write(hdr(2, 1, 2))
open('$T/bpf-dyn.o', 'wb').write(hdr(2, 1, 3))
open('$T/bpf-elf32.o', 'wb').write(hdr(1, 1, 1))
open('$T/bpf-be.o', 'wb').write(hdr(2, 2, 1))
"
# Sanity: variants really do pass the historical checks (else the negatives
# would prove nothing about the new screen).
for _v in exec dyn elf32 be; do
    case "$(file -b "$T/bpf-$_v.o")" in
        *ELF*eBPF*) ok "fixture bpf-$_v.o passes historical file(1) eBPF check" ;;
        *) bad "fixture bpf-$_v.o passes historical file(1) eBPF check" ;;
    esac
    case "$(readelf -h "$T/bpf-$_v.o" 2>/dev/null | grep 'Machine:' || true)" in
        *BPF*) ok "fixture bpf-$_v.o passes historical Machine-BPF check" ;;
        *) bad "fixture bpf-$_v.o passes historical Machine-BPF check" ;;
    esac
done
check_elf_reject() {
    if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxv" \
            --harvest "$1" >"$T/out" 2>&1; then
        bad "$2 rejected (got exit 0)"
    else
        grep -q "$3" "$T/out" \
            && ok "$2 rejected with diagnosis ($3)" \
            || bad "$2 rejected with diagnosis ($3) (saw: $(head -1 "$T/out"))"
        snapshot_prefix "$T/pfxv" "$T/pfxv.now"
        cmp -s "$T/pfxv.snap" "$T/pfxv.now" \
            && ok "$2 failure leaves existing prefix unchanged" \
            || bad "$2 failure leaves existing prefix unchanged"
    fi
}
check_elf_reject "$T/bpf-exec.o" "ET_EXEC BPF object" "Type is EXEC"
check_elf_reject "$T/bpf-dyn.o" "ET_DYN BPF object" "Type is DYN"
check_elf_reject "$T/bpf-elf32.o" "ELF32 BPF object" "Class is ELF32"
check_elf_reject "$T/bpf-be.o" "big-endian BPF object" "big endian"

# ============ fix round: newline-smuggled manifest identities ============
# A host sha256 field carrying newline-separated values must not supply
# identities for the other artifacts through positional reads; BPF
# entries without recorded hashes fail even when the smuggled values
# would verify.
mk_variant "$T/v-smuggle"
python3 - "$T/v-smuggle" <<'EOF'
import hashlib, json, os, sys
d = sys.argv[1]
def ident(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest(), os.path.getsize(p)
hh, hl = ident(d + "/host-bin")
vh, vl = ident(d + "/harvest.o")
ch, cl = ident(d + "/count.o")
p = d + "/manifest.json"
m = json.load(open(p))
for a in m["artifacts"]:
    if a.get("role") == "host-binary":
        a["sha256"] = "\n".join([hh, str(hl), vh, str(vl), ch, str(cl)])
    else:
        a.pop("sha256", None)
        a.pop("bytes", None)
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
EOF
if "$SH_BIN" "$INSTALL" --manifest "$T/v-smuggle/manifest.json" --prefix "$T/pfxv" >"$T/out" 2>&1; then
    bad "newline-smuggled manifest identities fail (got exit 0)"
else
    grep -q 'sha256\|newline' "$T/out" \
        && ok "newline-smuggled identities fail closed with identity diagnosis" \
        || bad "newline-smuggled identities fail closed with identity diagnosis (saw: $(head -1 "$T/out"))"
    snapshot_prefix "$T/pfxv" "$T/pfxv.now"
    cmp -s "$T/pfxv.snap" "$T/pfxv.now" \
        && ok "smuggled-identity failure leaves existing prefix unchanged" \
        || bad "smuggled-identity failure leaves existing prefix unchanged"
fi

# ============ fix round: aliased destinations keep verified identities ============
# Distinct harvest/count bytes; existing destinations aliased (symlink and
# hardlink). Reinstall must succeed with each destination holding its own
# verified bytes and the receipt matching the verified staged sources.
mk_variant "$T/v-distinct"
python3 - "$T/v-distinct" <<'EOF'
import hashlib, json, os, sys
d = sys.argv[1]
for name, pad in (("harvest.o", b"-harvest-pad"), ("count.o", b"-count-pad--")):
    p = d + "/" + name
    with open(p, "ab") as f:
        f.write(pad)
p = d + "/manifest.json"
m = json.load(open(p))
for a in m["artifacts"]:
    a["sha256"] = hashlib.sha256(open(a["path"], "rb").read()).hexdigest()
    a["bytes"] = os.path.getsize(a["path"])
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
EOF
check_aliased_reinstall() {
    if "$SH_BIN" "$INSTALL" --manifest "$T/v-distinct/manifest.json" --prefix "$2" >/dev/null 2>&1; then
        ok "setup: good distinct-bytes install into $1-alias prefix"
    else
        bad "setup: good distinct-bytes install into $1-alias prefix"
        return 0
    fi
    rm "$2/lib/osslscope/osslscope-count"
    if [ "$1" = "symlink" ]; then
        ln -s osslscope-harvest "$2/lib/osslscope/osslscope-count"
    else
        ln "$2/lib/osslscope/osslscope-harvest" "$2/lib/osslscope/osslscope-count"
    fi
    if "$SH_BIN" "$INSTALL" --manifest "$T/v-distinct/manifest.json" --prefix "$2" >"$T/out" 2>&1; then
        ok "reinstall over $1-aliased destinations exits 0"
    else
        bad "reinstall over $1-aliased destinations exits 0 (rc=$?; $(head -1 "$T/out"))"
        return 0
    fi
    if cmp -s "$T/v-distinct/harvest.o" "$2/lib/osslscope/osslscope-harvest" \
       && cmp -s "$T/v-distinct/count.o" "$2/lib/osslscope/osslscope-count"; then
        ok "$1 alias: each destination holds its own verified bytes"
    else
        bad "$1 alias: each destination holds its own verified bytes"
    fi
    if python3 -c "
import hashlib, json
m = json.load(open('$2/share/osslscope/install-manifest.json'))
h = {a.get('bin', a['role']): a for a in m['artifacts']}
for name in ('osslscope-harvest', 'osslscope-count'):
    src = '$T/v-distinct/' + name.split('-')[1] + '.o'
    want = hashlib.sha256(open(src, 'rb').read()).hexdigest()
    assert h[name]['sha256'] == want, (name, h[name]['sha256'], want)
" 2>"$T/err"; then
        ok "$1 alias: receipt hashes match the verified staged sources"
    else
        bad "$1 alias: receipt hashes match the verified staged sources ($(cat "$T/err"))"
    fi
}
check_aliased_reinstall symlink "$T/pfxa-sym"
check_aliased_reinstall hardlink "$T/pfxa-hard"

# ============ fix round: final-write fault controls ============
# Post-validation write failures (artifact copy, chmod, receipt publish)
# fail deterministically; the receipt publish is atomic so a failure
# never leaves a truncated receipt.
REAL_CP="$(command -v cp)"
mk_tool_farm() {
    mkdir -p "$1"
    for tool in python3 file readelf cp mkdir chmod mktemp mv cmp rm grep awk sed cat realpath; do
        dest="$(command -v "$tool")" || { echo "test prereq missing: $tool" >&2; exit 1; }
        ln -sf "$dest" "$1/$tool"
    done
}
mk_tool_farm "$T/faultbin-cp"
rm "$T/faultbin-cp/cp"
cat >"$T/faultbin-cp/cp" <<EOF
#!/bin/sh
: "\${FAIL_CP_PREFIX:?test bug: FAIL_CP_PREFIX unset}"
for _a in "\$@"; do
    case "\$_a" in
        "\$FAIL_CP_PREFIX"*) echo "fault-injected cp failure: \$_a" >&2; exit 1 ;;
    esac
done
exec "$REAL_CP" "\$@"
EOF
chmod +x "$T/faultbin-cp/cp"

# Artifact-copy failure at replacement start: deterministic error, prefix kept.
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxc" >/dev/null 2>&1; then
    ok "setup: good install into copy-fault prefix"
else
    bad "setup: good install into copy-fault prefix"
fi
snapshot_prefix "$T/pfxc" "$T/pfxc.snap"
if FAIL_CP_PREFIX="$T/pfxc" PATH="$T/faultbin-cp:$PATH" "$SH_BIN" "$INSTALL" \
        --manifest "$T/manifest.json" --prefix "$T/pfxc" >"$T/out" 2>&1; then
    bad "artifact-copy fault fails (got exit 0)"
else
    grep -q 'cannot install' "$T/out" \
        && ok "artifact-copy fault fails with install diagnosis" \
        || bad "artifact-copy fault fails with install diagnosis (saw: $(head -1 "$T/out"))"
    snapshot_prefix "$T/pfxc" "$T/pfxc.now"
    cmp -s "$T/pfxc.snap" "$T/pfxc.now" \
        && ok "artifact-copy fault leaves existing prefix unchanged" \
        || bad "artifact-copy fault leaves existing prefix unchanged"
fi

# Artifact-copy failure mid-replacement: the install stops; already
# replaced artifacts keep validated bytes, the failed artifact and the
# receipt keep prior bytes (rerun to complete).
mk_variant "$T/v-new"
python3 -c "
import hashlib, json
d = '$T/v-new'
open(d + '/harvest.o', 'ab').write(b'-new-bytes-harvest')
open(d + '/count.o', 'ab').write(b'-new-bytes-count--')
open(d + '/host-bin', 'ab').write(b'new')
p = d + '/manifest.json'
m = json.load(open(p))
for a in m['artifacts']:
    a['sha256'] = hashlib.sha256(open(a['path'], 'rb').read()).hexdigest()
    import os
    a['bytes'] = os.path.getsize(a['path'])
json.dump(m, open(p, 'w'), indent=2, sort_keys=True)
"
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxm2" >/dev/null 2>&1; then
    ok "setup: good install into mid-replacement prefix"
else
    bad "setup: good install into mid-replacement prefix"
fi
cp "$T/pfxm2/share/osslscope/install-manifest.json" "$T/pfxm2.receipt-orig"
if FAIL_CP_PREFIX="$T/pfxm2/lib/osslscope/osslscope-count" PATH="$T/faultbin-cp:$PATH" "$SH_BIN" "$INSTALL" \
        --manifest "$T/v-new/manifest.json" --prefix "$T/pfxm2" >"$T/out" 2>&1; then
    bad "mid-replacement copy fault fails (got exit 0)"
else
    grep -q 'cannot install' "$T/out" \
        && ok "mid-replacement copy fault fails with install diagnosis" \
        || bad "mid-replacement copy fault fails with install diagnosis (saw: $(head -1 "$T/out"))"
    cmp -s "$T/v-new/host-bin" "$T/pfxm2/bin/osslscope" \
        && ok "mid-replacement fault: replaced artifact keeps validated bytes" \
        || bad "mid-replacement fault: replaced artifact keeps validated bytes"
    cmp -s "$T/count.o" "$T/pfxm2/lib/osslscope/osslscope-count" \
        && ok "mid-replacement fault: failed artifact keeps prior bytes" \
        || bad "mid-replacement fault: failed artifact keeps prior bytes"
    cmp -s "$T/pfxm2.receipt-orig" "$T/pfxm2/share/osslscope/install-manifest.json" \
        && ok "mid-replacement fault: receipt keeps prior bytes" \
        || bad "mid-replacement fault: receipt keeps prior bytes"
fi

# chmod failure during replacement: deterministic permissions error.
mk_tool_farm "$T/faultbin-chmod"
rm "$T/faultbin-chmod/chmod"
cat >"$T/faultbin-chmod/chmod" <<'EOF'
#!/bin/sh
echo "fault-injected chmod failure" >&2
exit 1
EOF
chmod +x "$T/faultbin-chmod/chmod"
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxh" >/dev/null 2>&1; then
    ok "setup: good install into chmod-fault prefix"
else
    bad "setup: good install into chmod-fault prefix"
fi
snapshot_prefix "$T/pfxh" "$T/pfxh.snap"
if PATH="$T/faultbin-chmod:$PATH" "$SH_BIN" "$INSTALL" \
        --manifest "$T/manifest.json" --prefix "$T/pfxh" >"$T/out" 2>&1; then
    bad "chmod fault fails (got exit 0)"
else
    grep -q 'cannot set permissions' "$T/out" \
        && ok "chmod fault fails with permissions diagnosis" \
        || bad "chmod fault fails with permissions diagnosis (saw: $(head -1 "$T/out"))"
    snapshot_prefix "$T/pfxh" "$T/pfxh.now"
    cmp -s "$T/pfxh.snap" "$T/pfxh.now" \
        && ok "chmod fault leaves existing prefix unchanged" \
        || bad "chmod fault leaves existing prefix unchanged"
fi

# Receipt-publish failure: deterministic error and the prior receipt kept
# byte-identical (atomic temp-file + rename publish).
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxr" >/dev/null 2>&1; then
    ok "setup: good install into receipt-fault prefix"
else
    bad "setup: good install into receipt-fault prefix"
fi
cp "$T/pfxr/share/osslscope/install-manifest.json" "$T/pfxr.receipt-orig"
mkdir "$T/pfxr/share/osslscope/install-manifest.json.install-tmp"
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxr" >"$T/out" 2>&1; then
    bad "blocked receipt publish fails (got exit 0)"
else
    grep -qi 'receipt' "$T/out" \
        && ok "blocked receipt publish fails with receipt diagnosis" \
        || bad "blocked receipt publish fails with receipt diagnosis (saw: $(head -1 "$T/out"))"
    cmp -s "$T/pfxr.receipt-orig" "$T/pfxr/share/osslscope/install-manifest.json" \
        && ok "blocked receipt publish keeps the prior receipt byte-identical" \
        || bad "blocked receipt publish keeps the prior receipt byte-identical"
fi
rmdir "$T/pfxr/share/osslscope/install-manifest.json.install-tmp" || true

# Receipt path unusable (a directory): deterministic receipt error, no success.
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxr2" >/dev/null 2>&1; then
    ok "setup: good install into receipt-path prefix"
else
    bad "setup: good install into receipt-path prefix"
fi
rm "$T/pfxr2/share/osslscope/install-manifest.json"
mkdir "$T/pfxr2/share/osslscope/install-manifest.json"
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxr2" >"$T/out" 2>&1; then
    bad "unwritable receipt path fails (got exit 0)"
else
    grep -qi 'receipt' "$T/out" \
        && ok "unwritable receipt path fails with receipt diagnosis" \
        || bad "unwritable receipt path fails with receipt diagnosis (saw: $(head -1 "$T/out"))"
fi

# ============ fix round 2: stale temp paths fail closed ============
# Temporary paths are fresh per run; a pre-existing "<dest>.install-tmp"
# path is refused, never followed, and cleanup removes only paths this
# run created.

# Doc temp path symlinked at the already-checked harvest: reinstall must
# refuse, leaving the verified harvest bytes intact.
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxalias" >/dev/null 2>&1; then
    ok "setup: good install into temp-alias prefix"
else
    bad "setup: good install into temp-alias prefix"
fi
snapshot_prefix "$T/pfxalias" "$T/pfxalias.snap"
ln -s "$T/pfxalias/lib/osslscope/osslscope-harvest" "$T/pfxalias/share/doc/osslscope/install.md.install-tmp"
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxalias" >"$T/out" 2>&1; then
    bad "doc temp-path symlink fails (got exit 0)"
else
    grep -qi 'temporary.*exists\|refus' "$T/out" \
        && ok "doc temp-path symlink fails closed with temp-path diagnosis" \
        || bad "doc temp-path symlink fails closed with temp-path diagnosis (saw: $(head -1 "$T/out"))"
    cmp -s "$T/harvest.o" "$T/pfxalias/lib/osslscope/osslscope-harvest" \
        && ok "doc temp-path symlink leaves already-checked harvest bytes intact" \
        || bad "doc temp-path symlink leaves already-checked harvest bytes intact"
    snapshot_prefix "$T/pfxalias" "$T/pfxalias.now"
    cmp -s "$T/pfxalias.snap" "$T/pfxalias.now" \
        && ok "doc temp-path symlink failure leaves existing prefix unchanged" \
        || bad "doc temp-path symlink failure leaves existing prefix unchanged"
fi

# Receipt temp path hardlinked to the live receipt, with a fault injected
# DURING the receipt-byte write: the prior receipt must survive byte-identical.
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxrw" >/dev/null 2>&1; then
    ok "setup: good install into mid-write receipt prefix"
else
    bad "setup: good install into mid-write receipt prefix"
fi
cp "$T/pfxrw/share/osslscope/install-manifest.json" "$T/pfxrw.receipt-orig"
ln "$T/pfxrw/share/osslscope/install-manifest.json" "$T/pfxrw/share/osslscope/install-manifest.json.install-tmp"
mkdir -p "$T/pyfault"
cat >"$T/pyfault/sitecustomize.py" <<'EOF'
import os, sys
if os.environ.get("FAULT_RECEIPT_MIDWRITE") == "1" and len(sys.argv) == 2 and sys.argv[1].endswith("/install-manifest.json"):
    import json as _json
    def _faulting_dump(obj, fp, *a, **k):
        fp.write('{"fault": "partial-bytes",\n')
        fp.flush()
        raise OSError("fault-injected mid-write receipt failure")
    _json.dump = _faulting_dump
EOF
if FAULT_RECEIPT_MIDWRITE=1 PYTHONPATH="$T/pyfault" "$SH_BIN" "$INSTALL" \
        --manifest "$T/manifest.json" --prefix "$T/pfxrw" >"$T/out" 2>&1; then
    bad "mid-write receipt fault fails (got exit 0)"
else
    grep -qi 'receipt' "$T/out" \
        && ok "mid-write receipt fault fails with receipt diagnosis" \
        || bad "mid-write receipt fault fails with receipt diagnosis (saw: $(head -1 "$T/out"))"
    cmp -s "$T/pfxrw.receipt-orig" "$T/pfxrw/share/osslscope/install-manifest.json" \
        && ok "mid-write receipt fault keeps the prior receipt byte-identical" \
        || bad "mid-write receipt fault keeps the prior receipt byte-identical"
fi

# Same mid-write fault with no alias in place: the fresh-temp atomic
# publish keeps the prior receipt byte-identical. (Passes pre-fix by
# design: with no alias the old predictable temp is already a separate
# file. It pins the publish path against direct-write regressions.)
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxrw2" >/dev/null 2>&1; then
    ok "setup: good install into mid-write receipt prefix (no alias)"
else
    bad "setup: good install into mid-write receipt prefix (no alias)"
fi
cp "$T/pfxrw2/share/osslscope/install-manifest.json" "$T/pfxrw2.receipt-orig"
if FAULT_RECEIPT_MIDWRITE=1 PYTHONPATH="$T/pyfault" "$SH_BIN" "$INSTALL" \
        --manifest "$T/manifest.json" --prefix "$T/pfxrw2" >"$T/out" 2>&1; then
    bad "mid-write receipt fault without alias fails (got exit 0)"
else
    grep -qi 'receipt' "$T/out" \
        && ok "mid-write receipt fault without alias fails with receipt diagnosis" \
        || bad "mid-write receipt fault without alias fails with receipt diagnosis (saw: $(head -1 "$T/out"))"
    cmp -s "$T/pfxrw2.receipt-orig" "$T/pfxrw2/share/osslscope/install-manifest.json" \
        && ok "mid-write receipt fault without alias keeps the prior receipt byte-identical" \
        || bad "mid-write receipt fault without alias keeps the prior receipt byte-identical"
fi

# Pre-existing temp-path directory: cleanup must remove only paths this
# run created, leaving the foreign directory and its sentinel alone.
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxsent" >/dev/null 2>&1; then
    ok "setup: good install into sentinel prefix"
else
    bad "setup: good install into sentinel prefix"
fi
mkdir "$T/pfxsent/bin/osslscope.install-tmp"
echo sentinel >"$T/pfxsent/bin/osslscope.install-tmp/sentinel"
snapshot_prefix "$T/pfxsent" "$T/pfxsent.snap"
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxsent" >"$T/out" 2>&1; then
    bad "pre-existing temp-path directory fails (got exit 0)"
else
    grep -qi 'temporary.*exists\|refus' "$T/out" \
        && ok "pre-existing temp-path directory fails closed with temp-path diagnosis" \
        || bad "pre-existing temp-path directory fails closed with temp-path diagnosis (saw: $(head -1 "$T/out"))"
    [ -f "$T/pfxsent/bin/osslscope.install-tmp/sentinel" ] \
        && ok "cleanup removes only paths this run created (sentinel kept)" \
        || bad "cleanup removes only paths this run created (sentinel kept)"
    snapshot_prefix "$T/pfxsent" "$T/pfxsent.now"
    cmp -s "$T/pfxsent.snap" "$T/pfxsent.now" \
        && ok "pre-existing temp-path failure leaves existing prefix unchanged" \
        || bad "pre-existing temp-path failure leaves existing prefix unchanged"
fi

# ============ fix round 2: manifest snapshot, no mixed identities ============
# The manifest bytes are read once per run. A cp shim swaps revision-A
# sources and manifest for revision B during staging (between the old
# revision read and hash read): the install must reject the changed
# bytes, never install B while recording A as manifest-verified.
mk_variant "$T/v-swapA" rev-A
mk_variant "$T/v-swapB" rev-B
python3 -c "
import hashlib, json, os
d = '$T/v-swapB'
for n in ('host-bin', 'harvest.o', 'count.o'):
    open(d + '/' + n, 'ab').write(b'-revB-pad-revB-pad')
p = d + '/manifest.json'
m = json.load(open(p))
for a in m['artifacts']:
    a['sha256'] = hashlib.sha256(open(a['path'], 'rb').read()).hexdigest()
    a['bytes'] = os.path.getsize(a['path'])
json.dump(m, open(p, 'w'), indent=2, sort_keys=True)
"
if "$SH_BIN" "$INSTALL" --manifest "$T/v-swapA/manifest.json" --prefix "$T/pfxswap" >/dev/null 2>&1; then
    ok "setup: good revision-A install into swap prefix"
else
    bad "setup: good revision-A install into swap prefix"
fi
snapshot_prefix "$T/pfxswap" "$T/pfxswap.snap"
mk_tool_farm "$T/swapbin"
rm "$T/swapbin/cp"
cat >"$T/swapbin/cp" <<EOF
#!/bin/sh
if [ ! -f "$T/swapped" ]; then
    for _a in "\$@"; do
        if [ "\$_a" = "$T/v-swapA/host-bin" ]; then
            "$REAL_CP" "$T/v-swapB/host-bin" "$T/v-swapA/host-bin"
            "$REAL_CP" "$T/v-swapB/harvest.o" "$T/v-swapA/harvest.o"
            "$REAL_CP" "$T/v-swapB/count.o" "$T/v-swapA/count.o"
            "$REAL_CP" "$T/v-swapB/manifest.json" "$T/v-swapA/manifest.json"
            touch "$T/swapped"
            break
        fi
    done
fi
exec "$REAL_CP" "\$@"
EOF
chmod +x "$T/swapbin/cp"
if PATH="$T/swapbin:$PATH" "$SH_BIN" "$INSTALL" \
        --manifest "$T/v-swapA/manifest.json" --prefix "$T/pfxswap" >"$T/out" 2>&1; then
    bad "swapped-manifest install fails (got exit 0)"
else
    grep -q 'sha256\|byte length' "$T/out" \
        && ok "swapped manifest fails closed with identity diagnosis" \
        || bad "swapped manifest fails closed with identity diagnosis (saw: $(head -1 "$T/out"))"
    snapshot_prefix "$T/pfxswap" "$T/pfxswap.now"
    cmp -s "$T/pfxswap.snap" "$T/pfxswap.now" \
        && ok "swapped-manifest failure leaves existing prefix unchanged" \
        || bad "swapped-manifest failure leaves existing prefix unchanged"
fi
[ -f "$T/swapped" ] \
    && ok "swap probe fired between reads" \
    || bad "swap probe fired between reads"

# ============ --setcap matrix ============
mkdir -p "$T/stubbin"
cat >"$T/stubbin/setcap" <<'EOF'
#!/bin/sh
echo "$*" >>"$SETCAP_LOG"
exit "${STUB_SETCAP_EXIT:-0}"
EOF
chmod +x "$T/stubbin/setcap"
export SETCAP_LOG="$T/setcap.log"

: >"$SETCAP_LOG"
if PATH="$T/stubbin:$PATH" "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" \
        --prefix "$T/pfx6" --setcap >"$T/out" 2>&1; then
    grep -q "cap_bpf,cap_perfmon+ep $T/pfx6/bin/osslscope" "$SETCAP_LOG" \
        && ok "--setcap applies caps to prefix binary" \
        || bad "--setcap applies caps to prefix binary"
else
    bad "--setcap with working setcap exits 0 (rc=$?)"
fi

: >"$SETCAP_LOG"
if STUB_SETCAP_EXIT=1 PATH="$T/stubbin:$PATH" "$SH_BIN" "$INSTALL" \
        --manifest "$T/manifest.json" --prefix "$T/pfx7" --setcap >"$T/out" 2>&1; then
    bad "--setcap with failing setcap fails (got exit 0)"
else
    grep -q 'labeled sudo' "$T/out" && grep -q 'osslscope doctor' "$T/out" \
        && ok "--setcap with failing setcap fails with labeled-sudo + doctor fallback" \
        || bad "--setcap with failing setcap fails with labeled-sudo + doctor fallback"
fi

# Deterministic missing-setcap PATH: a symlink farm with every tool the
# installer needs except setcap/getcap (a bare /usr/bin:/bin still carries
# setcap on merged-usr platforms).
mkdir -p "$T/nocapbin"
for tool in python3 file readelf cp mkdir chmod mktemp mv cmp rm grep awk sed cat realpath; do
    dest="$(command -v "$tool")" || { echo "test prereq missing: $tool" >&2; exit 1; }
    ln -s "$dest" "$T/nocapbin/$tool"
done
if PATH="$T/nocapbin" "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" \
        --prefix "$T/pfx8" --setcap >"$T/out" 2>&1; then
    bad "--setcap without setcap fails (got exit 0)"
else
    rc=$?
    if [ "$rc" -eq 3 ] && grep -q 'libcap' "$T/out"; then
        ok "--setcap without setcap exits 3 with libcap install hint"
    else
        bad "--setcap without setcap exits 3 with libcap install hint (rc=$rc)"
    fi
fi

# ============ members object (traversal triple, R19) ============
cp "$T/harvest.o" "$T/members.o"
cat >"$T/manifest-members.json" <<EOF
{"schema": "osslscope-dev-build-manifest-v1",
 "product_ref": "deadbeef-test",
 "product_ref_short": "deadbee",
 "product_dirty": false,
 "artifacts": [
   {"role": "host-binary", "path": "$T/host-bin"},
   {"role": "bpf-object", "bin": "osslscope-harvest", "path": "$T/harvest.o"},
   {"role": "bpf-object", "bin": "osslscope-count", "path": "$T/count.o"},
   {"role": "bpf-object", "bin": "osslscope-members", "path": "$T/members.o"}
 ]}
EOF

# Manifest WITH members: triple installs, receipt names 4 artifacts.
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest-members.json" --prefix "$T/pfxm" >"$T/out" 2>&1 \
   && [ -f "$T/pfxm/lib/osslscope/osslscope-members" ] \
   && cmp -s "$T/members.o" "$T/pfxm/lib/osslscope/osslscope-members"; then
    ok "manifest with members installs osslscope-members byte-identical"
else
    bad "manifest with members installs osslscope-members byte-identical"
fi
if python3 -c "import json; m=json.load(open('$T/pfxm/share/osslscope/install-manifest.json')); assert len(m['artifacts'])==4, m; assert any(a.get('bin')=='osslscope-members' and 'sha256' in a for a in m['artifacts']), m" 2>"$T/err"; then
    ok "install-manifest.json records the members artifact with sha256"
else
    bad "install-manifest.json records the members artifact with sha256 ($(cat "$T/err"))"
fi

# Pair-only manifest stays valid: no members file, 3-artifact receipt.
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxp" >/dev/null 2>&1 \
   && [ ! -e "$T/pfxp/lib/osslscope/osslscope-members" ]; then
    ok "pair-only manifest installs without members (old installs valid)"
else
    bad "pair-only manifest installs without members (old installs valid)"
fi

# Explicit --members overrides the manifest (operator-built object).
cp "$T/members.o" "$T/op-members.o"
printf 'x' >>"$T/op-members.o"
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest-members.json" --prefix "$T/pfxo" \
        --members "$T/op-members.o" >/dev/null 2>&1 \
   && cmp -s "$T/op-members.o" "$T/pfxo/lib/osslscope/osslscope-members"; then
    ok "explicit --members overrides the manifest path"
else
    bad "explicit --members overrides the manifest path"
fi

# Explicit --members onto a pair-only manifest adds the third object.
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" --prefix "$T/pfxa" \
        --members "$T/members.o" >/dev/null 2>&1 \
   && cmp -s "$T/members.o" "$T/pfxa/lib/osslscope/osslscope-members"; then
    ok "explicit --members extends a pair-only manifest install"
else
    bad "explicit --members extends a pair-only manifest install"
fi

# Incompatible --members fails closed with the eBPF diagnosis.
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest-members.json" --prefix "$T/pfxb" \
        --members "$T/host-bin" >"$T/out" 2>&1; then
    bad "x86-64 executable as members object fails closed (got exit 0)"
else
    grep -qi 'ebpf' "$T/out" \
        && ok "x86-64 executable as members object fails closed with eBPF diagnosis" \
        || bad "x86-64 executable as members object fails closed with eBPF diagnosis"
fi

# Missing --members file fails naming the artifact.
if "$SH_BIN" "$INSTALL" --manifest "$T/manifest-members.json" --prefix "$T/pfxc" \
        --members "$T/does-not-exist.o" >"$T/out" 2>&1; then
    bad "missing --members file fails (got exit 0)"
else
    grep -q 'does-not-exist.o' "$T/out" \
        && ok "missing --members file fails naming the artifact" \
        || bad "missing --members file fails naming the artifact"
fi

# Members never satisfies the required triple alone: --members with
# no manifest still needs --binary/--harvest/--count.
if "$SH_BIN" "$INSTALL" --members "$T/members.o" --prefix "$T/pfxd" >"$T/out" 2>&1; then
    bad "--members alone with no manifest fails (got exit 0)"
else
    grep -q 'all three of --binary/--harvest/--count' "$T/out" \
        && ok "--members alone with no manifest still requires the base triple" \
        || bad "--members alone with no manifest still requires the base triple"
fi

echo "---"
echo "pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
