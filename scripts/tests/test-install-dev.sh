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

if PATH="/usr/bin:/bin" "$SH_BIN" "$INSTALL" --manifest "$T/manifest.json" \
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

echo "---"
echo "pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
