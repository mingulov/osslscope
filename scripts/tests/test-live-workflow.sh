#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# test-live-workflow.sh — host-runnable tests for .github/workflows/live-known-n.yml.
#
# R10 (F12/F13): the live workflow's ledger channel and doctor
# disposition. This suite executes the workflow's EXACT probe,
# capture and oracle shell blocks (extracted from the YAML at test
# time) with fixture doctor reports/return codes and a stub
# check subcommand that writes the workload file only through the
# block's own --workload-out argument (the host
# workload-output seam); the oracle block then consumes those
# capture outputs directly. Wiring drift guards pin the exact
# ledger paths, the typed-disposition markers, the archived
# channels and the NOT-RUN status. Nothing here runs a live lane.
#
# Usage: ./scripts/tests/test-live-workflow.sh
# Exit: 0 all pass; 1 any failure.
set -eu

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$REPO/.github/workflows/live-known-n.yml"
CHECK_YML="$REPO/.github/workflows/check.yml"
ORACLE="$REPO/scripts/live-oracle.py"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT INT TERM

if [ ! -f "$WF" ]; then
    bad "live-known-n.yml exists"
    echo "---"; echo "pass=$PASS fail=$FAIL"; exit 1
fi
if [ ! -f "$ORACLE" ]; then
    bad "scripts/live-oracle.py exists"
    echo "---"; echo "pass=$PASS fail=$FAIL"; exit 1
fi

# --- exact-block extraction -------------------------------------------
# step_text prints the raw YAML lines of one named step; extract_run
# prints its de-indented `run:` block (the 10-space content prefix is
# stripped, so heredoc terminators land on column 0 exactly as the
# runner sees them). Step names match with string equality.

step_text() {
    awk -v name="$1" '
        /^      - name: / { if (active) exit; active = (substr($0, 15) == name) }
        active { print }
    ' "$WF"
}

extract_run() {
    awk -v name="$1" '
        /^      - name: / { active = (substr($0, 15) == name); inrun = 0; next }
        active && /^        run: \| *$/ { inrun = 1; next }
        inrun && /^          / { print substr($0, 11); next }
        inrun && /^ *$/ { print ""; next }
        { inrun = 0 }
    ' "$WF" >"$2"
    [ -s "$2" ]
}

# --- probe harness ----------------------------------------------------
# A stub $RUNNER_TEMP/ossl-pfx/bin/osslscope replays one fixture
# doctor stdout and exits one fixture status; the extracted probe
# block runs unmodified against it with GITHUB_OUTPUT pointed at a
# temp file.

mkdir -p "$T/runner/ossl-pfx/bin"
cat >"$T/stub-osslscope" <<'EOF'
#!/bin/sh
# Test double for $PFX/bin/osslscope: doctor replays one fixture
# report/status; check parses its own output arguments and writes
# the workload file ONLY through the supplied --workload-out path
# (absent flag: the workload goes nowhere, mirroring the real
# /dev/null default), the report through --out, diagnostics to
# stdout. No channel path is hardcoded here: if the block drops
# --workload-out, no workload file appears.
if [ "${1:-}" = "check" ]; then
    WO=""
    OUT=""
    PREV=""
    for a in "$@"; do
        if [ "$PREV" = "--workload-out" ]; then WO="$a"; PREV=""; continue; fi
        if [ "$PREV" = "--out" ]; then OUT="$a"; PREV=""; continue; fi
        case "$a" in --workload-out|--out) PREV="$a";; esac
    done
    if [ -z "$OUT" ]; then echo "stub osslscope: no --out" >&2; exit 2; fi
    cp "$OSSLSCOPE_REPORT_SRC" "$OUT"
    if [ -n "$WO" ]; then cp "$OSSLSCOPE_WORKLOAD_SRC" "$WO"; fi
    cat "$OSSLSCOPE_DRIVER_SRC"
    exit "${OSSLSCOPE_CHECK_RC:-0}"
fi
cat "$OSSLSCOPE_FIXTURE_OUT"
exit "$OSSLSCOPE_FIXTURE_RC"
EOF
cp "$T/stub-osslscope" "$T/runner/ossl-pfx/bin/osslscope"
chmod +x "$T/runner/ossl-pfx/bin/osslscope"
# Fake lane libcrypto advertisement for the capture block's
# ldconfig lookup (the stub check never opens the path).
cat >"$T/stub-ldconfig" <<'EOF'
#!/bin/sh
echo "	libcrypto.so.3 (libc6,x86-64) => /stub/lib/libcrypto.so.3"
EOF
chmod +x "$T/stub-ldconfig"

PROBE_RC=0
run_probe() {
    rm -rf "${T:?}/$3"; mkdir -p "$T/$3"
    if (cd "$T/$3" && OSSLSCOPE_FIXTURE_OUT="$1" OSSLSCOPE_FIXTURE_RC="$2" \
        RUNNER_TEMP="$T/runner" GITHUB_OUTPUT="$T/$3/gh-out" \
        sh "$T/probe-block.sh" >"$T/$3/stdout.log" 2>&1); then
        PROBE_RC=0
    else
        PROBE_RC=$?
    fi
}

gh_has() { grep -q -F -x "$2" "$T/$1/gh-out" 2>/dev/null; }
gh_no_capable() { [ ! -f "$T/$1/gh-out" ] || ! grep -q 'capable=' "$T/$1/gh-out"; }
disp_has() { grep -q -F "$2" "$T/$1/doctor-disposition.txt" 2>/dev/null; }
rc_file_is() { [ -f "$T/$1/doctor-rc.txt" ] && [ "$(cat "$T/$1/doctor-rc.txt")" = "$2" ]; }

# --- oracle harness ---------------------------------------------------
# The extracted oracle block runs unmodified in a case dir holding
# the invocation's own files; scripts/ is symlinked so the block's
# relative `scripts/live-oracle.py` resolves exactly as on the runner.

ORACLE_RC=0
run_oracle_block() {
    if (cd "$T/$1" && MODE="$2" \
        sh "$T/oracle-block.sh" >"$T/$1/block-stdout.log" 2>&1); then
        ORACLE_RC=0
    else
        ORACLE_RC=$?
    fi
}

# --- capture harness --------------------------------------------------
# The extracted capture block runs unmodified under bash (the
# runner's shell: the block uses pipefail) with a stub PFX whose
# check subcommand writes the workload file only through the
# parsed --workload-out argument, plus a stub ldconfig
# advertising a lane libcrypto. The case dir then feeds the
# oracle block directly: capture-to-oracle coupling, not copies.

CAPTURE_RC=0
run_capture_block() {
    rm -rf "${T:?}/$1"; mkdir -p "$T/$1/runner/ossl-pfx/bin" "$T/$1/stubbin"
    cp "$T/stub-osslscope" "$T/$1/runner/ossl-pfx/bin/osslscope"
    chmod +x "$T/$1/runner/ossl-pfx/bin/osslscope"
    cp "$T/stub-ldconfig" "$T/$1/stubbin/ldconfig"
    chmod +x "$T/$1/stubbin/ldconfig"
    ln -s "$REPO/scripts" "$T/$1/scripts"
    if (cd "$T/$1" && MODE="$2" RUNNER_TEMP="$T/$1/runner" \
        OSSLSCOPE_WORKLOAD_SRC="$T/w-good.log" \
        OSSLSCOPE_REPORT_SRC="$T/rep.json" \
        OSSLSCOPE_DRIVER_SRC="$T/driver-decoy.log" \
        OSSLSCOPE_CHECK_RC=0 \
        PATH="$T/$1/stubbin:$PATH" \
        bash "$3" >"$T/$1/capture-stdout.log" 2>&1); then
        CAPTURE_RC=0
    else
        CAPTURE_RC=$?
    fi
}

# --- doctor fixtures (typed report shape: target/checks/verdict/exit) ---

mkdoc() {
    printf '{"target": null, "checks": %s, "verdict": "%s", "exit": %s}' "$4" "$2" "$3" >"$1"
}
ck() {
    printf '{"id": "%s", "status": "%s", "message": "%s"}' "$1" "$2" "$3"
}

P_KERN=$(ck kernel pass "features ok on 6.12.0 (informational)")
P_CAPS=$(ck caps pass "CAP_BPF+CAP_PERFMON effective")
P_LOCK=$(ck lockdown pass "lockdown=integrity (BPF allowed)")
P_LSM=$(ck lsm pass "no LSM denial (BPF ops succeed; active: none)")
P_HV=$(ck objects-harvest pass "harvest object: /pfx/osslscope-harvest (explicit, compatible)")
P_CT=$(ck objects-count pass "count object: /pfx/osslscope-count (explicit, compatible)")
P_SPAWN=$(ck spawn-access pass "spawn setup maps read ok: pre-exec child maps readable (4096 bytes; self dumpable=1)")
F_CAPS=$(ck caps fail "missing caps: CAP_BPF+CAP_PERFMON (have neither file caps nor root)")
F_KERN=$(ck kernel fail "wrong kernel: uprobe-multi unsupported (feature probe, not uname; release 6.1.0 informational)")
F_LOCK=$(ck lockdown fail "lockdown=confidentiality blocks BPF even with caps")
F_LSM=$(ck lsm fail "likely LSM denial with caps held (enforcing: AppArmor)")
F_HV=$(ck objects-harvest fail "incompatible object: harvest was built for another map layout")
F_CT=$(ck objects-count fail "incompatible object: count ABI mismatch")
F_UNK=$(ck frobnicator fail "unknown check failed")
F_KERN_OOM=$(ck kernel fail "ringbuf failed (errno 12)")
F_KERN_NODENY=$(ck kernel fail "uprobe-multi denied (errno 1) with caps held, no lockdown/LSM/seccomp")
F_LSM_NOATTR=$(ck lsm fail "BPF denied with caps held, no lockdown/LSM/seccomp attribution")
F_KERN_LOCK=$(ck kernel fail "kprobe-load blocked by lockdown=confidentiality")
F_LSM_LOCKPTR=$(ck lsm fail "BPF denied with caps held — lockdown=confidentiality, not LSM")

mkdoc "$T/d-ok.json" ok 0 "[$P_KERN, $P_CAPS, $P_LOCK, $P_LSM, $P_SPAWN, $P_HV, $P_CT]"
mkdoc "$T/d-caps.json" fail-closed 4 "[$P_KERN, $F_CAPS, $P_LOCK, $P_LSM, $P_SPAWN, $P_HV, $P_CT]"
mkdoc "$T/d-kernel.json" fail-closed 4 "[$F_KERN, $P_CAPS, $P_LOCK, $P_LSM, $P_SPAWN, $P_HV, $P_CT]"
mkdoc "$T/d-lockdown.json" fail-closed 4 "[$P_KERN, $P_CAPS, $F_LOCK, $P_LSM, $P_SPAWN, $P_HV, $P_CT]"
mkdoc "$T/d-lsm.json" fail-closed 4 "[$P_KERN, $P_CAPS, $P_LOCK, $F_LSM, $P_SPAWN, $P_HV, $P_CT]"
mkdoc "$T/d-obj.json" fail-closed 4 "[$P_KERN, $P_CAPS, $P_LOCK, $P_LSM, $P_SPAWN, $F_HV, $P_CT]"
mkdoc "$T/d-mixed.json" fail-closed 4 "[$P_KERN, $F_CAPS, $P_LOCK, $P_LSM, $P_SPAWN, $P_HV, $F_CT]"
mkdoc "$T/d-unknown.json" fail-closed 4 "[$P_KERN, $P_CAPS, $P_LOCK, $P_LSM, $F_UNK]"
mkdoc "$T/d-nofail.json" fail-closed 4 "[$P_KERN, $P_CAPS, $P_LOCK, $P_LSM, $P_SPAWN, $P_HV, $P_CT]"
printf '{"target": null, "checks": [%s], "verdict": "maybe", "exit": 4}' "$F_CAPS" >"$T/d-badverdict.json"
printf 'osslscope doctor: unknown arg --frobnicate\nusage: osslscope doctor ...\n' >"$T/d-text.txt"
: >"$T/d-empty.txt"
mkdoc "$T/d-enomem.json" fail-closed 4 "[$F_KERN_OOM, $P_CAPS, $P_LOCK, $P_LSM, $P_SPAWN, $P_HV, $P_CT]"
mkdoc "$T/d-kern-nodeny.json" fail-closed 4 "[$F_KERN_NODENY, $P_CAPS, $P_LOCK, $P_LSM, $P_SPAWN, $P_HV, $P_CT]"
mkdoc "$T/d-lsm-noattr.json" fail-closed 4 "[$P_KERN, $P_CAPS, $P_LOCK, $F_LSM_NOATTR, $P_SPAWN, $P_HV, $P_CT]"
mkdoc "$T/d-lockdown-full.json" fail-closed 4 "[$F_KERN_LOCK, $P_CAPS, $F_LOCK, $F_LSM_LOCKPTR, $P_SPAWN, $P_HV, $P_CT]"
printf '{"target": null, "checks": [], "verdict": "ok", "exit": 0}' >"$T/d-emptychecks.json"
mkdoc "$T/d-noobjects.json" ok 0 "[$P_KERN, $P_CAPS, $P_LOCK, $P_LSM]"
printf '{"target": null, "checks": [%s, "oops", 42], "verdict": "fail-closed", "exit": 4}' "$F_CAPS" >"$T/d-malformed-rows.json"
printf '{"target": null, "checks": [%s, %s, %s, %s, %s, {"id": "objects-harvest", "status": "bogus", "message": "made up"}, %s], "verdict": "fail-closed", "exit": 4}' "$P_KERN" "$F_CAPS" "$P_LOCK" "$P_LSM" "$P_SPAWN" "$P_CT" >"$T/d-badstatus.json"
printf '{"target": null, "checks": [%s, %s, %s, %s, %s, %s, %s], "verdict": "ok"}' "$P_KERN" "$P_CAPS" "$P_LOCK" "$P_LSM" "$P_SPAWN" "$P_HV" "$P_CT" >"$T/d-noexit.json"
mkdoc "$T/d-dup.json" ok 0 "[$P_KERN, $P_CAPS, $P_LOCK, $P_LSM, $P_SPAWN, $P_HV, $P_CT, $P_CAPS]"
mkdoc "$T/d-nospawn-ok.json" ok 0 "[$P_KERN, $P_CAPS, $P_LOCK, $P_LSM, $P_HV, $P_CT]"
mkdoc "$T/d-nospawn-fc.json" fail-closed 4 "[$P_KERN, $F_CAPS, $P_LOCK, $P_LSM, $P_HV, $P_CT]"

# --- workload + report fixtures (host workload-output seam) ---

printf 'LEDGER mode=ecdsa fetches=1 signs=1 verifies=1\nORDDONE mode=ecdsa rc=0\n' >"$T/w-good.log"
printf 'osslscope check: observation window complete\nreport: known-n.json (PARTIAL, 2 sites)\nrun: workload exited with status 0\n' >"$T/driver.log"
printf 'LEDGER mode=ecdsa fetches=1 signs\nORDDONE mode=ecdsa rc=0\n' >"$T/smoke-corrupt.txt"
printf 'LEDGER mode=ecdsa fetches=1 signs=1 verifies=1\nLEDGER mode=ecdsa loop_secs=10 ops=11 fetches=22\nORDDONE mode=ecdsa rc=0\n' >"$T/w-odd11.log"
printf 'LEDGER mode=ecdsa fetches=1 signs=1 verifies=1\nORDDONE mode=ecdsa rc=1\n' >"$T/w-rc1.log"
printf 'LEDGER mode=kem skipped=old-openssl\nORDDONE mode=kem rc=0\n' >"$T/w-skip.log"
printf 'osslscope check: observation window complete\nLEDGER mode=ecdsa loop_secs=10 ops=99 fetches=198 signs=99 verifies=99\nORDDONE mode=ecdsa rc=0\nreport: known-n.json (PARTIAL, 2 sites)\nrun: workload exited with status 0\n' >"$T/driver-decoy.log"

C11='{"op": 12, "funcid": 11, "provider_class": "default", "algorithm_classes": ["ECDSA"]}'
C15='{"op": 12, "funcid": 15, "provider_class": "default", "algorithm_classes": ["ECDSA"]}'
site() {
    # Declares candidates_coverage complete explicitly: definite
    # operation evidence requires it (missing fails closed).
    printf '{"calls": %s, "candidates": [%s], "object": "lib", "device": 1, "inode": %s, "offset": 4096, "generation": 0, "candidates_coverage": "complete"}' "$1" "$3" "$2"
}
S11=$(site 3 101 "$C11"); S15=$(site 2 102 "$C15")
printf '{"schema_version": "observed-crypto-v2.0", "completeness": {"status": "PARTIAL"}, "sites": [%s, %s]}' "$S11" "$S15" >"$T/rep.json"
S11B=$(site 6 101 "$C11"); S15B=$(site 5 102 "$C15")
printf '{"schema_version": "observed-crypto-v2.0", "completeness": {"status": "PARTIAL"}, "sites": [%s, %s]}' "$S11B" "$S15B" >"$T/rep11.json"
S11C=$(site 5 101 "$C11"); S15C=$(site 5 102 "$C15")
printf '{"schema_version": "observed-crypto-v2.0", "completeness": {"status": "PARTIAL"}, "sites": [%s, %s]}' "$S11C" "$S15C" >"$T/rep10.json"

# --- 0. extraction integrity (exact blocks must exist to execute) ---

if extract_run "Probe live capability (doctor)" "$T/probe-block.sh"; then
    ok "probe block extracts from live-known-n.yml"
else
    bad "probe block extracts from live-known-n.yml"
fi
if extract_run "Ledger oracle (independent counts)" "$T/oracle-block.sh"; then
    ok "oracle block extracts from live-known-n.yml"
else
    bad "oracle block extracts from live-known-n.yml"
fi
if extract_run "Bounded live check (known workload)" "$T/capture-block.sh"; then
    ok "capture block extracts from live-known-n.yml"
else
    bad "capture block extracts from live-known-n.yml"
fi
if grep -q -- '- name: ' "$T/probe-block.sh" 2>/dev/null; then
    bad "probe extraction stops at the next step"
else
    ok "probe extraction stops at the next step"
fi
if grep -q -- '- name: ' "$T/oracle-block.sh" 2>/dev/null; then
    bad "oracle extraction stops at the next step"
else
    ok "oracle extraction stops at the next step"
fi
if grep -q -- '- name: ' "$T/capture-block.sh" 2>/dev/null; then
    bad "capture extraction stops at the next step"
else
    ok "capture extraction stops at the next step"
fi

# --- wiring drift guards (F12 ledger paths) ---

# 1. The check invocation captures the workload channel explicitly.
if step_text "Bounded live check (known workload)" | grep -q -F -- '--workload-out known-n-workload.log'; then
    ok "capture step passes --workload-out known-n-workload.log"
else
    bad "capture step passes --workload-out known-n-workload.log"
fi

# 2. The oracle reads this invocation's workload file, not observer output.
if step_text "Ledger oracle (independent counts)" | grep -q -F 'live-oracle.py known-n-workload.log known-n.json'; then
    ok "oracle step reads known-n-workload.log + known-n.json"
else
    bad "oracle step reads known-n-workload.log + known-n.json"
fi

# 3. Observer diagnostics are never oracle input.
if step_text "Ledger oracle (independent counts)" | grep -q -F 'live-oracle.py known-n-driver.log'; then
    bad "oracle step never reads known-n-driver.log"
else
    ok "oracle step never reads known-n-driver.log"
fi

# --- wiring drift guards (F13 typed disposition) ---

# 4. The probe consumes the typed report plus the process status.
if step_text "Probe live capability (doctor)" | grep -q -F -- '--format json' \
    && step_text "Probe live capability (doctor)" | grep -q -F 'doctor-rc.txt'; then
    ok "probe step uses doctor --format json + doctor-rc.txt"
else
    bad "probe step uses doctor --format json + doctor-rc.txt"
fi

# 5. The disposition classifier block is present and publishes capable=.
if step_text "Probe live capability (doctor)" | grep -q -F 'BEGIN DOCTOR-DISPOSITION' \
    && step_text "Probe live capability (doctor)" | grep -q -F 'END DOCTOR-DISPOSITION' \
    && step_text "Probe live capability (doctor)" | grep -q -F 'GITHUB_OUTPUT'; then
    ok "probe step carries the DOCTOR-DISPOSITION classifier"
else
    bad "probe step carries the DOCTOR-DISPOSITION classifier"
fi

# --- wiring drift guards (archived channels + identity) ---

# 6. Both channels, doctor report/rc, observation, oracle result and
# one invocation identity are uploaded.
UPLOAD_OK=1
for f in known-n-workload.log known-n-driver.log known-n.json oracle.txt \
    doctor.json doctor.stderr doctor-rc.txt doctor-disposition.txt \
    invocation.txt product-ref.txt kernel.txt check-exit.txt \
    driver-smoke.txt lane-libcrypto.txt; do
    if ! step_text "Upload live artifacts (pass, fail, or capability skip)" | grep -q -F "$f"; then
        UPLOAD_OK=0
    fi
done
if [ "$UPLOAD_OK" -eq 1 ]; then
    ok "upload step archives both channels + doctor report/rc + observation + oracle + identity"
else
    bad "upload step archives both channels + doctor report/rc + observation + oracle + identity"
fi

# 7. The untyped doctor.txt channel is gone.
if step_text "Upload live artifacts (pass, fail, or capability skip)" | grep -q -F 'doctor.txt'; then
    bad "upload step drops doctor.txt"
else
    ok "upload step drops doctor.txt"
fi

# 8. Artifacts upload even when the probe fails setup (plain always()).
if step_text "Upload live artifacts (pass, fail, or capability skip)" | grep -q "steps.probe.outcome == 'success'"; then
    bad "upload step is not gated on probe success"
else
    ok "upload step is not gated on probe success"
fi

# --- wiring drift guards (retained: status, triggers, lane, ids) ---

# 9. The workflow stays dispatch-only NOT-RUN until a separately
# authorized capable execution supplies exact receipts.
if grep -q 'NOT-RUN' "$WF" \
    && grep -q '^  workflow_dispatch:' "$WF" \
    && ! grep -q -E '^  (push|pull_request):' "$WF"; then
    ok "workflow stays dispatch-only NOT-RUN"
else
    bad "workflow stays dispatch-only NOT-RUN"
fi

# 10. The owned-lane placement is unchanged (scoped to runs-on: a
# comment naming the lane must not satisfy this guard — see leg 58).
if grep -q 'runs-on:.*osslscope-bpf' "$WF"; then
    ok "workflow stays on the self-hosted osslscope-bpf lane"
else
    bad "workflow stays on the self-hosted osslscope-bpf lane"
fi

# 11. The oracle still propagates its own return code.
# Single quotes below are intentional: grep -F matches the literal
# text `exit $rc` (double quotes would expand $rc and break this).
# shellcheck disable=SC2016
if step_text "Ledger oracle (independent counts)" | grep -q -F 'exit $rc'; then
    ok "oracle step still propagates exit rc"
else
    bad "oracle step still propagates exit rc"
fi

# 12. The capture shape is unchanged apart from the workload channel.
if step_text "Bounded live check (known workload)" | grep -q -F 'run -- ' \
    && step_text "Bounded live check (known workload)" | grep -q -F '0|3|10|11'; then
    ok "capture step keeps run -- and usable-rc 0|3|10|11"
else
    bad "capture step keeps run -- and usable rc 0|3|10|11"
fi

# 13. Step ids and downstream references still line up.
if grep -q 'id: probe' "$WF" \
    && grep -q -F 'steps.probe.outputs.capable' "$WF" \
    && grep -q -F 'steps.mode.outputs.mode' "$WF"; then
    ok "probe id and downstream step references line up"
else
    bad "probe id and downstream step references line up"
fi

# 14. The verdict summary still labels skip vs setup failure, never a pass.
if step_text "Verdict summary (skip and setup failure are labeled, never a pass)" | grep -q -F 'SETUP FAILURE' \
    && step_text "Verdict summary (skip and setup failure are labeled, never a pass)" | grep -q -F 'SKIP(live-capability)' \
    && step_text "Verdict summary (skip and setup failure are labeled, never a pass)" | grep -q -F 'no observation is claimed'; then
    ok "verdict summary labels skip vs setup failure, never a pass"
else
    bad "verdict summary labels skip vs setup failure, never a pass"
fi

# --- check.yml wiring (packaging job, live job untouched) ---

# 15. This suite is wired into the packaging job.
if grep -q -F './scripts/tests/test-live-workflow.sh' "$CHECK_YML"; then
    ok "check.yml packaging job runs test-live-workflow.sh"
else
    bad "check.yml packaging job runs test-live-workflow.sh"
fi

# 16. The live-gates job stays SKIP-only (scoped to the job block:
# carries the SKIP echo and no live execution).
GATES_BLOCK=$(awk '/^  live-gates:/{f=1} f{print} f&&/^  [a-z-]+:/&&!/live-gates/{exit}' "$CHECK_YML")
if echo "$GATES_BLOCK" | grep -q 'SKIP(live-capability)' \
    && ! echo "$GATES_BLOCK" | grep -qE 'cargo (test|run)|test-live-|live-oracle|osslscope run'; then
    ok "check.yml live-gates stay SKIP-only"
else
    bad "check.yml live-gates stay SKIP-only"
fi

# 17. Both touched workflows still parse (same check check.yml runs).
if python3 -c "import yaml,sys; [yaml.safe_load(open(f)) for f in sys.argv[1:]]" "$CHECK_YML" "$WF" 2>"$T/yaml.log"; then
    ok "both workflows parse as YAML"
else
    bad "both workflows parse as YAML"
fi

# --- probe disposition (exact block + stub doctor) ---

# 18. A capable runner yields capable=true.
run_probe "$T/d-ok.json" 0 p-ok
if [ "$PROBE_RC" -eq 0 ] && gh_has p-ok "capable=true"; then
    ok "probe ok report + rc 0 yields capable=true"
else
    bad "probe ok report + rc 0 yields capable=true (rc=$PROBE_RC)"
fi

# 19-22. Admitted capability absences yield a genuine skip.
run_probe "$T/d-caps.json" 4 p-caps
if [ "$PROBE_RC" -eq 0 ] && gh_has p-caps "capable=false"; then
    ok "probe denied caps + rc 4 yields capable=false"
else
    bad "probe denied caps + rc 4 yields capable=false (rc=$PROBE_RC)"
fi
run_probe "$T/d-kernel.json" 4 p-kernel
if [ "$PROBE_RC" -eq 0 ] && gh_has p-kernel "capable=false"; then
    ok "probe too-old kernel + rc 4 yields capable=false"
else
    bad "probe too-old kernel + rc 4 yields capable=false (rc=$PROBE_RC)"
fi
run_probe "$T/d-lockdown.json" 4 p-lockdown
if [ "$PROBE_RC" -eq 0 ] && gh_has p-lockdown "capable=false"; then
    ok "probe lockdown=confidentiality + rc 4 yields capable=false"
else
    bad "probe lockdown=confidentiality + rc 4 yields capable=false (rc=$PROBE_RC)"
fi
run_probe "$T/d-lsm.json" 4 p-lsm
if [ "$PROBE_RC" -eq 0 ] && gh_has p-lsm "capable=false"; then
    ok "probe LSM denial + rc 4 yields capable=false"
else
    bad "probe LSM denial + rc 4 yields capable=false (rc=$PROBE_RC)"
fi

# 23. RED (F13): incompatible objects are setup failure, never a skip.
run_probe "$T/d-obj.json" 4 p-obj
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-obj; then
    ok "probe incompatible objects + rc 4 fails setup without capable="
else
    bad "probe incompatible objects + rc 4 fails setup without capable= (rc=$PROBE_RC)"
fi

# 24. RED (F13): a crashed doctor (empty output, rc 139) is setup
# failure, never a skip.
run_probe "$T/d-empty.txt" 139 p-139
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-139; then
    ok "probe empty output + rc 139 fails setup without capable="
else
    bad "probe empty output + rc 139 fails setup without capable= (rc=$PROBE_RC)"
fi

# 25. Malformed (non-JSON) reports are setup failure, never a skip.
run_probe "$T/d-text.txt" 4 p-malformed
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-malformed; then
    ok "probe malformed report + rc 4 fails setup without capable="
else
    bad "probe malformed report + rc 4 fails setup without capable= (rc=$PROBE_RC)"
fi

# 26. Usage exits are setup failure, never a skip.
run_probe "$T/d-text.txt" 2 p-rc2
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-rc2; then
    ok "probe usage text + rc 2 fails setup without capable="
else
    bad "probe usage text + rc 2 fails setup without capable= (rc=$PROBE_RC)"
fi

# 27. Internal-error exits are setup failure, never a skip.
run_probe "$T/d-empty.txt" 1 p-rc1
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-rc1; then
    ok "probe empty output + rc 1 fails setup without capable="
else
    bad "probe empty output + rc 1 fails setup without capable= (rc=$PROBE_RC)"
fi

# 28. An artifact failure alongside a capability absence is still setup
# failure: an admitted absence never launders a foreign failure.
run_probe "$T/d-mixed.json" 4 p-mixed
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-mixed; then
    ok "probe caps + objects-count failures fail setup without capable="
else
    bad "probe caps + objects-count failures fail setup without capable= (rc=$PROBE_RC)"
fi

# 29. Unknown failing check ids fail closed, never skip.
run_probe "$T/d-unknown.json" 4 p-unknown
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-unknown; then
    ok "probe unknown failing check id fails setup without capable="
else
    bad "probe unknown failing check id fails setup without capable= (rc=$PROBE_RC)"
fi

# 30-32. Report/status inconsistencies are setup failure, never a skip.
run_probe "$T/d-ok.json" 4 p-ok-rc4
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-ok-rc4; then
    ok "probe ok report + rc 4 fails setup without capable="
else
    bad "probe ok report + rc 4 fails setup without capable= (rc=$PROBE_RC)"
fi
run_probe "$T/d-caps.json" 0 p-fc-rc0
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-fc-rc0; then
    ok "probe fail-closed report + rc 0 fails setup without capable="
else
    bad "probe fail-closed report + rc 0 fails setup without capable= (rc=$PROBE_RC)"
fi
run_probe "$T/d-nofail.json" 4 p-nofail
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-nofail; then
    ok "probe fail-closed verdict with no failing check fails setup"
else
    bad "probe fail-closed verdict with no failing check fails setup (rc=$PROBE_RC)"
fi

# 33. Unknown verdicts are setup failure, never a skip.
run_probe "$T/d-badverdict.json" 4 p-badverdict
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-badverdict; then
    ok "probe unknown verdict fails setup without capable="
else
    bad "probe unknown verdict fails setup without capable= (rc=$PROBE_RC)"
fi

# 34. The probe retains the typed exit status on disk.
if rc_file_is p-ok 0 && rc_file_is p-caps 4 && rc_file_is p-obj 4 && rc_file_is p-139 139; then
    ok "probe retains doctor-rc.txt across capable/skip/setup outcomes"
else
    bad "probe retains doctor-rc.txt across capable/skip/setup outcomes"
fi

# 35. The disposition receipt names the outcome and the reason.
if disp_has p-ok "capable=true" && disp_has p-caps "caps" \
    && disp_has p-obj "setup-failure" && disp_has p-139 "setup-failure" \
    && disp_has p-139 "139"; then
    ok "probe disposition receipt names outcome + reason"
else
    bad "probe disposition receipt names outcome + reason"
fi

# --- oracle channel (exact block + host workload-output seam) ---

# 36. RED (F12): this invocation's workload file satisfies the oracle
# while observer diagnostics and a corrupt stale smoke cannot.
mkdir -p "$T/o-pass"
cp "$T/w-good.log" "$T/o-pass/known-n-workload.log"
cp "$T/driver.log" "$T/o-pass/known-n-driver.log"
cp "$T/smoke-corrupt.txt" "$T/o-pass/driver-smoke.txt"
cp "$T/rep.json" "$T/o-pass/known-n.json"
ln -s "$REPO/scripts" "$T/o-pass/scripts"
run_oracle_block o-pass ecdsa
if [ "$ORACLE_RC" -eq 0 ] \
    && grep -q 'ORACLE PASS' "$T/o-pass/oracle.txt" \
    && grep -q '0 ledgered iterations' "$T/o-pass/oracle.txt"; then
    ok "oracle block passes on the workload file (known-0, smoke ignored)"
else
    bad "oracle block passes on the workload file (known-0, smoke ignored) (rc=$ORACLE_RC)"
fi

# 37. RED (F12): a lost workload file fails closed, never skips.
mkdir -p "$T/o-lost"
cp "$T/driver.log" "$T/o-lost/known-n-driver.log"
cp "$T/rep.json" "$T/o-lost/known-n.json"
ln -s "$REPO/scripts" "$T/o-lost/scripts"
run_oracle_block o-lost ecdsa
if [ "$ORACLE_RC" -ne 0 ] \
    && grep -q 'ORACLE FAIL' "$T/o-lost/oracle.txt" 2>/dev/null \
    && ! grep -q 'ORACLE PASS\|ORACLE SKIP' "$T/o-lost/oracle.txt" 2>/dev/null; then
    ok "oracle block fails closed on a lost workload file"
else
    bad "oracle block fails closed on a lost workload file (rc=$ORACLE_RC)"
fi

# 38. The odd-count lower bound stays exact through the wired channel.
mkdir -p "$T/o-odd"
cp "$T/w-odd11.log" "$T/o-odd/known-n-workload.log"
cp "$T/driver.log" "$T/o-odd/known-n-driver.log"
cp "$T/rep11.json" "$T/o-odd/known-n.json"
ln -s "$REPO/scripts" "$T/o-odd/scripts"
run_oracle_block o-odd ecdsa
if [ "$ORACLE_RC" -eq 0 ] \
    && grep -q '11 op calls over 11' "$T/o-odd/oracle.txt"; then
    ok "oracle block passes 11 op calls over 11 ledgered"
else
    bad "oracle block passes 11 op calls over 11 ledgered (rc=$ORACLE_RC)"
fi

# 39. The odd-count shortfall still fails through the wired channel.
mkdir -p "$T/o-oddshort"
cp "$T/w-odd11.log" "$T/o-oddshort/known-n-workload.log"
cp "$T/driver.log" "$T/o-oddshort/known-n-driver.log"
cp "$T/rep10.json" "$T/o-oddshort/known-n.json"
ln -s "$REPO/scripts" "$T/o-oddshort/scripts"
run_oracle_block o-oddshort ecdsa
if [ "$ORACLE_RC" -ne 0 ] \
    && grep -q 'mode-op calls 10 below ledgered 11 iterations' "$T/o-oddshort/oracle.txt" 2>/dev/null; then
    ok "oracle block fails 10 op calls under 11 ledgered"
else
    bad "oracle block fails 10 op calls under 11 ledgered (rc=$ORACLE_RC)"
fi

# 40. A workload whose driver did not complete rc=0 fails
# (through the workflow block, not a direct oracle call).
mkdir -p "$T/o-rc1"
cp "$T/w-rc1.log" "$T/o-rc1/known-n-workload.log"
cp "$T/driver.log" "$T/o-rc1/known-n-driver.log"
cp "$T/rep.json" "$T/o-rc1/known-n.json"
ln -s "$REPO/scripts" "$T/o-rc1/scripts"
run_oracle_block o-rc1 ecdsa
if [ "$ORACLE_RC" -ne 0 ] \
    && grep -q 'did not complete rc=0' "$T/o-rc1/oracle.txt" 2>/dev/null; then
    ok "workload ORDDONE rc=1 fails"
else
    bad "workload ORDDONE rc=1 fails (rc=$ORACLE_RC)"
fi

# 41. Version-gated fixtures still skip with exit 3
# (through the workflow block; the report stays unopened).
mkdir -p "$T/o-skip"
cp "$T/w-skip.log" "$T/o-skip/known-n-workload.log"
cp "$T/driver.log" "$T/o-skip/known-n-driver.log"
ln -s "$REPO/scripts" "$T/o-skip/scripts"
run_oracle_block o-skip kem
if [ "$ORACLE_RC" -eq 3 ] \
    && grep -q 'ORACLE SKIP' "$T/o-skip/oracle.txt" 2>/dev/null; then
    ok "skipped ledger skips without opening report (exit 3)"
else
    bad "skipped ledger skips without opening report (rc=$ORACLE_RC)"
fi

# --- probe disposition hardening (fix round 1: findings 1+2) ---

# 42. RED (finding 1): an empty-checks ok report authorizes
# nothing, even with a matching exit and process status.
run_probe "$T/d-emptychecks.json" 0 p-emptychecks
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-emptychecks; then
    ok "probe ok report with empty checks fails setup without capable="
else
    bad "probe ok report with empty checks fails setup without capable= (rc=$PROBE_RC)"
fi

# 43. An ok report missing the artifact rows authorizes nothing.
run_probe "$T/d-noobjects.json" 0 p-noobjects
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-noobjects; then
    ok "probe ok report missing objects rows fails setup without capable="
else
    bad "probe ok report missing objects rows fails setup without capable= (rc=$PROBE_RC)"
fi

# 44. Malformed rows beside a failing caps row are setup failure,
# never an admitted skip.
run_probe "$T/d-malformed-rows.json" 4 p-malformed-rows
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-malformed-rows; then
    ok "probe caps failure plus malformed rows fails setup without capable="
else
    bad "probe caps failure plus malformed rows fails setup without capable= (rc=$PROBE_RC)"
fi

# 45. Unrecognized check statuses fail closed, never skip.
run_probe "$T/d-badstatus.json" 4 p-badstatus
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-badstatus; then
    ok "probe unrecognized check status fails setup without capable="
else
    bad "probe unrecognized check status fails setup without capable= (rc=$PROBE_RC)"
fi

# 46. The report exit field is required, not optional.
run_probe "$T/d-noexit.json" 0 p-noexit
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-noexit; then
    ok "probe ok report without exit fails setup without capable="
else
    bad "probe ok report without exit fails setup without capable= (rc=$PROBE_RC)"
fi

# 47. Duplicate check ids fail closed, never authorize.
run_probe "$T/d-dup.json" 0 p-dup
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-dup; then
    ok "probe duplicate check id fails setup without capable="
else
    bad "probe duplicate check id fails setup without capable= (rc=$PROBE_RC)"
fi

# 48. RED (finding 2): an unexpected kernel probe errno (ENOMEM)
# is setup failure, never an admitted capability absence.
run_probe "$T/d-enomem.json" 4 p-enomem
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-enomem; then
    ok "probe ENOMEM kernel failure fails setup without capable="
else
    bad "probe ENOMEM kernel failure fails setup without capable= (rc=$PROBE_RC)"
fi

# 49. An unattributed LSM denial is setup failure, never a skip.
run_probe "$T/d-lsm-noattr.json" 4 p-lsm-noattr
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-lsm-noattr; then
    ok "probe unattributed LSM denial fails setup without capable="
else
    bad "probe unattributed LSM denial fails setup without capable= (rc=$PROBE_RC)"
fi

# 50. An unexplained kernel denial (attributionless despite
# the "no lockdown/LSM/seccomp" text) is setup failure.
run_probe "$T/d-kern-nodeny.json" 4 p-kern-nodeny
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-kern-nodeny; then
    ok "probe unexplained kernel denial fails setup without capable="
else
    bad "probe unexplained kernel denial fails setup without capable= (rc=$PROBE_RC)"
fi

# 51. Attributed denials stay an admitted skip: a lockdown
# denial with the kernel/LSM rows pointing at lockdown.
run_probe "$T/d-lockdown-full.json" 4 p-lockdown-full
if [ "$PROBE_RC" -eq 0 ] && gh_has p-lockdown-full "capable=false"; then
    ok "probe lockdown denial with attributed rows yields capable=false"
else
    bad "probe lockdown denial with attributed rows yields capable=false (rc=$PROBE_RC)"
fi

# --- capture-to-oracle seam (fix round 1: finding 3) ---

# 52. The capture block runs under the runner's shell.
if command -v bash >/dev/null 2>&1; then
    ok "bash available to execute the capture block (runner shell)"
else
    bad "bash available to execute the capture block (runner shell)"
fi

# 53. RED (finding 3): this invocation's check command produces
# the consumed channel — the stub writes the workload file only
# through the block's --workload-out argument, and the oracle
# block consumes those capture outputs (decoy observer
# diagnostics in the driver log cannot satisfy it).
run_capture_block c-seam ecdsa "$T/capture-block.sh"
run_oracle_block c-seam ecdsa
if [ "$CAPTURE_RC" -eq 0 ] \
    && grep -q '^LEDGER ' "$T/c-seam/known-n-workload.log" 2>/dev/null \
    && grep -q '^ORDDONE mode=ecdsa rc=0' "$T/c-seam/known-n-workload.log" 2>/dev/null \
    && grep -q 'ops=99' "$T/c-seam/known-n-driver.log" 2>/dev/null \
    && [ "$ORACLE_RC" -eq 0 ] \
    && grep -q 'ORACLE PASS' "$T/c-seam/oracle.txt" 2>/dev/null; then
    ok "capture block output feeds the oracle block (stub seam PASS)"
else
    bad "capture block output feeds the oracle block (stub seam PASS) (capture_rc=$CAPTURE_RC oracle_rc=$ORACLE_RC)"
fi

# 54. The negative control really drops the argument.
grep -v -F -- '--workload-out known-n-workload.log' "$T/capture-block.sh" >"$T/capture-mutant.sh"
if grep -q -F 'workload-out' "$T/capture-mutant.sh" 2>/dev/null; then
    bad "capture mutant drops the --workload-out argument"
else
    ok "capture mutant drops the --workload-out argument"
fi

# 55. The seam detects a dropped --workload-out: capture stays
# silent (rc 0, no workload file) and the oracle fails closed.
run_capture_block c-mutant ecdsa "$T/capture-mutant.sh"
run_oracle_block c-mutant ecdsa
if [ "$CAPTURE_RC" -eq 0 ] \
    && [ ! -f "$T/c-mutant/known-n-workload.log" ] \
    && [ "$ORACLE_RC" -ne 0 ] \
    && grep -q 'ORACLE FAIL' "$T/c-mutant/oracle.txt" 2>/dev/null \
    && ! grep -q 'ORACLE PASS' "$T/c-mutant/oracle.txt" 2>/dev/null; then
    ok "capture without --workload-out fails the oracle (mutant red)"
else
    bad "capture without --workload-out fails the oracle (mutant red) (capture_rc=$CAPTURE_RC oracle_rc=$ORACLE_RC)"
fi

# --- required-row completeness (fix round 2: spawn-access) ---

# 56. An ok report missing only the spawn-access setup gate
# authorizes nothing: the producer always emits that row
# (doctor.rs check_spawn_access), and it can fail when the
# spawn probe cannot fork.
run_probe "$T/d-nospawn-ok.json" 0 p-nospawn-ok
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-nospawn-ok; then
    ok "probe ok report missing spawn-access fails setup without capable="
else
    bad "probe ok report missing spawn-access fails setup without capable= (rc=$PROBE_RC)"
fi

# 57. A fail-closed admitted report missing only spawn-access
# is setup failure, never a skip.
run_probe "$T/d-nospawn-fc.json" 4 p-nospawn-fc
if [ "$PROBE_RC" -ne 0 ] && gh_no_capable p-nospawn-fc; then
    ok "probe fail-closed report missing spawn-access fails setup without capable="
else
    bad "probe fail-closed report missing spawn-access fails setup without capable= (rc=$PROBE_RC)"
fi

# --- R10 guard-scope mutants (RED-proven) ---

# 58. Guard 10 is scoped to runs-on: a mutant workflow with the lane
# removed from runs-on but named in a comment fools the old
# anywhere-grep yet fails the scoped check.
sed -e 's/^\( *runs-on:.*\)osslscope-bpf/\1mutant-lane/' "$WF" >"$T/wf-mutant.yml"
echo "# mutant: osslscope-bpf named in a comment only" >>"$T/wf-mutant.yml"
if grep -q 'osslscope-bpf' "$T/wf-mutant.yml" \
    && ! grep -q 'runs-on:.*osslscope-bpf' "$T/wf-mutant.yml"; then
    ok "guard 10 mutant: comment-only lane fools anywhere-grep, fails scoped check"
else
    bad "guard 10 mutant: comment-only lane fools anywhere-grep, fails scoped check"
fi

# 59. Guard 16 is scoped to the live-gates block: a mutant check.yml
# with live execution inside live-gates (SKIP echo kept) fools the
# old anywhere-grep yet fails the scoped block check.
awk '{print} /live-known-n workflow is dispatch-only/{print "      - run: cargo test --live"}' "$CHECK_YML" >"$T/check-mutant.yml"
MUTANT_BLOCK=$(awk '/^  live-gates:/{f=1} f{print} f&&/^  [a-z-]+:/&&!/live-gates/{exit}' "$T/check-mutant.yml")
if grep -q 'SKIP(live-capability)' "$T/check-mutant.yml" \
    && echo "$MUTANT_BLOCK" | grep -q 'SKIP(live-capability)' \
    && echo "$MUTANT_BLOCK" | grep -qE 'cargo (test|run)|test-live-|live-oracle|osslscope run'; then
    ok "guard 16 mutant: live execution in live-gates fools anywhere-grep, fails scoped check"
else
    bad "guard 16 mutant: live execution in live-gates fools anywhere-grep, fails scoped check"
fi

echo "---"
echo "pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
