#!/usr/bin/env bash
# P0-8 observe-arm verification. Runs ONLY inside the vng guest.
set -euo pipefail
export RUSTUP_HOME=/home/agent/.rustup CARGO_HOME=/home/agent/.cargo
export PATH=/home/agent/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export RUST_TEST_THREADS=1
export TRACE_LIVE_SMOKE=1
export OSSL_PROVIDER_OBSERVATION_TEST_BPF=/work/osslscope-ws/osslscope/target/debug/osslscope-provider-observation
export TMPDIR=/tmp/osslscope-vng-live OSSL_TEST_ROOT=/tmp/osslscope-vng-live OSSL_PACKAGE_TEST_PRIVATE_DIR=/tmp/osslscope-vng-live/pkg
mkdir -p "$TMPDIR" "$OSSL_PACKAGE_TEST_PRIVATE_DIR" && chmod 700 "$TMPDIR" "$OSSL_PACKAGE_TEST_PRIVATE_DIR"
SHARE=/work/osslscope-ws/tmp/vng-lane/sigint-obs-evidence
mkdir -p "$SHARE"
trap 'cp /tmp/obs_out.txt /tmp/obs_err.txt /tmp/obs2_out.txt /tmp/obs2_err.txt "$SHARE"/ 2>/dev/null || true' EXIT
stat -f -c "%T %n" /dev/shm
mkdir -p /dev/shm/ossl-tmpfs
cp /usr/lib/x86_64-linux-gnu/libcrypto.so.3 /dev/shm/ossl-tmpfs/
export LD_LIBRARY_PATH=/dev/shm/ossl-tmpfs
uname -r; id -u
cd /work/osslscope-ws/osslscope
LD_LIBRARY_PATH=/dev/shm/ossl-tmpfs /home/agent/.cargo/bin/cargo +1.88.0 build --locked --offline --bin osslscope
BIN=/work/osslscope-ws/osslscope/target/debug/osslscope
# Root-owned staging (lane pattern from crash-repro-direct.sh): load_companion
# trust-checks the binary path when euid=0, so the agent-owned target tree
# would degrade to passive inventory. Staging proves the arm is LIVE.
STAGE=/opt/ossl-observe-$$
mkdir -p "$STAGE"
cp "$BIN" /work/osslscope-ws/osslscope/target/debug/osslscope-provider-observation /work/osslscope-ws/osslscope/target/debug/osslscope-focused-count "$STAGE"/
chown root:root "$STAGE"/osslscope "$STAGE"/osslscope-provider-observation "$STAGE"/osslscope-focused-count
chmod 755 "$STAGE"/osslscope; chmod 644 "$STAGE"/osslscope-provider-observation "$STAGE"/osslscope-focused-count
sha256sum "$STAGE"/osslscope-provider-observation "$STAGE"/osslscope-focused-count
BIN="$STAGE/osslscope"
LD_LIBRARY_PATH=/dev/shm/ossl-tmpfs python3 -c "import ssl, time; time.sleep(300)" & WORKLOAD=$!
sleep 1
grep "libcrypto" /proc/$WORKLOAD/maps | head -2 || echo "NO_LIBCRYPTO_IN_MAPS"
MAPS_TMPFS=$(grep -c "ossl-tmpfs" /proc/$WORKLOAD/maps || true)
echo "WORKLOAD_TMPFS_MAPS=$MAPS_TMPFS"
test "$MAPS_TMPFS" -gt 0
LINKS_BEFORE=$(bpftool link list 2>&1 | grep -c . || true)
echo "LINKS_BEFORE=$LINKS_BEFORE"
LD_LIBRARY_PATH=/dev/shm/ossl-tmpfs $BIN scan --pid $WORKLOAD --watch --observe-crypto --interval 1 --duration 120 >/tmp/obs_out.txt 2>/tmp/obs_err.txt & OBSERVER=$!
sleep 8
LINKS_DURING=$LINKS_BEFORE
for i in $(seq 1 12); do
  LINKS_DURING=$(bpftool link list 2>&1 | grep -c . || true)
  if test "$LINKS_DURING" -gt "$LINKS_BEFORE"; then break; fi
  sleep 5
done
echo "LINKS_DURING=$LINKS_DURING"
kill -0 $OBSERVER && echo "OBSERVER_ALIVE" || echo "OBSERVER_DEAD"
echo "--- pre-kill stdout tail ---"; tail -8 /tmp/obs_out.txt
echo "--- pre-kill stderr tail ---"; tail -8 /tmp/obs_err.txt
test "$LINKS_DURING" -gt "$LINKS_BEFORE"
START=$(date +%s%N)
kill -INT $OBSERVER
ACK_MS=-1
for i in $(seq 1 200); do
  if grep -q "shutting down" /tmp/obs_err.txt 2>/dev/null; then ACK_MS=$(( ($(date +%s%N) - START) / 1000000 )); break; fi
  sleep 0.05
done
CODE=0; wait $OBSERVER || CODE=$?
END=$(date +%s%N)
ELAPSED_MS=$(( (END - START) / 1000000 ))
echo "ACK_MS=$ACK_MS ELAPSED_MS=$ELAPSED_MS EXIT=$CODE"
echo "--- stdout tail ---"; tail -5 /tmp/obs_out.txt
echo "--- stderr tail ---"; tail -5 /tmp/obs_err.txt
grep -q "shutting down" /tmp/obs_err.txt
# End record is route-specific: the inventory-watch arm prints "Watch ended:",
# while this crypto-watch arm ends with "Crypto watch end: cancelled, ...".
tail -5 /tmp/obs_out.txt | grep -q "Crypto watch end"
tail -5 /tmp/obs_out.txt | grep -q "cancelled"
test "$CODE" -eq 3
test "$ACK_MS" -ge 0
test "$ELAPSED_MS" -lt 5000
kill -0 $WORKLOAD
# Second-signal variant: two rapid SIGINTs must exit 130 immediately.
# Back-to-back kills (no 0.2s gap): shutdown latency on this arm is bimodal
# (~31ms with no drain state at interval 30, ~2.6s attached at interval 1,
# and one ~210ms fast exit at interval 1 in run 8), so any fixed gap is racy
# — runs 4-6/8 exited 3 (second kill on a zombie), run 7 exited 130. Two
# kills microseconds apart both land on the live process (minimum observed
# shutdown 31ms; SigBlk=0, so no coalescing), and the shared Shutdown
# handler _exit(130)s on the second delivery. Same task-3-N2 sync-repair
# precedent: only synchronization changed, asserted 130 verbatim.
LINKS2_BEFORE=$(bpftool link list 2>&1 | grep -c . || true)
echo "LINKS2_BEFORE=$LINKS2_BEFORE"
LD_LIBRARY_PATH=/dev/shm/ossl-tmpfs $BIN scan --pid $WORKLOAD --watch --observe-crypto --interval 1 --duration 300 >/tmp/obs2_out.txt 2>/tmp/obs2_err.txt & OBSERVER2=$!
sleep 8
LINKS2=$LINKS2_BEFORE
for i in $(seq 1 12); do
  LINKS2=$(bpftool link list 2>&1 | grep -c . || true)
  if test "$LINKS2" -gt "$LINKS2_BEFORE"; then break; fi
  sleep 5
done
echo "LINKS2_DURING=$LINKS2"
test "$LINKS2" -gt "$LINKS2_BEFORE"
grep SigBlk /proc/$OBSERVER2/status || echo "SIGBLK_UNKNOWN"
T2_START=$(date +%s%N)
kill -INT $OBSERVER2
KILL2_RC=$?
kill -INT $OBSERVER2 2>/tmp/kill2_err.txt
KILL2_RC2=$?
ACK2_MS=-1; DEATH2_MS=-1
for i in $(seq 1 250); do
  NOW_MS=$(( ($(date +%s%N) - T2_START) / 1000000 ))
  if test "$ACK2_MS" -lt 0 && grep -q "shutting down" /tmp/obs2_err.txt 2>/dev/null; then ACK2_MS=$NOW_MS; fi
  STATE2=$(awk '/^State:/{print $2}' /proc/$OBSERVER2/status 2>/dev/null || echo gone)
  if test "$STATE2" = "Z" || test -z "$STATE2" || test "$STATE2" = "gone"; then DEATH2_MS=$NOW_MS; break; fi
  if test "$NOW_MS" -ge 5000; then break; fi
  sleep 0.02
done
echo "KILL2_DIAG: kill1_rc=$KILL2_RC kill2_rc=$KILL2_RC2 kill2_err=$(cat /tmp/kill2_err.txt 2>/dev/null) ack2_ms=$ACK2_MS death2_ms=$DEATH2_MS state2=$STATE2"
CODE2=0; wait $OBSERVER2 || CODE2=$?
echo "SECOND_SIGNAL_EXIT=$CODE2 (expect 130)"
echo "--- variant2 stderr tail ---"; tail -5 /tmp/obs2_err.txt
test "$CODE2" -eq 130
kill -0 $WORKLOAD
kill $WORKLOAD || true
echo "GUEST_DMESG_BPF_ERRORS=$(dmesg 2>&1 | grep -ciE 'bpf|uprobe' || true)"
dmesg 2>&1 | grep -iE 'bpf|uprobe' | cut -c1-200 | head -5 || true
dmesg 2>&1 | grep -iE '\boops\b|\bpanic\b|\bgpf\b|\bBUG\b' | cut -c1-200 | head -5 || echo "GUEST_NO_OOPS_PANIC"
rm -rf "$STAGE"
echo "OBSERVE_ARM_SIGINT_OK"
