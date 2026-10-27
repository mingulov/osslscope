#!/bin/sh
# v0.2 gap-accept 13/14: the pinned ebpf build must emit zero
# rustc warnings. The bpf-linker LLVM dlopen fallback note
# ("unable to open LLVM shared lib", linker_messages) is an
# accepted toolchain-environment property — build-dev.sh records
# it as DIAGNOSTICS ("Not a toolchain defect; do not upgrade
# toolchains for it.") — and is the ONLY permitted warning text.
set -eu
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT INT TERM
if ! (cd "$REPO/crates/ebpf" && cargo +nightly-2026-05-20 build --locked -Z build-std=core --target bpfel-unknown-none --release --bin osslscope-harvest --bin osslscope-count --bin osslscope-members --bin osslscope-provider-observation --bin osslscope-focused-count >"$LOG" 2>&1); then
    echo "ebpf build failed:"; cat "$LOG"; exit 1
fi
if grep -E '^warning: (comparison is useless|unused)' "$LOG"; then
    echo "FAIL: rustc warnings present in the ebpf build"; exit 1
fi
if grep '^warning:' "$LOG" | grep -v -E 'linker stderr: unable to open LLVM shared lib|generated [0-9]+ warning'; then
    echo "FAIL: unexpected warning text in the ebpf build"; exit 1
fi
echo "ebpf build warnings: clean (LLVM dlopen note only)"
