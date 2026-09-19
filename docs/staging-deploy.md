<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Staging deploy

CI gates with `run --`. Staging observes already-running
services with `report --pid` from an ephemeral privileged
debug container that shares the target's pid namespace.
`--pid` windows are PARTIAL by architecture
(`pid-prewindow-blind` plus usually `no-query` on warm
targets), so staging evidence is triage-grade: good for
confirming what executes, never a COMPLETE inventory.
<!-- source: --pid blind by design: src/capture.rs; run-vs-pid
     trigger behavior: trigger-matrix.md -->

## Debug container shape

Requirements for the ephemeral container:

- Shares the target's pid namespace (`pid:` of the target pod /
  `--pid container:<target>` under plain docker).
- Privileged enough to observe: file caps
  `CAP_BPF`+`CAP_PERFMON` on the osslscope binary (plus
  `CAP_SYS_PTRACE` when the target runs as a foreign uid), or
  full privilege as the documented fallback.
- Carries the osslscope binary plus the two BPF objects
  (`--object`, `--count-object`) and the provider path the
  target uses.

Example (Kubernetes; plain-docker equivalent uses
`--pid container:<name> --privileged --rm`):

```sh
kubectl debug -it <target-pod> --image=<tools-image> \
  --target=<target-container> --share-processes -- <shell>
```

The debug session is ephemeral: observe, copy the JSON/CBOM
artifacts out, exit. Nothing persists in the target.

## Observe

```sh
osslscope doctor --pid <PID>     # target preflight; exit 4 refuses unsuitable targets
osslscope report --provider /path/to/libcrypto.so.3 --builtin \
  --object ./osslscope-harvest --count-object ./osslscope-count \
  --duration 60 --format json --out staging.json --cbom staging.cbom.json \
  --pid <PID>
```

Generate real traffic during the window (staging load or a
handshake driver); an idle target yields `no-query` PARTIAL
with zero rows. Expect PARTIAL: harvest needs a post-attach
query, and pre-attach history is invisible. The measured
staging shape for a TLS terminator is PARTIAL with a single
structural `lowlevel-fallback-uninstrumented` reason, exact
traffic-scaled counts (handshake multiples), and a passing
`--require-executed` rule -- actionable evidence despite the
PARTIAL status.
<!-- source: frozen staging recipe (run + warmup + quit
     discipline) and measured shape: staging-nginx note;
     design-partner env verdicts (TLS, static, FIPS):
     p6-entry-envs note -->

For a statically linked target, point `--provider` at the
static binary with `--builtin` (unstripped: harvest resolves
via symtab; stripped: expect disclosed zero-row blindness).
For a FIPS provider module, use provider mode (`--provider
.../fips.so`, not `--builtin`) per
[the FIPS interim rule](fips-interim.md).

## Gate-disable procedure

When a staging gate blocks deploys (persistent exit 4 or a
contested exit 10), disable the gate -- never bypass evidence
collection:

1. Flip the gate step to warn-plus-artifacts (keep running
   `check`, keep uploading JSON/CBOM; stop failing the
   pipeline on its exit). Record who approved and why.
2. Triage off the artifacts: [attach failures](attach-failures.md)
   for exit 4, [violation triage](violation-triage.md) for
   exit 10, [PARTIAL runbook](partial-runbook.md) for exit 3
   under strict-fail policy.
3. Re-enable the fail behavior only when the same gate passes
   (or warns, for accepted PARTIAL shapes) on the fixed
   staging deployment.

The gate step stays in the pipeline in warn mode throughout:
a disabled gate that still collects evidence is a paused
enforcer, while a deleted gate step is lost coverage.
