<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Staging deploy

CI gates with `run --`. Staging observes already-running
services with `report --pid` from an ephemeral privileged
debug container that shares the target's pid namespace.
`--pid` cannot recover pre-attach execution. Read current typed
startup/coverage/loss reasons and candidate uncertainty rather
than expecting the legacy display strings `pid-prewindow-blind`
or `no-query` in v2 JSON. A failed provider attachment may instead
produce AttachZero; its policy eligibility depends on proved
in-window ENGINE evidence. See [the exit table](usage.md#exit-codes).
Staging evidence confirms observed execution under disclosed
limits; it supplies no complete historical inventory.

## Debug container shape

Requirements for the ephemeral container:

- Shares the target's pid namespace (`pid:` of the target pod /
  `--pid container:<target>` under plain docker).
- Privileged enough to observe: file caps
  `CAP_BPF`+`CAP_PERFMON` on the osslscope binary (plus
  `CAP_SYS_PTRACE` when the target runs as a foreign uid), or
  full privilege as the documented fallback.
- Carries the matching osslscope binary and harvest/count/members
  development roles (explicit `--object`, `--count-object`,
  `--members-object`) plus access to the target provider file.
  A deliberate pair-only image stays harvest-only. Current package
  builders do not supply BPF; implicit traversal requires a trusted
  install with matching receipt, not three loose files.

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
osslscope doctor --pid <PID> \
  --object ./osslscope-harvest --count-object ./osslscope-count \
  --members-object ./osslscope-members
osslscope report --provider /path/to/libcrypto.so.3 --builtin \
  --object ./osslscope-harvest --count-object ./osslscope-count \
  --members-object ./osslscope-members \
  --duration 60 --format json --out staging.json --cbom staging.cbom.json \
  --pid <PID>
```

Generate real traffic during the window (staging load or a
handshake driver). Harvest needs observed provider queries; an idle
or preloaded target can yield no rows. Read actual typed reasons,
physical-site counts and policy evidence. Affected GLOB_DAT imports
remain uninstrumented and surface as `loss` with
`legacy.lowlevel_uninstrumented`; this is not a universal TLS
reason/count shape. Historical spawn-and-warmup staging results do
not qualify this current live-attach recipe. Current integrated
COMPLETE-window qualification remains open; switching to `run --`
improves custody without guaranteeing startup/first-call coverage.

For a statically linked target, point `--provider` at the
static binary with `--builtin` (unstripped: harvest resolves
via supported symtab; unknown stripped: report/check need explicit
enrollment, while inspect can expose zero-row blindness).
For a FIPS provider module, use provider mode (`--provider
.../fips.so`, not `--builtin`), omitting explicit `--members-object`
from both preflight and capture, per
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
