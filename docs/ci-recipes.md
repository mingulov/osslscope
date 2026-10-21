<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# CI gate recipes

CI gates use `check` in spawn mode (`run --`). Never `--pid` in
CI: pid attach is racy and staging-only by contract.
Spawn mode improves custody; it and warmup do not prove first-call
or COMPLETE coverage. Current integrated live/package qualification
remains open; these recipes describe current invocation semantics.

## Runner image

- Preferred: GHA `ubuntu-24.04` runners (full VM with sudo) or
  self-hosted 6.9+ runners with sudo for the one-time file-caps
  setup. The gate itself then runs unprivileged.
- Avoid `ubuntu-22.04` images (below the kernel floor; see
  [who should NOT adopt](what-it-proves.md#who-should-not-adopt-read-before-installing)).
- On Ubuntu 24.04 **servers** (which default to the GA kernel),
  install the HWE kernel first -- the 6.8 GA kernel is below the
  6.9 support floor. `doctor` gates on its functional feature
  probe, never the release number (the release is informational
  only), so a below-floor kernel is unsupported whether or not it
  happens to pass a given probe:

```sh
sudo apt-get install -y linux-generic-hwe-24.04
sudo reboot
# after reboot: uname -r must show a 6.9+ kernel
```

## Setup phase (privileged, once per runner)

```sh
sudo dpkg -i osslscope_<ver>-1_amd64.deb   # or: sudo dnf install ./osslscope-<ver>-1.*.x86_64.rpm
getcap /usr/bin/osslscope                  # expect: cap_bpf,cap_perfmon+ep
```

Current packages contain the host binary and install docs only.
Build the matching harvest/count/members roles with the pinned
toolchains (see [build](build.md)). For implicit traversal, install
through `scripts/install-dev.sh` into a trusted system prefix with
its matching receipt; three copied files do not establish it.
Selection searches trusted directories for a triple before a
pair; pair fallback requires members to be absent everywhere.
Alternatively use the explicit local-prefix recipe below.
Deliberate harvest/count-only installs remain valid without traversal.
If the install hook
warned about caps, re-apply:
`sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/osslscope`.
See [install](install.md).

## Gate step (unprivileged)

Preflight with the same objects the gate will use, then gate.
With a trusted system install, both resolve the BPF objects
implicitly; with a user-owned prefix (never trusted implicitly),
pass the same explicit harvest/count/members flags to both:

```sh
osslscope doctor || exit 4                      # preflight first, always

osslscope check \
  --provider /path/to/libcrypto.so.3 --builtin \
  --deny-weak --deny-provider legacy \
  --require-executed ML-KEM-768 \
  --duration 30 --grace 5 \
  --format json --out gate.json --image-digest "$IMAGE_DIGEST" \
  --workload-out workload.log \
  run -- ./my-app --smoke-test \
  >driver.log 2>&1                             # observer diagnostics only
```

User-owned-prefix variant (normal three-role install, same selected
objects on both commands):

```sh
PFX="$HOME/.local"
"$PFX/bin/osslscope" doctor --object "$PFX/lib/osslscope/osslscope-harvest" \
  --count-object "$PFX/lib/osslscope/osslscope-count" \
  --members-object "$PFX/lib/osslscope/osslscope-members" || exit 4

"$PFX/bin/osslscope" check \
  --provider /path/to/libcrypto.so.3 --builtin \
  --object "$PFX/lib/osslscope/osslscope-harvest" \
  --count-object "$PFX/lib/osslscope/osslscope-count" \
  --members-object "$PFX/lib/osslscope/osslscope-members" \
  --deny-weak --deny-provider legacy \
  --require-executed ML-KEM-768 --duration 30 --grace 5 \
  --format json --out gate.json --image-digest "$IMAGE_DIGEST" \
  --workload-out workload.log \
  run -- ./my-app --smoke-test >driver.log 2>&1
```

Notes:

- `check` needs at least one rule; a ruleless pass is a usage
  error (exit 2), never a green gate.
- `--builtin` observes libcrypto's built-in provider; drop it
  and point `--provider` at a provider `.so` to observe an
  external provider module instead. Omit explicit `--members-object`
  for that mode: traversal requires a builtin query anchor;
  automatic triple selection can degrade to harvest-only.
- `--image-digest` records the container digest in the actionability
  tuple (empty string on bare metal).
- `--workload-out workload.log` captures the workload's own
  stdout/stderr to a file; without it the workload output goes
  to /dev/null and observer stdout stays a pure artifact
  channel. Observer diagnostics stay in `driver.log` and are
  never oracle input.
- Defaults when flags are omitted: `--duration 30`,
  `--settle 2`, `--timeout 60`, `--grace 5` (all seconds).
  <!-- source: defaults: src/report.rs, src/check.rs, src/capture.rs -->

## Exit handling

| Exit | Meaning | Gate action |
|---|---|---|
| 0 | clean (COMPLETE, no violation) | pass |
| 3 | PARTIAL evidence, passing policy verdict | warn + upload artifacts; gate passes by default (strict-fail is team policy) |
| 10 | proved policy violation (on COMPLETE, PARTIAL or usable FATAL) | fail; triage per [violation triage](violation-triage.md) |
| 11 | inconclusive: a requirement is unproven under relevant uncertainty | fail; triage the relevant gap per [the PARTIAL runbook](partial-runbook.md) -- the requirement is unproven, never fabricated |
| 4 | unusable fatal/no verdict (environment, recycled target, bare AttachZero) | fail; run `doctor`, remediate, retry (see [attach failures](attach-failures.md)) |
| 1 | usable fatal, child failure or delivery failure | fail; read `disposition`, `completeness.fatal_kind` and delivery diagnostics |
| 2 | usage/config error | fail; fix the invocation |

Current integrated COMPLETE-window qualification is open (see [who should NOT
adopt](what-it-proves.md#who-should-not-adopt-read-before-installing)).
Affected GLOB_DAT imports remain uninstrumented, but not every TLS
target has the same reason or count shape. Gate on actual policy
and disclosed gaps. A proved violation dominates every tool failure,
including failed delivery or usable fatal evidence. Runtime is
eligible even with zero counts; AttachZero needs proved positive
in-window ENGINE evidence. Usability proves no particular rule.
A usable fatal without violation exits 1. Child/delivery failures
also outrank inconclusive, so a per-rule inconclusive result does
not guarantee exit 11. See [the full precedence](usage.md#exit-codes).

## Artifact upload

Always upload available artifacts, including on violation, PARTIAL
and fatal outcomes. The capture paths attempt each requested primary
and CBOM independently, including typed fatal output. A destination
can fail: retain delivery diagnostics and do not assume a file exists.

- `gate.json` (the full evidence document: window, completeness,
  sites, coverage, legacy partition, policy).
- The CBOM file when `--cbom` is passed (CycloneDX 1.6; PARTIAL
  evidence travels as a `metadata` disclaimer property).
- `workload.log` (the workload's own output) and `driver.log`
  (observer diagnostics) for triage.

Example (GitHub Actions):

```yaml
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: cryptogate
    path: |
      gate.json
      cbom.json
      workload.log
      driver.log
```

## CI timeout

`--duration` sets the requested observation window; the CI
step timeout is a separate, outer bound and must exceed the
capture window plus drain grace plus twice the unobserved
test baseline:

```text
CI timeout >= duration + grace + test-baseline x 2
```

With defaults (30 s window, 5 s grace) and a 60 s smoke-test
baseline, set the step timeout above 155 s so the runner never
kills the observer mid-window (a signal-cut window is always
PARTIAL). That outer timeout is protection against the kill,
not against over-budget: `capture.over_budget` fires whenever
the target is still alive at window expiry, however generous
the CI timeout (the observer never kills its child). Fit the
workload inside the requested window instead --
quit-before-expiry discipline, split windows, or a `--duration`
the workload actually fits in (a 60 s smoke test needs a window
above 60 s, not a 30 s window with a long timeout).
<!-- source: window/disposition behavior: src/capture.rs;
     typed completeness: src/evidence.rs -->

At window end the observer detaches a still-running owned child
and leaves it running (`disposition: detached-running` with its
pid; the child is never signaled). The observer forked that
child, so once the observer exits the workload reparents away
from the invoking shell -- the shell cannot `wait()` on a
grandchild it never parented. Run the step under a
supervisor/sub-reaper arrangement (the CI agent's own process
supervision, a supervisor such as `tini`/`dumb-init`, or an init
that adopts orphans): the step monitors the pid from
`disposition` and shuts the workload down (signal, wait for
exit), while the supervisor is what actually reaps it. Size the
timeout for the workload's own shutdown either way.
