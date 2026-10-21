<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Staging-to-production promotion checklist

Current development supports bounded observation with artifacts.
The historical `v0.1.0` baseline and matrix do not qualify the
current integrated artifact. Service operation and expanded target
selection remain forthcoming; permanent privacy boundaries remain
in force. These acceptance checks do not declare release readiness.

## Platform

- [ ] **Exact prod-class artifact qualified.** Retain current
  evidence for the target OS, kernel, libc, OpenSSL and installed
  artifact combination. Use the [historical matrix](overhead-matrix.md#support-matrix)
  for context; `doctor` environment/target admission alone is not
  integrated correctness or performance qualification.
- [ ] **Both overhead budgets measured.** Measure latency and
  wall-clock at representative rates on the actual platform.
  Historical fixture passes and the documented 6.9 nested-virt
  outlier do not replace a current measurement.
- [ ] **Security controls preserved.** Qualify required Secure Boot,
  lockdown and enforcing SELinux states as enabled. A disabled-state
  control, root/container success or a different distro does not
  qualify them. Secure Boot operation remains unqualified until
  enabled-state evidence exists; do not disable controls to pass.

## Evidence quality

- [ ] **Coverage and PARTIAL reasons attributed.** Inspect typed
  reasons, loss counters and candidate uncertainty per
  [the PARTIAL runbook](partial-runbook.md). Bound address-taken
  GLOB_DAT gaps to the actual target. New or unexplained gaps block
  acceptance; never assume one universal TLS reason or count shape.
  Keep ordinary failed/PARTIAL windows in completeness-rate
  denominators; exclude only predeclared expected-PARTIAL negatives.
- [ ] **No silent misattribution or secret capture.** Verify
  generation fencing, conserved physical counts and the no-secret
  canary suite on the exact artifact. Candidate alternatives are
  not separately executed algorithms.
- [ ] **Exact observed binaries admitted.** Recheck hashes,
  build-ids and anchors after rebuilds. Unknown supported symtab
  builds can qualify without a table row; unknown stripped builds
  require explicit enrollment per [the built-in runbook](builtin-runbook.md).
  Enrollment alone proves no live/performance acceptance.
- [ ] **FIPS results interpreted manually.** Preserve the original
  counts and policy verdict, self-test uncertainty and independent
  rationale per [the FIPS interim rule](fips-interim.md). Do not
  rely on a guaranteed `fips-unlabeled` v2 reason or infer
  certification.

## Operations

- [ ] **Time-boxed capture.** Set duration/grace and size outer
  timeouts per [CI recipes](ci-recipes.md#ci-timeout). Spawn mode,
  warmup and a long timeout alone prove no complete window.
- [ ] **Policy and exit handling exercised.** An operator has
  traced a rule's actual evidence to its service and re-verified
  the correction per [violation triage](violation-triage.md).
  Respect [exit precedence](usage.md#exit-codes), including usable
  fatal and inconclusive outcomes.
- [ ] **Evidence retained.** Upload available JSON/CBOM on every
  outcome, including fatal. Requested artifacts are attempted
  independently; verify delivery and retain diagnostics when a
  destination fails. Keep workload logs under appropriate access
  controls.
- [ ] **Installed journey qualified.** Current package builders
  contain the host binary and install documentation only. A local
  development triple/receipt is not acceptance of a forthcoming
  matched redistributable host+BPF package; see [install](install.md).
- [ ] **Gate-disable procedure known.** Use approved
  warn-plus-artifacts handling while triaging a blocking gate;
  retain collection per [staging deploy](staging-deploy.md#gate-disable-procedure).
