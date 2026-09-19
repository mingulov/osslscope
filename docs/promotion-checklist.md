<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Staging-to-production promotion checklist

v1 promotes bounded, evidence-carrying observation from staging
to production-like capture. Always-on production attach is v2+
and out of scope: every item below assumes time-boxed windows
with artifacts. Promote only when every item passes.
<!-- source: checklist shape: PLAN.md P6 exit 2; evidence:
     p5-gate-record.md, p6-entry-envs note -->

## Platform

- [ ] **Matrix green on the prod-class platform.** Target OS,
  kernel, and OpenSSL release are all inside
  [the support matrix](overhead-matrix.md#support-matrix), and
  `doctor` (env plus `--pid`/`--libcrypto` target checks)
  reports green there -- not just on the CI runner.
- [ ] **Worst-cell budgets sustained.** The prod kernel class
  carries a passing overhead row in the matrix (pin
  overhead-sensitive gates to 6.12+ runners); the known
  report-only outlier class (6.9 guest kernel with CET-built
  targets under nested virt) is either absent from prod or
  accepted as documented-slow with correctness intact.
- [ ] **No SecureBoot-qualified claim.** If prod boots with
  SecureBoot enabled, v1 claims no qualified status there
  (qualification deferred post-v1). Record the gap or move
  observation to a non-SB host.

## Evidence quality

- [ ] **PARTIAL rate and reasons stable.** The staging PARTIAL
  shape is understood and attributed per
  [the PARTIAL runbook](partial-runbook.md) (for TLS
  terminators: single structural reason, exact
  traffic-scaled counts, passing require rules). Prod-class
  windows show the same reasons -- any NEW reason blocks
  promotion until attributed.
- [ ] **Zero silent misattributions.** Generation fencing is
  intact (remap/reload counts land in fenced stale buckets,
  never on stale keys); the no-secret canary suite is green
  on the release build. A fenced count is honest evidence; a
  misattributed one would be a product lie -- the latter
  blocks promotion absolutely.
- [ ] **Change control on observed binaries.** Every libcrypto
  build in prod is enrolled (known build-id) BEFORE the
  deploy that ships it. Rebuilds mint new build-ids even from
  identical sources, so the deploy pipeline re-enrolls (or
  fails closed on unknown ids) rather than observing blind.
- [ ] **FIPS lanes under the interim rule.** Any FIPS-provider
  window in prod is triaged manually per
  [the FIPS interim rule](fips-interim.md); no auto
  pass/fail on `fips-unlabeled` counts.

## Operations

- [ ] **Time-boxed capture only.** All captures carry explicit
  `--duration`/`--grace`, and step timeouts follow the
  `duration + grace + test-baseline x 2` rule. No unbounded
  runs exist anywhere in the pipeline (there is no
  `--forever` in v1).
- [ ] **Violation triage exercised.** An operator unfamiliar
  with the fixture has walked a staged violation from the
  JSON record to the owning service and re-verified the fix
  with the same gate (see [violation
  triage](violation-triage.md)). Image digests flow into the
  actionability tuple for container fleets.
- [ ] **Evidence retained.** Gate artifacts (JSON report,
  CBOM) upload on every outcome including violation and
  PARTIAL; PARTIAL CBOMs carry the completeness disclaimer
  for downstream consumers.
- [ ] **Gate-disable procedure known.** The on-call path for a
  blocking gate is warn-plus-artifacts with recorded
  approval -- never deleting the gate step (see
  [staging deploy](staging-deploy.md#gate-disable-procedure)).
