<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Violation triage

`check` exits 10 on violation -- on COMPLETE or PARTIAL evidence
alike (violation dominates the exit precedence). Fatal evidence
never yields a violation (NO VERDICT instead). Triage reads the
record, walks it to the owning service, fixes the cause, and
re-verifies with the same gate.
<!-- source: exit precedence (violation dominates), no verdict on
     fatal: src/check.rs -->

## 1. Read the record

The JSON document's `policy` section carries `verdict`,
per-rule `rules[]`, and one `violations[]` entry per breach.
Every violation carries the actionability tuple:

- `rule` + `matcher` (which rule, which name matched or was absent)
- identity: provider label, op, `alg_class`, funcid, count,
  first/last-seen window position
- target: pid, `target.comm`, `target.argv_redacted: true` (raw argv
  never publishes — the fixed `(argv-redacted)` placeholder renders
  instead), `target.container_id`, `image_digest` (empty
  on bare metal)
- provider object path + `provider.build_id`

<!-- source: violation shape + actionability tuple: src/check.rs,
     field tokens: docs/privacy/allowlist-v1.md -->

Two fail-closed shapes to recognize immediately:

- `--require-executed X` absent from PARTIAL evidence is a
  violation, not a pass: degraded evidence must not silently
  pass a require rule. Re-run for better evidence before
  concluding the algorithm is truly absent.
- `--deny-algorithm` is blind to SIGN/MAC/KDF digest selection
  (parameter values are never captured); the human output says
  so on every run. A digest-identity question needs a different
  instrument, not a tighter rule.

## 2. Walk to the owning service

`target.comm` names the process image (raw argv never publishes —
see `target.argv_redacted`); `target.container_id` +
`image_digest` name the deployed unit. Map that tuple to the
owning service and config in your inventory (the image digest is
the join key in container fleets). On bare metal, pid/
`target.comm` plus the provider path/`provider.build_id`
identify the deployment; join invocations via your own process
accounting, never the redacted argv.

## 3. Reproduce with `report`

Re-run the same window as `report run --` with the same
provider/objects/duration and confirm the violating identity
executes (same op/`alg_class`/funcid, count > 0). If the
reproduction is PARTIAL in a way that hides the identity,
follow [the PARTIAL runbook](partial-runbook.md) first -- do
not fix a service on evidence you cannot reproduce.

## 4. Fix by rule class

| Rule | Usual cause | Fix direction |
|---|---|---|
| `deny-algorithm` / `deny-weak` | Legacy algorithm still configured or negotiated (old peer, default config, fallback path). | Pin the modern algorithm in config; remove the legacy name from negotiation lists; upgrade the peer or fence the legacy path and re-verify. |
| `deny-provider` | Wrong provider serves the call (legacy provider loaded, third-party provider in the module path). | Unload/remove the denied provider from config and module path; verify the intended provider serves the fetch. |
| `deny-engine` | 3.x ENGINE API still invoked. | Migrate the caller to provider APIs (4.x removes ENGINE upstream). |
| `require-provider` / `require-executed` | Expected crypto never executed in-window (misconfig, dead code path, or a window that missed the traffic). | Confirm traffic actually flowed in-window (warmup + measured load); fix config so the required path executes; re-run. |

FIPS-lane violations always need manual triage per
[the FIPS interim rule](fips-interim.md) -- counts there may
include self-test executions.

## 5. Re-verify with the same gate

Re-run the identical `check` invocation (same rules, same
target, same window flags). Close the loop only when the rule
passes; keep the before/after JSON artifacts together for the
audit trail.

## Out of v1 scope

Call-site granularity is out of v1: a violation names the
executed dispatch identity (provider/op/algorithm/function),
not the source line or stack that called it. Per-call trace
output and latency attribution are post-v1. If a violation's
owning call site is ambiguous, narrow it by re-running scoped
workloads (one code path per window) rather than by asking the
document for stacks it never captured.
