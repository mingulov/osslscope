<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# PARTIAL runbook: per-reason response

A PARTIAL window (exit 3) carries `reasons[]`, each with exactly
one honest story. Find your reason below and follow the response.
Reasons marked **clean** describe an empty-but-honest window;
**blind** reasons describe evidence that exists but is
unobserved -- treat those windows as lower bounds, not
inventories.
<!-- source: reason vocabulary + blind/clean taxonomy:
     src/report.rs (reason_class), src/capture.rs -->

General rules:

- Always read the JSON (`completeness.counters`), not just the
  exit code. Fix the cause, then re-run; never average PARTIAL
  windows into a COMPLETE claim.
- `check` fails closed where missing evidence matters: a
  `--require-executed` name absent from PARTIAL evidence is a
  violation, not a pass.
- Window-only claims still hold: "none observed in window" never
  means "not present".

## Window / trigger reasons

| Reason | Class | Meaning | Response |
|---|---|---|---|
| `no-query` | clean | No provider query fired post-attach, so no rows were harvested (idle target, or `--pid` onto a pre-loaded provider). | Use `run --` so queries fire post-attach; add warmup traffic during harvest (a handshake before the window opens); for `--pid` on a warm target this shape is expected -- see `pid-prewindow-blind`. |
| `empty-inventory` | clean | Queries fired but yielded no rows. | Same as `no-query`: warmup traffic plus `run --`. |
| `harvest-no-query-trigger` | clean | The harvest phase itself saw no query trigger. | Same as `no-query`; check the target actually performs crypto during harvest. |
| `cold-gap` | blind | Executions happened before the affected keys attached (lazy fetch after exec). Counter: `cold_gap_calls`. | Use `run --` (pre-exec attach) plus warmup traffic during harvest so fetches query before plan/attach. |
| `pid-prewindow-blind` | blind | `--pid` attach: the target ran unobserved during the multi-second harvest-to-attach phase, so pre-window zero is unprovable. `--pid` COMPLETE is unreachable by design. | Use `run --` when completeness matters; `--pid` is staging-only (see [staging deploy](staging-deploy.md)). |
| `over-budget` | blind | The target was still alive at window expiry (`over_budget=1`); post-window executions are unobserved. The observer never kills its child. | Shorten the workload or split it into several windows with quit-before-expiry discipline; raise `--duration` only if the workload then fits inside one window. |
| `interrupted` | blind | SIGTERM/SIGINT cut the window; signal-cut windows are always PARTIAL by construction. | Size the CI timeout per [the recipes](ci-recipes.md#ci-timeout) and re-run undisturbed. |
| `fork-exec-ignored` | blind | v1 is single-TGID: fork/exec children are out of scope (counter: `fork_exec_ignored`). | Observe the child directly (`run --` the child command, or `--pid` on the child in staging). |
| `drain-shortfall` | blind | Keys remained unpolled at grace expiry (counter: `drain_shortfall`). | Raise `--grace` and re-run. |
| `dropped-events` | blind | Ring/map pressure dropped events (counters: `dropped_events` BPF + userspace split). | Shorten the window or reduce the dispatch rate under observation, then re-run; drops are counted, never silent. |

## Attach / plan reasons

| Reason | Class | Meaning | Response |
|---|---|---|---|
| `missed-attaches` | blind | Some planned probes attached nowhere (counter: `missed_attaches`). Refusals can be kernel-specific and stable across runs. | Run `doctor`, remediate, re-run. If the count is stable (e.g. a fixed set of kernel-refused dispatch sites on one build), record it as disclosed blindness and check whether the blind sites matter for your rule. |
| `unresolved-offsets` | blind | Some offsets could not be resolved for attach (counter: `unresolved_offsets`). | Same as `missed-attaches`: `doctor`, remediate, re-run; stable residuals are disclosed blindness. |
| `unattributed` | blind | Events arrived for keys with no stable backing (staleness race). | Re-run; persistent cases indicate mapping churn under the window -- narrow the window to a quieter phase. |
| `reharvest-skipped` / `replan-skipped` | blind | A fence-triggered re-harvest or re-plan was skipped. | Re-run; if it recurs, the target is churning mappings faster than revalidation -- narrow the window. |
| `reharvest-no-query` | blind | A re-harvest fired but no query re-triggered. | Add warmup traffic so re-queries fire; otherwise accept the fenced (stale-bucket) counts. |
| `reharvest-failed` | blind | A re-harvest attempt failed outright. | Run `doctor` and re-run; treat like an attach failure (see [attach failures](attach-failures.md)). |
| `pid-recycled` / `harvest-pid-recycled` | blind | The target exited and its pid was reused mid-run; observations are discarded rather than misattributed. | Re-run; prefer `run --` for short-lived targets. |

## Harvest reasons (`harvest-*`)

These mirror the `inspect` harvest verdict. The most common:

| Reason | Class | Meaning | Response |
|---|---|---|---|
| `harvest-anchor-unresolved` | blind | No resolution rung found the query offset (unknown build-id, no symtab, dead fallback delta). Zero rows. | Enroll the build per [the built-in runbook](builtin-runbook.md) (`--table` / `--force-offset` from an unstripped twin). Stripped static binaries with no twin are disclosed blindness, not evidence. |
| `harvest-zero-rows` | blind | Anchor resolved but the walk produced no rows. | Warmup traffic during harvest; verify the anchor offset is live (re-derive, never ship a guess). |
| `harvest-fenced-rows` | blind | Harvested rows failed manifest attestation (forged or shifted tables) and were fenced to count-only. Zero misattribution by design. | Investigate provider integrity (unexpected build, patch drift, or tampering); re-enroll known-good builds. |
| `harvest-zero-row-ops` | blind | Some ops yielded queries but no rows (few-query slot coverage). | Warmup traffic covering those ops; the remaining blindness is disclosed per-op. |
| `harvest-truncated-walk` | blind | A dispatch walk hit the pagination bound. | Re-run; if stable, the provider legitimately exceeds the walk bound -- supported evidence is the walked prefix plus this reason. |
| `harvest-partial` | blind | Harvest degraded for another classified cause. | Read the paired counters and follow the matching row above. |

## Legacy / provider-shape reasons

| Reason | Class | Meaning | Response |
|---|---|---|---|
| `lowlevel-fallback-uninstrumented` | blind | Low-level fallback symbols could not be tripwired. On libssl-linked targets this is structural (four `Transform` imports via `R_X86_64_GLOB_DAT`, no PLT stub) and every window carries it. | On TLS apps: accept it -- evidence and policy rules stay usable (see [who should NOT adopt](what-it-proves.md#who-should-not-adopt-read-before-installing)). Elsewhere: check the `legacy` block `capability` counters for what is blind. |
| `engine-fallback-uninstrumented` / `meth-fallback-uninstrumented` | blind | ENGINE / `*_meth_new` fallback symbols uninstrumented (absent from `.dynsym`, e.g. static link or ENGINE-less 4.x). | Read the per-entry `legacy` block: disclosed-blind per entry, never bare "none". On OpenSSL 4.x the ENGINE shape is absent by upstream design. |
| `fips-unlabeled` | blind | FIPS-provider rows were harvested; counts may include self-test executions. | See [the FIPS interim rule](fips-interim.md): manual triage, sized windows, keygen-aware reading. |
