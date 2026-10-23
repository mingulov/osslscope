<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# PARTIAL runbook: per-reason response

A PARTIAL document carries `completeness.reasons[]`,
typed objects with a `kind` discriminator (see [the v2
contract](observed-crypto-v2.md#completeness-coverage-counters)).
Find your reason `kind` below and follow the response. Every
typed reason is **blind**: some observation, attribution or coverage
proof is missing. Treat counts under those limits as lower bounds,
not complete inventories. (An empty-but-honest window with full coverage is
COMPLETE, not PARTIAL.)
<!-- source: reason vocabulary: src/evidence.rs (GapReason) -->

General rules:

- Always read the JSON (`completeness.reasons`,
  `completeness.counters`, `coverage`), not just the exit
  code. Fix the cause, then re-run; never average PARTIAL
  windows into a COMPLETE claim.
- Policy is three-valued: a `--require-executed` name absent
  from PARTIAL evidence is an **inconclusive rule** when
  the gap is relevant to the rule -- never a violation and
  never a pass. Under complete relevant coverage, proved absence
  can violate require even when an unrelated gap makes the whole
  document PARTIAL. Definite positive use passes require or violates
  deny. A proved violation exits 10; aggregate inconclusive exits
  11 only when no higher priority condition applies.
- Window-only claims still hold: "none observed in window"
  never means "not present".
- FATAL is not PARTIAL. Runtime is eligible for policy even with
  zero positive counts and retains collected observations.
  AttachZero is also eligible when it carries proved positive
  in-window ENGINE evidence. Eligibility proves no particular
  rule. A proved violation exits 10; other usable fatal outcomes
  exit 1. Environment, Recycled and bare AttachZero yield no
  verdict (exit 4). Child/delivery failures can also outrank
  inconclusive or PARTIAL. See
  [the v2 contract](observed-crypto-v2.md#completeness-coverage-counters)
  and [the exit table](usage.md#exit-codes).

## Coverage reasons

| Kind | Class | Meaning | Response |
|---|---|---|---|
| `unknown-denominator` (`scope`) | blind | The denominator is unknown for `scope` (`op:<id>`, `legacy`, or `dispatch`): a tainted or unterminated op walk, superseded legacy anchors, or an unattached dispatch surface. | Read the matching `coverage` row (`expected`/`discovered`/`attached`). Re-run a quieter or narrower window; if the gap is stable, record it as disclosed blindness and check whether the blind scope matters for your rule. |
| `undiscovered-sites` (`scope`, `missing`) | blind | Expected sites were never discovered (`missing` short). | Add warmup traffic during harvest so queries fire; check the target actually performs crypto in-window. Unknown stripped builds need explicit enrollment per [the built-in runbook](builtin-runbook.md) -- never a guessed offset. |
| `unattached-sites` (`scope`, `missing`) | blind | Expected sites lack attached probes: `missing` is expected − attached, so it also counts never-discovered sites, not only discovered-but-refused ones. Refusals can be kernel-specific and stable across runs. | Compare with the `undiscovered-sites` row to split never-discovered from refused. For refused sites run `doctor`, remediate, re-run (see [attach failures](attach-failures.md)). If the count is stable, record it as disclosed blindness and check whether the blind sites matter for your rule. |

## Loss and attribution reasons

| Kind | Class | Meaning | Response |
|---|---|---|---|
| `loss` (`counter`, `source`, `value`) | blind | A positive loss counter: an evidence guarantee is missing. Common names: `capture.over_budget` (source `lifecycle`: the target was still alive at window expiry -- the observer never kills its child) and `count.drain_shortfall` (source `drain`: an exactly enumerated number of keys could not be read). | Read the named counter, its units and source. For `over_budget`: shorten the workload or split it into several windows with quit-before-expiry discipline; raise `--duration` only if the workload then fits inside one window. For count drain uncertainty use the table below. For ring/map pressure: shorten the window or reduce the dispatch rate under observation, then re-run. Losses are counted, never silent. |
| `unattributed-calls` (`sites`, `calls`) | blind | Executed calls arrived at sites whose candidate coverage is unknown: tainted or unterminated op walks, or unlocalizable loss, degraded the site set. No staleness race is required. | Read the accompanying `unknown-denominator` / `loss` reasons -- they name the taint. Re-run a quieter or narrower window; if the gap is stable, record it as disclosed blindness and check whether the blind calls matter for your rule. |

- `lifecycle.signal_prefix_unwitnessed`: conservative at-least-one prefix gaps on post-activity first sightings (one per CPU whose prefix was unwitnessed — notably every `--pid` window). NEVER a proven transport-drop count; use `lifecycle.signal_dropped` (proven seq holes + Drops delta) for loss magnitude. Both are Loss and both withhold COMPLETE.

## Terminal count uncertainty

Current development emits `observed-crypto-v2.2`. It preserves positive
current/fenced observations when count completion fails. A count loss
event is not a measured missing call: pending writers, unread keys and
unavailable counter components leave call upper bounds unknown.

| Counter | Units and meaning | Response |
|---|---|---|
| `count.quiescence_unknown` | Events: no validated terminal writer witness. Equal ADMITTED/count totals cannot exclude a pending callback. | Preserve the positive observations and treat relevant absence as inconclusive. Current live kernel/source profiles remain unqualified; grace alone cannot establish the witness. |
| `count.reference_inventory_invalid` | Events: link inventory, command frontier or receipt identity cannot be validated. | Keep diagnostics and exact host/BPF identities for investigation; do not infer a smaller writer set. |
| `count.close_failed` | Events: a checked count-link close failed. | Treat the runtime failure and cleanup status as unresolved. Repeated salvage cannot retry the consumed descriptor or renew grace. |
| `count.owner_failed` | Events: count-owner operation, publication or infrastructure failed. | Retain the failure diagnostics, positive prefix and cleanup ticket. A coordinator result does not prove the owner has exited. |
| `count.drain_read_failed` | Events: a row or cumulative component read failed. Missing components are unavailable, never zero. | Keep successful rows. Investigate the reported failure; no complete ledger reconciliation follows from a partial read. |
| `count.drain_unenumerated` | Events: key enumeration did not finish; unread keys and their call volume are unknown. | Re-run after investigating the cause. Increasing grace can help ordinary budget exhaustion, but cannot repair a missing proof or guarantee progress from a stalled kernel operation. |
| `count.drain_shortfall` | Events: an exact number of unread keys, available only after enumeration finishes. It is not the number of missing calls. | Investigate the read/budget failure; a longer allowed grace may help a subsequent capture. |
| `count.close_time_uncertain` | Events: the effective endpoint lacks a valid actual stop bound. An ordinary nonzero stop bracket alone is not this loss. | Use the disclosed conservative effective window; do not restamp observed calls or treat worker wait as coverage. |
| `count.owner_capacity` | Events from attach: a finite owner resource or membership ceiling was reached. | Reduce the observed scope or investigate capacity. Earlier observations survive; the refusal does not qualify the larger workload. |
| `count.map_insert_dropped`, `count.unattributed`, `count.ledger_delta` | Calls: known map-insert drops, observed calls without retained attribution, or a ledger discrepancy with all required terminal inputs. | Keep each counter's actual domain. Do not add stale activity again or substitute these finite values for an unknown read/writer tail. |

`--grace` remains 0–30 seconds, default 5, with one deadline across
terminal admission, stopping, close and read. Zero grace waits for no
new count I/O. A late cleanup result does not promote the finalized
capture or supply a fresh observation window. Keep requested scope,
programmed admission and effective coverage distinct; v2.2 can preserve
actual admitted timestamps beyond a conservative effective endpoint.

These count controls do not close discovery, member/return/continuation,
lifecycle, startup, generation-selection, identity or privacy gaps.
Actual kernel holds, process/resource disappearance, performance and
installed-package/platform qualification remain separate requirements.
See [the development proof boundary](what-it-proves.md#terminal-count-proof-in-development).

## Window-edge reasons

| Kind | Class | Meaning | Response |
|---|---|---|---|
| `startup-gap` (`missing_ns`) | blind | The effective window starts `missing_ns` after the requested start: executions before readiness are unobserved. `--pid` has unavoidable pre-attach blindness. | Prefer `run --` for target custody and drive representative warmup/traffic; neither establishes first-call or COMPLETE coverage. Read the actual effective window and loss reasons. See [staging deploy](staging-deploy.md) for live attach. |
| `tail-gap` (`missing_ns`) | blind | The effective window ends `missing_ns` before the requested end: the tail of the window went unobserved. | Same discipline as `over_budget` above: quit-before-expiry, split windows, or a fitting `--duration`. |
| `signal-cut` (no fields) | blind | SIGTERM/SIGINT cut the window; signal-cut windows are always PARTIAL by construction. | Size the CI timeout per [the recipes](ci-recipes.md#ci-timeout) and re-run undisturbed. |

## Structural coverage caveats

These are disclosed limits of the observation surface. The
low-level fallback also surfaces on each affected document
as a `loss` reason (counter
`legacy.lowlevel_uninstrumented`), so check the document's
reasons rather than assuming silence:

- Low-level fallback: affected address-taken taxonomy imports
  use `R_X86_64_GLOB_DAT` without an instrumented PLT stub.
  They remain unprobed even when uniquely resolved. Inspect
  the actual imports and typed loss; do not infer the same
  four imports or PARTIAL shape for every TLS workload.
  Evidence and policy rules remain usable under their limits — see
  [who should NOT adopt](what-it-proves.md#who-should-not-adopt-read-before-installing).
  On OpenSSL 4.x the ENGINE shape is absent by upstream
  design.
- FIPS providers: counts may include self-test executions
  (no KAT discriminator). See [the FIPS interim
  rule](fips-interim.md): manual triage, sized windows,
  keygen-aware reading.
