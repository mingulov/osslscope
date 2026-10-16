<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# PARTIAL runbook: per-reason response

A PARTIAL window (exit 3) carries `completeness.reasons[]`,
typed objects with a `kind` discriminator (see [the v2
contract](observed-crypto-v2.md#completeness-coverage-counters)).
Find your reason `kind` below and follow the response. Every
typed reason is **blind**: it describes evidence that exists
but is unobserved -- treat those windows as lower bounds, not
inventories. (An empty-but-honest window with full coverage is
COMPLETE, not PARTIAL.)
<!-- source: reason vocabulary: src/evidence.rs (GapReason) -->

General rules:

- Always read the JSON (`completeness.reasons`,
  `completeness.counters`, `coverage`), not just the exit
  code. Fix the cause, then re-run; never average PARTIAL
  windows into a COMPLETE claim.
- Policy is three-valued: a `--require-executed` name absent
  from PARTIAL evidence is **inconclusive** (exit 11) when
  the gap is relevant to the rule -- never a violation and
  never a pass. A violation needs definite evidence, and a
  proved violation still exits 10 on PARTIAL evidence.
- Window-only claims still hold: "none observed in window"
  never means "not present".
- FATAL is not PARTIAL: a salvaged `runtime`-fatal document
  keeps every collected observation and still evaluates
  policy (proved violation exits 10, otherwise exit 1);
  every other fatal kind carries no verdict (exit 4). See
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
| `loss` (`counter`, `source`, `value`) | blind | A positive loss counter: named evidence went unobserved. Common names: `capture.over_budget` (source `lifecycle`: the target was still alive at window expiry -- the observer never kills its child) and `count.drain_shortfall` (source `drain`: keys remained unpolled at grace expiry). | Read the named counter and its source. For `over_budget`: shorten the workload or split it into several windows with quit-before-expiry discipline; raise `--duration` only if the workload then fits inside one window. For drain shortfall: raise `--grace` and re-run. For ring/map pressure: shorten the window or reduce the dispatch rate under observation, then re-run. Losses are counted, never silent. |
| `unattributed-calls` (`sites`, `calls`) | blind | Executed calls arrived at sites whose candidate coverage is unknown: tainted or unterminated op walks, or unlocalizable loss, degraded the site set. No staleness race is required. | Read the accompanying `unknown-denominator` / `loss` reasons -- they name the taint. Re-run a quieter or narrower window; if the gap is stable, record it as disclosed blindness and check whether the blind calls matter for your rule. |

## Window-edge reasons

| Kind | Class | Meaning | Response |
|---|---|---|---|
| `startup-gap` (`missing_ns`) | blind | The effective window starts `missing_ns` after the requested start: executions before readiness are unobserved. `--pid` attach always carries this shape (pre-window target activity is invisible), so `--pid` COMPLETE is unreachable by design. | Use `run --` (pre-exec attach) plus warmup traffic during harvest so fetches query before plan/attach. `--pid` is staging-only (see [staging deploy](staging-deploy.md)). |
| `tail-gap` (`missing_ns`) | blind | The effective window ends `missing_ns` before the requested end: the tail of the window went unobserved. | Same discipline as `over_budget` above: quit-before-expiry, split windows, or a fitting `--duration`. |
| `signal-cut` (no fields) | blind | SIGTERM/SIGINT cut the window; signal-cut windows are always PARTIAL by construction. | Size the CI timeout per [the recipes](ci-recipes.md#ci-timeout) and re-run undisturbed. |

## Structural coverage caveats

These are disclosed limits of the observation surface. The
low-level fallback also surfaces on each affected document
as a `loss` reason (counter
`legacy.lowlevel_uninstrumented`), so check the document's
reasons rather than assuming silence:

- Low-level fallback: on libssl-linked targets, four digest
  `Transform` imports arrive via `R_X86_64_GLOB_DAT` (no
  PLT stub) and stay unprobed, so real TLS windows end
  PARTIAL. Evidence and policy rules stay usable -- see
  [who should NOT adopt](what-it-proves.md#who-should-not-adopt-read-before-installing).
  On OpenSSL 4.x the ENGINE shape is absent by upstream
  design.
- FIPS providers: counts may include self-test executions
  (no KAT discriminator). See [the FIPS interim
  rule](fips-interim.md): manual triage, sized windows,
  keygen-aware reading.
