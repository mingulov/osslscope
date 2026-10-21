<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Violation triage

`check` exits 10 on a proved violation; this dominates tool and
delivery failures. Rules evaluate on COMPLETE, PARTIAL and usable
FATAL documents. Runtime is eligible even without positive counts;
AttachZero needs proved in-window ENGINE evidence. Environment,
Recycled and bare AttachZero yield `no-verdict`. Eligibility does
not establish any rule: read its bounds and evidence. See
[the exit table](usage.md#exit-codes).

## 1. Read the record

The v2 JSON has aggregate `policy.verdict` and `policy.rules[]`.
Select rules with `result: "violation"`; there is no separate
`policy.violations[]` carrier. Each rule has `rule`, `predicate`,
`result`, `definite`, `possible` and `evidence`, plus
`engine_evidence` when present. `possible: null` means the upper
bound is unknown (`src/check.rs` `policy_record`, `src/report.rs`).

Resolve site evidence refs by object/device/inode/offset and
generation through `sites` and `fenced`; inspect candidate metadata
and first/last timestamps there. Resolve object fingerprints through
`objects` for display locators. ENGINE refs join
`engine_observations` by observation key, generation and entrypoint.
Use those opaque object fingerprints and available build metadata;
v2 has no `provider.build_id` field.

Two uncertainty rules matter:

- A required name absent under a relevant gap is an inconclusive
  rule. It violates only with complete relevant coverage and zero
  possible use; definite positive use passes despite unrelated
  gaps. Global PARTIAL alone determines none of these answers.
  An aggregate inconclusive verdict exits 11 only if no higher
  priority condition applies: a violation yields 10, a usable fatal
  yields 1, and child/delivery failures can also yield 1.
- Algorithm rules cannot recover parameter-selected digest/cipher
  identities in MAC, KDF, SIGNATURE or ASYM_CIPHER operations.
  Parameter values and key sizes are never captured. The current
  v2 human footer does not emit a dedicated parameter warning on
  every run; apply this limitation when interpreting any output.

## 2. Walk to the owning service

Join `target.pid`, `target.comm`, `target.container_id`,
`target.image_digest`, `window` and object display locators to your
deployment inventory. Container/image values may be empty;
`image_digest` is operator-supplied provenance. Raw argv never
publishes: `target.argv_redacted` is always true. Join invocations
through your own process accounting, not argv or a pathname alone.

## 3. Reproduce with `report`

Repeat the same target, selected objects and window flags in
`report run --`. Confirm the relevant physical site/candidate
evidence or ENGINE observation, preserving uncertainty. If a gap
hides the identity, follow [the PARTIAL runbook](partial-runbook.md)
before concluding that the service changed. Neither spawn mode nor
warmup guarantees a complete window.

## 4. Fix by rule class

| Rule | Usual cause | Fix direction |
|---|---|---|
| `deny-algorithm` / `deny-weak` | A legacy algorithm remains configured or selected through a fallback. | Change the algorithm configuration or peer/fallback path, then re-verify definite execution evidence. |
| `deny-provider` | A denied provider serves the observed call. | Correct provider configuration and module selection, then verify the intended provider. |
| `deny-engine` | A 3.x ENGINE API still executes. | Migrate the caller to provider APIs; OpenSSL 4.x removes ENGINE. |
| `require-provider` / `require-executed` | Required execution is absent in a sufficiently covered window. | Confirm representative traffic and configuration. An inconclusive rule needs gap triage before an absence conclusion. |

FIPS-lane policy results need manual interpretation per
[the FIPS interim rule](fips-interim.md): observed executions may
include self-tests, which are not filtered from policy evidence.

## 5. Re-verify with the same gate

Repeat the identical `check` rules, target and window flags. Keep
before/after JSON together and inspect each rule result and its
evidence before closing the fix.

## Current granularity and forthcoming work

The current document identifies physical callback sites and possible
dispatch identities, not the application source line or stack that
called them. Metadata-only per-call trace and latency reporting are
forthcoming; they must preserve the capture allowlist. Narrow a
scoped workload when application ownership remains ambiguous. TLS
and application-payload tracing remain outside the product boundary.
