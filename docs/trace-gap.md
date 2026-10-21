<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# osslscope vs OSSL_TRACE: the gap

`OSSL_TRACE` is the built-in rival. We shot it out against three
cases a migration/audit tool must answer. TRACE answers none of
them at the needed level.

| Aspect | OSSL_TRACE | osslscope |
|---|---|---|
| Needs app changes | yes, API calls | no, external |
| Works on stock builds | no, no-trace default | supported admitted targets, with disclosed gaps |
| Env var control | none exists | n/a (no cooperation) |
| Per-call execution proof | no, fetch-time only | yes, tripwired |
| Low-level / ENGINE calls | no coverage | observed entrypoints counted; uninstrumented imports disclosed |
| Machine-readable verdict | no, free text + pointers | JSON + exit codes |
| CI gate signal | none (app's exit 0) | `check` verdict, exit 10 on violation |

## Case by case

**Uncooperative app.** Stock OpenSSL builds ship `no-trace`
(upstream `./Configure` default; `enable-trace` is opt-in): the
trace API is inert and no `OSSL_TRACE` environment variable exists
in the 4.0 source. An unmodified app emits zero trace bytes, with or
without env set. osslscope observes supported admitted targets
externally, with physical-site counts, candidate uncertainty and
explicit coverage/loss limits.

**Fallback execution.** Even on an `enable-trace` build with a fully
cooperative app, one fetch emits ~18KB of free text containing a
single fetch-time line (`resolves to provider legacy`) — no
per-call record, no implementation identity (only ASLR-unstable
store pointers), and zero coverage of low-level or ENGINE execution
paths (no trace points there in the 4.0 source). osslscope records
physical callback execution with possible implementation identities
and counts instrumented legacy/low-level entrypoints. Address-taken
GLOB_DAT imports remain an observation gap. COMPLETE/PARTIAL coverage
and attribution certainty are separate; neither licenses multiplying
shared counts across candidates. Fetch-time naming is not execution
proof.

**CI exit code.** TRACE output is voluminous free text; the process
exit code is always the application's. There is no verdict to gate
on. osslscope emits `COMPLETE`/`PARTIAL`/`FATAL` JSON with typed
reasons. `check` requires at least one rule and uses pass,
violation, inconclusive or no-verdict results: exit 10 for a proved
violation, 11 for inconclusive when no stronger failure applies,
3 for passing policy on PARTIAL, and 0 for clean COMPLETE. Unusable
fatal evidence yields 4; usable fatal or child/delivery failure can
yield 1. See [the full exit precedence](usage.md#exit-codes).

## Reproduction

Build 4.0.2 with `./Configure enable-trace`, fetch one algorithm
under two providers with a channel attached, and diff the
pointer-masked logs: only the fetch-time provider line differs.
osslscope's side is pinned by the `legacy-tp` / `legacy-tn` /
static-PARTIAL goldens under `tests/goldens/`.
