<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# osslscope vs OSSL_TRACE: the gap

`OSSL_TRACE` is the built-in rival. We shot it out against three
cases a migration/audit tool must answer. TRACE answers none of
them at the needed level.

| Aspect | OSSL_TRACE | osslscope |
|---|---|---|
| Needs app changes | yes, API calls | no, external |
| Works on stock builds | no, no-trace default | yes |
| Env var control | none exists | n/a (no cooperation) |
| Per-call execution proof | no, fetch-time only | yes, tripwired |
| Low-level / ENGINE calls | no coverage | counted + fenced |
| Machine-readable verdict | no, free text + pointers | JSON + exit codes |
| CI gate signal | none (app's exit 0) | `check` verdict, exit 10 on violation |

## Case by case

**Uncooperative app.** Stock OpenSSL builds ship `no-trace`
(upstream `./Configure` default; `enable-trace` is opt-in): the
trace API is inert and no `OSSL_TRACE` environment variable exists
in the 4.0 source. An unmodified app emits zero trace bytes, with or
without env set. osslscope inventories such apps fully from outside.

**Fallback execution.** Even on an `enable-trace` build with a fully
cooperative app, one fetch emits ~18KB of free text containing a
single fetch-time line (`resolves to provider legacy`) — no
per-call record, no implementation identity (only ASLR-unstable
store pointers), and zero coverage of low-level or ENGINE execution
paths (no trace points there in the 4.0 source). osslscope attributes
executed calls to implementations and counts legacy/low-level calls
by entrypoint and family — or says PARTIAL explicitly where it is
blind. Fetch-time naming is not execution proof.

**CI exit code.** TRACE output is voluminous free text; the process
exit code is always the application's. There is no verdict to gate
on. osslscope emits `COMPLETE`/`PARTIAL` JSON with a frozen reason
vocabulary, refuses unsuitable targets with exit 4 (`doctor`),
and gates policy with `check` (exit 10 on violation, exit 0
clean — at least one rule required).

## Reproduction

Build 4.0.2 with `./Configure enable-trace`, fetch one algorithm
under two providers with a channel attached, and diff the
pointer-masked logs: only the fetch-time provider line differs.
osslscope's side is pinned by the `legacy-tp` / `legacy-tn` /
static-PARTIAL goldens under `tests/goldens/`.
