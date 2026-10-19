<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# What osslscope proves (and what it does not)

osslscope is a runtime cryptographic observer for OpenSSL. It proves
which provider-dispatch implementation callbacks actually execute in
a running Linux application, without changing the application, its
configuration, or its environment.

## The claim chain

```text
installed
    != loaded
    != advertised by provider
    != fetched
    != selected
    != EXECUTED
```

osslscope reports the last stage: the `OSSL_DISPATCH` callback that
ran, identified by `(provider, operation, algorithm class,
function id)` plus an attested file offset. Fetch/selection stages
are supporting context only. Claim granularity stops at the dispatch
callback: hardware variants selected inside one callback are out of
claim.

Every report states its observation window (target, start/end,
duration). Claims are window-only: "none observed in window" never
means "not present / never used".

## COMPLETE vs PARTIAL

- `COMPLETE`: every entry in the window is attributed to a
  generation-valid key; no gap counter is nonzero; no FIPS module
  was harvested.
- `PARTIAL` plus `reasons[]`: exactly one honest story per reason.
  PARTIAL is a result, not a failure: the evidence it carries is
  usable, and policy rules still evaluate over it. See
  [the PARTIAL runbook](partial-runbook.md) for the per-reason
  response.
- Absence of a trigger (a window in which no provider query fired)
  is PARTIAL (`no-query`), never COMPLETE-zero.

Counts are entry counts: N for one identity means "N entries
observed in the window". v1 does not split success from failure and
records no per-call latency (first/last-seen timestamps per key
only).

## Non-goals

v1 does not do TLS/libssl tracing, handshake observation,
cipher-suite inventory, PCAP, network tracing, plaintext/key
extraction, per-call trace output, latency histograms, cgroup or
multi-target attach, daemon mode, or `--exe` inspection. Pre-3.0
OpenSSL (the ENGINE-era method tables, with no `OSSL_DISPATCH`) is
out of scope, as is any always-on production agent posture
(always-on is post-v1).

## Who should NOT adopt (read before installing)

This section is the headline, not a footnote. Each item below is a
measured v1 boundary.

**CI gating on COMPLETE status: not qualified.** v1 is NOT
qualified for CI gating on COMPLETE. On real TLS-terminating apps
COMPLETE is structurally unreachable: libssl takes the addresses of
four digest `Transform` routines through `R_X86_64_GLOB_DAT` (no
PLT stub), so four low-level imports stay unprobed and every window
ends PARTIAL with `lowlevel-fallback-uninstrumented`.
<!-- source: p5-gate-record.md; staging verdict 0/12 COMPLETE at
     durations 30/60/120 x grace 5/15, over_budget=0 throughout,
     cold_gap/drain_shortfall p50/p99 0/0: staging-nginx note -->
Twelve measured windows at three durations and two graces returned
0% COMPLETE with zero over-budget expiries, so no duration/grace
re-tune can fix it. Gate on policy verdicts (exit 10 on violation,
exit 3 as warn-plus-artifacts) instead; see
[the CI recipes](ci-recipes.md). PARTIAL evidence, policy rules,
and violation detection remain fully supported.

**Kernels below 6.9: not supported.** The floor is kernel 6.9 with
`uprobe_multi`. Do not adopt on RHEL 9 / EL9 (5.14, no multi
backport), Ubuntu 22.04 (GA 5.15, HWE 6.8 -- both below the floor),
Ubuntu 24.04 GA (6.8; install the HWE kernel to qualify), or Debian
12 (6.1).
<!-- source: PRD.md section 8; kernel/distro matrix: ebpf-privileges note -->
`doctor` refuses these environments fail-closed via a functional
feature probe, never a version-string match.

**Non-x86-64 targets: not supported.** v1 is x86-64-only. No ARM64
(or 32-bit) observation evidence exists for v1, and none is
claimed: `doctor` refuses non-x86-64 targets fail-closed (exit 4),
and the refusal paths are covered by committed goldens.
<!-- source: arch decision + clean-refusal goldens: p5-gate-record.md -->

**SecureBoot-qualified operation: not claimed.** SecureBoot
qualification is deferred post-v1: the qualification attempt
failed on the host hypervisor (KVM rejects the firmware's SMM
entry, so no SecureBoot-enabled guest reaches userspace), which
leaves open what SecureBoot blocks for BPF attach. v1 claims no
SecureBoot-qualified status.
<!-- source: SecureBoot cell + deferral: p5-exit1-cells note, p5-gate-record.md -->

**Stripped static binaries: disclosed blindness, not evidence.**
Observing a stripped statically linked binary yields zero rows
(PARTIAL with anchor/trigger reasons): there is no dynamic symbol
table to resolve the harvest anchor and no enrolled build-id row.
Unstripped static binaries observe normally via symtab. If your
fleet ships stripped static binaries, v1 cannot inventory them.
<!-- source: static boundary probe (0 rows stripped, 62 rows
     unstripped): p6-entry-envs note -->

**Cold-gap preflight in `doctor`: warned.** v0.2 `doctor --pid`
reports a `cold-gap-preflight` degraded check; disclosure rides
these docs plus the post-hoc `pid-prewindow-blind` / `cold-gap`
emission in capture documents. `--pid` windows are blind to
pre-attach execution by architecture; use `run --` with warmup
traffic when completeness matters.
<!-- source: R4 deferral: p5-gate-record.md; trigger matrix: trigger-matrix.md -->

**Rebuilt OpenSSL needs re-enrollment.** OpenSSL source builds
embed build dates, so ANY rebuild mints new GNU build-ids even
from identical sources. A rebuilt libcrypto is an unknown build
to `doctor` until its build-id row is enrolled (see
[the built-in runbook](builtin-runbook.md)). Pin and enroll the
exact binaries you observe; after any rebuild, re-enroll before
re-gating.
<!-- source: rebuild/re-enrollment standing rule, build-id table
     (10 entries): p5-gate-record.md -->

## Further reading

- [Overhead and support matrix](overhead-matrix.md): budgets,
  worst-cell numbers, qualified platforms.
- [CI recipes](ci-recipes.md): runner choice, gate wiring, timeouts.
- [Privacy residuals](privacy/residuals.md): what the no-secret
  guarantee does not cover.
- [The OSSL_TRACE gap](trace-gap.md): why built-in tracing is not
  a substitute.
