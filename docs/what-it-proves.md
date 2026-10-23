<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# What osslscope proves (and what it does not)

osslscope observes OpenSSL provider-dispatch callback execution in
supported Linux targets without changing the application or its
configuration. Current development emits the
[v2.2 evidence contract](observed-crypto-v2.md); integrated live and
package qualification remains open. The historical `v0.1.0` release
has its own source-specific qualification and limitations.

## The claim chain

```text
installed
    != loaded
    != advertised by provider
    != fetched
    != selected
    != EXECUTED
```

The counted unit is entry into a physical `OSSL_DISPATCH` callback,
identified by backing object, device, inode, file offset and
generation. Candidate metadata describes possible provider,
operation, algorithm-class and function identities. A shared site
with N calls contributes N calls once; it does not prove N calls
for each candidate. Fetch/selection stages supply context only.
Hardware variants selected inside one callback remain unobservable.

Every report states its target and requested/effective window.
"None observed in window" never means "not present / never used".

## COMPLETE vs PARTIAL

Count conservation, attribution certainty and observation coverage
are separate axes:

- `COMPLETE` requires no fatal failure, no instrumentation coverage
  gap, no positive loss counter, no executed unknown-coverage
  candidate set, and full requested/effective window coverage
  without a signal cut. Fully attached quiet sites are covered.
  Nonzero activity counters and ambiguous complete candidate sets
  are compatible with COMPLETE.
- `PARTIAL` carries typed `completeness.reasons[]` describing
  coverage, loss, attribution or window gaps. Its observations
  remain useful under those limits; missing observations cannot
  be turned into absence proofs where a gap is relevant.
- `FATAL` describes a tool or target failure. Runtime failures
  remain eligible for policy evaluation, even with zero calls.
  AttachZero is eligible only with proved in-window ENGINE
  evidence. Environment, Recycled and bare AttachZero are
  unusable and yield no policy verdict. Eligibility alone proves
  no rule; see [exit handling](usage.md#exit-codes).

A missing provider query is harvest context, not an independent
v2 completeness rule. Read the actual coverage and typed reasons;
do not translate legacy `no-query` text into a COMPLETE-zero or
PARTIAL conclusion without them. See [the PARTIAL runbook](partial-runbook.md)
and `src/evidence.rs` (`finalize`).

Counts are callback entries under disclosed coverage and loss,
without a success/error split. First/last timestamps locate counted
entries; they are not callback-duration measurements. Algorithm
names do not reveal key sizes or parameter-selected digests/ciphers.

## Terminal count proof in development

Equal count scans cannot prove that counting has finished. A callback
can pass the window check, pause before updating the admitted ledger,
and later add a call after two apparently equal totals were read.

The development count path prepares one resource owner before acquiring
count descriptors. At close it seals new commands, attempts to stop
admission, explicitly closes every inventoried count link, and reads
the retained maps. A terminal writer witness requires checked final
close acknowledgments, exclusive link references, the exact writer
inventory and an applicable reviewed kernel/source profile. Only after
that witness can a complete read reconcile current, fenced,
unattributed and known dropped calls. Attribution and coverage retain
their separate requirements.

**Current live writer proof remains unproven.** The implementation
admits no live kernel/source profile yet. Host interleaving tests and
analysis of selected upstream source tags do not qualify an installed
kernel, vendor backports, actual callback selection or a genuine held
kernel callback. Increasing grace cannot supply a missing profile.
For a nonempty count-writer family, current live captures therefore
disclose count uncertainty even when their observed ledger totals agree.

One grace deadline bounds the coordinator's count wait. Expiry retains
positive observations and an unknown tail with the same cleanup owner;
eventual cleanup cannot rewrite the finalized document. A blocked owner
can outlive that deadline. This design does not establish that the
observer process and all resources disappear by grace expiry. Actual
terminal latency, cleanup/recovery, callback rate and added latency,
ordinary COMPLETE windows, platform coverage and installed-package
qualification remain open.

The v2.2 document can retain count timestamps within the acknowledged
programmed admission interval while separately showing a conservative
effective coverage endpoint. A later observed timestamp is preserved;
it does not extend effective coverage or prove an unobserved tail.
See [the contract](observed-crypto-v2.md) and
[the PARTIAL runbook](partial-runbook.md#terminal-count-uncertainty).

## Permanent boundaries and forthcoming capabilities

No TLS/libssl tracing, handshake observation, cipher-suite inventory,
PCAP, network tracing, plaintext/key extraction, passwords, or
application payload capture. Pre-3.0 OpenSSL method-table observation
is outside the provider-dispatch surface. The
[capture allowlist](privacy/allowlist-v1.md) remains binding.

Current capture is bounded and targets one process. Metadata-only
per-call trace, latency histograms, cgroup/multiple-target capture,
executable-based observation/following and a service posture are
forthcoming capabilities; they are not implemented by these docs.
`doctor --exe` already preflights executable discovery, which is
distinct from an executable-based capture mode.

## Who should NOT adopt (read before installing)

**CI gating on COMPLETE status: not qualified.** Current integrated
COMPLETE-window qualification is open. A real structural gap remains
for address-taken taxonomy imports using `R_X86_64_GLOB_DAT`: even
uniquely resolved imports have no instrumented PLT stub. Affected
low-level imports produce a typed `loss` reason with counter
`legacy.lowlevel_uninstrumented` (`src/discovery/legacy.rs`,
`src/capture.rs`; pinned by `tests/provider_coverage.rs`). This can
make affected TLS workloads PARTIAL, but does not prove that every
TLS workload has the same imports or that COMPLETE is universally
unreachable. Duration/grace changes cannot instrument a missing
site. Gate on actual policy results and disclosed gaps per
[the CI recipes](ci-recipes.md); do not assume every TLS run exits 3.

**Kernels below 6.9 and non-x86-64 targets: unsupported.** Admission
uses functional feature probes and target ELF checks, not a kernel
version string alone. The historical matrix includes a 6.9 lane;
it does not qualify every current artifact on every newer kernel.
See [the scoped matrix](overhead-matrix.md).

**Secure Boot qualification: not claimed.** Enabled-state
qualification remains open. Keep Secure Boot, lockdown and SELinux
controls in the required state; a disabled-state or alternative-host
success does not qualify the enabled environment. `doctor` supplies
environment admission evidence, not platform certification.

**Stripped/static targets need an admitted anchor.** Supported
symtab resolution can admit unstripped builds, including static
targets in `--builtin` mode. Unknown stripped builds need explicit
exact-binary enrollment; otherwise report/check refuse, while inspect
can expose zero-row blindness. No guessed offset is an inventory.
See [the built-in runbook](builtin-runbook.md).

**Live-process attachment misses history.** `--pid` cannot observe
pre-attach execution and carries startup coverage limits. `run --`
improves custody and enables pre-exec setup; it and warmup do not
guarantee first-call or COMPLETE coverage. Inspect effective window
edges and the typed startup/loss reasons.

**Rebuilt OpenSSL must be rechecked.** Rebuilds can change build-id
and offsets. Pin exact bytes and repeat admission after a rebuild.
The current table contains eleven exact-build entries; an unknown
build with a supported symtab route need not gain a table row,
whereas an unknown stripped build needs explicit enrollment.
Enrollment is not live or performance qualification.

**FIPS counts need manual interpretation.** There is no KAT
discriminator and no FIPS certification inference. A COMPLETE
coverage status does not exclude self-tests from counts. See
[the FIPS interim rule](fips-interim.md).

## Further reading

- [Overhead and support matrix](overhead-matrix.md): historical
  fixture results and current qualification boundaries.
- [CI recipes](ci-recipes.md): runner choice, gate wiring, timeouts.
- [Privacy residuals](privacy/residuals.md): limits beyond the allowlist.
- [The OSSL_TRACE gap](trace-gap.md): observation-surface comparison.
