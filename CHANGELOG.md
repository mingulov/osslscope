<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Changelog

## 0.3.0 source candidate (unreleased)

- Automatic ELF/process discovery, sampled watch and intersecting PID/cgroup/
  supplied-module inventory scopes without enrolled profiles or manual offsets.
- Public provider lifecycle/query observation and bounded physical callback
  counting for one selected process incarnation or owned run. Retained fixed
  observation/focused-count companions install and resolve automatically.
- Ordinary report/check use learned candidates with Unknown coverage, PARTIAL
  reports, inconclusive algorithm policy and no definite assets from Unknown
  attribution. Shared-site counts remain conserved; first-call/final-tail,
  warm/built-in and invalidation gaps stay explicit.
- Functional scanner-owned doctor controls, namespace refusal, independent
  callback-counter fixture and CI compilation/fresh-object preparation coverage.
  Fixture/host/object checks do not establish installed runtime qualification.
- Root package version 0.3.0; helper-crate versions unchanged. Explicit
  `--libcrypto` retains historical fixed-profile diagnostics. Final installed,
  stock-build, two-kernel, privacy/resource and overhead qualification remains
  pending; no unrun platform or performance claim. See
  [candidate notes](docs/release-v0.3.0.md).

## 0.2.0 source preview

- Count-only foreground `doctor` / `report` / `check` workflow for one owned
  process and its threads, using a finite reviewed catalogue and native kernel
  group confinement before exec. One exact Ubuntu amd64/OpenSSL3.5.5/kernel
  build is enrolled and exercised; unmatched profiles refuse.
- Definite SHA-256 and AES-256-GCM context observations plus a shared GCM update.
  Human/JSON (`observed-crypto-v2.3`), definite-only CBOM and CLI/TOML algorithm
  policies retain shared counts, unknown coverage and partial absence semantics.
- Installed native controls cover known counts, worker/exec/fork/foreign groups,
  mismatched inputs, outputs/policies, signals, deadlines and attach failure.
  Fixed a retired-owner setup wait and preserved usable positive evidence when
  the sole missing capability is the terminal-writer completion theorem.
- Setup cancellation reaches pending Count load/attach/open waits without
  releasing the stopped workload. Late owner cleanup retains its original
  deadline and resource custody. Primary/CBOM output aliases refuse the CBOM
  delivery and preserve the report instead of silently replacing it.
- Every capture remains PARTIAL; no absence, crypto-success or complete-window
  claim. Pre-exec observer crash can strand a stopped child. Tight loops have
  material overhead; [measured limits](docs/overhead-matrix.md) apply.
- Source distribution with pinned tools/lockfiles and local-prefix installation.
  No bundled binaries/dependencies; root package0.2.0, internal helper crates
  retain their existing versions. General discovery, external attach, broader
  profiles, services and DEB/RPM remain later work. See
  [release notes](docs/release-v0.2.0.md) and [roadmap](ROADMAP.md).

## Earlier development history (broader product track)

The entries in this section record earlier source work, including deferred
features. The scoped0.2.0 workflow and its qualification are described above.

- `check --policy FILE` admits reusable bounded TOML policies before
  target or output effects, adds CLI constraints, and rejects impossible
  file-mode conjunctions. One-shot rules remain fixed for the window;
  live/service reload and exact-package qualification remain open. See
  [policy files](docs/usage.md#reusable-policy-files).

- Current report/check emits `observed-crypto-v2.2`: conserved
  physical-site counts, candidate uncertainty, typed coverage/loss/
  window gaps, argv redaction, and three-valued policy rules with
  site and optional ENGINE evidence. See
  [the current contract](docs/observed-crypto-v2.md).
- Development count completion uses one prepared resource owner,
  checked count-link closes, explicit partial reads and one retained
  terminal result. v2.2 preserves programmed admission separately from
  conservative effective coverage. Equal ledgers alone are no writer
  witness; all live kernel/source profiles remain unqualified, and
  grace does not establish process/resource disappearance. See
  [the proof boundary](docs/what-it-proves.md#terminal-count-proof-in-development)
  and [count uncertainty responses](docs/partial-runbook.md#terminal-count-uncertainty).
- Source includes the admitted physical-count ledger, per-key
  accounting, callback-latency collection, traversal integration
  and an eleven-entry exact-build table. These implementations and
  their source/fixture checks do not establish current integrated
  live, overhead, COMPLETE-window or package qualification.
- The normal development build produces the host binary plus
  harvest/count/members BPF roles; deliberate pair-only installs
  remain supported. Current deb/rpm builders contain the host
  binary and install documentation only. Matched redistributable
  host+BPF packages remain forthcoming, subject to licensing,
  provenance and exact-package qualification.
- Metadata-only trace, latency histograms, expanded targeting and
  service operation remain forthcoming. Permanent privacy and
  observation exclusions remain unchanged; see
  [what it proves](docs/what-it-proves.md).

`v0.1.0` remains the historical tagged baseline until owner publication of the
source preview. Its source-specific results below do not qualify later builds.

## 0.1.0 (2026-10-18)

First release. Execution-backed OpenSSL crypto inventory on eBPF
uprobes: `doctor`, `inspect`, `report`, `check`, `alias-audit`.
(The tree previously carried an unreleased 1.0.0 label; 0.1.0 is
the first version actually cut, qualified, and tagged.)

- License: GPL-3.0-or-later for userspace, docs, and scripts
  (`LICENSE`); GPL-2.0-only for BPF programs in `crates/ebpf/`
  (`LICENSES/GPL-2.0-only.txt`); per-file SPDX tags. Contributions
  under `CONTRIBUTING.md` (broad sublicensing/relicensing grant).
- Version 0.1.0 across the root crate and
  `crates/{ossl-discover,manifest,ebpf-common,bpf-sys}`.
  `crates/ebpf` stays 0.0.0 by design: unpublished-internal (own
  workspace + lockfile + nightly toolchain, `publish = false`),
  its BPF objects were operator-built outside the packages for
  that release, so it sits off the release line.
- Packaging: deb + rpm with file-caps default install
  (`packaging/`); version read from `Cargo.toml` at build time.
- Docs: claim chain + who-should-NOT-adopt, overhead matrix, CI
  recipes, PARTIAL/attach/violation runbooks, install guide
  (see `docs/`).
- Qualification: full 23-item remediation plan executed with
  independent review gates (review-accepted fixes, RED-first
  proofs, sealed-candidate live re-qualification on lane-b).
  Suite 1171/0, CI green.
- Known limitations recorded at that baseline: COMPLETE verdict
  0/10 on real shapes (attach/late-attach/close-tail losses);
  physical callback ledger, hot-key/per-key counts, live
  compositions, callback-latency distributions and a second
  kernel/libc profile remained open; registry alias/cancel
  hardening was parked and several arms had unit coverage only.
  Later source implementation is described under Unreleased;
  historical open lists are not the current qualification record.

### P6 auditor story

- `docs/auditor-story.md`: end-to-end auditor walk (report + CBOM,
  golden conformance check, violation-detection gating,
  declared-vs-executed, Dependency-Track status).
- `tests/auditor_golden.json` + `tests/auditor_report.rs`: frozen
  auditor-report shape + conformance test (strict key/type/
  vocabulary checks, tamper rejections, live-story validation via
  `OSSLSCOPE_AUDITOR_STORY`).
- `README.md`: docs index.

### P6 public docs

- `docs/`: what-it-proves (claim chain, non-goals, who-should-NOT-adopt
  headline incl. no CI gating on COMPLETE), overhead-matrix
  (worst-cell numbers + support matrix), ci-recipes, partial-runbook,
  attach-failures, violation-triage, staging-deploy, fips-interim,
  promotion-checklist, privacy/residuals.
- `README.md`: docs index.

### P4 privacy hardening

- `docs/privacy/allowlist-v1.md`: finalized capture allowlist (complete
  eBPF/userspace emission set, BPF map inventory, classifiers, change
  rule) with `tests/privacy_allowlist.rs` pins.
- `HARVESTDBG` now logs classified alg classes, never raw provider
  names.
- Test-only `OSSL_CANARY_DUMP` ring tap for the P4 canary suite
  (capped raw-payload dump, never enabled in production).
- P4 canary fixtures: `secret_driver` (sentinel buffers through
  digest/sign/cipher/MAC/KEM/KDF/RAND/password/salt/propquery
  paths, threaded stack lanes) and `sentinel` provider (hostile
  alg names + 264-entry overlong array).
- Raw loader names kernel programs and maps (bpftool-visible;
  enables name-based map inventory); `evp_driver` gains
  `SPIKE_PROPQ` to decouple the fetch propquery name from the
  provider load name.

### P3 semantics + policy

- `report`: bounded-window execution counts (human + `observed-crypto-v1.0`
  JSON, byte-stable), legacy-path section, PARTIAL taxonomy (blind vs
  clean), exit codes 0/3/4 (+1 child failure, 2 usage), 30 s default
  window, `--cbom FILE` CycloneDX 1.6 export.
- `check`: CI policy gate (6 rules: require/deny-provider, deny-engine,
  deny-algorithm, deny-weak, require-executed) with exit 10 on violation
  and per-violation actionability tuple (window/cmdline/container/image/
  provider build-id).
- `schemas/observed-crypto-v1.json` + reader compat (`v1.x` accepts,
  other majors reject); 16 report/CBOM goldens; `--help` everywhere.
- Capture: legacy blind-spot PARTIAL wiring, wall-clock window edges,
  cmdline/container/build-id identity, signal-graceful drain (exit 3).

### P2 capture engine (gated)

- Keyed exactness (hotkey 100k), fenced remaps/re-harvest, bounded
  windows, no-eviction DROPFAIL discipline, wall-clock budgets,
  trigger matrix, allowlist draft, capture-semantics record.

### P1 discovery (gated)

- Privilege model + pid pinning, OSSL_TRACE gap matrix, frozen
  registries, libcrypto flavor classifier, `inspect --pid/--builtin`,
  built-in harvest with dumper parity, legacy tripwire design.

### P1-0 scaffolding

- Workspace layout (`src/`, `crates/{ossl-discover,manifest,ebpf-common,bpf-sys,ebpf}`)
  with pinned toolchains (host 1.88.0, eBPF nightly-2026-05-20 + rust-src).
- CLI skeleton (`doctor/inspect/report/check` dispatch; subcommands land per phase).
- Discovery fixtures promoted into `crates/ossl-discover/tests/fixture/`.
- Frozen registries (`src/kinds.rs` v1): 14 ops, 280 funcids, 132 ENGINE
  symbols + 6 `*_meth_new`, 13 fetch entry points, 13 SKEY fns, 14
  low-level families, weak-alg list, 4 struct shapes -- all
  version-keyed from 3.0/3.5/3.6/4.0 headers and lane dynsyms.
- libcrypto flavor classifier (`discovery/flavor.rs`): OpenSSL 3.x/4.x
  vs BoringSSL/AWS-LC lookalikes from ELF bytes.
- R12 layout asserts (`layout_assert.c`) green on all four versions.
- `inspect --pid` discovery (P1 exit 1): 625-name algorithm registry,
  class-only emission, per-lane goldens (`tests/goldens/`).
- Built-in provider harvest (P1 exit 2): `inspect --builtin` resolves
  the core-static query fn via a frozen build-id table with
  symtab and dynsym-anchor+delta fallback rungs; array-mapped
  attribution across providers sharing the core wrapper (anonymous
  runtime-built arrays attributed by implementation; cross-provider
  twin dedup arbitrated arrival-order-free); containing-file
  relocation for shared-code rows; PARTIAL docs with coverage
  counters (`queries_observed`, `zero_row_ops`, `foreign_rows_dropped`,
  `uninstrumented_ops`) and a frozen reason vocabulary; `alias-audit`
  grouping by implementation hash. Gate: 100% dumper parity on
  3.0/3.5/4.0 incl. stripped libs, forced/natural shift cells go
  PARTIAL with zero rows, per-lane goldens.

### Initial scaffolding

Repository created. Scope defined: eBPF-based runtime proof of executed
OpenSSL provider dispatch callbacks. No implementation yet.
