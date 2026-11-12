<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Changelog

## Unreleased (v0.6.0 signals)

- P0-8 interrupt contract: the first SIGINT/SIGTERM across setup,
  acquisition, observation, and teardown prints one stderr ack
  (`osslscope: received {SIGINT|SIGTERM}, shutting down…`), then ends
  with the arm's normal end record plus the normal exit (usually 3),
  and never signals the observed workload. EINTR checks cancellation
  before retry; teardown closes are bounded by a best-effort
  one-second `SHUTDOWN_DEADLINE` (no universal 1s shutdown guarantee).
  A second signal exits immediately with 130 (SIGINT) or 143 (SIGTERM)
  and no end-record guarantee. The capture path is off BSD `signal()`
  onto the shared `Shutdown` token; one-shot `scan`/`inspect` stay
  uninstrumented (conventional `128 + signo` status). See
  `docs/usage.md` ("Interrupt contract").

## Unreleased (v0.6.0 human surface)

- BREAKING (S1/S3/S5/S6 stdout split): human stdout no longer
  embeds the JSON document — `scan`/`inspect` print readable rows
  by default and `--json` stdout is now pure (parses alone).
  Consumers parsing mixed stdout must pass `--json`. See
  `docs/usage.md` ("Human output") for the row shapes, `-v`/`-vv`
  levels, kind legend, privilege hint, and per-reason gap
  meanings.
- Machine-visible refinement (serialization shape unchanged):
  watch `changes[]` no longer repeats steady-state
  `visibility_lost` entries every tick — they fire on transition,
  with steady uncertainty heartbeats instead of per-tick repeats.
- `inspect --module` human output now carries `path=` on every
  row by default (the operator-supplied spelling, labeled —
  previously omitted without `--resolve-paths`), the `kinds:`
  legend, and `-v`/`-vv` detail (grouped errors, per-module
  exports, per-error records, safe counters). Exits, stderr,
  counts, and `--json` bytes are unchanged.

## Unreleased (v0.6.0 machine surface)

- Additive discovery machine fields, pinned by
  `schemas/discovery-v1.json`: `verified_path` /
  `verified_path_unavailable` / `maps_spelling` on every mapped record
  (JSON always carries them; `--resolve-paths` now gates only the human
  TTY `path=` fragment), bounded `comm`/`comm_status` + `exe`/`exe_status`
  process identity, own-`DT_SONAME` `file_soname` with validated rodata
  `file_openssl_version` / `file_version_status`, and `errno`/`actor_euid`
  on gaps. File evidence is never a runtime claim. Reader break: v0.5
  `deny_unknown_fields` readers reject v0.6 documents; v0.6 readers accept
  v0.5 documents. Machine consumers must parse `--json`/NDJSON only — the
  human stdout shape is owned by the human-surface plan, which splits
  stdout by mode (human rows by default, pure JSON under `--json`).
- `scan --module` takes a file PATH only (repeatable); bare hashes fail
  with exit 4 and a message naming the PATH form. Digest selectors
  (`sha256:...`) are not accepted in v0.6.
- `--json` snapshot bytes are deterministic across runs modulo wall-clock
  fields (`interval`, `capture_unix_ms`) and the live-input `read_bytes`
  accounting total (covered by
  `v060_json_bytes_deterministic_modulo_wall_clock`).

## 0.5.0 (candidate — 2026-11-02)

- Honesty + attribution slice over 0.4.0: named acquisition-failure
  taxonomy (`acquire_cause`, single source of truth); sectioned
  doctor (`self_attach` / `foreign_backing` / `target`) with
  functional map_files/pagemap probes and sysctl context; one stderr
  reason for exits 3/4 plus exit-code help; inventory verified-vs-
  locator share and gaps coalesced by (reason, device, pid) with
  JSON unchanged; fenced-generation attribution (G2).
- Suite green where 0.4.0 was red: `identity_domain_audit` passes
  (device-domain pins complete) and `cargo clippy -- -D warnings`
  (CI form) passes. Full host suite: lib 1239 passed / 0 failed /
  99 ignored; BPF shape/prep gates and the packaging script matrix
  pass. (`clippy --all-targets` still fails on pre-existing
  test-only lints, identical at the 0.4.0 base.)
- Known limits: typed-program positives stay blocked — R5 refuted
  as-built (`typed_return` exceeds the kernel-7.0 verifier limit;
  revision options scoped, none selected). No 3.0.x or 4.x runtime
  lane on hand. DEB/RPM install/remove CLOSED by the rc.1 proof
  (Debian cell + Fedora 43 cell, G6) and native re-measure CLOSED at
  5.425× (below) — the "stay open" rows from the 2026-11-02
  candidate stage are superseded. Reports remain PARTIAL where
  evidence is partial; attribution stays Unknown where unproven.
- Installed journey (HISTORICAL — candidate-tarball observation from
  the 2026-11-02 stage, preserved verbatim; superseded for release
  claims by the rc.1 PARTIAL evidence): companion-trust
  matrix closed (mismatch/ownership/ancestry refused, root-owned +
  matching + trusted ancestry available, doctor exit 0). Host 3.5.5
  `report run -- openssl dgst`: 2857 sites, 11,560 calls, exited
  code=0, attribution Unknown, named gaps, workload canary absent.
  Container 3.5.7 scan from host userns: exit 4 with named
  namespace/process gaps, no silent empty capture.
- Limited-capability container image (source-built, never
  `--privileged`; owned mode as non-root with `BPF`+`PERFMON`, host
  observer as root-in-container with the 5-cap set) plus a shipped
  seccomp profile and drill transcripts (`docs/container.md`).
- Plain Kubernetes manifests (`deploy/kubernetes/`: one-shot Job
  supported, DaemonSet service experimental, stock config refuses exit
  2, exec doctor probes) with a kind drill transcript.
- One-page [quickstart](docs/quickstart.md) drilled from a clean
  clone (binary install → doctor → scan → PARTIAL `report run` →
  containers → uninstall), a README support matrix, and an uninstall
  path for every install kind.
- Measured overhead for this tree: 5.425× median baseline/observed
  ratio on the stock SHA-256 hot loop, superseding the 4.66× v0.4.0
  figure (reproduced as the 4.661 control in the same campaign); see
  `docs/overhead-matrix.md`.
- Root package version 0.5.0; helper crates retain their versions.
- Kernel-panic quarantine: `EVP_DigestInit_ex2` (API 21) unprobed —
  probing its entry stub panics kernels. The refusal is named at the
  user surface (`quarantined_api` setup gap,
  `focused.attach_refused_quarantined` loss counter; the API 21 row
  shows `not_attached`); residual risk, sibling follow-ups, and the
  deferred kernel-bug status live in
  `docs/kernel-quarantine-note.md`.

## 0.4.0 current-state alpha (automatic observation)

- Published as a current-state alpha. Known limits: reports remain PARTIAL
  with Unknown attribution; one host audit test (`identity_domain_audit`)
  fails pending a device-domain re-pin (22 sites), and
  `cargo clippy -- -D warnings` fails on 10 pre-existing items. Live/native
  qualification for this tree is pending. See
  [alpha scope and limits](docs/release-v0.4.0.md).

- Recover bounded public-table candidates from verified ELF files, prearm owned
  startup dependencies and retain warm-process physical entry evidence without
  algorithm/version admission profiles. Static shapes remain entry-only hints.
- Separate independently observed public-ABI advertisements, physical callback
  totals, dynamic candidate identities and scalar public API activity in optional
  `observed-crypto-v2.4` sections. Reject overlapping API failure subsets.
- Add `crypto-watch-v1` sampled discovery and per-incarnation observation with
  four active slots and one shared 256 MiB accounted state budget. Temporary
  capacity pressure preserves retained discovery progress for later resumption.
  A later verified inventory row also triggers fresh acquisition when an early
  loader snapshot supplied only a refused locator candidate. Independently
  revalidated unchanged Count custody retains its physical cookies across this
  metadata upgrade; actual backing/namespace/process loss still retires links.
- Render bounded human crypto-watch summaries by default, with distinct
  physical/API totals and explicit uncertainty; `--json` retains NDJSON.
- Root package version 0.4.0; helper crates retain their versions. Reports remain
  PARTIAL, attribution Unknown and algorithm policy inconclusive. See
  [candidate qualification and limits](docs/release-v0.4.0.md).

## 0.3.0 discovery preview

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
  `--libcrypto` retains historical fixed-profile diagnostics. A bounded
  single-PID scan/watch sample reports inventory cost with tracing disabled;
  it does not establish broad platform or performance support. Installed,
  stock-build, two-kernel and privacy/resource qualification belong to the
  artifact-specific release record. See [release notes](docs/release-v0.3.0.md).

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

`v0.1.0` is an earlier tagged baseline. Later v0.2.0 and v0.3.0 releases are
described above; its source-specific results below do not qualify later builds.

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
