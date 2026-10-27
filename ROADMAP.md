<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Roadmap

osslscope is in development toward v0.3.0. It is not released. Discovery and focused execution are implemented in source. Discovery is
the normal starting point; the v0.2.0 fixed-profile foreground route remains a
legacy diagnostic with its original qualification boundary.

## v0.3.0: discover first, then observe

- **D1 — snapshot and passive-file workflows implemented and checked.** `scan` inventories
  visible processes or selected PIDs; `inspect` inventories one PID or supplied
  ELF files. The same bounded parser recognizes finite OpenSSL interfaces from
  file bytes without profiles, manual offsets, code loading or BPF. Access,
  identity and resource gaps remain visible. Mapping candidates are distinct
  from verified backing. Activation/interfaces are unknown and execution is
  not observed.
- **D2 — workflows implemented and checked:** sampled watch,
  intersecting PID/cgroup/module selectors, namespace provenance and bounded
  metadata reuse. Host-side container workflows use independently resolved
  PIDs/cgroups. Watch is sampled inventory, with explicit visibility loss and
  candidate backing; it does not establish process exit, provider unload or
  lossless following. Native scope exclusion, churn, container and integration
  checks cover these workflows within their stated observation limits.
- **D3 — source implemented:** public provider lifecycle/init/query observation,
  verified backing custody and candidate retirement. Warm/built-in activation,
  query races and unknown advertisements remain explicit limits.
- **D4 — source implemented; final qualification pending:** learned physical
  callback counting, ordinary PID/run report/check, functional doctor and fixed
  installed companions. Candidate attribution stays Unknown, reports PARTIAL,
  and algorithm policy inconclusive. The independent callback fixture is a
  stimulus oracle, not installed observation acceptance.

All stages are required for v0.3.0. Source implementation and local fixtures
do not establish platform/provider or release qualification. Discovery metadata alone produces neither an executed CBOM nor a policy verdict.
The final unchanged installed CLI/companion pair still needs the finite
fixture/stock-build, lifecycle, namespace, resource, privacy, overhead and
two-kernel checks described in [candidate notes](docs/release-v0.3.0.md).
No release is authorized by source completion alone.

## v0.2.0: a usable foreground preview

This milestone concentrates on running one unchanged application and
answering a useful question: which enrolled OpenSSL implementation callbacks
actually executed?

Implemented and exercised on the exact enrolled profile:

- Build from source, install into a local prefix and check the environment with
  `doctor`.
- Observe one owned process and its threads with `report` and `check`.
- Start with SHA-256 and AES-GCM observations in one exact stock OpenSSL 3
  library on one qualified Linux x86-64 profile.
- Produce human/JSON reports and CBOM assets for definite observations; check
  observed algorithm use with command-line rules or a policy file.
- Keep shared-site counts, ambiguity and incomplete coverage explicit.

Capture uses a limited reviewed callback catalogue and the count program.
Ordinary results remain PARTIAL: absence does not prove non-use. Callback
entries do not prove cryptographic success, runtime provider activation or
complete application coverage. Unsupported modes and unmatched enrolled OpenSSL libraries will
be rejected. The CLI enforces these restrictions before target/BPF acquisition.

The initial distribution is source plus a documented local build/install
workflow. Native installed checks cover positive counts, foreign/forked group
exclusion, policy/output behavior and normal cleanup, with
[measured overhead and limits](docs/overhead-matrix.md). The pre-exec observer
crash limitation remains explicit. See [release notes](docs/release-v0.2.0.md).
Full binary-package and cross-platform qualification is later work.

## Beyond this delivery

Broader OpenSSL, kernel, libc and container support will be qualified
incrementally. Additional capabilities remain later work:

- Daemon operation and Prometheus/OpenTelemetry export.
- Latency histograms and metadata-only per-call tracing.
- Advanced artifact identity/build provenance and DEB/RPM lifecycle support.
- Stronger completeness/first-call guarantees and broader performance,
  platform/provider and consumer qualification.

These later tracks do not replace the remaining installed/runtime delivery gates.
ARM64 and OpenSSL before 3.0 remain later evaluation. Platform and performance
claims will follow actual results, with their limits documented.

The permanent boundaries remain: no keys, passwords, plaintext or application
payload capture; no TLS interception, application changes or interposition.
