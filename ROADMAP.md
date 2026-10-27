<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Roadmap

v0.3.0 is a released discovery preview with focused execution.
Discovery is the normal starting point; the v0.2.0 fixed-profile foreground
route remains a legacy diagnostic with its original qualification boundary.

## v0.4.0: automatic observation

Planned next milestone: make ordinary OpenSSL workloads produce useful activity
without an enrolled build, manual offsets, application changes or a provider-
query driver. SHA/AES examples are regression cases, not an algorithm whitelist.

- Discover public provider dispatch/algorithm table candidates from each exact
  mapped ELF, with bounded relocation, function-start and backing validation.
  Use public table pointers to find built-in query entrypoints even when their
  symbols are hidden. Static-only sites use entry-only counting; a shape match
  does not authorize target-data traversal or prove runtime advertisement.
  No private EVP/provider layout or stored build offsets.
- Cover all discoverable operation families and algorithms, including unfamiliar
  providers/names. Runtime table identities and physical sites determine what
  can be observed; name registries improve labels rather than admission.
- Combine static table candidates, naturally observed public query returns,
  exported API activity and callback counts. Preserve their different evidence
  levels and shared-site ambiguity; static candidates do not prove activation.
- Automatically prearm verified dependency candidates for owned runs and handle
  warm processes/late objects. Add bounded discovery-to-observation watch for
  selected PID/cgroup or visible-host scopes, with explicit membership/resource
  gaps. No universal first-call or lossless following promise.
- Show readable candidate hints even when coverage is Unknown. Preserve strict
  policy/CBOM semantics; API calls do not become provider execution proof.
- Qualify the real installed command path on independent stock builds, ordinary
  workloads across multiple crypto families and available supported kernels;
  measure actual tracing cost separately from passive inventory.

This is planned work. Public-table recovery needs production false-positive,
relocation and safe-attachment controls; experiments are not release acceptance.
Feature completion and truthful runtime checks decide readiness, not a fixed
date or a fallback to a small enrolled-algorithm release.

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
- **D4 — source implemented; release qualification is separate:** learned physical
  callback counting, ordinary PID/run report/check, functional doctor and fixed
  installed companions. Candidate attribution stays Unknown, reports PARTIAL,
  and algorithm policy inconclusive. The independent callback fixture is a
  stimulus oracle, not installed observation acceptance.

Source implementation and local fixtures do not establish platform/provider
or release qualification. Discovery metadata alone produces neither an executed
CBOM nor a policy verdict. Apply the finite fixture/stock-build, lifecycle,
namespace, resource, privacy and two-kernel checks to one unchanged installed
CLI/companion pair; see the [release procedure](docs/release-v0.3.0.md).
The [published record](https://github.com/mingulov/osslscope/releases/tag/v0.3.0)
reports the completed finite release checks; it does not close the ordinary
default-provider or attribution gaps. The
[bounded inventory cost sample](docs/release-v0.3.0.md#measured-inventory-cost)
is separate from tracing and broad performance qualification. Source completion
alone does not authorize a release.

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

These later tracks do not replace qualification of each newly shipped workflow.
ARM64 and OpenSSL before 3.0 remain later evaluation. Platform and performance
claims will follow actual results, with their limits documented.

The permanent boundaries remain: no keys, passwords, plaintext or application
payload capture; no TLS interception, application changes or interposition.
