<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Roadmap

osslscope starts with automatic OpenSSL discovery, then observes selected
workloads through public interfaces and validated callback sites. Available
algorithms and library builds determine what can be observed; there is no
algorithm or exact-build admission list on the normal path.

v0.3.0 is published. The v0.4.0 automatic-observation state is published as a
current-state alpha, with its finite installed qualification and known limits
described in [the alpha notes](docs/release-v0.4.0.md). v0.7.0 is the
current release (interim Phase 1+2 aggregate-only close-out; explicitly
**not** the feature-complete milestone once planned under the v0.7
number). The next release, v0.8.0, covers pre-armed library mode, the
first-run journey, the fork-classifier fix, flake gates, and the audit
remainder; every item under "Beyond v0.7.0" below stays deferred
(assigning deferred items a version number remains an owner decision).
The milestones below are planned capabilities, not claims about the current app,
except where a status paragraph says otherwise.

## v0.5.0: useful execution answers and practical installation

**0.5.0 status (RnD slice shipped).** 0.5.0 ships honest PARTIAL-only
observation on one lane (x86-64, 6.9+ feature-probed kernel, BTF,
cgroup v2, stock OpenSSL 3.5.x), a limited-capability container image,
plain Kubernetes manifests (Job supported, DaemonSet service
experimental), matched prefix/DEB/RPM packages, and the
[quickstart](docs/quickstart.md). Deferred out of 0.5.0 from the plan
below: positive algorithm/provider attribution, overlay-active tracing
as complete (locator + explicit gap only), `service` as supported,
Prometheus/OpenTelemetry export, before/after migration comparison,
and the 3.0.x/4.x qualification matrix.

The intended workflow is: install a complete package, discover a real process
or container, select its scope, and obtain an understandable execution report
that can support a useful policy decision or CBOM.

- Add positive algorithm/provider attribution where naturally observed public
  relationships establish it. Keep unresolved shared implementations and warm
  state explicit; never promote API activity or static table hints into proof.
- Integrate that evidence into existing policy files and CBOM output. Support
  safe object-bound selectors for unfamiliar algorithms, with clear limits on
  comparisons across different builds.
- Extend operational API observations, including KEM and key generation.
  Algorithm admission remains dynamic; finite test examples do not limit use.
- Qualify installed workflows against OpenSSL 3.0.x, 3.5.x and 4.x with matching
  libraries and providers. Detect available interfaces dynamically and preserve
  useful observations when newer APIs or algorithms are absent.
- Improve tracing cost from measured causes and preserve useful identity and
  provenance within bounded reports. Publish actual workload impact and limits.
- Support active observation of ordinary overlay-backed Docker and kind
  workloads on declared capable hosts, with verified mapped-file identity,
  namespace scope and sibling exclusion.
- Deliver matched CLI and BPF objects in binary bundles, DEB and RPM packages;
  qualify installation, upgrades, removal, privileges and mixed-object rejection.
- Provide a short first-use journey, actionable diagnostics, real consumer
  integration and regular installed live regression checks.

Attribution, mapped-file authority and complete-window feasibility are early
engineering gates. A failed gate changes the implementation or schedule; safe
refusal alone does not complete the intended active workflow.

## v0.6.0: continuous operation and deeper investigation

**0.6.0 status (shipped).** 0.6.0 ships the usability slice over
0.5.0 described in the [README](README.md) and
[CHANGELOG](CHANGELOG.md): row-shaped discovery, pure `--json`
stdout, file-path/identity/version evidence, and the interrupt
contract — still honest PARTIAL on the one declared lane. The
continuous-operation plan below was only partly realized in
0.6.0; remaining items carry into the interim v0.7.0 section
with their honest limits stated there.

- Follow selected process lifecycles and fork/exec transitions with explicit
  identity, loss and fair resource admission.
- Add continuous service operation with bounded windows, policy reload,
  restart/recovery, retention and backpressure.
- Export finalized observations to Prometheus and OpenTelemetry with bounded
  labels and explicit uncertainty; provide compact operator summaries.
- Add opt-in callback-duration histograms, bounded metadata-only traces and
  reviewed scalar status/error observations. Timing is separate from the
  overhead introduced by tracing.
- Improve startup, coverage and close guarantees for declared ordinary
  workloads; preserve unknowns where passive observation cannot establish them.
- Support useful before/after migration comparison and qualify operational
  performance, privacy and package lifecycle together.

## v0.7.0 (interim): Phase 1+2 aggregate-only close-out

**Naming note (read first).** This section supersedes the earlier
"v0.7.0: complete the known feature set" plan. The interim v0.7.0
is a Phase 2 completion release only; the former feature-complete
scope moves to "Beyond v0.7.0" below under a later version to be
chosen by the owner. Do not read any feature-complete claim
(ARM64, OpenSSL 1.1.1, RHEL/Secure Boot, broad matrix, p11scope
correlation, human acceptance) into the v0.7.0 number.

In scope for interim v0.7.0, on the one declared lane (Linux
x86-64, 6.9+ feature-probed kernel, BTF, cgroup v2, stock
OpenSSL 3.5.x):

- Passive discovery (`scan`/`inspect`, sampled `--watch`) and
  public provider-API observation (`--observe-providers`) with
  expanded fetch/load/query request evidence. Fetch evidence is
  request evidence only: it never proves the fetched object was
  used, which provider served a call, or that crypto executed;
  execution remains `not_observed` on that plane.
- Focused per-window `report`/`check` physical callback counts
  for one process incarnation (or one owned `run --`), with
  late-cut withholding. Normal reports stay PARTIAL, candidates
  stay Unknown, and no definite algorithm/provider count or
  definite CBOM asset is claimed from normal runs.
- Bounded-window continuous operation as shipped commands:
  `service` (windows to an out-DIR), `export` (Prometheus
  `GET /metrics` plus optional OTLP push from that out-DIR) and
  `watch` (one operator frame). The service slice is present
  but not production-qualified: no clean-COMPLETE bootstrap and
  no operational per-call trace in the service slice are claimed.
- Aggregate trace only. `--trace off|metadata` proceed as
  aggregates; operational modes (`latency|status|all`) and
  `--trace-histogram-by-api` degrade to the aggregate-only
  fallback on public paths while latency/rate acceptance (C023)
  remains OPEN. C023 results publish as measurements, not as a
  latency, wall-clock or rate qualification.

Explicitly deferred out of interim v0.7.0: definite
algorithm/provider execution attribution and per-call serving
provider/algorithm; operational per-call trace, durations and
histograms as supported output; latency/rate qualification;
COMPLETE-window claims; fork/exec following and cross-process
totals as qualified claims; and every item under "Beyond
v0.7.0" below.

## Beyond v0.7.0: feature-complete milestone (not in v0.7.0)

The former v0.7 plan, preserved verbatim as deferred scope. An
unfinished requirement keeps feature completion open rather than
silently moving to a later version; assigning it a version
number is an owner decision at re-planning time.

- Broaden the tested OpenSSL 3/4, kernel, libc and provider matrix, including
  default, legacy, FIPS and third-party providers.
- Add ARM64 and separate OpenSSL 1.1.1 inventory/public EVP/ENGINE observation.
  OpenSSL 1.1.1 has no provider interface; its results retain that distinction.
- Qualify genuine RHEL with enforcing SELinux and Secure Boot controls, and
  node-local Docker/containerd/Kubernetes deployment on supported hosts.
- Provide an explicitly invoked isolated helper for exploring supplied provider
  modules. Its observations describe its own execution, not another application.
- Add passive executable inspection beyond environment prediction, with clear
  static/dynamic dependency, plugin-loading and multiple-library limitations.
- Add a documented correlation workflow with p11scope while preserving each
  tool's evidence and clock/coverage limits.
- Complete package channels, consumer compatibility, remaining correctness and
  privacy work, and real operator/practitioner acceptance before feature freeze.

## Toward 1.0: stabilization

After the feature-complete milestone, focus on correctness, security, performance, usability, documentation
and deployment fixes. Qualify the integrated packages across the supported
matrix, continuous-operation soak, useful consumer imports and real operator
journeys. Stable CLI/schema behavior and reproducible release artifacts matter
as much as feature count. Release dates follow demonstrated readiness.

## Reuse and boundaries

Review implemented mechanisms in p11scope, including its development branches,
for mapped-file identity, lifetime handling, bounded counters/output, diagnostics,
comparison and distribution. Adapt each mechanism to OpenSSL's different public
interfaces and privacy rules; upstream source or tests do not qualify osslscope.

The initial platform remains Linux x86-64 with capable kernels. ARM64 and the
explicit legacy OpenSSL path are planned above. Windows/macOS, older kernel
backends, cgroup v1, remote cluster inventory and universal detection of hidden
static/JIT crypto are outside the selected 1.0 scope.

No keys, passwords, plaintext, application payloads, private OpenSSL layouts,
application injection or interposition. Discovery, advertisement, API activity,
physical entries and attributable execution remain distinct. Missing visibility
never proves non-use, and provider identity never proves FIPS certification or
hardware protection.

Historical release behavior remains documented in the
[v0.3.0 release](https://github.com/mingulov/osslscope/releases/tag/v0.3.0) and
[v0.2.0 notes](docs/release-v0.2.0.md). The old fixed-profile route is a legacy
diagnostic with its original qualification boundary.
