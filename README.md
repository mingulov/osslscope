<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# osslscope

Discover OpenSSL-compatible libraries, provider modules and consumers, then
observe public provider interfaces and count entries at learned callback sites
for selected processes or automatically discovered watched scopes. Normal workflows
need no enrolled library profile,
manual offsets or application changes.

**v0.4.0 automatic observation release candidate.** Short owned commands,
warm processes and sampled watched scopes expose physical callback entries and
separate public API activity. See the [candidate scope and qualification
limits](docs/release-v0.4.0.md). The [v0.3.0 release
record](https://github.com/mingulov/osslscope/releases/tag/v0.3.0) retains its
historical artifact-specific scope; this candidate has not been published.

Tracing hot loops can be costly: the finite stock SHA-256 sample measured a
4.67× baseline/observed throughput ratio. See [measured cost and limits](docs/release-v0.4.0.md#measured-cost-and-practical-limits).

## Discover, select, observe

Build the host CLI with `cargo build --locked --bin osslscope` for passive
inventory. Tracing additionally needs the source-built BPF companions and
BPF/perf privileges; follow [build](docs/build.md) and [install](docs/install.md).
Use actual host-visible PIDs and file paths:

```sh
osslscope scan --json
osslscope scan --watch --interval 1 --duration 30 --json
osslscope scan --watch --observe-crypto --duration 30 --json
osslscope scan --cgroup /sys/fs/cgroup/example.service --json
osslscope inspect --pid 1234 --json
osslscope inspect --module /usr/lib/x86_64-linux-gnu/libcrypto.so.3 --json
osslscope doctor --format json
osslscope report --pid 1234 --duration 30 --format json --out report.json --cbom bom.json
osslscope check --pid 1234 --duration 30 --require-executed SHA256
```

Scan/watch narrows PID, cgroup and supplied-module selectors by intersection.
For [Docker/kind](docs/usage.md#host-side-container-workflows), independently
resolve the workload in host PID/cgroup coordinates, inventory it, then pass
one selected PID to report/check, or watch the scope with `--observe-crypto`.
Report/check cover one process incarnation and its threads. Crypto watch streams
separate per-incarnation documents as eligible processes enter and leave the
sampled scope; it never creates a cross-process aggregate.

Passive discovery uses ordinary procfs/filesystem access and loads no supplied
module. Add `--observe-providers` to a PID scan/watch or PID inspection for
bounded public lifecycle/query observation. Report/check automatically use the
installed `osslscope-provider-observation` and `osslscope-focused-count` pair.
Doctor checks inventory, namespace and companion integrity and performs
scanner-owned functional BPF load/self-attachment controls. Target attachment
and access remain scope dependent.

## Interpret the evidence

ELF interfaces and mappings establish metadata inventory, not activation or
execution. Public queries advertise callbacks; advertisement is not execution.
A physical callback entry establishes neither cryptographic nor application
success. A shared implementation contributes its physical count once.
Candidates and their coverage remain **Unknown**; learned advertisements do
not establish a definite algorithm/provider count or definite CBOM asset.
Normal reports remain **PARTIAL** and algorithm checks remain inconclusive.

Report/check also discover entry-only candidates from public-table shapes in
verified mapped ELF files. This allows warm ordinary default-provider activity
to produce physical entry evidence without an application query or build
profile. These candidates are hints, not proof of an advertised OpenSSL ABI or
of crypto use. A called lookalike is counted without reading its arguments or
return value. Public query/getter observations remain a separate evidence source.
Zero counts do not establish non-use: coverage, unsupported linkage, attach
latency and bounded discovery can leave gaps.

Owned foreground commands prearm entry-only sites from retained executable and
dependency files before release, preserving counts even after a short command exits.
Independently verified public operational exports also provide scalar API activity
for digest, cipher, MAC, KDF, PKEY and RAND. Candidate hints/custom IDs and API
returns are displayed separately from callback totals; wrappers and size queries
are included, and no algorithm/provider binding or crypto-success claim is inferred.

There is no universal first-call guarantee. Warm/built-in activation can remain
unknown; startup, polling, invalidation and final drain leave explicit gaps.
Calls before attachment or after retirement are uncovered. Unavailable backing,
permissions, namespace mismatch and resource caps retain partial/unavailable
semantics. Linux x86-64/OpenSSL 3 is the initial scope; kernel admission is
feature based. A pinned OpenSSL 4.0.3 compatibility lane is included in the candidate
qualification; broader OpenSSL 4 matrices, ARM64, pre-3.0 and RHEL/Secure Boot
remain deferred. See [usage](docs/usage.md) for bounds, privacy,
exit codes and cancellation.

## Historical diagnostics and documentation

Explicit `--libcrypto PATH` selects the v0.2 fixed-profile foreground diagnostic.
Its exact enrolled-library/kernel and Count-only restrictions still apply.
Historical results in the [v0.2 release notes](docs/release-v0.2.0.md),
[catalogue](profiles/README.md) and [overhead matrix](docs/overhead-matrix.md)
retain their original scope. A separate [bounded v0.3 inventory cost
sample](docs/release-v0.3.0.md#measured-inventory-cost) measures one selected PID
with tracing disabled; it does not establish broad performance limits.

- [CLI and policy files](docs/usage.md), [build](docs/build.md), [install](docs/install.md)
- [v0.3 release notes](docs/release-v0.3.0.md), [roadmap](ROADMAP.md), [documentation index](docs/README.md)
- [Output contract](docs/observed-crypto-v2.md), [observation meaning](docs/what-it-proves.md)

Permanent boundaries: no keys, passwords, plaintext or application payload
capture; no TLS interception, interposition or target environment/argv readers.

## License

GPL-3.0-or-later for the host, documentation and scripts. BPF/common and
independent contract components have distinct terms; see
[component licensing](docs/licensing.md) and [LICENSES](LICENSES/README.md).
