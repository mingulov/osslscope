<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# osslscope

Discover OpenSSL-compatible libraries, provider modules and consumers, then
observe public provider interfaces and count entries at learned callback sites
for one selected process. Normal workflows need no enrolled library profile,
manual offsets or application changes.

**v0.3.0 released discovery preview.** The
[release record](https://github.com/mingulov/osslscope/releases/tag/v0.3.0)
reports the installed/runtime checks and their artifact identities. These finite
results do not qualify every application or platform. See
[release scope and qualification procedure](docs/release-v0.3.0.md).

## Discover, select, observe

Build the host CLI with `cargo build --locked --bin osslscope` for passive
inventory. Tracing additionally needs the source-built BPF companions and
BPF/perf privileges; follow [build](docs/build.md) and [install](docs/install.md).
Use actual host-visible PIDs and file paths:

```sh
osslscope scan --json
osslscope scan --watch --interval 1 --duration 30 --json
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
one selected PID to report/check. Execution documents cover one process
incarnation and its threads; they do not follow children or cgroup membership.

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

Ordinary default-provider activity can produce no callback counts: its internal
initialization/query path can bypass the exported hooks currently observed.
This can affect a sustained workload, as well as short commands that finish
before probes attach. Discovery remains useful, but a zero callback result does
not establish non-use. The [next-version plan](ROADMAP.md#v040-automatic-observation)
prioritizes automatic observation of these ordinary applications.

There is no universal first-call guarantee. Warm/built-in activation can remain
unknown; startup, polling, invalidation and final drain leave explicit gaps.
Calls before attachment or after retirement are uncovered. Unavailable backing,
permissions, namespace mismatch and resource caps retain partial/unavailable
semantics. Linux x86-64/OpenSSL 3 is the initial scope; kernel admission is
feature based. ARM64, pre-3.0/OpenSSL 4, RHEL/Secure Boot and broader platform
qualification remain deferred. See [usage](docs/usage.md) for bounds, privacy,
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
