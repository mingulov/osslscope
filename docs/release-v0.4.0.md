<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# v0.4.0 automatic observation candidate

This source candidate adds automatic entry-only table discovery, owned startup
prearming, warm-process observation, public API activity and sampled crypto
watch. It is not a published release. Build and install using the pinned
[build](build.md) and [installation](install.md) recipes.

```sh
osslscope report --duration 5 --format json run -- openssl dgst -sha3-256 /dev/null
osslscope report --pid 1234 --duration 10 --format json
osslscope scan --watch --observe-crypto --duration 30 --json
```

Operators select scope and duration. Available algorithms are examples, not
admission profiles. Static table shapes establish candidate entry sites only;
these probes never dereference arguments or returned memory. Public-ABI facts,
physical entries and scalar API results remain distinct. Shared implementations
contribute one physical count. API success includes wrappers and size queries;
it does not establish application or cryptographic success.

Reports remain PARTIAL with Unknown attribution, no definite assets from
candidate hints and inconclusive algorithm policy. Unsupported loaders, late
objects, missing backing, permission denial, sampling and final drain leave
explicit gaps. No universal first-call or complete-window guarantee is made.
Crypto watch has four default active slots and a global 256 MiB accounted-state
budget; this is not an RSS bound or a promise that four maximal sessions fit.
Unobserved or denied members never become inactive crypto verdicts.

The initial qualification scope is Linux x86-64 with two independent stock
OpenSSL 3 builds and two available supported kernels. A pinned official stable
OpenSSL 4.0.3 compatibility lane uses its own compiled application and matching
libraries; this does not qualify the entire OpenSSL 4 family. Broader platforms,
ARM64, pre-3.0, RHEL and Secure Boot remain outside this candidate's evidence.

Installed runtime receipts must bind the CLI and all five BPF object hashes.
Source checks and fresh-object preparation do not substitute for those receipts.
Finite performance measurements separate passive scanner CPU/RSS, observer
process CPU and workload throughput. No general 100k calls/s, 4 microsecond or
2x overhead guarantee is claimed. Artifact-specific results will be recorded
here after the candidate's installed workflows are exercised.

See [usage](usage.md) for cancellation, exit codes, privacy and the distinct
native-device/report-device identity encodings in crypto-watch records.
