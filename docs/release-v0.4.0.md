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
The following finite results bind the ordinary release build from source
`03e053c00c1bcd8c44e151373cac0c18bf038595`. Later release-prose changes
leave these runtime bytes unchanged. This is a source-prefix
installation qualification, not binary-package or publication acceptance.

## Measured cost and practical limits

**Tracing reduced this SHA-256 hot loop's throughput by about 4.66×**: the
median baseline/observed ratio was 4.664, range 4.637–4.699. Five paired runs
followed one warmup pair and alternated order, using the identical stock command
`openssl speed -elapsed -seconds 6 -bytes 16384 -evp sha256`. Median throughput
was 2.498 GB/s alone and 0.535 GB/s under ordinary `report run`. Both the workload
exit and positive physical/API evidence were checked independently.

This sample uses host kernel 7.0.0-38-generic, stock OpenSSL 3.5.5, warm caches,
two-CPU affinity and the host's powersave governor. It is not a general overhead
bound; tight loops can be expensive. No 100k calls/s, 4 microsecond or 2× overhead
guarantee is claimed.

| Separate measurement | Observed finite result |
| --- | --- |
| One-PID passive scan, five runs | 13.16–13.49 ms scanner interval; 11,180–11,296 KiB peak RSS; seven objects and 12,006,791 charged read bytes per invocation |
| Four-second passive watch | 0.01 s user CPU, system CPU below the timer's 0.01 s display resolution; 11,316 KiB peak RSS; subsequent cached samples charged 10,283 bytes each |
| Observer process under tracing | Per-run mean CPU 21.4–24.1% of one CPU, including setup; one-second samples 0–100%; sampled RSS at most 30,216 KiB |

The observer CPU samples select only the observer PID. They do not measure total
kernel/probe CPU, workload CPU or per-call latency. Sampled RSS excludes kernel
map memory and is not the global accounted-state budget. Scanner CPU readings
below timer resolution are not zero-cost claims.

All six observed hot-loop runs also hit the explicit
`focused.metadata_output_limit`: optional `algorithm_identities` and
`site_provenance` sections were omitted while core physical counts and API rows
remained available. Large candidate sets can therefore lose optional metadata
at the output cap even when useful activity counts survive. The cap was not
raised for qualification.

## Performed qualification

| Actual input | Performed cells |
| --- | --- |
| Host Linux x86-64, kernel 7.0.0-38-generic, stock OpenSSL 3.5.5 | Short/warm CLI, six-family public-API client, default and legacy provider, unmodified curl TLS, installed scope/cancellation/privacy/resource controls |
| Same host, independent Debian OpenSSL 3.5.7 library/module build | Matching-library public-API client; short digest and warm external-provider activity with the stock 3-linked CLI selecting those ABI-compatible libraries |
| Same host, official stable OpenSSL 4.0.3 | Its own 4-linked CLI/client and matching libraries; static tables, public query/dispatch facts, six-family API activity, default/legacy, short/warm observations |
| Host observer selecting two Docker containers with distinct PID/mount namespaces | Passive and automatic-watch PID/cgroup/module intersections, sibling exclusion, matching host incarnation coordinates, explicit backing refusal and workload survival |
| Cached kernel 6.12.114-0612114-generic | Unchanged observer artifacts; seven installed focused controls plus both stock 3 public-API clients on verified guest-local tmpfs backing |

All six-family clients exited successfully. SHA3/BLAKE2 digest values matched
independent hashlib oracles; legacy MD4 matched a fixed known value. Unused
fetches had zero operational API entries on all three builds, while initialization
could still produce physical candidate entries. ChaCha20 and Camellia round trips
preserved public test bytes. Curl completed a certificate-verified local TLS
request with HTTP 200 and exit 0; its fixture server was outside the selected
process. Native controls include lookalikes, shared and unused callbacks, renamed/
replaced/unlinked/late objects, denied access, actual PID reuse and global caps.
Reports remain PARTIAL and checked algorithm policy remains inconclusive.

Default crypto-watch output now provides bounded human process/object/activity
summaries with separate physical and API entries; `--json` retains NDJSON.
Native authority-refresh control prearmed 2,860 physical sites on four links,
then supplied partial and stronger verified inventory. Independent calls before
and after refresh conserved 37 + 11 = 48 without replaying cookies or duplicating
links. Stable snapshots added no read/accounting churn; a real backing-file
change retired the links. The 4,096-cookie ceiling remains unchanged.

Container-backed crypto files remained locator-only, with explicit identity/read
gaps and zero observed activity, not an inactivity verdict. Guest warm/sustained
controls passed with byte-identical executable and loaded dependencies whose
actual mapped backing was verified as tmpfs. These results do not qualify
overlayfs or 9p backing. The table is the performed set, not a complete
cross-product of applications, algorithms, libraries and kernels. OpenSSL 4.0.3 is one pinned
compatibility lane; broader OpenSSL 4 qualification remains open.

Source checks pass with 2,058 tests and 138 explicit ignores. Fifteen fresh-object
preparation controls, fourteen installed host-command controls and nine direct
native source/producer controls pass; source tests and capability skips are not
runtime passes. Known shared-test-helper warnings and the pinned BPF-linker's
LLVM fallback warning remain disclosed. Whole-change independent review remains
part of candidate acceptance; no release has been published.

## Runtime identity

The CLI reports version 0.4.0. The ordinary pinned release build and protected
installation produced these SHA-256 values; guest copies were checked unchanged:

| Artifact | SHA-256 |
| --- | --- |
| `osslscope` | `72a1ee2b215d3b3829571259c817c83a5d4c6aea35b53ae79360385409d7ec51` |
| `osslscope-harvest` | `fa4f1ee35f5bce8a0e86232e25c15fcab372f98af3d137995caf3f0f2b7ffca2` |
| `osslscope-count` | `a6ddb29c44cc9845875cdd8f48558e856e30170101323fe187db91f52a76ea75` |
| `osslscope-members` | `abda2a14b3a32a416cc3e4ce3678cc3bb498854f0cdb806d1518a2e46f628800` |
| `osslscope-provider-observation` | `8d1faa01b05ed778cb57ab2805c0ee9290e7d6cd3761380ba9c317ba6a208115` |
| `osslscope-focused-count` | `35b6c2f499a5ad61134cf6ba946f7fb8e4a40ae8bf7980711038f7e48f750add` |

See [usage](usage.md) for cancellation, exit codes, privacy and the distinct
native-device/report-device identity encodings in crypto-watch records.
