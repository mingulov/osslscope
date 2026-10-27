<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# v0.3.0 discovery preview

Scope: public source behavior, bounded inventory measurements and the release
qualification procedure. The published release record carries artifact-specific
qualification results; this document does not assert a passed runtime/CI matrix.

The normal workflow is scan/watch/inspect, select one host-visible PID, then
report/check. Passive ELF inventory needs no profile, offsets or BPF. Opt-in
public provider observation learns incomplete callback advertisements; focused
counting records physical entries at verified current sites. Report/check also
support one owned `run -- COMMAND`. The installed observation/focused-count
companions resolve automatically. Functional doctor probes scanner-owned BPF
load/self-attachment plus inventory, namespace and companion integrity.

Counts are physical, conserved across shared advertisements and current/fenced
rows. Candidate coverage and expected scope remain Unknown. No definite
algorithm/provider count or CBOM asset follows from a learned advertisement;
algorithm policy remains inconclusive and normal reports remain PARTIAL.
Callback entry does not establish crypto/application success. First calls,
warm/built-in activation, invalidation/reattachment intervals and the final
production tail can remain uncovered. Namespace mismatch refuses. See
[usage and finite limits](usage.md) and [trusted installation](install.md).

The initial scope is Linux x86-64 and OpenSSL 3 public interfaces, with kernel
feature admission. ARM64, pre-3.0/OpenSSL 4 and RHEL/Secure Boot qualification
remain deferred. No target environment/argv, payload, key or plaintext reader,
manual offset catalogue or injected provider is part of the normal route.

## Qualification boundary

Source/fixture checks, object compilation and pure object preparation are useful
independent tiers. They establish neither verifier acceptance nor observation
success. The fixture owns its callback counter independently of the observer;
query-only stimulus must remain zero, and N=37 controlled entries must produce
37 total physical counts at one shared attachment after verified readiness.
Repeated queries must not duplicate attachments; retirement and explicitly
uncovered pre-reattachment calls must remain visible.

Before release, bind all mandatory results to one unchanged installed binary
and companion pair, recording input identities and environment. Required cells
include installed PID/run/check, independent fixture count conservation and
Unknown policy/CBOM semantics; sibling exclusion, timeout/cancellation target
survival, target exit/replacement, denied BPF, object replacement/access failure,
resource caps and privacy canaries; two independent stripped stock OpenSSL 3
builds (including renamed/multiple mappings), natural external provider
success/failure, warm activation and module removal/replacement; passive module
inspection; two supported kernels; accepted host PID/cgroup/Docker/kind
inventory-to-PID selection and churn; source-archive build/install and final
whole-workspace/CI checks. Unavailable cells remain unresolved. Stock workload
success alone is not observer acceptance.

A source or companion rebuild requires new artifact-bound receipts. Publication
requires actual results for the mandatory release cells; source/ABI checks alone
are not certification.

## Measured inventory cost

One bounded sample measured read-only inventory of one owned stock OpenSSL 3.5.5
process running `openssl speed -seconds 6 -bytes 16384 -evp sha256`. The
filesystem cache was warm and BPF tracing was disabled. The observer ran on
Linux x86-64, kernel `7.0.0-38-generic`, using a Rust 1.88.0 release build from a
source archive. The commands selected only that process:

```sh
osslscope scan --pid PID --json
osslscope scan --watch --pid PID --interval 1 --duration 4 --json
```

| Scanner operation | Wall time | CPU time (user + system) | Child-reported peak RSS |
| --- | --- | --- | --- |
| Single snapshot | 13.93 ms | 12.953 ms (6.975 + 5.978) | 13,292 KiB |
| Watch, 1 s interval, 4 snapshots plus end | 4.003 s | 19.900 ms (13.267 + 6.633) | 13,420 KiB |

The snapshot inspected 7 executable objects and charged 12,006,803 bytes of
read work. Watch's initial snapshot inspected 7 objects and charged 12,006,788
bytes; each of its three cached follow-ups inspected no new objects and charged
10,280 bytes. Both commands returned 3 with `identity_unverified`
mapping-association gaps while retaining `openssl_compatible` and
`openssl_consumer` evidence. This is partial inventory, not fully verified
mapping coverage. Peak RSS is the scanner child's `wait4` resource report,
not total kernel memory or a separately isolated incremental-memory measure.

Sample identity:

- Source: `ce64a8efbca5856cff48092d12962cee29007659`.
- Source archive SHA-256: `f819377db98da8baa3f8faf90df85582b02db23543e23f5ca652104942da0974`.
- CLI: 5,131,312 bytes; SHA-256 `28a43db48a84f5cc38bdd0011d715bc4629ed63b8ed3e0d78ef84f7e29540320`.

These are single samples of scanner cost for the named source/artifact and
visibility scope. Application CPU time was 6.003319 s without the observer,
6.003839 s during snapshot and 6.002950 s during watch. Those noisy samples do
not establish a throughput or cryptographic-latency effect. No system-wide
scaling, hot callback-tracing cost or broader performance budget follows from
this measurement. It does not qualify a later rebuilt artifact. The
[historical overhead matrix](overhead-matrix.md) measures the earlier diagnostic
route and retains its original scope.

## Historical compatibility

Explicit `--libcrypto PATH` retains the v0.2 exact-profile foreground diagnostic;
it is never a hidden fallback. Its [release notes](release-v0.2.0.md),
[catalogue](../profiles/README.md) and historical results keep their original
scope. The root package is version 0.3.0; internal helper versions are unchanged.
Use [build](build.md), [install](install.md) and [usage](usage.md) for current
commands. Binary-package and broader platform qualification remain later work.
