<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# v0.2.0 source preview

Build from source, install into a local prefix, and run one unchanged OpenSSL
application with `report` or `check`. The preview counts enrolled implementation
callback entries in the original process and its threads. Human/JSON output,
definite-only CBOM and algorithm require/deny policies share the same evidence.

## Qualified profile

Ubuntu 26.04.1 amd64, stock OpenSSL `3.5.5-1ubuntu3.7`, kernel
`7.0.0-38-generic` package `7.0.0-38.38`, initial PID namespace/procfs.
The exact library SHA/build ID and kernel build ID are pinned in the
[catalogue](../profiles/stock-openssl3-v1.json). This is one build combination,
not version-wide support. BPF/perf privileges remain an operator prerequisite.

The documented recipe's Count object has SHA-256
`a6ddb29c44cc9845875cdd8f48558e856e30170101323fe187db91f52a76ea75`.
Native checks exercise SHA-256 and AES-256-GCM entries, shared-site conservation,
worker/exec behavior, forked and separately started foreign process exclusion,
actual output/policy exits, mismatched inputs, namespace refusal, signals,
deadline, observer death and a real injected link-creation failure.
The matching compiled Count has no target-memory read helpers. An arbitrary
explicit Count override is operator-trusted code and inherits no privacy claim.

## Limits to use correctly

- Every capture is PARTIAL. Positive definite entries are useful; absence is
  inconclusive. No complete inventory, first-call or terminal-writer guarantee.
- SHA-256/AES-256-GCM context creation and a seven-candidate GCM update are the
  only enrolled sites. Shared N entries stay N; ambiguous assets are omitted.
- Counts do not establish message count, crypto success, key size, runtime
  provider activation or FIPS state. No target arguments, payloads, keys or
  return values are read.
- Capture aggregates the original group across leader exec. Nonleader exec or
  leader retirement can lose coverage. Forked groups are excluded.
- Normal setup/signal paths clean owned resources. Released live workloads
  remain running at observation end. Observer SIGKILL/crash before child exec
  can strand the stopped child; startup crash recovery is deferred.
- Handled setup cancellation disposes the stopped child even while a Count
  operation remains pending. Its late resources remain with the owner;
  this does not promise a hard deadline for arbitrary blocked kernel cleanup.
  The killed child's wait status stays with that owner until delayed Count
  work closes, preserving its PID identity through late attachment.
- Tight loops pay material overhead. Read the actual
  [matched timings and sampling limits](overhead-matrix.md); no historical
  production performance budget is claimed.
- The explicitly empty deferred `--image-digest ""` flag is currently ignored.
  It supplies no image attribution; nonempty values are rejected. This minor
  validation inconsistency is deferred.

General discovery, foreign-PID attach, additional profiles/providers, containers,
services/export, per-call tracing/latency, stronger completeness, DEB/RPM and
advanced artifact builders remain [later work](../ROADMAP.md). Genuine RHEL and
enabled Secure Boot qualification are not part of this preview.

## Distribution and start

This release channel contains first-party source, tests, metadata, schemas,
documentation, scripts and lockfiles. No host/BPF binaries, OpenSSL/kernel image
or vendored dependency/toolchain sources are bundled. See
[source notices](../NOTICE.md) for the conveyed inventory and component licenses.
Internal helper crate versions remain0.1.0; the root app is0.2.0.

Follow [build](build.md), [install](install.md) and [usage](usage.md). Normal
partial report/positive require exits3; definite deny10; inconclusive11;
invalid/deferred usage2; setup/environment refusal4; usable runtime or child
failure1. A definite violation retains precedence over a child failure.
