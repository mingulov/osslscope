<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Roadmap

osslscope is in development. The v0.2.0 source preview has one qualified
foreground workflow. Broader features remain planned releases.

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

## After v0.2.0

The next priorities are additional useful profiles/algorithms, external-process
attach and general provider discovery with the required identity/privacy
controls. Broader OpenSSL, kernel, libc and container support will be qualified
incrementally.

Later releases can add independently useful features:

- Multiple processes, cgroups and process following.
- Daemon operation, Prometheus/OpenTelemetry export and operator workflows.
- Latency histograms and metadata-only per-call tracing.
- Advanced artifact identity/build provenance and DEB/RPM lifecycle support.
- Stronger completeness/first-call guarantees and broader performance,
  platform/provider and consumer qualification.

These are future tracks, not prerequisites for the first usable preview.
ARM64 and OpenSSL before 3.0 remain later evaluation. Platform and performance
claims will follow actual results, with their limits documented.

The permanent boundaries remain: no keys, passwords, plaintext or application
payload capture; no TLS interception, application changes or interposition.
