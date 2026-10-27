<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# OpenSSL tracing and osslscope

OpenSSL's `OSSL_TRACE` API and the `OPENSSL_TRACE` environment variable provide
cooperative diagnostic tracing. **`OPENSSL_TRACE` exists.** Upstream builds
disable tracing by default; `enable-trace` enables it. The OpenSSL CLI configures
channels from the variable. Other applications need appropriate channel or
callback integration; setting a variable alone cannot activate an inert build
or supply an arbitrary application's missing integration. See the official
[environment documentation](https://docs.openssl.org/3.5/man7/openssl-env/),
[trace channel API](https://docs.openssl.org/3.5/man3/OSSL_trace_set_channel/)
and [CLI setup](https://github.com/openssl/openssl/blob/openssl-3.5.5/apps/openssl.c).

| Aspect | OpenSSL tracing | osslscope v0.3 |
| --- | --- | --- |
| Activation | Trace-enabled build and configured category channels/callbacks | External process/file access; tracing additionally needs installed BPF companions and privileges |
| Application cooperation | The CLI already provides integration; other apps vary | No injection, application changes or interposition |
| Evidence | Category-specific diagnostic messages | Mappings, observed public provider facts and physical entries at learned callback sites |
| Algorithm/provider attribution | Depends on the diagnostic category and emitted message | Candidate coverage stays Unknown in normal reports; shared sites stay ambiguous |
| Coverage | Only instrumented categories/code paths | Only discovered and attached sites during the observed interval; internal default-provider paths can remain invisible |
| Machine-readable policy | The tracing API supplies no osslscope-style policy verdict | Typed JSON and conservative policy/exit results |

OpenSSL includes ENGINE selection/reference diagnostic categories. Diagnostic
messages about loading, selection or references do not establish a universal
per-operation execution counter. Likewise, osslscope's ordinary v0.3 path does
not promise general low-level/ENGINE coverage. Older diagnostic fixtures retain
their own scope; they do not qualify the normal scanner.

A provider advertisement or fetch is not callback execution. A counted entry
does not establish crypto/application success, FIPS state or a complete
inventory. Normal v0.3 reports remain PARTIAL, algorithm policy is inconclusive,
and default-provider activity may produce no learned callback rows. Read
[observation limits](what-it-proves.md) before interpreting a zero result.

`check` distinguishes proved violation, inconclusive evidence and ordinary
failures. Exit 10 denotes a proved policy violation and 11 inconclusive when no
stronger failure applies. Passing policy on PARTIAL yields 3; fatal/delivery/
child failures have their own precedence. See [exit codes](usage.md#exit-codes).

Choose cooperative tracing when its categories answer the diagnostic question
and the application/build supports it. Use external inventory/observation for
unmodified workloads, while preserving the disclosed observation gaps. Neither
tool's mechanism alone establishes complete crypto use or negligible overhead.
