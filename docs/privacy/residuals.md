<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Privacy residuals

The [capture allowlist](allowlist-v1.md) is the complete set the
eBPF programs and the userspace capture path may emit: anything
not listed there is a bug, and a canary suite fails the release
if any secret byte reaches any artifact. This note discloses what
that guarantee does NOT cover. Field names below mirror the
allowlist legend exactly.
<!-- source: docs/privacy/allowlist-v1.md; src/evidence.rs;
     src/report.rs; schemas/observed-crypto-v2.json -->

## alg-name-only strength

Algorithm classes (`alg_class` in inspect, `algorithm_classes` in
v2 candidates) carry NAME classes only. Key sizes,
modes, and parameters are unobservable by design: RSA-1024 and
RSA-2048 are the same class to this tool, as are any two key
lengths of one algorithm. MAC/KDF/SIGNATURE/ASYM_CIPHER can select
digests or ciphers through parameters that the observer never
captures. Current human output ends with argv-redaction,
file-offset and window-only notes; it does not emit a dedicated
strength/parameter warning on every run. Apply these limits to
all formats. Size/parameter compliance questions need a different
instrument.

## Counts as a side channel

Counts record physical callback entries once per site/generation,
under the document's coverage and loss limits. Candidate identities
are attribution possibilities; a shared count is not a separate
count for each algorithm. Counts and first/last execution timing
can still reveal workload shape and activity patterns. Treat
report/JSON/CBOM artifacts as
operational telemetry: retain them under the same access
controls as other production counters, and redact before
sharing outside the trust boundary.

## Registry staleness degrades to `other`

Unknown algorithm names classify to `other` (never verbatim).
A stale registry therefore hides real algorithms behind the
`other` class instead of mislabeling them -- honest but blind.
When `other` counts are load-bearing for a verdict, check for
a registry update before concluding anything about the
underlying algorithms.

## Scalar aliasing and bytes-not-types reads

The hostile-input rule (bounded reads, exact-membership key
match, exact-shape gate, any failure to `other`/unreadable with
no partial decode) bounds what aliased or malformed provider
memory can inject into the pipeline -- but the residual shape
risk stays with the reader: a hostile provider controls the
bytes the harvester classifies. The emission stays
secret-free; the classification of a lying provider is fenced
to count-only, never trusted.

## Weaker built-in-provider provenance

External providers and libcrypto need exact-byte provenance;
the built-in provider's identity depends on its backing libcrypto.
Use v2 opaque fingerprints joined through `objects`, plus available
disk-ELF GNU build-id and hashes. A display path alone is not identity,
and v2 has no `provider.build_id` carrier. Recheck admission after
rebuilds: supported symtab builds can qualify without a table hit,
whereas unknown stripped builds need explicit exact enrollment
(see [attach failures](../attach-failures.md)).

## Stripped targets need explicit admission

Stripped binaries lose the symtab resolution rung. Without an
enrolled build-id row or explicitly selected supported fallback,
report/check refuse with enrollment remediation; inspect can
expose degraded or zero-row harvest rather than guessing.
Read the actual status and reasons. A stripped fleet without
admitted anchors yields blindness, not inventory (see
[who should NOT adopt](../what-it-proves.md#who-should-not-adopt-read-before-installing)).

## Root-operator model

The observer runs with `CAP_BPF`+`CAP_PERFMON` (at minimum) and
reads process identity/admission metadata plus mappings and disk
ELF. Artifacts retain safe pid, `target.comm`, container/image
provenance and unconditional `target.argv_redacted: true`.
There is no raw argv/cmdline field: paths that need a cmdline-shaped
value use `(argv-redacted)`, and inspect's marker admission emits
no matched argv. A root operator can already read target
memory; osslscope adds no new privilege to that model, but it
is not a least-privilege-everywhere tool: anyone who can run
captures can observe crypto counts and process metadata for
the targets they may attach to. Never pass secrets as target argv:
system-wide `/proc` exposure remains even though osslscope redacts
argv from its artifacts (see the allowlist's Scope rule).

## What is never captured (recap)

No `OSSL_PARAM` values, property strings, verbatim algorithm
names, key/IV/plaintext/ciphertext/AAD/tag/salt/password/seed
bytes, KEM secrets, KDF/RAND/signature/digest outputs, `EVP_PKEY`
buffers, bignum limbs, PEM/DER/PKCS#12 bytes, error strings, or
TLS payloads. Raw code addresses stay in the transient internal
discovery transport as join/relocation keys, consumed and discarded
at relocation; every artifact carries file `offset` plus one-way
`addr_hash` only. See the allowlist for the audited read sites and
the change rule for adding any.
