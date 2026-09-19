<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Privacy residuals

The [capture allowlist](allowlist-v1.md) is the complete set the
eBPF programs and the userspace capture path may emit: anything
not listed there is a bug, and a canary suite fails the release
if any secret byte reaches any artifact. This note discloses what
that guarantee does NOT cover. Field names below mirror the
allowlist legend exactly.
<!-- source: residual list: PRD.md section 7; field tokens:
     docs/privacy/allowlist-v1.md -->

## alg-name-only strength

`alg_class` carries the algorithm NAME class only. Key sizes,
modes, and parameters are unobservable by design: RSA-1024 and
RSA-2048 are the same class to this tool, as are any two key
lengths of one algorithm. Every human report ends with the
footer note "alg-name-only strength (key sizes unobservable);
window-only claims" so the limit travels with the evidence.
Size compliance questions need a different instrument.

## Counts as a side channel

Per-key execution counts are exact -- and exact counts of crypto
operations can leak workload shape (how much signing, how many
handshakes, when). Treat report/JSON/CBOM artifacts as
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

External provider modules are pinned by object path plus
build-id; the built-in provider lives inside libcrypto, so its
provenance is only as strong as the libcrypto identification.
Pin the observed libcrypto by `provider.build_id` (GNU
build-id) and object hash, enroll exact builds before gating,
and treat unknown build-ids as fail-closed (see
[attach failures](../attach-failures.md)).

## Stripped targets degrade to count-only / PARTIAL

Stripped binaries lose the symtab resolution rung; where no
enrolled build-id row or live fallback covers the build,
harvest degrades to count-only or zero-row PARTIAL rather than
guessing. The degradation is explicit in `status`/`reasons[]`
-- but a stripped fleet without enrolled twins yields
blindness, not inventory (see
[who should NOT adopt](../what-it-proves.md#who-should-not-adopt-read-before-installing)).

## Root-operator model

The observer runs with `CAP_BPF`+`CAP_PERFMON` (at minimum) and
reads target process metadata (`target.comm`,
`target.cmdline` capped at 8 KiB, `target.container_id`) plus
mappings and disk ELF. A root operator can already read target
memory; osslscope adds no new privilege to that model, but it
is not a least-privilege-everywhere tool: anyone who can run
captures can observe crypto counts and process metadata for
the targets they may attach to. `target.cmdline` is bounded
process metadata that can reflect operator input -- never pass
secrets as target argv.

## What is never captured (recap)

No `OSSL_PARAM` values, property strings, verbatim algorithm
names, key/IV/plaintext/ciphertext/AAD/tag/salt/password/seed
bytes, KEM secrets, KDF/RAND/signature/digest outputs, `EVP_PKEY`
buffers, bignum limbs, PEM/DER/PKCS#12 bytes, error strings, or
TLS payloads. Raw code addresses stay in-kernel as join keys
(`inspect` retains a runtime address for attribution debugging;
report/check/CBOM carry file `offset` plus one-way `addr_hash`
only). See the allowlist for the audited read sites and the
change rule for adding any.
