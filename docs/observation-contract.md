<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Observation contract

Provider observation associates its existing public API roles with executable
sites in the retained, identity-validated ELF backing. On x86-64, acquisition
can follow one transparent tail jump from the exported
`OSSL_PROVIDER_query_operation` or `OSSL_PROVIDER_unquery_operation` entry.
This improves visibility when ordinary OpenSSL paths call the forwarded
implementation directly.

The accepted wrapper is exactly one direct relative `E9` or `EB` jump,
optionally preceded by `ENDBR64`, occupying the entire nonzero defined
function symbol. It preserves the public arguments and return convention.
The destination must resolve unambiguously to executable file bytes in the
same retained object. Source and destination cannot use writable executable
backing. Self jumps, instruction-body overlaps, interiors of other defined
dynamic functions, conflicting public roles, IFUNC destinations, recognized
PLT/GOT sections and immediate indirect-transfer stubs are refused. The
observer follows at most one hop and performs no private-symbol lookup.

An unsupported architecture, wrapper or destination keeps the validated
public export entry as its observation site. Calls that bypass that entry
can remain unseen. This finite decoder does not recognize every possible
linkage stub or establish universal visibility across OpenSSL builds.
Existing object, mapping, process and namespace revalidation still applies.

This change preserves the existing finite API identifiers and argument
read allowlist. It adds no target-memory reads, opaque object-layout reads,
provider enrollment or version-specific exceptions. Raw instruction bytes
and addresses remain private acquisition inputs.

Static algorithm-table candidates continue to authorize physical entry
counting only. They do not establish a callback signature or authorize
argument reads. Forwarded public query visibility does not by itself prove
which algorithm produced a callback entry, establish definite algorithm
attribution, or qualify a COMPLETE observation window. Existing partial
coverage and attribution limits still apply.

For an owned process held before exec, independently exported provider load,
try-load, unload, built-in registration, init, query, unquery and dispatch-getter
roles can be armed on retained startup files alongside scalar operational APIs.
All public roles participate in collision refusal; fetch stays mapped-only.
Startup metadata uses the same reviewed public ABI and finite read allowlist.
It grants no executable address ranges. Algorithm advertisements can therefore
be observed while callback/code relocation is explicitly refused.

The first independently validated mapped authority adopts matching startup
links, cookies, generation and pending event sequences. It retains original
held-process custody and does not renew an invalidated advertisement lease.
Already queued startup records can also be drained after the original owned
process exits, bound to its retained pidfd, cookie, generation and unchanged
file. This historical drain grants no new attachment or relocation authority;
unavailable current process/namespace checks and prior losses remain explicit.
A confirmed process, namespace or backing mismatch invalidates that retained
source authority; later exit or unavailable identity reads cannot restore it.
Neither startup nor historical metadata establishes execution-backed algorithm
attribution or a COMPLETE window.
