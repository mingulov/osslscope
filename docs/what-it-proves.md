<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Observation meaning and limits

## Current v0.3 discovery and observation

Normal `scan`/`inspect` discover mapped OpenSSL-compatible objects and provider
interfaces without an enrolled build or supplied offset. Watch samples changes;
PID/cgroup/module selectors narrow inventory. A mapping is presence evidence,
not provider activation or crypto execution.

Public provider API/init/query observation can learn advertised callbacks.
Normal `report`/`check` count physical entries at verified learned sites in one
selected process and its threads. An entry contributes once even if several
algorithms/providers share the address. Candidate coverage stays Unknown:
normal reports are PARTIAL, algorithm policies inconclusive and definite CBOM
assets absent. API success, advertisement and callback entry remain different
facts; none establishes crypto/application success or FIPS/HSM state.

Ordinary built-in default-provider initialization/query may bypass the exported
hooks, so an actively computing application can yield zero callback counts.
Warm/cached state, short startup, polling, invalidation and final-tail gaps also
remain. Zero counts are not non-use. The [next-version plan](../ROADMAP.md#v040-automatic-observation)
targets automatic table discovery and these ordinary workload paths.

Inventory can cover multiple processes/cgroups; execution reports do not follow
children or membership. Permission/namespace/backing/resource failures stay
explicit. There is no injection, target environment reader or private-layout
enrollment in the normal path. Current [usage](usage.md),
[release scope](release-v0.3.0.md) and the
[actual release record](https://github.com/mingulov/osslscope/releases/tag/v0.3.0)
take precedence over historical diagnostics below. Installed results qualify
only the named artifacts/workflows, not every provider/platform.

## Historical v0.2 fixed-profile diagnostic

The remainder describes the explicit `--libcrypto` legacy route and its earlier
qualification; its exact-build restriction does not apply to normal v0.3 discovery.

The v0.2.0 foreground route observes entries into a finite set of compiled
OpenSSL implementation callbacks in one exact enrolled library/kernel profile.
It launches one unchanged application, counts its original thread group and
threads, and produces the existing
[observed-crypto-v2.3 document](observed-crypto-v2.md). Native qualification
covers the [one advertised profile](release-v0.2.0.md); source tests and
catalogue enrollment alone do not qualify another runtime environment.

## What a positive entry establishes

Each site has a verified backing object/device/inode/file offset and a static
compiled candidate set. One physical entry contributes one call. A definite
algorithm classification requires a complete candidate set whose meanings agree;
a shared site's N entries remain N, with uncertainty preserved.

The initial catalogue includes SHA-256 NEWCTX, AES-256-GCM NEWCTX and one shared
AES/ARIA/SM4 GCM UPDATE. NEWCTX observes context creation attempts; UPDATE may
handle AAD, empty input or a failed operation. Entry counts and first/last entry
timestamps do not establish message count, callback duration, processing success,
key size, provider activation or FIPS state. Provider metadata describes compiled
candidates, not the runtime instance that advertised or selected them.

## Incomplete coverage stays explicit

Every capture has `UnknownDenominator` for its finite profile and remains
PARTIAL. Other algorithms, objects, sites, process groups and periods are
unobserved. A missing observation cannot become an absence proof. Positive
requirements may succeed under partial coverage; definite deny evidence can
violate policy. Unobserved known algorithms remain inconclusive.

Human, JSON and definite-only CBOM outputs describe the same finalized document.
A shared/unknown candidate set produces no definite CBOM asset. The selected
Count bytes/hash/trust selection are recorded separately from library identity;
no harvest/members bundle or authenticated build-input record is fabricated.

## Count and target identity

The observer pins and hashes the protected stock library. Before release it
attaches the enrolled file offsets through the existing Count owner using the
owned child's nonzero PID and the selected kernel's native retained-group filter.
Observer/child initial PID namespace and matching procfs are required. There is
no PID-zero fallback, numeric rebinding or target-memory discovery.

Counts aggregate across the original process lifetime. Forked groups are outside
scope. Leader retirement/nonleader exec can lose coverage, so there is no
seamless-follow or per-image guarantee. The library/catalogue and native kernel
behavior require the actual installed qualification controls.

<a id="terminal-count-proof-in-development"></a>

## Closure, custody and privacy

Child exit is observed without consuming its wait status. The existing count
terminal is selected before final reap/detach. Available positive counts survive
normal degraded tails and runtime failures; typed loss/cleanup reasons remain
visible. Equal scans do not prove writer completion, and successful close calls
alone do not establish a universal terminal-writer theorem.

The preview keeps a missing terminal-writer guarantee as PARTIAL when link
closes and reads succeeded and it is the sole limitation. The strict Count
receipt still retains `count.quiescence_unknown`, `count.close_failed` and
`count.owner_failed` for that missing completion certification. No completion
witness or counters are rewritten. Additional close, read, inventory or cleanup
failures remain runtime failures.

Normal setup and signal paths resolve stopped children and owned resources.
A released live workload stays running at observation end. SIGKILL/crash during
the stopped pre-exec interval can strand the child: crash-safe startup custody
is deferred. There is no final report guarantee after observer death.

The qualified Count program reads no target arguments, strings, payloads, keys
or return values. The app records a safe target token rather than argv/comm.
An explicit Count override remains operator-trusted code; compatibility/hash
admission does not authenticate arbitrary instructions. Privacy/release claims
attach to the exact source-built object actually inspected and qualified.
Privileged in-place library updates, deliberate code patching/JIT, provider
injection and privileged process/FD tampering are outside the preview model.

See [usage](usage.md#exit-codes), [catalogue provenance](../profiles/README.md)
and the [later roadmap](../ROADMAP.md) before applying broader developer
references. General providers, foreign attach, services, tracing/export,
stronger completeness guarantees and broader platforms are later work.
