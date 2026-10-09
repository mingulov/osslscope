<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# osslscope capture allowlist v1

Rule: this is the complete set the eBPF programs and the userspace
capture path may emit. Anything not listed is a bug.

Scope: osslscope never captures crypto-derived secret bytes. The
allowlisted process/observer metadata below is not target memory, but
it can reflect operator input. In particular, `cmdline` is bounded
process metadata: operators must not pass secrets as target argv.

## 1. eBPF count program

`crates/ebpf/src/bin/count.rs`, program `count_entry`.

Reads nothing from target memory. It combines an attach-time cookie,
a generation cell, the current TGID, and kernel timestamps into
per-key counters. It emits no strings, pointers, or target bytes.

Maps: `COUNTS`, `GEN`, `TARGET`, `DROPFAIL` (see §4).

## 2. eBPF harvest programs

`crates/ebpf/src/bin/harvest.rs`. Attached programs:

- `init_entry`, `init_return`
- `trip_count`, `trip_str0`, `trip_str1`
- `query_entry`, `query_return`
- `walk_dispatch` and `classify_alg` are BPF subprograms used by
  `query_return`.

There are exactly ten target-memory reads. Only two move bytes, and
both land in kernel stack scratch that is classified in-kernel and
never emitted; the rest move fixed scalars.

| site | read | bound | purpose | failure |
|---|---|---|---|---|
| `init_return` | provider dispatch-table pointer | `u64` | stage-1 anchor | return, no event |
| `init_return` dispatch scan | function id | `u32` | find query operation | return, no event |
| `init_return` dispatch scan | function pointer | `u64` | find query operation | return, no event |
| `trip_str0`, `trip_str1` | engine/provider-load argument string | 32-byte NUL-bounded string | kernel trip verdict | explicit unreadable verdict, counter only on missing arg |
| `walk_dispatch` | dispatch function id | `u32` | per-alg dispatch walk | stop walk |
| `walk_dispatch` | dispatch function pointer | `u64` | per-alg dispatch walk | stop walk |
| `query_return` | algorithm `names` pointer | `u64` | alg-slot join key | abort slot, overflow bit only on slot 0 |
| `query_return` | algorithm `impl` pointer | `u64` | alg-slot join key | abort slot, overflow bit only on slot 0 |
| `query_return` | array tail slot | `u64` | overrun detection | overflow bit |
| `query_return` | algorithm `names` string | 128-byte NUL-bounded string | kernel registry verdict | explicit unreadable verdict, slot freeze, overflow bit only on slot 0 |

Kernel classification: the 128-byte alias window is split on `:`
(max 8 segments) and each segment is hashed (FNV-1a-64 prefilter)
and looked up in the observer-populated `ALG_CLASS` table, with an
exact byte confirm before any match is accepted; the 32-byte trip
window is hashed and confirmed against `TRIP_CLASS` the same way.
Saturated windows (the helper filled the whole window, so an
exact-fit read and a truncated read are indistinguishable) fail
closed to overlong with no retained prefix. Statuses are explicit:
`OK`/`UNKNOWN`/`OVERLONG`/`TRUNCATED`/`UNREADABLE` (algorithms) and
`OK`/`UNREADABLE`/`OVERLONG` (trips).

Ring payloads (shared wire ABI v2, defined once in
`crates/ebpf-common` — the BPF program defines no wire structs of
its own):

- `InitRetEvent`: kind/op/funcid plus query-fn address and attach
  cookie. 32 bytes.
- `RowEvent`: kind/op/funcid plus join addresses/index; no name.
  40 bytes (`KIND_QUERY_RET` liveness shares the shape).
- `AlgEvent`: kind/op plus class id, status, weak flag, and the
  (array, index) join key. 32 bytes.
- `TripEvent`: kind/cookie plus class id and status. 16 bytes.

No ring payload carries target string bytes, string lengths, or
string prefixes: the wire structs are too small to hold the read
windows, which the protocol tests pin by size.

Addresses on the ring are transient internal structural-relocation
transport only: array bases attribute rows to provider mappings,
implementation addresses relocate to file-backed triples, and the
init report routes the stage-2 attach. Userspace consumes and
discards them at relocation; file-backed triples plus one-way
hashes are emitted instead. No public or debug artifact carries raw
runtime addresses — not `inspect`, report, check, CBOM,
alias-audit, logs, or diagnostics.

## 3. Userspace boundary

No target string bytes cross into userspace: classification happens
in the kernel (see §2), and userspace decodes finite class ids to
table labels, rejecting out-of-range ids, unknown statuses, and
short/unknown payloads before any label or count is produced:

| kernel verdict | decoder | emitted as |
|---|---|---|
| algorithm class id + weak flag | registry index to `alg_class` label, `OTHER` to `other` | `alg_class`, `weak` |
| `ENGINE_by_id` class id | engine taxonomy | `dynamic`, `builtin`, or `other` counts |
| provider-load class id | provider taxonomy | `legacy`, `default`, `fips`, or `other` counts |
| unknown/overlong/truncated/unreadable status | explicit status handling | `other` class or `unreadable` counters plus findings |

Unknown, overlong, truncated, unreadable, or hostile-aliased
input becomes `other`/unreadable plus counters and findings. There
is no partial decode, no retained prefix, and no verbatim target
string in any artifact, including debug logs.

The only other userspace read from target address space is
`pretouch_mappings`: one byte per mapped provider page, read only to
fault pages in before nofault BPF walks. Those bytes land in a
throwaway sink buffer and are never stored, classified, logged, or
emitted.

Non-target provenance:

- `provider`: observer-chosen provider path stem, not target memory.
- `backing`: `/proc` maps plus disk ELF, not target memory.
- `offset`: file offset, stable across ASLR.
- `addr_hash`: one-way hash over the attested backing triple.
- `target.comm`: `/proc/<pid>/comm` task name.
- `target.cmdline`: rendered `/proc/<pid>/cmdline`, capped at 8 KiB
  with a truncation marker.
- `target.container_id`: selected cgroup path segment, else empty.
- `image_digest`: caller-supplied CI value, not observed.
- `kernel`: observer `uname` release.
- `provider.build_id`: disk-ELF GNU build-id.
- window epochs/counters/reasons/status: observer clocks and state.

## 4. Observer-owned BPF map inventory

This fenced list is the checked-in inventory. Privacy tests and the
canary scanner parse this block; they must not carry another copy.

```text map-inventory
# harvest
EVENTS
PENDING_INIT
PENDING_QUERY
QUERY_NEXT
TRUNC
CALLS
TRIP
LGCALLS
ALG_CLASS
TRIP_CLASS
# count
COUNTS
GEN
TARGET
DROPFAIL
```

All maps hold numeric keys/values/counters/cursors except `EVENTS`,
which carries the ring structs in §2, and the two classifier
tables, which hold observer-owned registry bytes (populated from
the frozen registry/taxonomy at load, before any attach —
`ALG_CLASS`: hash → class/weak/name; `TRIP_CLASS`: hash →
engine/load class/name). No map stores target string bytes at rest.

## 5. Emitted artifacts

`inspect` JSON:

- provider/op/`alg_class`/`weak`/`status`/funcid/`addr_hash`/
  `addr_backed`/backing/gen/trigger/status/counters/reason
  (row `status` is the kernel read verdict: `ok`, `unknown`,
  `overlong`, or `truncated`).
- Optional `legacy` block: entry states, call counts, engine/load
  classes, weak rollup, tripwire capability, flags/findings.
- No raw provider/target strings. No runtime addresses.

`report` JSON and human output:

- `schema_version`, target pid/comm/cmdline/container/image,
  planned/actual window plus epoch edges, kernel, provider
  path/build-id, completeness status/reasons/counters, executions
  as cookie/provider/op/funcid/`alg_class`/offset/count/first/last
  plus aliases, adopted `legacy` block plus executed-weak rollup,
  fenced generations, `drain_wall_us`, optional `child_exit`.
- Human output renders the same fields plus fixed doctrine notes.
- Runtime addresses are absent; offsets are file offsets.

`check` JSON and human output:

- report document plus `policy`: verdict, rule results, violations,
  unseen deny providers, parameter-blind caveat, KAT caveat.
- Each violation carries rule/matcher/identity plus the same
  capture-level actionability tuple: window, cmdline, container,
  image, provider path/build-id.
- No verdict on fatal evidence.

CBOM:

- CycloneDX 1.6 `cryptographic-asset` components derived only from
  executed identities, provider object/build-id, op display names,
  counts, generation, window edges, and completeness.
- No key sizes, modes, primitives, parameters, or secret metadata.

`alias-audit`:

- groups input harvest rows by `addr_hash`; members carry only
  op/`alg_class`/funcid plus counts. Group keys are hashes.

`doctor`:

- target identity from observer reads: exe/libcrypto path, target
  and self UIDs.
- environment/target checks as id/status/message/remediation plus
  verdict/exit. Disk-ELF flavor/build-id/arch rows come from file
  bytes, never target memory.

stderr diagnostics:

- fixed labels plus allowlisted values: pids, counts, op/kind ids,
  table labels, statuses, reasons, paths, file offsets, and
  observer errors. Never target strings, string lengths, or
  runtime addresses — not even under debug flags.
- `HARVESTDBG` debug logs print already-classified records (op,
  slot, class, weak, status); they never print raw target strings.
- Errors may echo observer inputs such as paths and CLI options;
  they never carry target memory.

## 6. Not captured

v1 does not capture OSSL_PARAM keys/values, property strings,
verbatim algorithm names, key/IV/plaintext/ciphertext/AAD/tag/salt/
password/seed bytes, KEM secrets, KDF/RAND/signature/digest outputs,
`EVP_PKEY` buffers, bignum limbs, PEM/DER/PKCS#12 bytes, error
strings, or TLS payloads.

The P1-0 digest/mdname value-allowlist proposal is explicitly
deferred for v1. There is no int-arg/value capture in v1; any future
value capture needs per-key-set approval, exact key/shape gates, and
its own canary lanes.

## 7. Change rule

A new probe read, map, emitted field, classifier, debug print of
target-derived data, or userspace target-memory read requires an
allowlist update plus tests. A registry or taxonomy change requires
re-checking the kernel table capacities, the hash collision-freedom
pins, and the classifier-agreement corpus in the same commit. A
canary sentinel in any emitted artifact, log, ring payload, or
listed live map is a release blocker; sentinel inputs must surface
only as `other`/unreadable classified evidence (the positive
control that the read sites fired).
