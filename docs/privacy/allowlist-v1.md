<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# osslscope capture allowlist v1

Rule: this is the complete set the eBPF programs and the userspace
capture path may emit. Anything not listed is a bug.

Scope: osslscope never captures crypto-derived secret bytes. The
allowlisted process/observer metadata below is not target memory, but
it can reflect operator input. Target argv is never copied into
evidence, logs, or debug output: spawn argv and `/proc/<pid>/cmdline`
both redact to the fixed `(argv-redacted)` placeholder, and v2
documents carry unconditional `argv_redacted: true` with no raw
argv/cmdline carrier anywhere. Operators must still not pass
secrets as target argv -- argv stays visible system-wide via
`/proc` regardless of what the observer retains.

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

There are exactly eleven target-memory reads. Only two move bytes, and
both land in kernel stack scratch that is classified in-kernel and
never emitted; the rest move fixed scalars. Chain-hop bodies (the
`def_hop!` arms, P5a-C2/C5) textually duplicate the entry slot sites
(verdict, names, impl, tail, name string) with identical classes,
bounds, and failure semantics — the pin counts textual sites, so it
runs ahead of this logical table without widening the surface.

| site | read | bound | purpose | failure |
|---|---|---|---|---|
| `init_return` | provider dispatch-table pointer | `u64` | stage-1 anchor | return, no event |
| `init_return` dispatch scan | function id | `u32` | find query operation | return, no event |
| `init_return` dispatch scan | function pointer | `u64` | find query operation | return, no event |
| `trip_str0`, `trip_str1` | engine/provider-load argument string | 32-byte NUL-bounded string | kernel trip verdict | explicit unreadable verdict, counter only on missing arg |
| `walk_dispatch` | dispatch function id | `u32` | per-alg dispatch walk | stop walk |
| `walk_dispatch` | dispatch function pointer | `u64` | per-alg dispatch walk | stop walk |
| `query_return` | caller `no_store` verdict | `u32` | provider lifetime (cacheable vs sample-once) | fail closed to `no_store` sample |
| `query_return` | algorithm `names` pointer | `u64` | alg-slot join key | abort slot, overflow bit (all slots) |
| `query_return` | algorithm `impl` pointer | `u64` | alg-slot join key | abort slot, overflow bit (all slots) |
| `query_return` | array tail slot | `u64` | overrun detection | overflow bit |
| `query_return` | algorithm `names` string | 128-byte NUL-bounded string | kernel registry verdict | explicit unreadable verdict, slot freeze, overflow bit (all slots) |

Kernel classification: the 128-byte alias window is split on `:`
(max 8 segments) and each segment is hashed (FNV-1a-64) and looked
up in the observer-populated `ALG_CLASS` table, matching on
hash+exact-length (no byte-compare confirm: it does not fit the
6.12 verifier budget — accepted 2^-64 accidental-collision
residual; within-table collisions stay impossible); the 32-byte
trip window is hashed and exactly confirmed against `TRIP_CLASS`.
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
- `RowEvent`: kind/op/funcid plus join addresses/index and the
  incarnation generation cookie; no name. 48 bytes
  (`KIND_QUERY_RET` liveness shares the shape).
- `AlgEvent`: kind/op plus class id, status, weak flag, the
  (array, index) join key, and the incarnation generation
  cookie. 40 bytes.
- `TripEvent`: kind/cookie plus class id and status. 16 bytes.
- `ScanCallEvent`: kind/op/tid plus hint+cause flags and the
  invocation seq. 24 bytes.
- `ScanRetEvent`: kind/op/flags/tid/seq plus the array id and
  incarnation generation cookie. 40 bytes.
- `GuardEvent`: kind/op/verdict/tid/seq plus the array id and
  incarnation generation cookie. 40 bytes.
- `ScanAlgEvent`: the `AlgEvent` harvest prefix byte-identical
  plus the (tid, seq) join key. 56 bytes.
- `ScanRowEvent`: the `RowEvent` harvest prefix byte-identical
  plus the (tid, seq) join key. 64 bytes.

No ring payload carries target string bytes, string lengths, or
string prefixes: the wire structs are too small to hold the read
windows, which the protocol tests pin by size. The scan-plane
join keys (tid, seq) are observer invocation ids, and the
harvest-prefix bytes obey the same numeric discipline as the
harvest kinds (kinds 10/11 share the prefix parsers' fail-closed
vocabulary — `scan_item4_wire_freeze`).

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

Workload output routing (not capture): a spawned workload's
stdout+stderr follow an explicit operator-chosen destination --
`/dev/null` by default, `--workload-out FILE` (create+truncate
per run), or `--workload-out-fd N` (a caller-held fd, validated
pre-fork with `fcntl(F_GETFD)`; the child never closes the
caller's descriptor). Explicit fd destinations intentionally
control workload routing: passing an observer-held fd (1/2)
routes workload bytes into that observer channel, which can
corrupt `--format json` or mix workload secrets into captured
diagnostics -- prefer null/default, a file, or an independent
fd (e.g. a harness pipe) to keep the channels separate.
Supported fds 1/2 are never silently rejected: parsing accepts
any non-negative integer, and only a fd that is not open fails
(a setup error before any spawn, never silent null).

Non-target provenance:

- `provider`: observer-chosen provider path stem, not target memory.
- `backing`: `/proc` maps plus disk ELF, not target memory.
- `offset`: file offset, stable across ASLR.
- `addr_hash`: one-way hash over the attested backing triple.
- `target.comm`: `/proc/<pid>/comm` task name.
- `target.argv_redacted`: unconditional `true`. Raw argv/cmdline
  has no carrier anywhere; where a cmdline-shaped string must
  render, the fixed `(argv-redacted)` placeholder is used
  (`inspect --marker` matches `/proc` cmdline at admission and
  likewise emits nothing).
- traversal tids: `/proc/<pid>/task` entry names (numeric tids for
  BIRTH registration; the backend reads directory names only —
  no target memory, and its map I/O touches only the §4
  observer-owned maps).
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
TERMD
LOSS
TRUNC
CALLS
TRIP
LGCALLS
ALG_CLASS
TRIP_CLASS
GEN
JUMPS
# count
COUNTS
GEN
TARGET
WINDOW
DROPFAIL
# members
EVENTS
GEN
LOSS
TRUNC
CALLS
ALG_CLASS
SCAN
SEQ
BIRTH
RCOUNT
T_CACHE
CTRL
ATTEMPT
BUCKET
TRUNC_SEQ
```

All maps hold numeric keys/values/counters/cursors except `EVENTS`,
which carries the ring structs in §2, and the two classifier
tables, which hold observer-owned registry bytes (populated from
the frozen registry/taxonomy at load, before any attach —
`ALG_CLASS`: hash → class/weak/name; `TRIP_CLASS`: hash →
engine/load class/name). No map stores target string bytes at rest.
`PENDING_QUERY` values are (op, `no_store`-pointer) pairs;
`TERMD`/`LOSS` are termination proofs and failure counters.
`JUMPS` (P5a-C1) holds kernel program fds (observer-loaded tail
callees, no target data — the chain jump table).
`WINDOW` holds the two observer-programmed monotonic window bounds
(start/deadline); like `GEN`/`TARGET` it is numeric observer state,
never target bytes. `GEN` exists in both objects with different
shapes (harvest: array base → incarnation generation, the
producer-bound ABA cookie; count: window generation); both are
observer counters. The `generation` cookie on ring records is
likewise numeric observer state. Generation diagnostics identify
tables by op id only — no diagnostic prints raw array addresses
(allowlist §2 rule; pinned by `no_raw_runtime_addresses_in_diagnostics`).

The members (traversal) object shares the `EVENTS`/`GEN`/`LOSS`/
`TRUNC`/`CALLS`/`ALG_CLASS` shapes above (same numeric discipline;
its `PENDING_QUERY` interim scaffold is dropped in stage D — R18
§6.1). The scan-plane maps hold numeric observer state only:
`SCAN` (one in-flight take record per thread: op,
`no_store`-pointer, seq, frozen EXPECTED/epoch — pointers are
stashed for the return-side read, never emitted), `SEQ`
(birth:16|ctr:48 invocation ids), `BIRTH` (registry births),
`RCOUNT` (count:32|lifecycle:32), `T_CACHE` (array → terminator +
generation, userspace-written — the writer is the item-4 backend
(integration commit); members peek it read-only and treat
GEN-mismatch as cold), `CTRL`
(EXPECTED/epoch/SKIP-ALL/governor occupancy bound), `ATTEMPT`
(entry-hit census), `BUCKET` (tid → tokens:8|last-refill:56 —
per-thread tier-1 rate state, numeric only), `TRUNC_SEQ`
(monotonic TRUNC flag-event generation — the drain-race guard,
numeric only). The entry plane reads
NO target memory (args + map cells only — the entry cannot see rv;
pinned by `probe_read_allowlist_is_complete`), so admission/skip
decisions never retain target bytes. Stage-D member reads (9 sites,
pinned): the slot tuple + dispatch + name (v1 shapes, same
bounds), the member-0 `no_store` verdict read (u32 → TRUNC flag,
never emitted), the would-skip-path `no_store` verdict re-read
(u32 → branch only — only a successfully-read zero skips; the
value is never retained past the branch), the T+1 boundary names
read (u64 → branch only — zero proves the terminator via an
explicit ALG_EMPTY, anything else cold-walks; the value is never
retained past the branch), and the guard's single
positional slot-512 names read (names-present verdict → GUARD
event only — no pointee content is read or emitted). Items 4–5 add
no read sites (scan kinds re-emit the walked bytes; the bucket
gate reads clock + cells only).

## 5. Emitted artifacts

`inspect` JSON:

- provider/op/`alg_class`/`weak`/`status`/funcid/`addr_hash`/
  `addr_backed`/backing/gen/trigger/status/counters/reason
  (row `status` is the kernel read verdict: `ok`, `unknown`,
  `overlong`, `truncated`, or `unreadable`).
- PARTIAL-only gap keys: `truncated_ops` (op → walk-shape bits),
  `unterminated_ops` (op ids without termination proof), `losses`
  (source name → failure count), `lossy_slots` (slots with lost
  identity). No array bases or runtime addresses.
- Optional `legacy` block: entry states, call counts, engine/load
  classes, weak rollup, tripwire capability, flags/findings.
- No raw provider/target strings. No runtime addresses.

`report` JSON and human output:

- `schema_version`, target pid/comm (`argv_redacted: true`)/container/image,
  requested/effective window edges, openssl state/version,
  completeness status/`fatal_kind`/reasons/counters, `sites` as
  object/device/inode/offset/generation/calls/first/last plus
  candidates, `fenced` generations in the same shape, `objects`
  (verified fingerprint plus display locator), per-scope
  `coverage`, the conserving `legacy_partition`, optional
  `context` (kernel release plus wall edges), and optional
  `disposition` (custody outcome, replacing `child_exit`).
- Optional `engine_observations` (R05, rendered only when observed):
  per-observation pinned caller-module triple (object fingerprint,
  encoded device, inode), stub file offset, binding generation,
  frozen-registry entrypoint index + display name, window
  (`in-window`/`pre-window`/`untimed`), untimed call count. No
  timestamps, no target strings, no runtime addresses.
- Human output renders the same fields plus fixed doctrine notes.
- Runtime addresses are absent; offsets are file offsets.

`check` JSON and human output:

- report document plus `policy`: `verdict` and `rules` (each rule
  carries rule/predicate names, a three-valued result, conserved
  definite/possible bounds, and site evidence refs).
- Each violation carries rule/matcher/identity plus the same
  capture-level actionability tuple: window, pid/comm/container,
  image, provider path/build-id. No cmdline: argv is redacted
  (see the Scope rule above). ENGINE-plane violations carry the
  observation key (object/device/inode/offset), generation,
  entrypoint index + name, untimed flag, and calls — the same
  allowlisted triple shape as sites, never raw addresses.
- Per-rule `engine_evidence` refs (R05, rendered only when present):
  the resolving observation key plus generation/entrypoint/calls.
- No verdict on evidence-free fatal documents (every fatal kind
  except salvaged `runtime`, which carries the evaluated
  verdict over its surviving observations).

CBOM:

- CycloneDX 1.6 `cryptographic-asset` components derived only from
  executed identities, provider object/build-id, op display names,
  counts, generation, window edges, and completeness.
- Optional engine metadata (R05, rendered only when observed):
  `osslscope:engine-observations` (count) and
  `osslscope:engine-in-window-calls` (count). Counts only, no
  identities.
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
