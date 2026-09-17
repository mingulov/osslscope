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
- `walk_dispatch` is a BPF subprogram used by `query_return`.

There are exactly ten target-memory reads. Only two move bytes; the
rest move fixed scalars.

| site | read | bound | purpose | failure |
|---|---|---|---|---|
| `init_return` | provider dispatch-table pointer | `u64` | stage-1 anchor | return, no event |
| `init_return` dispatch scan | function id | `u32` | find query operation | return, no event |
| `init_return` dispatch scan | function pointer | `u64` | find query operation | return, no event |
| `trip_str0`, `trip_str1` | engine/provider-load argument string | 32-byte NUL-bounded string | cold identity class | return, counter only |
| `walk_dispatch` | dispatch function id | `u32` | per-alg dispatch walk | stop walk |
| `walk_dispatch` | dispatch function pointer | `u64` | per-alg dispatch walk | stop walk |
| `query_return` | algorithm `names` pointer | `u64` | alg-slot join key | abort slot, overflow bit only on slot 0 |
| `query_return` | algorithm `impl` pointer | `u64` | alg-slot join key | abort slot, overflow bit only on slot 0 |
| `query_return` | array tail slot | `u64` | overrun detection | overflow bit |
| `query_return` | algorithm `names` string | 128-byte NUL-bounded string | registry classification | abort slot, overflow bit only on slot 0 |

Ring payloads:

- `Event`: kind/op/funcid plus join addresses plus 128-byte name.
- `RowEvent`: kind/op/funcid plus join addresses/index; no name.
- `TripEvent`: kind/cookie plus 32-byte argument.

Addresses on the ring are join keys. Userspace converts them to
file-backed triples plus one-way hashes before emission. `inspect`
also retains the runtime address for debugging/attribution; runtime
addresses are ASLR-varying code pointers, not secret bytes. Report,
check, CBOM, and alias-audit outputs do not carry runtime addresses.

## 3. Userspace boundary

Target bytes cross into userspace only through the two bounded
string reads above. Both are classified and discarded at emission:

| input | classifier | emitted as |
|---|---|---|
| 128-byte algorithm names | exact registry match to `alg_class`, plus `weak` when any `:`-segment is registry-weak | `alg_class`, `weak` |
| 32-byte `ENGINE_by_id` argument | exact engine taxonomy | `dynamic`, `builtin`, or `other` counts |
| 32-byte provider-load argument | exact provider taxonomy | `legacy`, `default`, `fips`, or `other` counts |

Unknown, overlong, unterminated, unreadable, or hostile-aliased
input becomes `other`/unreadable plus counters. There is no partial
decode and no verbatim target string in any artifact, including
debug logs.

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
# count
COUNTS
GEN
TARGET
DROPFAIL
```

All maps hold numeric keys/values/counters/cursors except `EVENTS`,
which carries the ring structs in §2. No map stores target string
bytes at rest.

## 5. Emitted artifacts

`inspect` JSON:

- provider/op/`alg_class`/`weak`/funcid/`addr`/`addr_hash`/
  `addr_backed`/backing/gen/trigger/status/counters/reason.
- Optional `legacy` block: entry states, call counts, engine/load
  classes, weak rollup, tripwire capability, flags/findings.
- No raw provider/target strings.

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
  reasons, paths, and observer errors.
- `HARVESTDBG` debug logs classify names before printing; they
  never print raw target strings.
- Errors may echo observer inputs such as paths and CLI options;
  they never carry target memory.
- Test-only ring dump: `OSSL_CANARY_DUMP=path` appends raw ring
  payloads (capped at 32 MiB) for the canary suite's ringbuf scan.
  The dump holds raw target strings by design; it is never enabled
  in production and never replaces classified emission.

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
allowlist update plus tests. A canary sentinel in any emitted
artifact, log, ring dump, or listed live map is a release blocker.
