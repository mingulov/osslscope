# Changelog

## Unreleased — P4 privacy hardening

- `docs/privacy/allowlist-v1.md`: finalized capture allowlist (complete
  eBPF/userspace emission set, BPF map inventory, classifiers, change
  rule) with `tests/privacy_allowlist.rs` pins.
- `HARVESTDBG` now logs classified alg classes, never raw provider
  names.
- Test-only `OSSL_CANARY_DUMP` ring tap for the P4 canary suite
  (capped raw-payload dump, never enabled in production).
- P4 canary fixtures: `secret_driver` (sentinel buffers through
  digest/sign/cipher/MAC/KEM/KDF/RAND/password/salt/propquery
  paths, threaded stack lanes) and `sentinel` provider (hostile
  alg names + 264-entry overlong array).

## Unreleased — P3 semantics + policy

- `report`: bounded-window execution counts (human + `observed-crypto-v1.0`
  JSON, byte-stable), legacy-path section, PARTIAL taxonomy (blind vs
  clean), exit codes 0/3/4 (+1 child failure, 2 usage), 30 s default
  window, `--cbom FILE` CycloneDX 1.6 export.
- `check`: CI policy gate (6 rules: require/deny-provider, deny-engine,
  deny-algorithm, deny-weak, require-executed) with exit 10 on violation
  and per-violation actionability tuple (window/cmdline/container/image/
  provider build-id).
- `schemas/observed-crypto-v1.json` + reader compat (`v1.x` accepts,
  other majors reject); 16 report/CBOM goldens; `--help` everywhere.
- Capture: legacy blind-spot PARTIAL wiring, wall-clock window edges,
  cmdline/container/build-id identity, signal-graceful drain (exit 3).

## P2 capture engine (gated)

- Keyed exactness (hotkey 100k), fenced remaps/re-harvest, bounded
  windows, no-eviction DROPFAIL discipline, wall-clock budgets,
  trigger matrix, allowlist draft, capture-semantics record.

## P1 discovery (gated)

- Privilege model + pid pinning, OSSL_TRACE gap matrix, frozen
  registries, libcrypto flavor classifier, `inspect --pid/--builtin`,
  built-in harvest with dumper parity, legacy tripwire design.

## Unreleased — P1-0 scaffolding

- Workspace layout (`src/`, `crates/{ossl-discover,manifest,ebpf-common,bpf-sys,ebpf}`)
  with pinned toolchains (host 1.88.0, eBPF nightly-2026-05-20 + rust-src).
- CLI skeleton (`doctor/inspect/report/check` dispatch; subcommands land per phase).
- Discovery fixtures promoted into `crates/ossl-discover/tests/fixture/`.
- Frozen registries (`src/kinds.rs` v1): 14 ops, 280 funcids, 132 ENGINE
  symbols + 6 `*_meth_new`, 13 fetch entry points, 13 SKEY fns, 14
  low-level families, weak-alg list, 4 struct shapes — all
  version-keyed from 3.0/3.5/3.6/4.0 headers and lane dynsyms.
- libcrypto flavor classifier (`discovery/flavor.rs`): OpenSSL 3.x/4.x
  vs BoringSSL/AWS-LC lookalikes from ELF bytes.
- R12 layout asserts (`layout_assert.c`) green on all four versions.
- `inspect --pid` discovery (P1 exit 1): 625-name algorithm registry,
  class-only emission, per-lane goldens (`tests/goldens/`).
- Built-in provider harvest (P1 exit 2): `inspect --builtin` resolves
  the core-static query fn via a frozen build-id table with
  symtab and dynsym-anchor+delta fallback rungs; array-mapped
  attribution across providers sharing the core wrapper (anonymous
  runtime-built arrays attributed by implementation; cross-provider
  twin dedup arbitrated arrival-order-free); containing-file
  relocation for shared-code rows; PARTIAL docs with coverage
  counters (`queries_observed`, `zero_row_ops`, `foreign_rows_dropped`,
  `uninstrumented_ops`) and a frozen reason vocabulary; `alias-audit`
  grouping by implementation hash. Gate: 100% dumper parity on
  3.0/3.5/4.0 incl. stripped libs, forced/natural shift cells go
  PARTIAL with zero rows, per-lane goldens.

## Initial scaffolding

Repository created. Scope defined: eBPF-based runtime proof of executed
OpenSSL provider dispatch callbacks. No implementation yet.
