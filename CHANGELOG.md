# Changelog

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

## Initial scaffolding

Repository created. Scope defined: eBPF-based runtime proof of executed
OpenSSL provider dispatch callbacks. No implementation yet.
