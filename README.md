# osslscope

Prove which OpenSSL crypto implementations actually execute in a running
Linux application — provider, operation, algorithm, and the dispatch
callback that ran — **without changing the application or its
configuration**.

`osslscope` is planned as a non-interposing OpenSSL execution observer
built on eBPF uprobes. It traces the provider architecture down to the
actually executed `OSSL_DISPATCH` implementation callback, so a
migration or audit can distinguish what merely *could* run from what
*really* ran:

```text
installed
    ≠ loaded
    ≠ advertised by provider
    ≠ fetched
    ≠ selected
    ≠ EXECUTED
```

> **Status: P3 semantics + policy done (report/check/CBOM work end to end).**
> Stack: Rust 1.88 + Aya 0.14 (raw multi-link primary) — confirmed at the P0 gate.
> Specs appear under `docs/`; see `docs/README.md`.

## Why

- **Migration verification** — "We moved this app to PQC. Is it really
  performing ML-KEM / ML-DSA, or is some old RSA/ECDSA/ECDH path still
  executing somewhere?"
- **Runtime crypto inventory / CBOM** — which (operation, algorithm,
  provider) triples execute, with counts (success/error split only if P2 proves a cheap path).
- **Legacy-path detection** — "You think the app migrated to providers,
  but this code path still drops into an old `ENGINE` or the legacy
  provider." (OpenSSL 3.x; `ENGINE` was removed in 4.x.)

Built-in `OSSL_TRACE` cannot answer these: it needs app cooperation,
ships inert on stock builds, and never proves per-call execution.
See [the side-by-side gap matrix](docs/trace-gap.md).

## Build

Prerequisites: Linux x86-64, kernel ≥ 6.9, Rust 1.88 (pinned by
`rust-toolchain.toml`) plus nightly-2026-05-20 with `rust-src` for
the eBPF object.

```sh
cargo build --locked
(cd crates/ebpf && cargo +nightly-2026-05-20 build -Z build-std=core \
    --target bpfel-unknown-none --release \
    --bin osslscope-harvest --bin osslscope-count)
```

This produces the two BPF objects `report`/`check` need via flags:

- `--object crates/ebpf/target/bpfel-unknown-none/release/osslscope-harvest`
- `--count-object crates/ebpf/target/bpfel-unknown-none/release/osslscope-count`

First run (one-time setup, then least-privilege runs):

```sh
sudo setcap 'cap_bpf,cap_perfmon=ep' target/debug/osslscope
./target/debug/osslscope doctor   # preflight; must print verdict: ok
```

Observe a command (30 s default window, human report):

```sh
./target/debug/osslscope report --provider /path/to/provider.so \
    --object <harvest above> --count-object <count above> \
    run -- my-app --serve
```

Gate a window in CI (exit 10 on violation; `--help` lists all rules):

```sh
./target/debug/osslscope check --provider /path/to/provider.so \
    --object <harvest> --count-object <count> \
    --deny-weak --deny-provider legacy --format json --out gate.json \
    run -- my-app --smoke-test
echo $?  # 0 clean · 10 violation · 3 PARTIAL · 4 environment · 2 usage
```

Installable packages (deb/rpm) land with the release.

## What it will NOT do

No `SSL_read`/`SSL_write` tracing, no TLS handshake observation, no
cipher-suite inventory, no PCAP, no network tracing, no generic libssl
observability — and no secrets: never plaintext, keys, passwords, or
application payloads.

## License

MIT OR Apache-2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.
