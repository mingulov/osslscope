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

> **Status: pre-implementation; scope defined, no code yet.** Stack: Rust + Aya proposed (owner: P0 phase gate).
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

## What it will NOT do

No `SSL_read`/`SSL_write` tracing, no TLS handshake observation, no
cipher-suite inventory, no PCAP, no network tracing, no generic libssl
observability — and no secrets: never plaintext, keys, passwords, or
application payloads.

## License

MIT OR Apache-2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.
