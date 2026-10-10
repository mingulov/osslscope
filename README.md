<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# osslscope

Prove which OpenSSL crypto implementations actually execute in a running
Linux application -- provider, operation, algorithm, and the dispatch
callback that ran -- **without changing the application or its
configuration**.

`osslscope` is a non-interposing OpenSSL execution observer
built on eBPF uprobes. It traces the provider architecture down to the
actually executed `OSSL_DISPATCH` implementation callback, so a
migration or audit can distinguish what merely *could* run from what
*really* ran:

```text
installed
    != loaded
    != advertised by provider
    != fetched
    != selected
    != EXECUTED
```

> **Status: development (unreleased).** The tree is mid-continuation toward
> the v2 evidence contract (`docs/observed-crypto-v2.md`); the last
> packaged baseline is 1.0.0 and no packages built from this branch are
> final distributables. Build and install locally per
> [build](docs/build.md) and [install](docs/install.md).
> Stack: Rust 1.88 + Aya 0.14 (raw multi-link primary).
> Specs appear under `docs/`; see `docs/README.md`.

## Why

- **Migration verification** -- "We moved this app to PQC. Is it really
  performing ML-KEM / ML-DSA, or is some old RSA/ECDSA/ECDH path still
  executing somewhere?"
- **Runtime crypto inventory / CBOM** -- which (operation, algorithm,
  provider) triples execute, with entry-observed counts (no
  success/error split: v1 observes entry only).
- **Legacy-path detection** -- "You think the app migrated to providers,
  but this code path still drops into an old `ENGINE` or the legacy
  provider." (OpenSSL 3.x; `ENGINE` was removed in 4.x.)

Built-in `OSSL_TRACE` cannot answer these: it needs app cooperation,
ships inert on stock builds, and never proves per-call execution.
See [the side-by-side gap matrix](docs/trace-gap.md).

## Docs

- [What it proves (and what it does not)](docs/what-it-proves.md) --
  claim chain, non-goals, who should NOT adopt
- [Overhead and support matrix](docs/overhead-matrix.md) --
  budgets, worst-cell numbers, qualified platforms
- [CI gate recipes](docs/ci-recipes.md) --
  runner choice, gate wiring, timeouts, artifacts
- [PARTIAL runbook](docs/partial-runbook.md) -- per-reason response
- [Attach failures](docs/attach-failures.md) -- exit-4 decision tree
- [Violation triage](docs/violation-triage.md) --
  from violation to fix to re-verify
- [Auditor story](docs/auditor-story.md) --
  evidence to verdict, worked example
- [Staging deploy](docs/staging-deploy.md) --
  debug-container observation, gate-disable procedure
- [FIPS interim rule](docs/fips-interim.md) --
  manual triage with quantified rates
- [Promotion checklist](docs/promotion-checklist.md) --
  staging to production
- [Operator's guide](docs/usage.md) -- CLI usage for all commands
- [Build from source](docs/build.md) -- host + BPF entrypoint, manifests, lockfiles
- [Install](docs/install.md) -- local prefix and packages, file caps, doctor-first verify
- [Built-in provider runbook](docs/builtin-runbook.md) --
  stripped/unknown libcrypto
- [osslscope vs OSSL_TRACE](docs/trace-gap.md) -- gap matrix
- [Capture allowlist](docs/privacy/allowlist-v1.md) --
  what may be observed
- [Privacy residuals](docs/privacy/residuals.md) --
  what the guarantee does not cover

## Build and install (development)

Prerequisites: Linux x86-64, kernel >= 6.9, Rust 1.88 plus
nightly-2026-05-20 with `rust-src` and `bpf-linker` 0.10.4 — see
[build](docs/build.md). One entrypoint builds host + BPF:

```sh
./scripts/build-dev.sh                # writes target/dev-build-manifest.json
./scripts/install-dev.sh              # installs into $HOME/.local (default prefix)
```

First run (one-time setup, then least-privilege runs):

```sh
sudo setcap 'cap_bpf,cap_perfmon=ep' "$HOME/.local/bin/osslscope"
"$HOME/.local/bin/osslscope" doctor \
  --object "$HOME/.local/lib/osslscope/osslscope-harvest" \
  --count-object "$HOME/.local/lib/osslscope/osslscope-count"
# preflight; must print verdict: ok
```

The prefix layout is `$PREFIX/bin/osslscope` plus both BPF objects
under `$PREFIX/lib/osslscope/`. A user-owned prefix is never
trusted implicitly, so `report`/`check` (and `doctor`) need the
explicit flags below; only the same layout under a root-owned
system dir auto-resolves (see [install](docs/install.md)):

```sh
"$HOME/.local/bin/osslscope" report --provider /path/to/provider.so \
    --object "$HOME/.local/lib/osslscope/osslscope-harvest" \
    --count-object "$HOME/.local/lib/osslscope/osslscope-count" \
    run -- my-app --serve
```

Gate a window in CI (one rule minimum; `--help` lists all rules):

```sh
"$HOME/.local/bin/osslscope" check --provider /path/to/provider.so \
    --object <harvest above> --count-object <count above> \
    --deny-weak --deny-provider legacy --format json --out gate.json \
    run -- my-app --smoke-test
echo $?  # 0 clean, 10 violation, 11 inconclusive, 3 PARTIAL, 4 environment, 2 usage, 1 child/artifact failure
```

System packages (deb/rpm): build per
[packaging/README.md](packaging/README.md), then follow
[docs/install.md](docs/install.md) (doctor-first). Packages from
this branch are development snapshots, not final distributables.

## What it will NOT do

No `SSL_read`/`SSL_write` tracing, no TLS handshake observation, no
cipher-suite inventory, no PCAP, no network tracing, no generic libssl
observability -- and no secrets: never plaintext, keys, passwords, or
application payloads.

## License

Public license: GPL-3.0-or-later - see [LICENSE](LICENSE).
BPF sources: GPL-2.0-only - see
[LICENSES/GPL-2.0-only.txt](LICENSES/GPL-2.0-only.txt).

Per-file SPDX tags (`GPL-3.0-or-later` for userspace, docs, and scripts;
`GPL-2.0-only` for BPF programs) remove any ambiguity.
