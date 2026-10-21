<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# osslscope

Observe which OpenSSL provider-dispatch callbacks execute in supported
Linux targets, with physical-site counts and explicit candidate
uncertainty -- **without changing the application or its configuration**.

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

> **Status: development (unreleased).** Current report/check output follows
> the [v2.1 evidence contract](docs/observed-crypto-v2.md). The historical
> tagged baseline is `v0.1.0`; 1.0.0 was an earlier unreleased label.
> Current integrated live and package qualification remains open, and
> packages built from this branch are development snapshots.
> Build and install locally per
> [build](docs/build.md) and [install](docs/install.md).
> Stack: Rust 1.88 + Aya 0.14 (raw multi-link primary).
> Specs appear under `docs/`; see `docs/README.md`.

## Why

- **Migration verification** -- "We moved this app to PQC. Is it really
  performing ML-KEM / ML-DSA, or is some old RSA/ECDSA/ECDH path still
  executing somewhere?"
- **Runtime crypto inventory / CBOM** -- physical callback entries with
  candidate (operation, algorithm, provider) identities. Counts are
  conserved once per site; CBOM assets require definite attribution.
  There is no success/error split.
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
  budgets, historical fixture results and qualification limits
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
  manual triage with historical self-test measurements
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
[build](docs/build.md). One entrypoint builds the host plus the
harvest, count and members BPF objects:

```sh
./scripts/build-dev.sh                # writes target/dev-build-manifest.json
./scripts/install-dev.sh              # installs into $HOME/.local (default prefix)
```

First run (one-time setup, then least-privilege runs):

```sh
sudo setcap 'cap_bpf,cap_perfmon=ep' "$HOME/.local/bin/osslscope"
"$HOME/.local/bin/osslscope" doctor \
  --object "$HOME/.local/lib/osslscope/osslscope-harvest" \
  --count-object "$HOME/.local/lib/osslscope/osslscope-count" \
  --members-object "$HOME/.local/lib/osslscope/osslscope-members"
# preflight; must print verdict: ok
```

The prefix layout is `$PREFIX/bin/osslscope` plus three BPF objects
under `$PREFIX/lib/osslscope/`. A user-owned prefix is never
trusted implicitly, so `report`/`check` (and `doctor`) need the
explicit flags below. Trusted system locations support automatic
selection. A fully automatic triple requires a matching install
receipt, not just three copied files. The implicit members role needs a
matching receipt; explicit roles are operator-trusted. Legacy
implicit harvest/count roles may be receiptless; when a receipt is
present, implicit roles must match it and stale/mismatched entries
refuse. Explicit members with a legacy receiptless implicit pair is
supported without receipt-backed matching provenance (see
[install](docs/install.md)). Deliberate harvest/count-only installs
remain valid without traversal:

```sh
"$HOME/.local/bin/osslscope" report --provider /path/to/libcrypto.so.3 --builtin \
    --object "$HOME/.local/lib/osslscope/osslscope-harvest" \
    --count-object "$HOME/.local/lib/osslscope/osslscope-count" \
    --members-object "$HOME/.local/lib/osslscope/osslscope-members" \
    run -- my-app --serve
```

Gate a window in CI (one rule minimum; `--help` lists all rules):

```sh
"$HOME/.local/bin/osslscope" check --provider /path/to/libcrypto.so.3 --builtin \
    --object "$HOME/.local/lib/osslscope/osslscope-harvest" \
    --count-object "$HOME/.local/lib/osslscope/osslscope-count" \
    --members-object "$HOME/.local/lib/osslscope/osslscope-members" \
    --deny-weak --deny-provider legacy --format json --out gate.json \
    run -- my-app --smoke-test
echo $?  # see docs/usage.md: 10 violation dominates; 1 also covers usable fatal evidence
```

Explicit traversal requires a resolved builtin query anchor. For
file-provider mode (`--provider /path/to/provider.so`, no `--builtin`),
omit `--members-object`; automatic installed selection can retain
the triple's provenance while using harvest-only discovery.

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
