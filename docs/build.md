<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Build from source

One reproducible entrypoint builds the host binary and both BPF
objects with pinned toolchains and locked dependencies:

```sh
./scripts/build-dev.sh --check-only   # prerequisites only; exit 0 here means ready
./scripts/build-dev.sh                # host + BPF; writes target/dev-build-manifest.json
```

The script never installs packages or moves toolchains. A missing
prerequisite fails with exit 3 and a manual install hint — an
environment condition, not a product regression. Every cargo
invocation passes `--locked`; the default network mode builds
`--offline` from the cargo cache and retries once online (locked set
only) on a cache miss. `CARGO_BUILD_JOBS` defaults to 2.

## Prerequisites

- Linux x86-64.
- Rust 1.88.0 (host) via rustup, plus nightly-2026-05-20 with the
  `rust-src` component (BPF `-Z build-std=core`).
- `bpf-linker` 0.10.4 on `PATH`.
- `python3`, `sha256sum`, `file`, `readelf`.

Check what the script sees:

```sh
./scripts/build-dev.sh --check-only
```

which prints the product revision, both toolchains, the linker, both
target directories, and the job/network/mode selection.

## Selected modes

```sh
./scripts/build-dev.sh --host-only    # host workspace only
./scripts/build-dev.sh --bpf-only     # both BPF objects only
./scripts/build-dev.sh --release      # host in release mode (BPF is always release)
./scripts/build-dev.sh --offline      # refuse any network; fail if the cache is incomplete
```

`--manifest PATH` redirects the manifest; `--jobs N` overrides the
job bound. Exit codes: 0 ok, 2 usage, 3 missing prerequisite,
1 build failure.

## Fresh-archive build

A source archive plus the prerequisites above must build without git
(the manifest then records a null product revision):

```sh
git archive HEAD -o osslscope-src.tar
rm -rf /tmp/ossl-build && mkdir /tmp/ossl-build
tar -x -f osslscope-src.tar -C /tmp/ossl-build
cd /tmp/ossl-build && ./scripts/build-dev.sh
```

## Lockfiles

Two committed lockfiles pin the two workspaces, and both cargo
invocations use `--locked`:

- `Cargo.lock` — host workspace (the BPF crate is excluded from the
  workspace by design).
- `crates/ebpf/Cargo.lock` — detached BPF workspace on the pinned
  nightly.

## Manifest and artifacts

`target/dev-build-manifest.json` records toolchain versions, the
product revision, per-artifact sha256/size/`file`/build-id identity,
the cargo log path, and the `install_layout` mapping that
`scripts/install-dev.sh` consumes:

- host binary → `bin/osslscope`
- `osslscope-harvest` → `lib/osslscope/osslscope-harvest`
- `osslscope-count` → `lib/osslscope/osslscope-count`

The objects land at:

- `target/debug/osslscope` (or `target/release/osslscope` with
  `--release`)
- `crates/ebpf/target/bpfel-unknown-none/release/osslscope-harvest`
- `crates/ebpf/target/bpfel-unknown-none/release/osslscope-count`

Confirm their identity with:

```sh
file target/debug/osslscope \
  crates/ebpf/target/bpfel-unknown-none/release/osslscope-harvest \
  crates/ebpf/target/bpfel-unknown-none/release/osslscope-count
```

expecting an x86-64 ELF executable plus two eBPF relocatables.

## Known linker warning

The BPF build may print a `bpf-linker` warning about a dlopen
fallback for a shared LLVM library. The build script detects this
exact warning, records it in the manifest `diagnostics` field, and
continues: the objects still link and are hash-verified. Do not
upgrade toolchains for it.

## Next step

Install the built tree into a local prefix with
`scripts/install-dev.sh` — see [install](install.md).
