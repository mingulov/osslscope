<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Build from source

Build the v0.3.0 source candidate for Linux x86-64 using pinned host/BPF
toolchains and locked dependencies. It is not released. Compilation and pure
object preparation are separate from installed verifier/runtime qualification;
see [candidate gates](release-v0.3.0.md). The historical exact-profile diagnostic
is selected only with `--libcrypto`.

The host/common, BPF programs and independent BPF contract have distinct terms
and dependencies; see [component licensing](licensing.md).

The existing entrypoint builds the host CLI plus five BPF objects: harvest,
legacy count, members, provider-observation and focused-count. Normal tracing
uses the last two automatically; passive scan/inspect needs only the host CLI.

```sh
./scripts/build-dev.sh --check-only
./scripts/build-dev.sh
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
- `python3` (3.11 or newer), `sha256sum`, `file`, `readelf`.

Check what the script sees:

```sh
./scripts/build-dev.sh --check-only
```

which prints the product revision, both toolchains, the linker, both
target directories, and the job/network/mode selection.

## Selected modes

```sh
./scripts/build-dev.sh --host-only    # host workspace only
./scripts/build-dev.sh --bpf-only     # all five BPF objects only
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
ossl_archive_dir=$(mktemp -d)
git archive HEAD -o "$ossl_archive_dir/osslscope-src.tar"
mkdir "$ossl_archive_dir/source"
tar -x -f "$ossl_archive_dir/osslscope-src.tar" -C "$ossl_archive_dir/source"
cd "$ossl_archive_dir/source"
./scripts/build-dev.sh
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
- `osslscope-members` → `lib/osslscope/osslscope-members`
- `osslscope-provider-observation` → `lib/osslscope/osslscope-provider-observation`
- `osslscope-focused-count` → `lib/osslscope/osslscope-focused-count`

The objects land at:

- `target/debug/osslscope` (or `target/release/osslscope` with
  `--release`)
- `crates/ebpf/target/bpfel-unknown-none/release/osslscope-harvest`
- `crates/ebpf/target/bpfel-unknown-none/release/osslscope-count`
- `crates/ebpf/target/bpfel-unknown-none/release/osslscope-members`
- `crates/ebpf/target/bpfel-unknown-none/release/osslscope-provider-observation`
- `crates/ebpf/target/bpfel-unknown-none/release/osslscope-focused-count`

Confirm their identity with:

```sh
file target/debug/osslscope \
  crates/ebpf/target/bpfel-unknown-none/release/osslscope-harvest \
  crates/ebpf/target/bpfel-unknown-none/release/osslscope-count \
  crates/ebpf/target/bpfel-unknown-none/release/osslscope-members \
  crates/ebpf/target/bpfel-unknown-none/release/osslscope-provider-observation \
  crates/ebpf/target/bpfel-unknown-none/release/osslscope-focused-count
```

Expect an x86-64 ELF executable and five eBPF relocatables. The installer
consumes all five roles from a normal manifest. Normal report/check resolves the
observation/focused-count pair from the installed executable layout; privileged
invocation requires root-owned protected files and ancestors. See [install](install.md).
Legacy harvest/count/members do not replace the normal companion pair.

## Known linker warning

The BPF build may print a `bpf-linker` warning about a dlopen
fallback for a shared LLVM library. The build script detects this
exact warning, records it in the manifest `diagnostics` field, and
continues: the objects still link and are hash-verified. Do not
upgrade toolchains for it.

## Next step

Install the built tree into a local prefix with
`scripts/install-dev.sh` — see [install](install.md).

## Host regression setup

The retained host suites use owned temporary directories, serial tests and the
actual Cargo-built lifecycle host driver. These are existing test inputs, not
runtime dependencies of the CLI. The three deferred embedded-host
recompilation fixtures are opt-in:

```sh
cargo +1.88.0 test --locked --test package_contract -- --ignored
cargo +1.88.0 test --locked --lib package::dev::tests::identity_v2_real_producer_selected_retained_and_embedded -- --ignored
```

For the default suite, prepare the four inputs once for the current source:

```sh
OSSL_TEST_ROOT="$(mktemp -d)"
mkdir "$OSSL_TEST_ROOT/tmp" "$OSSL_TEST_ROOT/package"
export TMPDIR="$OSSL_TEST_ROOT/tmp"
export OSSL_PACKAGE_TEST_PRIVATE_DIR="$OSSL_TEST_ROOT/package"
export RUST_TEST_THREADS=1
cargo +1.88.0 test --locked --test lifecycle_producer_host --no-run --message-format=json > "$OSSL_TEST_ROOT/driver.jsonl"
export OSSL_LIFECYCLE_TEST_DRIVER="$(python3 -c 'import json,sys; a=[r["executable"] for line in open(sys.argv[1]) if (r:=json.loads(line)).get("reason")=="compiler-artifact" and r["target"]["name"]=="lifecycle_producer_host" and r.get("executable")]; assert len(a)==1; print(a[0])' "$OSSL_TEST_ROOT/driver.jsonl")"
cargo +1.88.0 fmt --all -- --check
cargo +1.88.0 check --workspace --locked
cargo +1.88.0 test --workspace --locked
cargo +1.88.0 clippy --workspace --locked -- -D warnings
```

Rebuild the driver after source changes. The enrolled-host metadata admission
control is separately opt-in; it reads metadata/namespaces and loads no BPF:
`cargo +1.88.0 test --locked --lib profile::tests::enrolled_host_metadata_admission -- --ignored`.
Live capture checks require an authorized supported host. CI builds all five
objects and explicitly selects the pure fresh-object preparation controls for
provider-observation and focused-count; those controls never load BPF. Neither
host tests nor object-shape success establish runtime/platform qualification.
