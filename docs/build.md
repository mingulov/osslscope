<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Build from source

Build the v0.5.0 automatic observation candidate for Linux x86-64 using pinned host/BPF
toolchains and locked dependencies. Compilation and pure object preparation
are separate from installed verifier/runtime qualification; see the
[release qualification procedure](release-v0.4.0.md) (latest qualification
record; no v0.5.0 record exists yet). The historical exact-profile
diagnostic is selected only with `--libcrypto`.

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
- `bpf-linker` exactly 0.10.4 on `PATH` (BPF modes only;
  `--host-only` needs no linker). `--check-only` and the build
  share the prerequisite gate: a missing linker or any other
  version fails hard with exit 3 and an install hint — there is
  no silent fallback, because the wrong linker miscompiles the
  BPF objects.
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
./scripts/build-dev.sh --online       # allow network for every cargo call (locked set only)
```

`--manifest PATH` redirects the manifest; `--jobs N` overrides the
job bound. Exit codes: 0 ok, 2 usage, 3 missing prerequisite,
1 build failure.

Network modes (every cargo call passes `--locked` in all three):
`--offline` refuses any network and fails on a cache miss; `--online`
runs every cargo call with network allowed; the default (neither flag)
tries `--offline` first and retries once online on a cache miss only.
The manifest records the selected mode and which path was used.

Identity-v2 dev admission (full default mode only):

```sh
./scripts/build-dev.sh --identity-v2-inputs FILE --identity-v2-dir DIR
```

Both flags are required together and are refused with `--host-only`
or `--bpf-only`. `FILE` must name an existing inputs file; `DIR` is
created when missing but must be fresh — the script refuses a
directory that already holds `dev-admission.json`. The run freezes
custody plus the four identity BPF roles, builds the observer-only
host binary against them, and writes the dev admission
(`dev-admission.json`) under `DIR`; `OSSL_PACKAGE_RECORD_DIR` points
at `DIR` only for that host build.

`CARGO_TARGET_DIR` (or `build.target-dir`) is honored: cargo writes
where it points, and the script resolves both real target directories
through `cargo metadata` — `--check-only` prints them and the manifest
records them (`host_target_dir`, `bpf_target_dir`,
`cargo_target_dir_env`). Only the per-invocation cargo log capture
stays fixed under `<repo>/target/.cargo-log-*/`.

Ambient Rust flags are normalized, not honored: every cargo invocation
runs with `RUSTFLAGS`/`CARGO_ENCODED_RUSTFLAGS` blanked and unstable
host-config selection disabled, so ambient flags cannot redirect the
pinned sysroot or leak host options into the BPF link. The blanking is
load-bearing — `-C target-cpu=native` breaks the bpfel link and
`--sysroot ALT` would silently redirect compilation while the manifest
still binds the pinned source identity — so custom Rust flags are
outside this pinned recipe. Proof:
`scripts/tests/test-runtime-source-binding.py`
(`test_environment_build_and_target_flags_cannot_redirect_source`).

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

## OpenSSL compatibility controls

The v0.5 test matrix includes OpenSSL 3.0.x, 3.5.x and 4.x. Each lane uses its
matching CLI, libraries and provider modules. These are test inputs, not a
version or algorithm admission list. An absent newer API or algorithm is a
capability limit; it does not exclude the library from discovery or testing.
For example, OpenSSL 3.0 provides RSA-KEM library APIs while its CLI lacks the
later encapsulation command, so its KEM control needs an ordinary public-API
application.

On an authorized native tracing host, the ignored library test
`provider_observation::session::startup_api_controls::first_natural_stock_queries_survive_without_a_mapped_snapshot`
accepts `OSSLSCOPE_TEST_OPENSSL` (default `/usr/bin/openssl`) and inherits the
matching `LD_LIBRARY_PATH`. Set `OSSL_PROVIDER_OBSERVATION_TEST_BPF` to the
freshly built provider-observation object. Prepare the current test artifacts
as described above; run the selected libtest executable with the required
tracing privileges and an owned temporary directory.

The control runs unchanged SHA-512 and SHA3-256 commands and checks retained
natural query/advertisement facts after exit. It adds no getter or query calls
to the application. This is a startup metadata control; it does not establish
definite algorithm/provider execution, complete coverage or full compatibility.
Installed application workflows and the broader family/provider controls remain
separate release gates.


## Matched package construction

A clean full pinned release build can feed the current five-role
[package builder](../packaging/README.md). It requires all six artifact identities
and refuses mixed/stale source and bytes. It constructs the same protected prefix
tree for tar/DEB/RPM without reviving historical source-graph executors.
Corresponding product source, both resolved dependency graphs, license notices
and upstream source links accompany the development output. Final source/rights,
clean double-build and installed lifecycle qualification remain separate gates.
