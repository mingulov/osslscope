<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Accompanying sources and build recipe

Keep `osslscope-<version>-accompanying-source.tar.gz` and
`package-manifest.json` alongside the matched binary downloads. Each binary
package's `share/doc/osslscope/source-availability.json` names and hashes that
source bundle. Its `accompanying-source-manifest.json` binds the product Git
revision/tree, CLI and five BPF artifact hashes, and every source payload file.
Use those hashes to select the source bundle for the binaries you received;
version numbers alone do not establish a match. This is source accompaniment,
with no written source offer or future human service commitment inferred.

The bundle contains the exact product source archive, both current locked
resolved Cargo graphs, original registry crate archives, the two pinned official
Rust library source components, a bounded host standard-library crate superset,
original notices and this recipe. Graph membership includes build, test and
other-target dependencies; inclusion does not prove code survived linking.
Project dependencies are derived anew from each checkout's lockfiles and Cargo
metadata. The reviewed Rust runtime pins are in `packaging/runtime-sources.json`.
Missing, altered or stale source inputs refuse package construction.

Verify the bundle's SHA256 against the accompanying package manifest or installed
source-availability metadata before extracting it into a new directory. From
that extracted directory, prepare a fresh source tree and Cargo directory source:

```sh
python3 source_payload.py --output ../rebuilt-sources
cd ../rebuilt-sources/product
```

The helper validates every payload length and hash before creating output. It
writes regular files only, materializes validated internal first-party file links,
rejects external links and dependency aliases, refuses an existing output
and writes `vendor/` and `.cargo/config.toml`. Both the host and detached BPF
workspace inherit this ordinary Cargo directory-source replacement, so a fresh
Cargo home does not need a registry index. Original `.crate` payloads and their
checksums remain available in the bundle. Do not modify either lockfile.
The four Aya BPF registry archives omit upstream license files; their exact-source
notice supplements remain in `notices/dependency-notices/` and the product's
`packaging/notices/`. Preserve those supplements with redistributed sources.

Install prerequisites separately: Rust/Cargo 1.88.0 for the host;
nightly-2026-05-20 with its matching rust-src component for BPF;
bpf-linker 0.10.4; an x86_64 GNU/Linux C toolchain and ordinary development
runtime; Python 3.11+, Git, shell and coreutils. The helper also unpacks both
Rust source components under `../rust-runtime/<toolchain>/`. To restore the
nightly component on an already installed pinned compiler, first check the
component installer's `--help` and verify the prefix, then explicitly install
only its source component if needed:

```sh
../rust-runtime/nightly-2026-05-20/rust-src-nightly/install.sh --help
rustc +nightly-2026-05-20 --print sysroot
../rust-runtime/nightly-2026-05-20/rust-src-nightly/install.sh \
  --prefix="$(rustc +nightly-2026-05-20 --print sysroot)" \
  --components=rust-src --disable-ldconfig
```

The preparation helper never changes installed toolchains. The host uses
the installed prebuilt std; this recipe does not bootstrap Rust or rebuild std.

With the pinned prerequisites available, the normal public entrypoints build and
install a modified or unmodified program:

```sh
# Optional: a fresh Cargo home demonstrates independence from your registry cache.
mkdir ../cargo-home
CARGO_HOME="$(cd ../cargo-home && pwd)" ./scripts/build-dev.sh --release --offline \
  --manifest target/rebuilt-build-manifest.json
./scripts/install-dev.sh --manifest target/rebuilt-build-manifest.json \
  --prefix /chosen/writable/prefix
```

`--offline` disables Cargo acquisition; installed compilers, bpf-linker and the
standard system tools remain prerequisites. Source-payload verification alone
is not proof that a build has run offline. An extracted archive has no Git
checkout; the normal build records null source identity. Do not fabricate Git
identity to pass the release package constructor. New binary packages require a
reviewed clean Git checkout and a fresh build/source receipt. This recipe does
not promise byte-identical reproduction or establish installed runtime behavior.

Rust source component root licenses, library copyright inventories, Unicode
permission texts, host-stdlib crate notices and original compiler-builtins terms
are preserved. Both compiler_builtins versions retain
`MIT AND Apache-2.0 WITH LLVM-exception AND (MIT OR Apache-2.0)`, including the
complete LLVM exception and per-file attribution; no blanket MIT election is
made. The Rust copyright inventories and official library source components are
cross-platform supersets, rather than exact maps of linked modules.

Ordinary compiler/linker implementations, system libraries, kernel and observed
OpenSSL implementations are external prerequisites. Standard C startup code may
be embedded; this boundary does not assert that every native runtime input is
dynamic. The native-runtime notices preserve original Ubuntu libc6-dev
2.43-2ubuntu2.4 and libgcc-15-dev 15.2.0-16ubuntu1 copyright/exception texts as a
reviewed standard-runtime reference. They do not prove exact per-object
contribution or cover a different platform automatically. In particular GCC
startup terms include the GCC Runtime Library Exception 3.1. Packaging on another
runtime requires reviewing its notices and source boundary. This bounded source
artifact does not archive the full compiler implementation or build machine.
Original terms grant the applicable permissions; packaging metadata grants none.
Final conveyance-rights review and release qualification remain separate gates.
