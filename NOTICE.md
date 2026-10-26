<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Source component notices

The root `osslscope` package, `ossl-bpf-sys`, `ossl-discover`,
`osslscope-ebpf-common` and `osslscope-manifest` declare version 0.1.0 and
GPL-3.0-or-later. Their license text is in [LICENSE](LICENSE).

`osslscope-ebpf` declares version 0.0.0 and GPL-2.0-only. The independent
`osslscope-bpf-contract` declares version 0.0.0 and GPL-2.0-or-later;
its GPL-2.0 option is selected for use with those BPF programs. The
[GPL-2.0 text](LICENSES/GPL-2.0-only.txt) applies to that option. The
contract retains its original GPL-2.0-or-later expression.

The source-only preview archive contains this project's source, fixtures,
catalogue metadata, schemas, documentation, scripts and both Cargo lockfiles.
It contains no prebuilt host/BPF binaries, vendored Rust dependencies, OpenSSL
library, kernel image or compiler/linker source bundle. Build prerequisites
and locked registry dependencies are obtained separately under their own terms.

These notices describe the source archive's first-party components. They are
not a transitive dependency/toolchain notice set for a later binary or vendored
distribution. Any separately conveyed dependency, tool source or binary needs
its applicable terms, notices and source availability reviewed for that
inventory. Declared SPDX expressions and hashes do not establish authorship
or conveyance rights.
See [the source license index](LICENSES/README.md) and
[licensing details](docs/licensing.md).
