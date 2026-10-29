<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Matched development packages

The current builder constructs a prefix tarball, DEB and RPM containing the CLI
and all five BPF roles from one clean pinned build. These are development
candidates. Construction and extraction do not establish installed platform,
reproducibility, final conveyance-rights or release qualification.

Build from a reviewed clean product checkout:

```sh
./scripts/build-dev.sh --release --offline
python3 packaging/build-package.py --source-archives /path/to/source-archives --output dist/current
# dist/current: prefix tarball, DEB, RPM, product source tar, accompanying-source bundle, package-manifest.json
```

The output directory must be new; existing output is refused. The builder never
installs software, changes privileges, acquires dependencies or starts workloads.
It requires Python 3.11+, the pinned Cargo toolchains, cached locked dependency
metadata and the original source archives described below. DEB construction
additionally needs `dpkg-deb`; RPM needs `rpmbuild`.
No Cargo compilation or network access occurs inside packaging.

A full clean `build-dev.sh --release` manifest must record the current source
revision/tree, pinned toolchains/linker, CLI and exact five-role membership,
per-artifact source identity, nonzero bytes, hashes and compatible ELF headers.
Missing, duplicate, stale or mixed roles refuse construction. Old manifests
without source-tree identity or build-time runtime-source binding, host-only
builds and bare CLI paths cannot create current packages. This is a trusted local recipe/manifest contract, not a signed
attestation against a malicious builder.

Select formats and the final tar installation prefix explicitly:

```sh
python3 packaging/build-package.py --source-archives /path/to/source-archives \
  --formats tar --prefix /opt/osslscope --output dist/prefix
./packaging/build-deb.sh --source-archives /path/to/source-archives --output dist/deb
RPM_RELEASE=2 ./packaging/build-rpm.sh --source-archives /path/to/source-archives --output dist/rpm
```

`--revision N`, `DEB_REVISION` and `RPM_RELEASE` select a positive numeric package
revision for lifecycle controls. DEB/RPM require `/usr`. Tar receipt paths bind
the selected prefix: extract into that exact protected prefix; relocation
requires rebuilding the package receipt. Do not extract over an existing
installation. Version comes from `Cargo.toml`; the builder does not bump it.

The shared prefix tree contains:

- `bin/osslscope` (0755).
- `lib/osslscope/osslscope-{harvest,count,members,provider-observation,focused-count}` (0644).
- `share/osslscope/install-manifest.json` (0644).
- `share/doc/osslscope/`: installation/licensing documentation, project license
  texts, actual locked host/BPF dependency graphs and copied dependency notices,
  Rust/runtime notices and source-availability metadata binding the product
  source tar and accompanying-source bundle.

DEB/RPM install this tree below `/usr`, owned by root with protected directories.
The current receipt binds the CLI and all five role hashes and source reference.
Normal installed companion resolution refuses a missing, historical, mixed or
mutated set before object loading. Under privileged invocation it also verifies
root-owned, non-writable ancestry/files. Ownership remains the trust root;
root-authorized replacement of both receipt and artifacts is outside this check.
Explicit object overrides retain their documented operator-trust behavior.
Historical embedded bundle contract parsing and executors remain separate.

## Source and notices

`osslscope-<version>-source.tar` is the exact tracked product revision, including
both lockfiles and recipes. `dependency-notices.json` inventories both actual
locked resolved Cargo graphs, with crate source URLs/checksums, declared license
expressions, dependency edges and copied applicable notice texts. These resolved
graphs include build/test/target dependencies and are broader than the final
linked code. Four BPF Aya crates omit license files from their registry tarballs;
[the restoration index](notices/restored.json) pins each archive checksum and
published VCS revision to both upstream license texts. The MIT distribution
option is recorded explicitly, retaining the upstream dual-license declaration.
Package construction validates these pins without network access.

`--source-archives` is required. Supply the original `.crate` files selected by
both **current** locked resolved graphs and the reviewed runtime inputs in
[runtime-sources.json](runtime-sources.json): two official rust-src components
and the bounded host standard-library crate superset. Filenames are the official
archive basenames. Every byte is checked against the live lock checksums or
reviewed runtime hashes; missing, changed or stale inputs refuse construction.
Rust component revisions must also match the installed pinned compilers. The
normal build records a canonical relative-file/length/hash identity for every
installed nightly library source file before and after compilation. It refuses
source changes during the build and binds the stable identity to the exact five
BPF artifact hashes. Packaging requires that receipt and compares the recorded
source identity to the supplied official component, including missing/extra
files. Restoring installed sources after a modified-source build cannot change
its recorded identity. Old manifests require rebuilding. This remains a trusted
local recipe/manifest contract, rather than malicious-builder attestation.
There is no download fallback, frozen project dependency list or compiler archive.

`osslscope-<version>-accompanying-source.tar.gz` contains the exact product
archive, original source payloads, dependency graphs, license/notice texts and a
[usable source build recipe](SOURCE-README.md). `source-manifest.json` binds
every payload hash to the current product revision/tree and exact six binary
artifact hashes. All package formats install the same runtime notices,
`accompanying-source-manifest.json` and source-availability metadata naming and
hashing the sidecar bundle. Preserve that sidecar and `package-manifest.json`
alongside every binary download under this source-accompaniment route; no
written offer or future human source service is inferred.

The preparation helper validates the payload and creates an ordinary Cargo
`vendor/` source replacement for both workspaces without a registry index.
Installed pinned compilers, bpf-linker and ordinary system development/runtime
prerequisites remain external. Runtime originals preserve the full
compiler_builtins conjunctive expression and LLVM exception, Unicode permission
texts, library copyright inventories and the reviewed native-runtime notices.
Read the recipe for the precise source boundary and tool prerequisites.

Payload construction/extraction alone does not establish an offline build,
byte-identical reproducibility, installed runtime qualification or final
conveyance-rights review. Original terms grant permissions; metadata grants
none. No upload/tag/publish occurs during builds.

## Capability lifecycle

DEB `postinst configure` applies `cap_bpf,cap_perfmon+ep`; `prerm` removes caps
only for `remove|deconfigure`, preserving upgrade behavior. RPM `%post` applies
caps, `%preun` clears only for erase (`$1 == 0`), and `%posttrans` restores caps
after the old package's scriptlets. This retains migration handling for older
unguarded `%preun` scripts. Missing/denied `setcap` produces a labeled-sudo
remediation and leaves the transaction successful; `doctor` reports the limit.
RPM's build must not strip or mutate receipt-bound prebuilt bytes. Its CLI file
entry declares the same capabilities in RPM metadata, so `rpm -V` verifies the
intended capability state. RPM installation requires filesystem/filecap support;
the existing scriptlets retain upgrade and old-scriptlet recovery behavior.

On an authorized qualification host, install the selected package with `dpkg -i`
or `dnf install`, then run ordinary-user `osslscope doctor`, `scan`, `report` and
`check` against independent workload truth. Privilege, upgrade/reinstall,
remove/purge, old-scriptlet migration, interruption, disk exhaustion and rollback
controls remain required. The historical `tests/guest-lifecycle.sh` builds the
old CLI-only archive recipe and is not the current five-role acceptance runner.

Host controls (no root):

```sh
python3 packaging/tests/test-current-package.py
python3 packaging/tests/test-source-payload.py
python3 scripts/tests/test-runtime-source-binding.py
./packaging/tests/test-scriptlets.sh
./scripts/tests/test-install-dev.sh
```

Synthetic ELF staging and scriptlet fixtures do not qualify installed runtime
behavior. Repeated construction from one build is also not a clean double-build
reproducibility result.


Check the actual constructed RPM's capability header without installing it:

```sh
python3 packaging/tests/test-rpm-metadata.py dist/current/osslscope-*.x86_64.rpm
```

This header check does not establish installed filecap behavior; verify the real
installation with `getcap /usr/bin/osslscope` and `rpm -V osslscope` on the
qualification host.
