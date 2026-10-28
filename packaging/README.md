<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Matched development packages

The current builder constructs a prefix tarball, DEB and RPM containing the CLI
and all five BPF roles from one clean pinned build. These are development
candidates. Construction and extraction do not establish installed platform,
reproducibility, source/license closure or release qualification.

Build from a reviewed clean product checkout:

```sh
./scripts/build-dev.sh --release --offline
python3 packaging/build-package.py --output dist/current
# dist/current: prefix tarball, DEB, RPM, product source tar, package-manifest.json
```

The output directory must be new; existing output is refused. The builder never
installs software, changes privileges, acquires dependencies or starts workloads.
It requires Python 3.11+, the pinned Cargo toolchains and cached locked dependency
metadata. DEB construction additionally needs `dpkg-deb`; RPM needs `rpmbuild`.
No Cargo compilation or network access occurs inside packaging.

A full clean `build-dev.sh --release` manifest must record the current source
revision/tree, pinned toolchains/linker, CLI and exact five-role membership,
per-artifact source identity, nonzero bytes, hashes and compatible ELF headers.
Missing, duplicate, stale or mixed roles refuse construction. Old manifests
without source-tree identity, host-only builds and bare CLI paths cannot create
current packages. This is a trusted local recipe/manifest contract, not a signed
attestation against a malicious builder.

Select formats and the final tar installation prefix explicitly:

```sh
python3 packaging/build-package.py --formats tar --prefix /opt/osslscope --output dist/prefix
./packaging/build-deb.sh --output dist/deb
RPM_RELEASE=2 ./packaging/build-rpm.sh --output dist/rpm
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
  plus source-availability metadata binding the accompanying product source tar.

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

Product source plus upstream source links is not a complete offline corresponding
source bundle. Final compiler/sysroot/native-runtime inventory, complete source
availability and rights review remain release gates. Metadata passing and
restored notices grant no new rights. Preserve the source tar and package manifest
alongside the development packages. No upload/tag/publish occurs during builds.

## Capability lifecycle

DEB `postinst configure` applies `cap_bpf,cap_perfmon+ep`; `prerm` removes caps
only for `remove|deconfigure`, preserving upgrade behavior. RPM `%post` applies
caps, `%preun` clears only for erase (`$1 == 0`), and `%posttrans` restores caps
after the old package's scriptlets. This retains migration handling for older
unguarded `%preun` scripts. Missing/denied `setcap` produces a labeled-sudo
remediation and leaves the transaction successful; `doctor` reports the limit.
RPM's build must not strip or mutate receipt-bound prebuilt bytes.

On an authorized qualification host, install the selected package with `dpkg -i`
or `dnf install`, then run ordinary-user `osslscope doctor`, `scan`, `report` and
`check` against independent workload truth. Privilege, upgrade/reinstall,
remove/purge, old-scriptlet migration, interruption, disk exhaustion and rollback
controls remain required. The historical `tests/guest-lifecycle.sh` builds the
old CLI-only archive recipe and is not the current five-role acceptance runner.

Host controls (no root):

```sh
python3 packaging/tests/test-current-package.py
./packaging/tests/test-scriptlets.sh
./scripts/tests/test-install-dev.sh
```

Synthetic ELF staging and scriptlet fixtures do not qualify installed runtime
behavior. Repeated construction from one build is also not a clean double-build
reproducibility result.
