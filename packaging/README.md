<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Packaging (deb + rpm)

> Development status: packages built from this branch are
> development snapshots, not final distributables. BPF objects are
> always operator-built (see [build](../docs/build.md)) and are never
> shipped in a package; distribution paperwork stays a separate,
> later decision that does not block local capture development.

File-caps default install: both packages ship the `osslscope` binary
plus `docs/install.md`, and a post-install hook grants
`CAP_BPF`+`CAP_PERFMON` file capabilities so the tool runs
unprivileged. The BPF objects (`--object`/`--count-object`) and the
`tests/goldens/` fixtures stay out of the packages: objects are
operator-built (nightly, see the project README) and passed by
flag; goldens are test-only.

Package contents:

- `/usr/bin/osslscope`
- `/usr/share/doc/osslscope/install.md`

The version is read from `Cargo.toml` `[package] version` at build
time, never hardcoded.

## Capability lifecycle across upgrade

Ordinary-user file capabilities must survive install, reinstall,
upgrade, and removal (removal takes the caps with the binary).

- deb: `postinst configure` applies caps; `prerm` only matches
  `remove|deconfigure`, so the `upgrade` call leaves caps alone.
- rpm: `%post` applies caps; `%preun` is erase-only (`$1 == 0`) so
  upgrades skip cleanup; `%posttrans` re-applies caps idempotently
  at the end of every install/upgrade transaction. The `%posttrans`
  step is the migration path: upgrading *from* the 1.0.0 package
  still runs that package's old unguarded `%preun` *after* the new
  `%post`, which would strip the new binary's caps — guarding only
  the new `%preun` cannot prevent the old script from running.

Every scriptlet warns with a labeled-sudo fallback and exits 0 when
`setcap` is missing or denied; a missing tool never fails the
transaction. `doctor` repeats the remediation.

## deb

Prerequisites: a cargo-built release binary, `dpkg-deb`.

```sh
cargo build --locked --release
./packaging/build-deb.sh            # or: ./packaging/build-deb.sh /path/to/osslscope
# -> osslscope_<ver>-1_amd64.deb
sudo dpkg -i osslscope_<ver>-1_amd64.deb
# NB: dpkg alone does not resolve Depends; if libcap2-bin is missing:
sudo apt-get install -f
```

The control file is `packaging/deb/DEBIAN/control.in`
(`@VERSION@`/`@REVISION@` substituted at build; `DEB_REVISION`
overrides the revision for upgrade-path testing, default 1);
`postinst` applies `setcap cap_bpf,cap_perfmon+ep` with a
labeled-sudo fallback note on failure; `prerm` clears caps
best-effort on removal only.

## rpm

Prerequisites: a cargo-built release binary, `rpmbuild`.

```sh
cargo build --locked --release
./packaging/build-rpm.sh            # or: ./packaging/build-rpm.sh /path/to/osslscope
# -> ~/rpmbuild/RPMS/x86_64/osslscope-<ver>-1.<dist>.x86_64.rpm
sudo dnf install ./osslscope-<ver>-1.*.x86_64.rpm   # pulls libcap via Requires
```

The spec is `packaging/rpm/osslscope.spec`. It takes the version as
an rpmbuild define (`--define "pkg_version <ver>"`, supplied by
`build-rpm.sh` from `Cargo.toml`) and installs a prebuilt binary —
no cargo/network inside the rpm build. `%post`/`%preun`/`%posttrans`
mirror the deb hooks with the upgrade semantics above.
`RPM_RELEASE` overrides the release for upgrade-path testing
(default 1): build the old tree with `RPM_RELEASE=1` and the new
tree with `RPM_RELEASE=2` at the same version.

## Tests

Host-runnable, no root (also run by the `packaging` CI job):

```sh
./packaging/tests/test-scriptlets.sh   # scriptlet argument matrix with stub setcap
./scripts/tests/test-install-dev.sh    # local prefix layout + diagnostics
```

Privileged lifecycle witness (prepared, NOT-RUN without an approved
guest — dry-run by default):

```sh
./packaging/tests/guest-lifecycle.sh --pkg rpm --old-ref <1.0.0-ref> --new-ref <rev>
./packaging/tests/guest-lifecycle.sh --pkg rpm --old-ref <1.0.0-ref> --new-ref <rev> --execute
```

`--execute` builds both packages from clean refs, then asserts
`getcap` keeps `cap_bpf+cap_perfmon` across install, upgrade,
reinstall, and that removal cleans up. It runs only on the approved
`installed`-suite lane.
