<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Packaging (deb + rpm)

File-caps default install: both packages ship the `osslscope` binary
plus `docs/install.md`, and a post-install hook grants
`CAP_BPF`+`CAP_PERFMON` file capabilities so the tool runs
unprivileged. The BPF objects (`--object`/`--count-object`) and the
`tests/goldens/` fixtures stay out of the packages: objects are
operator-built (nightly, see README) and passed by flag; goldens are
test-only.

Package contents:

- `/usr/bin/osslscope`
- `/usr/share/doc/osslscope/install.md`

The version is read from `Cargo.toml` `[package] version` at build
time, never hardcoded.

## deb

Prerequisites: a cargo-built release binary, `dpkg-deb`.

```sh
cargo build --locked --release
./packaging/build-deb.sh            # or: ./packaging/build-deb.sh /path/to/osslscope
# -> osslscope_<ver>-1_amd64.deb
sudo dpkg -i osslscope_<ver>-1_amd64.deb   # pulls libcap2-bin via Depends
```

The control file is `packaging/deb/DEBIAN/control.in`
(`@VERSION@` substituted at build); `postinst` applies
`setcap cap_bpf,cap_perfmon+ep` with a labeled-sudo fallback note on
failure; `prerm` clears caps best-effort.

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
no cargo/network inside the rpm build. `%post`/`%preun` mirror the
deb hooks.
