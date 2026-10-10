#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build osslscope-<ver>-1.<dist>.x86_64.rpm from a cargo-built release binary.
# Usage: ./packaging/build-rpm.sh [PATH_TO_BINARY]   (default: target/release/osslscope)
# Version is read from Cargo.toml at build time, never hardcoded.
set -eu
cd "$(dirname "$0")/.."
ver=$(sed -n '/^\[package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ -n "$ver" ] || { echo "build-rpm: cannot read version from Cargo.toml" >&2; exit 1; }
bin=${1:-target/release/osslscope}
[ -x "$bin" ] || { echo "build-rpm: binary not found: $bin (build with: cargo build --locked --release)" >&2; exit 1; }
command -v rpmbuild >/dev/null 2>&1 || { echo "build-rpm: rpmbuild not found" >&2; exit 1; }
top=${RPM_TOPDIR:-$HOME/rpmbuild}
# RPM_RELEASE overrides the package release (default 1) for upgrade-path
# testing: build the old tree with RPM_RELEASE=1 and the new tree with
# RPM_RELEASE=2 at the same version to exercise %preun/%posttrans ordering.
release=${RPM_RELEASE:-1}
mkdir -p "$top"/BUILD "$top"/RPMS "$top"/SOURCES "$top"/SPECS "$top"/SRPMS
st=$(mktemp -d)
trap 'rm -rf "$st"' EXIT INT TERM
mkdir -p "$st/osslscope-$ver"
cp "$bin" "$st/osslscope-$ver/osslscope"
cp docs/install.md "$st/osslscope-$ver/install.md"
tar -czf "$top/SOURCES/osslscope-$ver.tar.gz" -C "$st" "osslscope-$ver"
cp packaging/rpm/osslscope.spec "$top/SPECS/osslscope.spec"
rpmbuild -bb --define "pkg_version $ver" --define "pkg_release $release" \
  --define "_topdir $top" "$top/SPECS/osslscope.spec"
found=
# Pin the release just built: the shared RPMS dir may hold older releases,
# and a first-match glob would return a stale rpm (silently turning an
# upgrade witness into a reinstall of the old package).
for f in "$top"/RPMS/x86_64/osslscope-"$ver"-"$release".*.x86_64.rpm; do
  [ -f "$f" ] && { found=$f; break; }
done
[ -n "$found" ] || { echo "build-rpm: no rpm for $ver release $release under $top/RPMS" >&2; exit 1; }
echo "built $found"
