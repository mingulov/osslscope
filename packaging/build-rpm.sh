#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build osslscope-<ver>-1.<dist>.x86_64.rpm from a cargo-built release binary.
# Usage: ./packaging/build-rpm.sh [PATH_TO_BINARY]   (default: target/release/osslscope)
# Version is read from Cargo.toml at build time, never hardcoded.
set -eu
cd "$(dirname "$0")/.."
ver=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ -n "$ver" ] || { echo "build-rpm: cannot read version from Cargo.toml" >&2; exit 1; }
bin=${1:-target/release/osslscope}
[ -x "$bin" ] || { echo "build-rpm: binary not found: $bin (build with: cargo build --locked --release)" >&2; exit 1; }
command -v rpmbuild >/dev/null 2>&1 || { echo "build-rpm: rpmbuild not found" >&2; exit 1; }
top=${RPM_TOPDIR:-$HOME/rpmbuild}
mkdir -p "$top"/BUILD "$top"/RPMS "$top"/SOURCES "$top"/SPECS "$top"/SRPMS
st=$(mktemp -d)
trap 'rm -rf "$st"' EXIT INT TERM
mkdir -p "$st/osslscope-$ver"
cp "$bin" "$st/osslscope-$ver/osslscope"
cp docs/install.md "$st/osslscope-$ver/install.md"
tar -czf "$top/SOURCES/osslscope-$ver.tar.gz" -C "$st" "osslscope-$ver"
cp packaging/rpm/osslscope.spec "$top/SPECS/osslscope.spec"
rpmbuild -bb --define "pkg_version $ver" --define "_topdir $top" "$top/SPECS/osslscope.spec"
echo "built $(ls -t "$top"/RPMS/x86_64/osslscope-$ver-*.x86_64.rpm | head -1)"
