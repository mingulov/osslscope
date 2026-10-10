#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build osslscope_<ver>-1_amd64.deb from a cargo-built release binary.
# Usage: ./packaging/build-deb.sh [PATH_TO_BINARY]   (default: target/release/osslscope)
# Version is read from Cargo.toml at build time, never hardcoded.
set -eu
cd "$(dirname "$0")/.."
ver=$(sed -n '/^\[package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ -n "$ver" ] || { echo "build-deb: cannot read version from Cargo.toml" >&2; exit 1; }
bin=${1:-target/release/osslscope}
[ -x "$bin" ] || { echo "build-deb: binary not found: $bin (build with: cargo build --locked --release)" >&2; exit 1; }
command -v dpkg-deb >/dev/null 2>&1 || { echo "build-deb: dpkg-deb not found" >&2; exit 1; }
st=$(mktemp -d)
trap 'rm -rf "$st"' EXIT INT TERM
chmod 755 "$st"
mkdir -p "$st/DEBIAN" "$st/usr/bin" "$st/usr/share/doc/osslscope"
sed -e "s/@VERSION@/$ver/" -e "s/@REVISION@/${DEB_REVISION:-1}/" packaging/deb/DEBIAN/control.in > "$st/DEBIAN/control"
cp packaging/deb/DEBIAN/postinst packaging/deb/DEBIAN/prerm "$st/DEBIAN/"
chmod 755 "$st/DEBIAN/postinst" "$st/DEBIAN/prerm"
cp "$bin" "$st/usr/bin/osslscope"
chmod 755 "$st/usr/bin/osslscope"
cp docs/install.md "$st/usr/share/doc/osslscope/install.md"
chmod 644 "$st/usr/share/doc/osslscope/install.md"
# DEB_REVISION overrides the debian revision (default 1) for upgrade-path
# testing: build the old tree with DEB_REVISION=1 and the new tree with
# DEB_REVISION=2 at the same version.
out="osslscope_${ver}-${DEB_REVISION:-1}_amd64.deb"
rm -f "$out"
dpkg-deb --build --root-owner-group "$st" "$out" >/dev/null
echo "built $out"
