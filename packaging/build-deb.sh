#!/bin/sh
# Build osslscope_<ver>-1_amd64.deb from a cargo-built release binary.
# Usage: ./packaging/build-deb.sh [PATH_TO_BINARY]   (default: target/release/osslscope)
# Version is read from Cargo.toml at build time, never hardcoded.
set -eu
cd "$(dirname "$0")/.."
ver=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ -n "$ver" ] || { echo "build-deb: cannot read version from Cargo.toml" >&2; exit 1; }
bin=${1:-target/release/osslscope}
[ -x "$bin" ] || { echo "build-deb: binary not found: $bin (build with: cargo build --locked --release)" >&2; exit 1; }
command -v dpkg-deb >/dev/null 2>&1 || { echo "build-deb: dpkg-deb not found" >&2; exit 1; }
st=$(mktemp -d)
trap 'rm -rf "$st"' EXIT INT TERM
mkdir -p "$st/DEBIAN" "$st/usr/bin" "$st/usr/share/doc/osslscope"
sed "s/@VERSION@/$ver/" packaging/deb/DEBIAN/control.in > "$st/DEBIAN/control"
cp packaging/deb/DEBIAN/postinst packaging/deb/DEBIAN/prerm "$st/DEBIAN/"
chmod 755 "$st/DEBIAN/postinst" "$st/DEBIAN/prerm"
cp "$bin" "$st/usr/bin/osslscope"
chmod 755 "$st/usr/bin/osslscope"
cp docs/install.md "$st/usr/share/doc/osslscope/install.md"
chmod 644 "$st/usr/share/doc/osslscope/install.md"
out="osslscope_${ver}-1_amd64.deb"
rm -f "$out"
dpkg-deb --build --root-owner-group "$st" "$out" >/dev/null
echo "built $out"
