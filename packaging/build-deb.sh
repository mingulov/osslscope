#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Current matched five-role DEB, corresponding source and notices.
# Usage: packaging/build-deb.sh --output FRESH_DIR [--manifest FILE]
# DEB_REVISION selects the numeric revision for lifecycle controls.
set -eu
REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
exec python3 "$REPO/packaging/build-package.py" --formats deb --revision "${DEB_REVISION:-1}" "$@"
