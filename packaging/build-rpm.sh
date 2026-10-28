#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Current matched five-role RPM, corresponding source and notices.
# Usage: packaging/build-rpm.sh --output FRESH_DIR [--manifest FILE]
# RPM_RELEASE selects pkg_release via the current builder for lifecycle controls.
set -eu
REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
exec python3 "$REPO/packaging/build-package.py" --formats rpm --revision "${RPM_RELEASE:-1}" "$@"
