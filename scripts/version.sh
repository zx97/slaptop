#!/usr/bin/env bash
# Print the project version, read from the single place it lives in.
# Usage: scripts/version.sh [--tag]   (--tag prefixes with "v")
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(sed -n 's/^project(slaptop VERSION \([0-9.]*\).*/\1/p' "$ROOT/CMakeLists.txt" | head -n1)"
[ -n "$VERSION" ] || { echo "cannot read the version from CMakeLists.txt" >&2; exit 1; }
if [ "${1:-}" = "--tag" ]; then
    echo "v$VERSION"
else
    echo "$VERSION"
fi
