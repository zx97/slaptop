#!/usr/bin/env bash
# Build the release artefacts locally, the same way the CI does:
#   dist/slaptop-<version>-linux-<arch>.tar.gz
#   dist/slaptop_<version>-1_<debarch>.deb      (when nfpm is available)
#   dist/slaptop-<version>-1.<rpmarch>.rpm      (when nfpm is available)
#   dist/SHA256SUMS
#
# The binary is the portable one: notcurses, libunistring and libdeflate are
# linked in, libldap stays dynamic (that is what keeps SASL EXTERNAL and
# ldaps:// working).  scripts/build-static.sh does the compiling.
#
# Usage: packaging/build-local.sh [--no-nfpm] [work-dir]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WITH_NFPM=1
if [ "${1:-}" = "--no-nfpm" ]; then
    WITH_NFPM=0
    shift
fi
WORK="${1:-/dev/shm/slaptop-portable}"

VERSION="$(scripts/version.sh)"
case "$(uname -m)" in
    x86_64|amd64)  TAR_ARCH=amd64; DEB_ARCH=amd64; RPM_ARCH=x86_64 ;;
    aarch64|arm64) TAR_ARCH=arm64; DEB_ARCH=arm64; RPM_ARCH=aarch64 ;;
    *) echo "unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
esac

echo "== building slaptop $VERSION ($TAR_ARCH)"
scripts/build-static.sh "$WORK"
BIN="$ROOT/build-static/slaptop"

rm -rf dist stage pkgroot
mkdir -p dist "stage/slaptop-$VERSION-linux-$TAR_ARCH"
cp "$BIN" "dist/slaptop-linux-$TAR_ARCH"
cp "dist/slaptop-linux-$TAR_ARCH" "stage/slaptop-$VERSION-linux-$TAR_ARCH/slaptop"
cp LICENSE README.md CHANGELOG.md "stage/slaptop-$VERSION-linux-$TAR_ARCH/"
cp -r docs "stage/slaptop-$VERSION-linux-$TAR_ARCH/docs"
tar -C stage -czf "dist/slaptop-$VERSION-linux-$TAR_ARCH.tar.gz" \
    "slaptop-$VERSION-linux-$TAR_ARCH"

if [ "$WITH_NFPM" = 1 ] && command -v nfpm >/dev/null 2>&1; then
    mkdir -p pkgroot
    cp "dist/slaptop-linux-$TAR_ARCH" pkgroot/slaptop
    cp LICENSE README.md CHANGELOG.md pkgroot/
    cp -r docs pkgroot/docs
    (cd pkgroot && PKG_VERSION="$VERSION" PKG_ARCH="$DEB_ARCH" \
        nfpm package -f "$ROOT/packaging/nfpm.yaml" -p deb -t "$ROOT/dist/")
    (cd pkgroot && PKG_VERSION="$VERSION" PKG_ARCH="$RPM_ARCH" \
        nfpm package -f "$ROOT/packaging/nfpm.yaml" -p rpm -t "$ROOT/dist/")
else
    echo "note: nfpm not found, .deb/.rpm skipped (install it to build them)" >&2
fi

(cd dist && sha256sum ./*.tar.gz ./*.deb ./*.rpm 2>/dev/null > SHA256SUMS || \
    sha256sum ./*.tar.gz > SHA256SUMS)
echo
ls -l dist
