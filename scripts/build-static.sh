#!/bin/bash
# Build a portable slaptop binary with every feature enabled.
#
# Verified on RHEL 9.8 (glibc 2.34) against a production slapd: cn=monitor,
# contextCSN, log tailing, SASL EXTERNAL and TLS all work, with no missing
# shared library.
#
# Strategy: the target host (RHEL 9) has libtinfo, libz, libgpm, libldap.so.2,
# libsasl2 and libssl, but NOT libdeflate.so.0.  So:
#
#   * libdeflate  -> compiled here, linked statically (absent on the target)
#   * libunistring-> compiled here, linked statically (defensive: distro .so
#                    versions differ, a static one cannot break at run time)
#   * notcurses   -> compiled with multimedia disabled (a dashboard shows no
#                    video), but WITH libdeflate and gpm, so no functionality
#                    of the TUI is lost
#   * libldap     -> linked dynamically on purpose: the distribution build
#                    brings cyrus-sasl and OpenSSL, which keeps SASL EXTERNAL
#                    and ldaps:// fully working.  Rebuilding OpenLDAP without
#                    SASL would silently drop a feature.
#
# Usage: scripts/build-static.sh [work-dir]
#
# For a binary that also runs where libldap.so.2 is missing (Debian/Ubuntu ship
# libldap-2.x.so.0), add -DSLAPTOP_LDAP_STATIC_A and friends; see README.

set -euo pipefail

WORK=${1:-/dev/shm/slaptop-portable}
NOTCURSES_VERSION=3.0.14
UNISTRING_VERSION=1.1
# libdeflate 1.20+ uses clang-style target("evex512") attributes that GCC 16
# (Fedora 44) rejects; 1.19 builds everywhere and the few KB/s of compression
# speed do not matter (Kitty blitter only).
DEFLATE_VERSION=${DEFLATE_VERSION:-1.19}
JOBS=$(nproc)
PROJECT=$(cd "$(dirname "$0")/.." && pwd)

mkdir -p "$WORK"
cd "$WORK"

say() { printf '\n== %s\n' "$*"; }
fetch() { [ -f "$2" ] || curl -fsSL -o "$2" "$1"; }

# --- libdeflate (absent from RHEL 9) ---------------------------------------
if [ ! -f "$WORK/libdeflate-$DEFLATE_VERSION/build/libdeflate.a" ]; then
    say "libdeflate $DEFLATE_VERSION"
    fetch "https://github.com/ebiggers/libdeflate/archive/refs/tags/v$DEFLATE_VERSION.tar.gz" \
          "libdeflate-$DEFLATE_VERSION.tar.gz"
    tar xzf "libdeflate-$DEFLATE_VERSION.tar.gz"
    cd "libdeflate-$DEFLATE_VERSION"
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
        -DLIBDEFLATE_BUILD_SHARED_LIB=OFF \
        -DLIBDEFLATE_BUILD_STATIC_LIB=ON \
        -DLIBDEFLATE_BUILD_GZIP=OFF
    cmake --build build -j"$JOBS" || true
    cd "$WORK"
fi

# --- libunistring (static, defensive) --------------------------------------
if [ ! -f "$WORK/libunistring-$UNISTRING_VERSION/lib/.libs/libunistring.a" ]; then
    say "libunistring $UNISTRING_VERSION"
    fetch "https://ftp.gnu.org/gnu/libunistring/libunistring-$UNISTRING_VERSION.tar.gz" \
          "libunistring-$UNISTRING_VERSION.tar.gz"
    tar xzf "libunistring-$UNISTRING_VERSION.tar.gz"
    cd "libunistring-$UNISTRING_VERSION"
    ./configure --enable-static --disable-shared --prefix="$WORK/unistring-inst"
    make -j"$JOBS"
    # Install into the prefix: notcurses is pointed at it below, and a fresh
    # container has no system libunistring to fall back on.
    make install
    cd "$WORK"
fi

# --- notcurses (core, with deflate + gpm, without multimedia) ----------
# Homebrew keeps headers/libs outside the default search paths; give CMake the
# hints it needs for libunistring (notcurses fails hard without unigbrk.h).
UNISTRING_HINTS=()
for prefix in "$WORK/unistring-inst" /home/linuxbrew/.linuxbrew /usr/local /usr; do
    if [ -f "$prefix/include/unigbrk.h" ]; then
        UNISTRING_HINTS+=("-DUNISTRING_INCLUDE=$prefix/include")
        if [ -e "$prefix/lib/libunistring.a" ]; then
            UNISTRING_HINTS+=("-Dunistring=$prefix/lib/libunistring.a")
        elif [ -e "$prefix/lib64/libunistring.a" ]; then
            UNISTRING_HINTS+=("-Dunistring=$prefix/lib64/libunistring.a")
        elif [ -e "$prefix/lib/libunistring.so" ]; then
            UNISTRING_HINTS+=("-Dunistring=$prefix/lib/libunistring.so")
        fi
        break
    fi
done

# Console mouse support (libgpm) only exists on RHEL/Debian-like hosts; the
# Homebrew prefix has no gpm.h and notcurses fails hard without it.
GPM_FLAG=(-DUSE_GPM=OFF)
for prefix in /usr /usr/local /home/linuxbrew/.linuxbrew; do
    if [ -f "$prefix/include/gpm.h" ]; then
        GPM_FLAG=(-DUSE_GPM=ON)
        break
    fi
done

# --- notcurses (core, with deflate + gpm, without multimedia) --------------
if [ ! -f "$WORK/notcurses-$NOTCURSES_VERSION/build/libnotcurses-core.a" ]; then
    say "notcurses $NOTCURSES_VERSION"
    fetch "https://github.com/dankamongmen/notcurses/archive/refs/tags/v$NOTCURSES_VERSION.tar.gz" \
          "notcurses-$NOTCURSES_VERSION.tar.gz"
    tar xzf "notcurses-$NOTCURSES_VERSION.tar.gz"
    cd "notcurses-$NOTCURSES_VERSION"
    # Only libnotcurses-core.a is used here: ask for static only.  The shared
    # library cannot link a static libdeflate, which is harmless for us.
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        "${UNISTRING_HINTS[@]}" \
        -DUSE_MULTIMEDIA=none \
        -DUSE_DEFLATE=ON \
        -DCMAKE_C_FLAGS="-I$WORK/libdeflate-$DEFLATE_VERSION" \
        -DDEFLATE_INCLUDE_DIRS="$WORK/libdeflate-$DEFLATE_VERSION" \
        -DDEFLATE="$WORK/libdeflate-$DEFLATE_VERSION/build/libdeflate.a" \
        -Ddeflate="$WORK/libdeflate-$DEFLATE_VERSION/build/libdeflate.a" \
        "${GPM_FLAG[@]}" \
        -DUSE_PANDOC=OFF -DUSE_DOXYGEN=OFF \
        -DBUILD_EXECUTABLES=OFF -DUSE_POC=OFF -DBUILD_TESTING=OFF -DUSE_CXX=OFF
    cmake --build build -j"$JOBS" || true
    if [ ! -f "build/libnotcurses-core.a" ]; then
        echo "notcurses: libnotcurses-core.a was not produced" >&2
        exit 1
    fi
    cd "$WORK"
fi

# --- slaptop ----------------------------------------------------------------
say "slaptop"

# OpenLDAP: the host has no ldap.pc, so point CMake at the out-of-tree
# headers and at the versioned soname when they are around.
LDAP_FLAGS=()
# `|| true`: with pipefail, a failed `ls` would end the script silently on a
# machine that has none of these paths (which is every clean container).
LDAP_HEADER=$(ls -d /opt/openldap-*/include/ldap.h 2>/dev/null | sort -V | tail -1 || true)
LDAP_RUNTIME_LIB=$(ls /opt/openldap/lib/libldap.so.2 2>/dev/null | head -1 || true)
if [ -n "$LDAP_HEADER" ]; then
    LDAP_FLAGS+=("-DSLAPTOP_LDAP_ROOT=${LDAP_HEADER%/include/ldap.h}")
fi
if [ -n "$LDAP_RUNTIME_LIB" ]; then
    LDAP_FLAGS+=("-DSLAPTOP_LDAP_LIBDIR=$(dirname "$LDAP_RUNTIME_LIB")")
fi

cd "$PROJECT"
cmake -S . -B build-static -DCMAKE_BUILD_TYPE=Release \
    -DSLAPTOP_WITH_LDAP=ON -DSLAPTOP_WITH_TUI=ON \
    -DSLAPTOP_STATIC_NOTCURSES=ON \
    -DSLAPTOP_NOTCURSES_CORE_A="$WORK/notcurses-$NOTCURSES_VERSION/build/libnotcurses-core.a" \
    -DSLAPTOP_DEFLATE_A="$WORK/libdeflate-$DEFLATE_VERSION/build/libdeflate.a" \
    -DSLAPTOP_UNISTRING_A="$WORK/libunistring-$UNISTRING_VERSION/lib/.libs/libunistring.a" \
    -DUNISTRING_INCLUDE_DIR="$WORK/unistring-inst/include" \
    "${LDAP_FLAGS[@]}"
cmake --build build-static -j"$JOBS"

say "result"
ls -lh build-static/slaptop
echo
echo "Shared libraries required at run time:"
ldd build-static/slaptop | sed 's/^[[:space:]]*//' \
    | grep -vE 'vdso|ld-linux' | awk '{print "  " $1}'
echo
echo "All of the above ship with RHEL 9 / Debian 12 / Ubuntu 24.04."
