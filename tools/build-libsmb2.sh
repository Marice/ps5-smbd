#!/usr/bin/env bash
# Builds libsmb2 (LGPL-2.1) as a static library, twice:
#   tools/build-libsmb2.sh ps5    for the payload, with the ps5-payload-dev SDK  -> .deps/ps5
#   tools/build-libsmb2.sh host   for the host build the tests run against       -> .deps/host
# The source is GitHub's archive of one commit of master, pinned by sha256, with patches/libsmb2-*.patch
# applied. Not the 6.3 release: its tag sits on a side branch 537 commits behind master, without master's
# server and decoder fixes (docs/decision-log.md D2).
set -euo pipefail

LIBSMB2_COMMIT=565460de50d97c451d2692d9fab48314b47e453a  # master, 2026-10-31
LIBSMB2_SHA256=f439041a248539e0c99e6581cdcf740c773700b4b25180f5862b5dba96147d30

target="${1:-}"
root="$(cd "$(dirname "$0")/.." && pwd)"
src="$root/.deps/src"
build="$root/.deps/build-$target"
prefix="$root/.deps/$target"

case "$target" in
  ps5)
    sdk="${PS5_PAYLOAD_SDK:-/opt/ps5-payload-sdk}"
    [[ -x "$sdk/bin/prospero-cmake" ]] || { echo "no payload SDK at $sdk (set PS5_PAYLOAD_SDK)" >&2; exit 1; }
    cmake=("$sdk/bin/prospero-cmake")
    ;;
  host)
    cmake=(cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON)
    ;;
  ps2)
    # in the ps2dev/ps2dev container (make ps2): the EE toolchain, no libdcerpc (no srvsvc on the PS2)
    [[ -f "${PS2DEV:-}/share/ps2dev.cmake" ]] || { echo "no PS2 toolchain (set PS2DEV, or use the ps2dev/ps2dev image)" >&2; exit 1; }
    cmake=(cmake "-DCMAKE_TOOLCHAIN_FILE=$PS2DEV/share/ps2dev.cmake")
    ;;
  *)
    echo "usage: $0 ps5|host|ps2" >&2
    exit 2
    ;;
esac

[[ -f "$prefix/lib/libsmb2.a" && ( "$target" == ps2 || -f "$prefix/lib/libdcerpc.a" ) ]] && exit 0
mkdir -p "$src" "$build"
archive="$src/libsmb2-$LIBSMB2_COMMIT.tar.gz"
if [[ ! -f "$archive" ]]; then
  curl -fsSL -o "$archive.part" "https://github.com/sahlberg/libsmb2/archive/$LIBSMB2_COMMIT.tar.gz"
  mv "$archive.part" "$archive"
fi
echo "$LIBSMB2_SHA256  $archive" | sha256sum -c - >/dev/null

rm -rf "$build"
mkdir -p "$build"
tar -xzf "$archive" -C "$build"
# Fixes to libsmb2's server, see each patch's file (patches/*.patch).
for patch in "$root"/patches/libsmb2-*.patch; do
  [[ -f "$patch" ]] && patch -s -p1 -d "$build/libsmb2-$LIBSMB2_COMMIT" < "$patch"
done
"${cmake[@]}" -S "$build/libsmb2-$LIBSMB2_COMMIT" -B "$build/out" -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$prefix" -DBUILD_SHARED_LIBS=OFF -DENABLE_LIBKRB5=OFF -DENABLE_GSSAPI=OFF \
  -DENABLE_LIBQUIC=OFF -DENABLE_RDMA=OFF -DENABLE_LIBDCERPC=OFF \
  -DENABLE_EXAMPLES=OFF >/dev/null
cmake --build "$build/out" --parallel 8 >/dev/null
cmake --install "$build/out" >/dev/null

if [[ "$target" != ps2 ]]; then
  # libdcerpc (BSD-2-Clause) from the same tree, without its libsmb2 transport: its coders and server runtime
  # for the srvsvc pipe (src/rpc.c). compat/ holds the one glibc header the PS5 lacks.
  "${cmake[@]}" -S "$build/libsmb2-$LIBSMB2_COMMIT/libdcerpc" -B "$build/dcerpc" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=OFF -DWITH_LIBSMB2=OFF -DENABLE_UTILS=OFF \
    -DENABLE_EXAMPLES=OFF -DCMAKE_C_FLAGS="-I$root/compat" >/dev/null
  cmake --build "$build/dcerpc" --parallel 8 >/dev/null
  cmake --install "$build/dcerpc" >/dev/null
fi
echo "libsmb2 and libdcerpc ${LIBSMB2_COMMIT:0:8} built for $target in $prefix"
