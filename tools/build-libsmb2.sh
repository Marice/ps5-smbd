#!/usr/bin/env bash
# Builds libsmb2 (LGPL-2.1) as a static library, twice:
#   tools/build-libsmb2.sh ps5    for the payload, with the ps5-payload-dev SDK  -> .deps/ps5
#   tools/build-libsmb2.sh host   for the host build the tests run against       -> .deps/host
# The source is GitHub's archive of one commit of master, pinned by sha256, with patches/libsmb2-*.patch
# applied. Not the 6.3 release: its tag sits on a side branch 537 commits behind master, without master's
# server and decoder fixes (docs/decision-log.md D2).
set -euo pipefail

LIBSMB2_COMMIT=727feaaa6d0f4fed1bae57745fbc2c5db9a30e64  # master, 2026-10-25
LIBSMB2_SHA256=ebb5118d338e452b5e8896f0dab4783babe6a368b0c892f1c1a34cf5fdc5f3f7

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
  *)
    echo "usage: $0 ps5|host" >&2
    exit 2
    ;;
esac

[[ -f "$prefix/lib/libsmb2.a" ]] && exit 0
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
  -DENABLE_EXAMPLES=OFF >/dev/null
cmake --build "$build/out" --parallel 8 >/dev/null
cmake --install "$build/out" >/dev/null
echo "libsmb2 ${LIBSMB2_COMMIT:0:8} built for $target in $prefix"
