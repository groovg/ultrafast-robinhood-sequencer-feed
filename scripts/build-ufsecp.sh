#!/usr/bin/env bash
# Build UltrafastSecp256k1's static library with clang, for `cargo build --features ufsecp`.
#
#   scripts/build-ufsecp.sh [dir] [march]
#   export UFSECP_LIB_DIR=<dir>/build
#
# march defaults to "native"; use x86-64-v3 for anything you ship. Linux and macOS.
set -euo pipefail

# Bump deliberately and rerun `cargo test --features ufsecp`.
COMMIT=38b066beab3142d2c6d27df8380f3a618023f3ab

dir=${1:-ufsecp}
march=${2:-native}

if [ ! -d "$dir/.git" ]; then
    git clone --quiet https://github.com/shrec/UltrafastSecp256k1 "$dir"
fi
git -C "$dir" fetch --quiet --depth 1 origin "$COMMIT"
git -C "$dir" checkout --quiet "$COMMIT"

# No OpenMP (batch-only, needs its runtime). No LTO: the Rust linker can't read bitcode.
cmake -S "$dir" -B "$dir/build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DSECP256K1_MARCH="$march" \
    -DSECP256K1_USE_LTO=OFF \
    -DSECP256K1_ENABLE_OPENMP=OFF \
    -DUFSECP_BUILD_SHARED=OFF \
    -DSECP256K1_BUILD_TESTS=OFF -DSECP256K1_BUILD_BENCH=OFF \
    -DSECP256K1_BUILD_EXAMPLES=OFF -DSECP256K1_BUILD_JAVA=OFF
cmake --build "$dir/build" --target ufsecp_static

echo "UFSECP_LIB_DIR=$(cd "$dir/build" && pwd)"
