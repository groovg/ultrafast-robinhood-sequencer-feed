#!/usr/bin/env bash
# Profile-guided release build of rhfeed: build instrumented, run the benchmark on the
# test fixture, build again with the profile. Arguments go to every cargo build.
#
#   scripts/pgo-build.sh --features ufsecp
#
# It helps where caches are cold between messages, as on the live feed: the median of the
# paced benchmark dropped from 92 to 76 µs on c7i and from 63 to 59 µs on c7a.
set -euo pipefail

rustup component add llvm-tools-preview > /dev/null 2>&1 || true
profdata=$(find "$(rustc --print sysroot)" -name 'llvm-profdata*' -type f | head -1)
if [ -z "$profdata" ]; then
    echo "llvm-profdata not found: rustup component add llvm-tools-preview" >&2
    exit 1
fi

root=$(pwd -W 2> /dev/null || pwd) # rustc on Windows needs a Windows path
data="$root/target/pgo-data"
rm -rf "$data"
flags=${RUSTFLAGS:-}

RUSTFLAGS="$flags -Cprofile-generate=$data" \
    cargo build --release --locked --example bench --target-dir target/pgo-gen "$@"
target/pgo-gen/release/examples/bench tests/fixtures/frames.jsonl > /dev/null
"$profdata" merge -o "$data/rhfeed.profdata" "$data"
RUSTFLAGS="$flags -Cprofile-use=$data/rhfeed.profdata" cargo build --release --locked "$@"
