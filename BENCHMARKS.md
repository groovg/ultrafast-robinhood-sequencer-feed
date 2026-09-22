# Benchmarks

Recorded on 2026-09-23 from 60 seconds of Robinhood Chain mainnet: 596 frames, 594
messages, 4,075 transactions. AMD Ryzen 9 9950X3D, Windows 11, single core. Each number
is the best of several rounds after a warm-up. Repeated runs came within 2% of each
other.

## Time per message

"Feed path" is the work `Feed` does on each new message before you get it: parse the
JSON frame, check the sequencer's signature, decode the transactions. This is the delay
our code adds on top of the network.

| | Python | Rust + libsecp256k1 | Rust + ufsecp (MSVC) | Rust + ufsecp (clang-cl) |
|---|---:|---:|---:|---:|
| **feed path, µs per message** | 111.6 | 52.4 | 49.8 | **38.4** |
| **per message, µs** | | | | |
| frame JSON to decoded txs | 33.0 | 3.5 | 3.7 | 3.5 |
| signature check | 73.8 | 49.5 | 47.2 | **35.7** |
| frame + signature + every sender | 543 | 326 | 306 | **217** |
| **per transaction, µs** | | | | |
| to_bytes, selector, value, nonce, gas | 1.84 | 0.065 | 0.062 | 0.063 |
| + hash | 7.11 | 2.02 | 2.01 | 2.01 |
| + to (checksummed) | 12.3 | 2.33 | 2.32 | 2.33 |
| + sender | 63.9 | 39.7 | 37.2 | **26.0** |
| **ECDSA recover to address, µs** | 39.3 | 34.8 | 32.3 | **21.1** |
| transactions/s on one core, sender included | 18.7k | 26.6k | 28.7k | **42.2k** |

Notes:

- The feed path is 2.1x faster than Python with the same ECDSA library and 2.9x faster
  with UltrafastSecp256k1. Almost everything left is cryptography: about 35 µs of ECDSA
  (21 µs with ufsecp) and about 12 µs of keccak over the ~14 KB signed message.
- The parts that aren't cryptography got 10 to 30 times faster. Going from a frame to
  decoded transactions is 9.4x faster, reading transaction fields 29x. Some of that is
  just Rust vs Python. The rest is SIMD base64 (3.3x faster than the `base64` crate) and
  assembly keccak (1.2x faster than tiny-keccak).
- Python already used libsecp256k1 (through coincurve), so on ECDSA alone Rust with the
  same library is only about 12% faster.
- The ufsecp (clang-cl) column looks much faster, but that's mostly the compiler. In the
  Rust + libsecp256k1 column, libsecp256k1 was compiled by MSVC. See the next section.
- In absolute terms none of this is much. The feed sends about 10 messages and 70
  transactions per second, so even the Python version uses a fraction of a percent of
  one core. Network delays are measured in milliseconds, which is why racing
  connections (below) helps more than anything in this table.

How the Rust feed path went from 61.0 µs to 52.4 µs (libsecp256k1, same recording):

| Change | Feed path |
|---|---:|
| straight port from Python | 61.0 µs |
| SIMD base64 (`base64-simd`) | 57.8 µs |
| assembly keccak (`keccak-asm`) | 55.4 µs |
| decode l2Msg once, hash the signed data as it's built | 54.3 µs |
| final run for the table above | 52.4 µs |

On this machine, differences smaller than about 0.3 µs are noise.

## Which ECDSA library

Our first numbers said UltrafastSecp256k1 was 1.65x faster than libsecp256k1. It turned
out the comparison wasn't fair. On Windows, the `secp256k1` crate compiles libsecp256k1
with MSVC, which has no 128-bit integers, so libsecp256k1 falls back to slower code.
Compiled with clang, it's as fast as UltrafastSecp256k1.

Recovering a public key, µs:

| Machine | libsecp256k1 | UltrafastSecp256k1 |
|---|---:|---:|
| Ryzen 9 9950X3D, Windows, MSVC | 34.4 | 32.3 |
| Ryzen 9 9950X3D, Windows, clang-cl | 21.4 | 21.1 |
| EPYC 7763 (GitHub runner), Linux, gcc / clang | 45.0 | 42.5 |

On Linux, the feed path on that runner was 55.2 µs with libsecp256k1 and 52.7 µs with
UltrafastSecp256k1, about 5% apart. So on Linux the default build is fine, and ufsecp
buys a few percent. On Windows, build with clang either way. The Linux numbers come from
`.github/workflows/bench.yml`, which you can rerun with `gh workflow run bench`.

## Two connections to the same feed

`rhfeed --feed mainnet --feed mainnet --seconds 30`, 2026-09-23, 292 messages:

| | first | second | average delay when second | worst delay |
|---|---:|---:|---:|---:|
| connection 1 | 144 | 148 | 30.2 ms | 88.8 ms |
| connection 2 | 148 | 144 | 30.9 ms | 108.3 ms |

Neither connection was faster overall. Each one lost about half the time, by about
30 ms on average. Taking the first copy of every message saves those 30 ms on half the
messages. That's roughly a thousand times more than the entire feed path above.

A third connection from the same IP was refused with HTTP 429.

## Running the benchmarks yourself

```bash
# record 60 s of the feed (8.7 MB, not committed)
uv run --project ../robinhood-chain-sequencer-feed python bench/capture.py bench/capture.jsonl 60

# Python
uv run --project ../robinhood-chain-sequencer-feed python bench/bench.py bench/capture.jsonl

# Rust
cargo run --release --example bench -- bench/capture.jsonl
UFSECP_LIB_DIR=<ufsecp build dir> [CLANG_RT_DIR=<llvm>/lib/clang/22/lib/windows] \
  cargo run --release --example bench --features ufsecp -- bench/capture.jsonl
```

If you compare several ufsecp builds, give each one its own `CARGO_TARGET_DIR`.
Otherwise cargo won't relink when only `UFSECP_LIB_DIR` changes.
