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

The feed path starts after the WebSocket library has inflated the frame. The public feed
compresses every frame (permessage-deflate), and inflating one takes 8.9 µs with
zlib-rs, which we use, or 11.9 µs with miniz_oxide, yawc's default. Measured by
recompressing the recording the way the protocol does it, since the feed's own
compressed bytes aren't recorded. Tiny-message WebSocket benchmarks don't show this
cost, and at ~10 frames a second it's the only part of the WebSocket layer that
matters.

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

## Zen 4 in AWS, and what AVX-512 buys

c7a.large (AMD EPYC 9R14, Zen 4, Linux), same recording, µs per message unless noted.
"generic" is a plain `cargo build --release`, "native" adds `-C target-cpu=native`:

| | generic | native | native, scalar keccak | native + ufsecp |
|---|---:|---:|---:|---:|
| feed path | 68.7 | 66.6 | 67.6 | **62.9** |
| JSON parse (sonic-rs) | 2.40 | 1.71 | 1.70 | 1.78 |
| transaction hash, µs per tx | 3.26 | 3.13 | 3.25 | 3.13 |
| ECDSA recover, µs | 40.5 | 40.6 | 40.5 | 37.2 |
| every sender of a message, one by one | 307 | 305 | 306 | 280 |
| every sender of a message, `recover_senders` (2 cores) | 184 | 183 | 183 | 170 |

- `target-cpu=native` makes sonic-rs 29% faster. keccak-asm switches to OpenSSL's
  AVX-512 code, which is only 4% faster per hash here.
- ufsecp saves 8% on each ECDSA recovery.
- `recover_senders` spreads a message's senders across cores. Even with two cores it
  cuts the time by 40%. With more cores the gain grows with the number of transactions.
- We also tried [asmcrypto](https://crates.io/crates/asmcrypto), which recovers 8
  signatures at once with AVX-512 IFMA. It took 53.6 µs per signature here and 28.6 µs
  on the Zen 5 desktop, slower than libsecp256k1 on both (40.5 and 21.4 µs), so we
  removed it again.
- On Windows, forcing keccak-asm's AVX-512 variant made the benchmark hang. We didn't
  look into it further, since the default build on Windows doesn't use it.

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

## Where to run it

In September 2026 we recorded the feed at the same time from several AWS regions, with
clocks synced through Amazon Time Sync, and compared when each place got the same
message (`bench/regions.py`). Two rounds, 30 and 15 minutes, about 27,000 messages:

| Region | Median behind the fastest place |
|---|---:|
| us-east-1 (Virginia) | fastest in both rounds |
| ca-central-1 (Montreal) | ~12 ms |
| us-west-2 (Oregon) | ~18 ms |
| us-east-2 (Ohio) | ~31 ms |
| eu-central-1 (Frankfurt) | ~110 ms |

What we took from it:

- The feed is served through Cloudflare, so what counts is the route from your
  Cloudflare location to wherever the feed is served from. Distance to the sequencer
  doesn't predict it: Oregon was ahead of Ohio.
- Virginia was the best place to read the feed from.
- Machines in the same region can differ too. Two instances in Virginia were about
  10 ms apart. If you care about milliseconds, try a few and keep the fastest.
- Two connections from one machine usually trade places message by message, a few ms
  apart. Sometimes one gets stuck on a slower path for a long time, which is why
  `Feed` replaces a connection that keeps losing.

## Running the benchmarks yourself

```bash
# record 60 s of the feed (8.7 MB, not committed)
uv run --project ../robinhood-chain-sequencer-feed python bench/capture.py bench/capture.jsonl 60

# Python
uv run --project ../robinhood-chain-sequencer-feed python bench/bench.py bench/capture.jsonl

# Rust
cargo run --release --example bench -- bench/capture.jsonl

# compare arrival times recorded in several places (seq<TAB>received_at per line)
python bench/regions.py place1=a.tsv place2=b.tsv
UFSECP_LIB_DIR=<ufsecp build dir> [CLANG_RT_DIR=<llvm>/lib/clang/22/lib/windows] \
  cargo run --release --example bench --features ufsecp -- bench/capture.jsonl
```

If you compare several ufsecp builds, give each one its own `CARGO_TARGET_DIR`.
Otherwise cargo won't relink when only `UFSECP_LIB_DIR` changes.
