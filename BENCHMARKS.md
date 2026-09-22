# Python vs Rust vs UltrafastSecp256k1

60 seconds of Robinhood Chain mainnet feed (2026-09-23): 596 frames, 594 messages,
4,075 transactions. AMD Ryzen 9 9950X3D, Windows 11, one core. Best of N rounds after a
warm-up; repeated runs agree within 2%.

The number that matters is the **feed path**: what `Feed` does to every new live
message before handing it over — parse the frame, check the sequencer's signature,
decode the transactions. It is the latency this code adds on top of the network.

| | Python | Rust + libsecp256k1 | Rust + ufsecp (MSVC) | Rust + ufsecp (clang-cl) |
|---|---:|---:|---:|---:|
| **feed path, µs per message** | 111.6 | 52.4 | 49.8 | **38.4** |
| **per message, µs** | | | | |
| frame JSON → decoded txs | 33.0 | 3.5 | 3.7 | 3.5 |
| feed signature check | 73.8 | 49.5 | 47.2 | **35.7** |
| all of it: frame, signature, every sender | 543 | 326 | 306 | **217** |
| **per transaction, µs** | | | | |
| to_bytes, selector, value, nonce, gas | 1.84 | 0.065 | 0.062 | 0.063 |
| + hash | 7.11 | 2.02 | 2.01 | 2.01 |
| + to (checksummed) | 12.3 | 2.33 | 2.32 | 2.33 |
| + sender | 63.9 | 39.7 | 37.2 | **26.0** |
| **ECDSA recover → address, µs** | 39.3 | 34.8 | 32.3 | **21.1** |
| one core, full decode incl. sender, tx/s | 18.7k | 26.6k | 28.7k | **42.2k** |

What it says:

- **The feed path is 2.1x faster than Python with the same crypto library, 2.9x with
  UltrafastSecp256k1.** What is left is almost all cryptography: ~35 µs of ECDSA
  (21 with ufsecp) and ~12 µs of keccak over the ~14 KB signed message.
- **Everything but cryptography got 10–30x faster.** A frame to decoded transactions
  is 9.4x, field extraction 29x: the interpreter overhead going away, plus SIMD base64
  (3.3x the `base64` crate on l2Msg) and assembly keccak (1.2x tiny-keccak).
- **ECDSA is the floor, and the backend is what moves it.** Python already called
  libsecp256k1 through coincurve, so Rust with the same library gains ~12% on
  recovery. UltrafastSecp256k1 built with clang-cl is 1.65x libsecp256k1; built with
  MSVC it is barely faster (1.08x), so the compiler matters as much as the library.
- **In absolute terms this is small.** The live feed carries ~10 messages and ~70
  transactions a second, so the feed path is ~0.04% of a core in the fastest build.
  Network timing is measured in milliseconds, which is why racing connections, below,
  matters more than everything in this table.

How the Rust feed path got from 61.0 to 52.4 µs (libsecp256k1, same capture):

| change | feed path |
|---|---:|
| straight port | 61.0 µs |
| SIMD base64 (base64-simd) | 57.8 µs |
| assembly keccak (keccak-asm) | 55.4 µs |
| l2Msg decoded once, signature preimage hashed as a stream | 54.3 µs |
| final run for this table | 52.4 µs |

Differences under ~0.3 µs are within this machine's run-to-run noise.

## Racing two connections

Latency to the feed is dominated by the network, not by decoding, so the
biggest win is not in this table. Two connections to the same public endpoint
(`rhfeed --feed mainnet --feed mainnet --seconds 30`, 2026-09-23, 292 messages):

| | first on | behind on | mean lag when behind | max lag |
|---|---:|---:|---:|---:|
| connection 1 | 144 | 148 | 30.2 ms | 88.8 ms |
| connection 2 | 148 | 144 | 30.9 ms | 108.3 ms |

Neither connection is consistently faster, so racing them saves ~30 ms on about half
of all messages — about a thousand times the whole feed path. A third
connection from the same IP is refused with HTTP 429.

## Reproduce

```bash
uv run --project ../robinhood-chain-sequencer-feed python bench/capture.py bench/capture.jsonl 60   # not committed: 8.7 MB
uv run --project ../robinhood-chain-sequencer-feed python bench/bench.py bench/capture.jsonl

cargo run --release --example bench -- bench/capture.jsonl
UFSECP_LIB_DIR=<ufsecp build dir> [CLANG_RT_DIR=<llvm>/lib/clang/22/lib/windows] \
  cargo run --release --example bench --features ufsecp -- bench/capture.jsonl
```

Use a separate `CARGO_TARGET_DIR` per ufsecp build, or cargo will not relink when only
`UFSECP_LIB_DIR` changes between them.
