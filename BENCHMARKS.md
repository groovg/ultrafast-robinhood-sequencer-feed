# Python vs Rust vs UltrafastSecp256k1

60 seconds of Robinhood Chain mainnet feed (2026-09-23): 596 frames, 594 messages,
4,075 transactions. AMD Ryzen 9 9950X3D, Windows 11, one core. Best of N rounds after a
warm-up; two full runs agreed within 2%.

| | Python | Rust + libsecp256k1 | Rust + ufsecp (MSVC) | Rust + ufsecp (clang-cl) |
|---|---:|---:|---:|---:|
| **per transaction, µs** | | | | |
| to_bytes, selector, value, nonce, gas | 1.82 | 0.062 | 0.062 | 0.062 |
| + hash | 7.03 | 2.37 | 2.37 | 2.37 |
| + to (checksummed) | 12.2 | 2.72 | 2.72 | 2.72 |
| + sender | 63.5 | 40.8 | 38.1 | **26.7** |
| **per message, µs** | | | | |
| frame JSON → decoded txs | 32.2 | 5.3 | 5.3 | 5.3 |
| feed signature check | 73.6 | 54.5 | 51.6 | **39.9** |
| all of it: frame, signature, every sender | 544 | 337 | 318 | **228** |
| **ECDSA recover → address, µs** | 39.4 | 34.8 | 32.4 | **21.0** |
| one core, full decode incl. sender, tx/s | 18.8k | 26.4k | 28.3k | **41.8k** |

What it says:

- **Everything but ECDSA got 5–30x faster** — field extraction ~29x, a whole frame to
  decoded transactions ~6x. That is the interpreter overhead going away.
- **ECDSA is the floor, and the backend is what moves it.** Python already called
  libsecp256k1 through coincurve, so Rust with the same library gains only ~12% on
  recovery. UltrafastSecp256k1 built with clang-cl is 1.66x libsecp256k1; built with
  MSVC it is barely faster (1.07x), so the compiler matters as much as the library.
- **The hash row is now keccak itself** (~2.3 µs for an average ~1 KB envelope in
  tiny-keccak). An assembly keccak is the next lever if `hash` ever matters.
- **In absolute terms this is small.** The live feed carried ~10 messages and ~68
  transactions a second. The worst case — verify every message and recover every
  sender — costs 0.54% of a core in Python and 0.23% in the fastest Rust build, and
  saves ~0.3 ms of latency per message. Without sender recovery the saving is ~27 µs
  per message. Network hops are milliseconds.

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
