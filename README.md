# ultrafast-robinhood-sequencer-feed

Decode Robinhood Chain's sequencer feed — the ordered transactions, before any RPC
can show them — in Rust, as fast as the hardware allows.

This started as a port of Chainstack's
[robinhood-chain-sequencer-feed](https://github.com/chainstacklabs/robinhood-chain-sequencer-feed),
which stays the reference: the Rust decoder is tested field by field against it, and
benchmarked against it. Its [README](https://github.com/chainstacklabs/robinhood-chain-sequencer-feed#readme)
explains what the feed is, why there is no public mempool, and what the decoded data can
and cannot tell you.

```bash
docker compose up -d --wait relay           # the official Nitro relay, see docker-compose.yml
cargo run --release                         # stream decoded transactions from it
cargo run --release -- --feed mainnet --verify
cargo test
```

Performance against the baseline: [BENCHMARKS.md](BENCHMARKS.md).

## Layout

| | |
|---|---|
| `src/` | the crate: `codec` (decoder), `verify` (feed signatures), `secp` (ECDSA backends), `consume` (WebSocket consumer), `main` (CLI) |
| `tests/golden.rs` | holds the decoder to the baseline, from `tests/golden.jsonl` |
| `tests/golden.py` | writes `golden.jsonl` from the baseline |
| `tests/fixtures/` | real mainnet frames and a signed message, from upstream |
| `examples/bench.rs`, `bench/` | the Rust and Python halves of the benchmark, and a feed capture script |

The Python scripts run against a checkout of the baseline next to this repository:

```bash
git clone https://github.com/chainstacklabs/robinhood-chain-sequencer-feed ../robinhood-chain-sequencer-feed
uv run --project ../robinhood-chain-sequencer-feed --extra dev python tests/golden.py > tests/golden.jsonl
```

## Differences from the baseline

- **Pull, not a generator.** `FeedConsumer::next_live().await` returns the next live
  message.
- **Malformed fields leave a transaction unmodeled** (hash and raw bytes only) instead of
  carrying, say, a 30-byte `to` through. Every node rejects such an envelope anyway.
- **WebSocket via [yawc](https://crates.io/crates/yawc)**, not tokio-tungstenite, because
  the public feed requires permessage-deflate and tungstenite has none.

## UltrafastSecp256k1 backend

Sender and signature recovery use libsecp256k1 by default — the same C library
coincurve wraps on the Python side. `--features ufsecp` switches to
[UltrafastSecp256k1](https://github.com/shrec/UltrafastSecp256k1) through its C ABI.
Its Rust crates are not on crates.io, so build its static library first — with
clang-cl, which makes it 1.66x libsecp256k1 where MSVC `cl` makes it 1.07x. From a VS x64
developer prompt with LLVM and Ninja on `PATH`:

```bat
git clone https://github.com/shrec/UltrafastSecp256k1 && cd UltrafastSecp256k1
cmake --preset windows-clang-cl -DSECP256K1_ENABLE_OPENMP=OFF -DSECP256K1_BUILD_TESTS=OFF ^
      -DSECP256K1_BUILD_BENCH=OFF -DSECP256K1_BUILD_EXAMPLES=OFF -DSECP256K1_BUILD_JAVA=OFF
cmake --build out/windows-clang-cl --target ufsecp_static
```

Static because the clang-cl build of its DLL does not compile (a `thread_local` inside a
`dllexport` function); OpenMP off because recovering one signature does not use it and
it would need its runtime linked. Then point cargo at the build directory:

```bash
export UFSECP_LIB_DIR=/path/to/UltrafastSecp256k1/out/windows-clang-cl
export CLANG_RT_DIR="C:/Program Files/LLVM/lib/clang/22/lib/windows"   # clang-cl builds only
cargo test --features ufsecp   # includes a check that both backends agree
```

The wrapper rejects r or s ≥ n before calling `ufsecp_eth_ecrecover`, which would
otherwise reduce them mod n where libsecp256k1 refuses them, and routes recovery ids 2
and 3, which `ecrecover`'s v mapping cannot express, through `ufsecp_ecdsa_recover`.

## License

Apache-2.0, as upstream. The Rust sources are a derivative work of the baseline; see
[NOTICE](NOTICE).
