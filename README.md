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
cargo run --release                         # stream decoded, signature-checked transactions off mainnet
cargo run --release -- --feed mainnet --feed mainnet   # race two connections, see below
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

- **Defaults to the public feed**, not a local relay: this client speaks the
  permessage-deflate the public feed requires, which is what the relay was for.
- **Signatures are checked by default.** Every message must be signed by the
  sequencer key (one ECDSA recovery, ~40 us); `--no-verify` turns that off.
- **Several sources, first copy wins.** `Feed::builder().source(a).source(b).spawn()`
  reads each source on its own task and delivers every message once, from whichever
  had it first. `Feed::recv().await` returns the next live message.
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

## Racing connections

Two connections to the *same* public endpoint do not receive a message at the same
moment: over 30 s of mainnet each won about half the messages, and the losing copy
arrived **~30 ms later on average, up to ~100 ms**. Taking the first copy of each cuts
that out, which is more than every decoding optimisation in this crate put together.
The summary line on exit shows, per source, how often it was first and how far behind
it was otherwise.

The public feed allows two connections per IP and answers a third with HTTP 429, so
racing beyond two needs more addresses or relays on other hosts.

## Running a relay

The public feed rate-limits per client, not per connection. To share one upstream
connection between several consumers, run Offchain Labs' relay and point them at it
with `--feed relay`:

```bash
docker run -d --name relay -p 127.0.0.1:9642:9642 --entrypoint relay   offchainlabs/nitro-node:v3.11.4-7d5ac27   --node.feed.output.addr=0.0.0.0 --chain.id=4663   --node.feed.input.url=wss://feed.mainnet.chain.robinhood.com
```

A relay verifies no signatures and hides reorgs (it dedups by sequence number), so
keep signature checking on (the default) and prefer the direct feed when reorgs matter.

## License

Apache-2.0, as upstream: the Rust sources are a derivative work of Chainstack's
robinhood-chain-sequencer-feed.
