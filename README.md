# ultrafast-robinhood-sequencer-feed

A Rust client for Robinhood Chain's sequencer feed. It shows you transactions in the
order the sequencer picked, before they reach any RPC node.

It started as a port of Chainstack's
[robinhood-chain-sequencer-feed](https://github.com/chainstacklabs/robinhood-chain-sequencer-feed)
(Python). We still use that project as the reference: the tests check our decoder
against it field by field, and the benchmarks compare the two. If you want to know how
the feed works and what you can and can't learn from it, their
[README](https://github.com/chainstacklabs/robinhood-chain-sequencer-feed#readme) is
the place to start.

## Quick start

```bash
cargo run --release                                    # mainnet, signatures checked
cargo run --release -- --feed mainnet --feed mainnet   # two connections, first copy wins
cargo run --release -- --json --to 0xabc...            # JSON lines, one contract
cargo test
```

Or with Docker (the image is built with UltrafastSecp256k1):

```bash
docker build -t rhfeed .
docker run --rm rhfeed --feed mainnet --feed mainnet
```

Speed numbers are in [BENCHMARKS.md](BENCHMARKS.md).

## Using it as a library

```rust
let mut feed = rhfeed::Feed::builder()
    .source(rhfeed::MAINNET_FEED)
    .source(rhfeed::MAINNET_FEED)
    .verify(rhfeed::MAINNET_VERIFIER.clone())
    .spawn();

while let Some(msg) = feed.recv().await {
    for tx in &msg.txs {
        // tx.to_bytes and tx.selector are free, tx.hash() and tx.sender() cost a hash / an ECDSA recovery
    }
}
```

## Two connections are faster than one

We opened two connections to the same public endpoint and compared arrival times. Each
connection got about half the messages first. The other copy showed up about 30 ms
later on average, sometimes 100 ms later. `Feed` keeps whichever copy arrives first and
drops the other, so you get the better of the two on every message. That's worth far
more than all the decoding work in this crate.

The public feed allows two connections per IP. A third one gets HTTP 429. To race more
than two you need more IPs, or relays on other machines.

When the program exits it prints, for each source, how often it was first and how far
behind it was the rest of the time.

## How it differs from the Python version

- It connects to the public feed by default. The Python version expects a local relay,
  mostly because the public feed requires permessage-deflate. This client handles that
  itself.
- It checks the sequencer's signature on every message by default. That costs about
  40 µs per message. Use `--no-verify` to skip it (you'll need that for testnet).
- It can read from several sources at once and deliver each message once.
- If a transaction has a field that can't be valid (a 30-byte `to` address, a nonce
  over 64 bits) we keep only its hash and raw bytes. Python passes the odd value
  through. No node would accept such a transaction anyway.
- The WebSocket client is [yawc](https://crates.io/crates/yawc). tokio-tungstenite
  doesn't support permessage-deflate.

## Faster ECDSA with UltrafastSecp256k1

Most of the time spent on a message goes to ECDSA. By default we use libsecp256k1, the
same C library the Python version calls through coincurve.
[UltrafastSecp256k1](https://github.com/shrec/UltrafastSecp256k1) is an alternative you
can turn on with `--features ufsecp`. On Linux it's about 5% faster. On Windows it
looked 1.65x faster at first, but that was because the `secp256k1` crate builds
libsecp256k1 with MSVC there. Built with clang, the two are equally fast. Details in
[BENCHMARKS.md](BENCHMARKS.md#which-ecdsa-library).

It isn't on crates.io, so you build it yourself first. On Linux:

```bash
scripts/build-ufsecp.sh ufsecp native        # or x86-64-v3 for a binary you'll copy elsewhere
export UFSECP_LIB_DIR=$PWD/ufsecp/build
cargo build --release --features ufsecp
```

On Windows, from a VS x64 developer prompt with LLVM and Ninja on `PATH`:

```bat
git clone https://github.com/shrec/UltrafastSecp256k1 && cd UltrafastSecp256k1
cmake --preset windows-clang-cl -DSECP256K1_ENABLE_OPENMP=OFF -DSECP256K1_BUILD_TESTS=OFF ^
      -DSECP256K1_BUILD_BENCH=OFF -DSECP256K1_BUILD_EXAMPLES=OFF -DSECP256K1_BUILD_JAVA=OFF
cmake --build out/windows-clang-cl --target ufsecp_static
```

Then point cargo at the build directory:

```bash
export UFSECP_LIB_DIR=/path/to/UltrafastSecp256k1/out/windows-clang-cl
export CLANG_RT_DIR="C:/Program Files/LLVM/lib/clang/22/lib/windows"   # clang-cl builds only
cargo test --features ufsecp   # also checks that both libraries give the same answers
```

A few notes on the build:

- We link the static library because the clang-cl build of the DLL fails to compile
  (a `thread_local` inside a `dllexport` function).
- OpenMP is off. Recovering a single signature doesn't use it, and leaving it on means
  linking its runtime too.
- `ufsecp_eth_ecrecover` reduces r and s modulo n, while libsecp256k1 rejects values
  that are too large. Our wrapper rejects them before the call so both libraries agree.
  Recovery ids 2 and 3 go through `ufsecp_ecdsa_recover` because `ecrecover` has no way
  to express them.

## Running a relay

The public feed limits connections per client. If several programs on one machine
need the feed, run Offchain Labs' relay once and point them all at it with
`--feed relay`:

```bash
docker run -d --name relay -p 127.0.0.1:9642:9642 --entrypoint relay \
  offchainlabs/nitro-node:v3.11.4-7d5ac27 \
  --node.feed.output.addr=0.0.0.0 --chain.id=4663 \
  --node.feed.input.url=wss://feed.mainnet.chain.robinhood.com
```

Keep in mind that the relay doesn't check signatures, and it hides reorgs because it
drops any message whose sequence number it has already sent. Leave signature checking
on, and connect to the feed directly if you care about reorgs.

## Repository layout

| Path | What's there |
|---|---|
| `src/codec.rs` | decoding frames and transactions |
| `src/verify.rs` | checking the sequencer's signature |
| `src/secp.rs` | ECDSA recovery, libsecp256k1 or UltrafastSecp256k1 |
| `src/consume.rs` | `Feed`: connections, reconnects, dedup, reorgs |
| `src/main.rs` | the `rhfeed` command |
| `tests/golden.rs` | checks the decoder against the Python version's output in `tests/golden.jsonl` |
| `tests/robustness.rs` | feeds the decoder broken input and makes sure it doesn't crash |
| `tests/feed.rs` | runs `Feed` against local WebSocket servers |
| `tests/fixtures/` | real mainnet frames and a signed message (from the Python repo) |
| `examples/bench.rs`, `bench/` | the Rust and Python benchmarks, and a script to record the feed |

The Python scripts need the Python repo checked out next to this one:

```bash
git clone https://github.com/chainstacklabs/robinhood-chain-sequencer-feed ../robinhood-chain-sequencer-feed
uv run --project ../robinhood-chain-sequencer-feed --extra dev python tests/golden.py > tests/golden.jsonl
```

## License

Apache-2.0, same as the Python version this code is derived from.
