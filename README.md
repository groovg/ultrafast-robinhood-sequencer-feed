# ultrafast-robinhood-sequencer-feed

A Rust client for [Robinhood Chain](https://docs.robinhood.com/chain/)'s sequencer
feed. It shows you transactions in the order the sequencer picked, before they reach
any RPC node. Robinhood Chain runs on [Arbitrum Nitro](https://github.com/OffchainLabs/nitro),
so this is a Nitro feed client with Robinhood's defaults.

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
cargo run --release -- --timing --seconds 60           # where the time goes, per stage
cargo test
```

Or with Docker (the image is built with UltrafastSecp256k1):

```bash
docker build -t rhfeed .
docker run --rm rhfeed --feed mainnet --feed mainnet
```

For the machine you'll run it on, build with `RUSTFLAGS="-C target-cpu=native"`. That
makes JSON parsing about 30% faster and lets keccak use AVX-512 where the CPU has it.

Speed numbers are in [BENCHMARKS.md](BENCHMARKS.md), along with measurements of where
the feed arrives first. In short: the network costs milliseconds and our decoding costs
microseconds, so where you run it matters far more than anything else here.

## Using it as a library

```rust
let mut feed = rhfeed::Feed::builder()
    .source(rhfeed::MAINNET_FEED)
    .source(rhfeed::MAINNET_FEED)
    .verify(rhfeed::MAINNET_VERIFIER.clone())
    .spawn();

// Read in a spawned task, see "Lowest latency" below.
tokio::spawn(async move {
    while let Some(msg) = feed.recv().await {
        for tx in &msg.txs {
            // tx.to_bytes and tx.selector are free, tx.hash() and tx.sender() cost a hash / an ECDSA recovery
        }
    }
});
```

It runs on [tokio](https://tokio.rs). Each source gets its own connection and task,
and each message is delivered once, from whichever source had it first.

## Plugging it into a bot

Add the crate as a git dependency:

```toml
[dependencies]
rhfeed = { git = "https://github.com/groovg/ultrafast-robinhood-sequencer-feed" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

[`examples/copy_trade.rs`](examples/copy_trade.rs) is the reading half of a
copy-trading bot. It follows a list of wallets and prints a JSON line the moment the
sequencer orders one of their transactions:

```bash
cargo run --release --example copy_trade -- 0xWALLET_1 0xWALLET_2
```

A few things to keep in mind:

- Filter on `to_bytes` and `selector` first. They're already sliced out and cost
  nothing. Senders need ECDSA, so recover them only for what's left.
- A transaction in the feed has been ordered, not executed. It can still revert.
- This crate only reads. Signing and sending your own transactions is up to you, for
  example with [alloy](https://github.com/alloy-rs/alloy).
- `Feed::recv()` hands you messages through a buffer of 1024. If your bot takes longer
  per message than the feed produces them, the buffer fills up and you get a warning.
  Do slow work on another task.

### Lowest latency

If you can spare the cores:

```rust
let mut feed = rhfeed::Feed::builder()
    .source(rhfeed::MAINNET_FEED)
    .source(rhfeed::MAINNET_FEED)
    .verify(rhfeed::MAINNET_VERIFIER.clone())
    .busy_poll(true) // one core at 100%, plus one for recv()
    .senders(7)      // seven more
    .spawn();
```

- `busy_poll` reads the feed on a thread that never sleeps and keeps its caches warm.
  On our desktop the time from the socket read to `recv()` went from 95 to 61 µs at the
  median. On a Linux VM it also cut the wait between a packet reaching the kernel and
  our first read from 153 to 46 µs.
- How much it helps depends on the CPU. On AWS c7a (AMD) it saved 21 µs and on c7i
  (Intel) 60 µs. On c8g (Graviton4) it saved almost nothing, because that machine
  already gets about 42 µs without it. See [BENCHMARKS.md](BENCHMARKS.md#three-aws-instance-types).
- `senders(7)` recovers every sender on 7 spinning threads while the signature is being
  checked, so `tx.sender()` is free when the message arrives. Recovering them after
  `recv()` with `recover_senders` took 273 µs per message, mostly spent waking
  [rayon](https://crates.io/crates/rayon)'s threads.
- Read `recv()` from a task you `tokio::spawn`. Waking `#[tokio::main]`'s own thread
  took ~14 µs per message, waking a spawned task ~4 µs.
- `rhfeed --timing` shows where the time goes on your machine, stage by stage. Every
  message carries the same timestamps in `msg.timing`.

`rhfeed --busy-poll` and `copy_trade --busy` use these settings.

## Two connections are faster than one

- We opened two connections to the same public endpoint and compared arrival times.
  Each got about half the messages first. The other copy showed up about 30 ms later on
  average, sometimes 100 ms later. `Feed` keeps whichever copy arrives first, so you get
  the better of the two on every message. That's worth far more than all the decoding
  work in this crate.
- The public feed allows two connections per IP, and a third gets HTTP 429. Don't try to
  get around the limit with extra addresses: the feed blocks whole address ranges for
  that, and says so in its 403 response.
- Usually the two connections split the wins about evenly. Now and then one lands on a
  path that's about 9 ms slower and stays there. If a connection is first on fewer than
  1 in 10 of its last 500 messages, `Feed` replaces it.
- A connection that sends nothing at all for 15 s, not even a ping, is replaced too.
- When the program exits it prints, for each source, how often it was first and how far
  behind it was the rest of the time.

## How it differs from the Python version

- It connects to the public feed by default. The Python version expects a local relay,
  mostly because the public feed requires permessage-deflate. This client handles that
  itself.
- It checks the sequencer's signature on every message by default, against the known
  key, which costs about 24 µs. Use `--no-verify` to skip it (you'll need that for
  testnet).
- It can read from several sources at once and deliver each message once.
- If a transaction has a field that can't be valid (a 30-byte `to` address, a nonce
  over 64 bits) we keep only its hash and raw bytes. Python passes the odd value
  through. No node would accept such a transaction anyway.
- It decodes transactions only from L2Message entries (kind 3), like arbos does. Python
  decodes l2Msg for every kind, so an EthDeposit whose address happens to start with
  byte 4 comes out as a bogus transaction there.
- The WebSocket client is [yawc](https://github.com/infinitefield/yawc).
  [tokio-tungstenite](https://github.com/snapview/tokio-tungstenite) doesn't support
  permessage-deflate.

## Faster sender recovery with UltrafastSecp256k1

Feed signatures are checked against the known key with precomputed tables, built on
[k256](https://crates.io/crates/k256). Transaction senders still need an ECDSA
recovery each. By default that's [libsecp256k1](https://github.com/bitcoin-core/secp256k1)
through the [`secp256k1`](https://crates.io/crates/secp256k1) crate, the same C library
the Python version calls through [coincurve](https://github.com/ofek/coincurve).

[UltrafastSecp256k1](https://github.com/shrec/UltrafastSecp256k1) is an alternative you
turn on with `--features ufsecp`. On Linux it's about 5% faster. On Windows it's about
1.5x faster than the default build, but only because the `secp256k1` crate builds
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

Notes on the build:

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
need the feed, run Offchain Labs' [feed relay](https://docs.arbitrum.io/run-arbitrum-node/run-feed-relay)
once and point them all at it with `--feed relay`:

```bash
docker run -d --name relay -p 127.0.0.1:9642:9642 --entrypoint relay \
  offchainlabs/nitro-node:v3.11.4-7d5ac27 \
  --node.feed.output.addr=0.0.0.0 --chain.id=4663 \
  --node.feed.input.url=wss://feed.mainnet.chain.robinhood.com
```

The image is [offchainlabs/nitro-node](https://hub.docker.com/r/offchainlabs/nitro-node).
Keep in mind that the relay doesn't check signatures, and it hides reorgs because it
drops any message whose sequence number it has already sent. Leave signature checking
on, and connect to the feed directly if you care about reorgs.

## Repository layout

| Path | What's there |
|---|---|
| `src/codec.rs` | decoding frames and transactions, `recover_senders`, `SenderPool` |
| `src/verify.rs` | checking the sequencer's signature |
| `src/secp.rs` | ECDSA: recovery (libsecp256k1 or UltrafastSecp256k1) and the known-key check |
| `src/consume.rs` | `Feed`: connections, reconnects, dedup, reorgs, timing, busy polling |
| `src/main.rs` | the `rhfeed` command |
| `tests/golden.rs` | checks the decoder against the Python version's output in `tests/golden.jsonl` |
| `tests/robustness.rs` | feeds the decoder broken input and makes sure it doesn't crash |
| `tests/feed.rs` | runs `Feed` against local WebSocket servers |
| `tests/fixtures/` | real mainnet frames and a signed message (from the Python repo) |
| `examples/copy_trade.rs` | following wallets, the reading half of a copy-trading bot |
| `examples/bench.rs`, `bench/` | the Rust and Python benchmarks, a script to record the feed, and one to compare recordings from different places |

The Python scripts need the Python repo checked out next to this one, and
[uv](https://docs.astral.sh/uv/):

```bash
git clone https://github.com/chainstacklabs/robinhood-chain-sequencer-feed ../robinhood-chain-sequencer-feed
uv run --project ../robinhood-chain-sequencer-feed --extra dev python tests/golden.py > tests/golden.jsonl
```

## License

Apache-2.0, same as the Python version this code is derived from.
