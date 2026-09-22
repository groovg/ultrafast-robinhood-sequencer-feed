# ultrafast-robinhood-sequencer-feed

Decode Robinhood Chain's sequencer feed — the ordered transactions, before any RPC
can show them — in Rust.

This started as a port of Chainstack's
[robinhood-chain-sequencer-feed](https://github.com/chainstacklabs/robinhood-chain-sequencer-feed),
which stays the reference: the Rust decoder is tested field by field against it. Its [README](https://github.com/chainstacklabs/robinhood-chain-sequencer-feed#readme)
explains what the feed is, why there is no public mempool, and what the decoded data can
and cannot tell you.

```bash
docker compose up -d --wait relay           # the official Nitro relay, see docker-compose.yml
cargo run --release                         # stream decoded transactions from it
cargo run --release -- --feed mainnet --verify
cargo test
```

## Layout

| | |
|---|---|
| `src/` | the crate: `codec` (decoder), `verify` (feed signatures), `secp` (ECDSA recovery), `consume` (WebSocket consumer), `main` (CLI) |
| `tests/golden.rs` | holds the decoder to the baseline, from `tests/golden.jsonl` |
| `tests/golden.py` | writes `golden.jsonl` from the baseline |
| `tests/fixtures/` | real mainnet frames and a signed message, from upstream |

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
- **ECDSA via libsecp256k1**, the same C library coincurve wraps on the Python side.

## License

Apache-2.0, as upstream. The Rust sources are a derivative work of the baseline; see
[NOTICE](NOTICE).
