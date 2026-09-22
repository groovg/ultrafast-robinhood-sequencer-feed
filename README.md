# ultrafast-robinhood-sequencer-feed

Decode Robinhood Chain's sequencer feed — the ordered transactions, before any RPC can
show them — in Rust.

A port of Chainstack's
[robinhood-chain-sequencer-feed](https://github.com/chainstacklabs/robinhood-chain-sequencer-feed),
which stays the reference: `tests/golden.rs` holds the decoder to it field by field over
real mainnet frames (`tests/fixtures/`) and signed envelopes of every layout.

```bash
cargo test
```

`tests/golden.jsonl` is written by the baseline, checked out next to this repository:

```bash
git clone https://github.com/chainstacklabs/robinhood-chain-sequencer-feed ../robinhood-chain-sequencer-feed
uv run --project ../robinhood-chain-sequencer-feed --extra dev python tests/golden.py > tests/golden.jsonl
```

## License

Apache-2.0, as upstream; see [NOTICE](NOTICE).
