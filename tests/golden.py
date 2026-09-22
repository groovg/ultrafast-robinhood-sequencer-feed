"""Dump what the Python baseline decodes, so the Rust port can be held to it field by field.

    uv run --project ../robinhood-chain-sequencer-feed --extra dev python tests/golden.py > tests/golden.jsonl

Run it with the baseline checked out next to this repository (or at $RHFEED_BASELINE):

    git clone https://github.com/chainstacklabs/robinhood-chain-sequencer-feed ../robinhood-chain-sequencer-feed

Two kinds of line: one per frame in `tests/fixtures/frames.jsonl` (real traffic), keyed by
its index among the non-empty lines, and one
per envelope signed from the baseline's `tests/test_codec.py` templates (every layout the decoder models,
plus a pre-EIP-155 legacy signature, which the capture does not contain).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = Path(os.environ.get("RHFEED_BASELINE", ROOT.parent / "robinhood-chain-sequencer-feed"))
sys.path.insert(0, str(BASELINE / "tests"))

from test_codec import ACCOUNT, TEMPLATES  # noqa: E402

from rhfeed import decode_transaction, parse_frame  # noqa: E402


def tx_record(tx, raw: bool = False) -> dict:
    # Raw bytes only where the Rust side has nothing else to decode from.
    return ({"raw": tx.raw.hex()} if raw else {}) | {
        "hash": tx.hash,
        "tx_type": tx.tx_type,
        "to": tx.to,
        "selector": tx.selector_hex,
        "nonce": tx.nonce,
        "gas": tx.gas,
        "value": str(tx.value),
        "data_len": tx.data_len,
        "kind": tx.kind,
        "sender": tx.sender,
    }


def main() -> None:
    frames = (ROOT / "tests" / "fixtures" / "frames.jsonl").read_text().splitlines()
    for index, line in enumerate(f for f in frames if f.strip()):
        messages = [
            {
                "seq": m.seq,
                "l1_kind": m.l1_kind,
                "l1_sender": m.l1_sender,
                "timestamp": m.timestamp,
                "block_hash": m.block_hash,
                "delayed_messages_read": m.delayed_messages_read,
                "l1_block_number": m.l1_block_number,
                "txs": [tx_record(t) for t in m.txs],
            }
            for m in parse_frame(json.loads(line))
        ]
        print(json.dumps({"line": index, "messages": messages}))

    pre155 = {k: v for k, v in TEMPLATES["legacy"].items() if k != "chainId"}
    for name, spec in [*sorted(TEMPLATES.items()), ("pre155", pre155)]:
        raw = bytes(ACCOUNT.sign_transaction(spec).raw_transaction)
        print(json.dumps({"template": name, "tx": tx_record(decode_transaction(raw), raw=True)}))


if __name__ == "__main__":
    main()
