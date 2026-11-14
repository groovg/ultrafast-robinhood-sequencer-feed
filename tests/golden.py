"""Dump what the Python baseline decodes, so the Rust port can be held to it field by field.

    uv run --project ../robinhood-chain-sequencer-feed --extra dev python tests/golden.py > tests/golden.jsonl

With the baseline checked out next to this repository (or at $RHFEED_BASELINE). Lines: every
frame of `tests/fixtures/frames.jsonl`, envelopes signed from the baseline's templates, its
l2Msg refusal cases, and its parent-chain entries.
"""

from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = Path(os.environ.get("RHFEED_BASELINE", ROOT.parent / "robinhood-chain-sequencer-feed"))
sys.path.insert(0, str(BASELINE / "tests"))

import test_codec  # noqa: E402
from test_codec import ACCOUNT, TEMPLATES  # noqa: E402

from rhfeed import decode_l2_message, decode_transaction, parse_frame  # noqa: E402


def tx_record(tx, raw: bool = False) -> dict:
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
                "request_id": m.request_id,
                "from_parent_chain": m.from_parent_chain,
                "txs": [tx_record(t) for t in m.txs],
            }
            for m in parse_frame(json.loads(line))
        ]
        print(json.dumps({"line": index, "messages": messages}))

    pre155 = {k: v for k, v in TEMPLATES["legacy"].items() if k != "chainId"}
    for name, spec in [*sorted(TEMPLATES.items()), ("pre155", pre155)]:
        raw = bytes(ACCOUNT.sign_transaction(spec).raw_transaction)
        l2 = len(decode_l2_message(bytes([test_codec.L2_SIGNED_TX]) + raw))
        tx = tx_record(decode_transaction(raw), raw=True)
        print(json.dumps({"template": name, "l2": l2, "tx": tx}))

    for name, l2_msg in l2_messages():
        hashes = [t.hash for t in decode_l2_message(l2_msg)]
        print(json.dumps({"l2msg": name, "hex": l2_msg.hex(), "hashes": hashes}))

    for name, entry, chain_id in parent_chain_entries():
        (msg,) = parse_frame({"messages": [entry]}, chain_id=chain_id)
        txs = [tx_record(t) | {"data": t.data.hex()} for t in msg.txs]
        print(json.dumps({"parent": name, "entry": entry, "chain_id": chain_id, "txs": txs}))


def parent_chain_entries():
    """The baseline's parent-chain entries and the malformed variants our typed frame parses."""
    import test_parent_chain as t

    for seq, node in sorted(t.NODE.items()):
        yield f"{seq}", t.ENTRIES[seq], node[0]
        yield f"{seq}-no-chain-id", t.ENTRIES[seq], None
    yield "18382981-wrong-chain", t.ENTRIES[18382981], 4663
    for cut in (0, 51):
        yield f"deposit-cut-{cut}", t._with_payload(18382979, t._payload(18382979)[:cut]), 99801
    retryable = t._payload(18382981)
    yield "retryable-8-words", t._with_payload(18382981, retryable[:287]), 99801
    yield "retryable-no-data", t._with_payload(18382981, retryable[:288]), 99801
    yield "retryable-short-tail", t._with_payload(18382981, retryable[:-1]), 99801
    gas = bytearray(retryable)
    gas[6 * 32 + 23] = 1
    yield "retryable-gas-past-uint64", t._with_payload(18382981, bytes(gas)), 99801
    no_id = copy.deepcopy(t.ENTRIES[18382979])
    del no_id["message"]["message"]["header"]["requestId"]
    yield "deposit-no-request-id", no_id, 99801
    for seq in (18382979, 18382981):
        yield f"{seq}-null-request-id", t._with_header(seq, requestId=None), t.NODE[seq][0]
        yield f"{seq}-null-sender", t._with_header(seq, sender=None), t.NODE[seq][0]
    yield "retryable-null-base-fee", t._with_header(18382981, baseFeeL1=None), 99801
    bad = copy.deepcopy(t.ENTRIES[18382981])
    bad["message"]["message"]["l2Msg"] = "abc"
    yield "retryable-not-base64", bad, 99801


def l2_messages():
    """A signed transaction beside each entry the baseline's refusal tests parametrize."""
    t = test_codec
    first = t._signed_l2_msg(0)
    for test in (
        t.test_an_entry_arbos_refuses_voids_its_siblings,
        t.test_a_valid_unsigned_entry_keeps_its_siblings,
    ):
        for i, param in enumerate(test.pytestmark[0].args[1]):
            entry = param.values[0] if hasattr(param, "values") else param
            yield getattr(param, "id", None) or f"{test.__name__}[{i}]", t._batch(first, entry)
    yield "too-deep-sibling", t._batch(first, t._nest(t._signed_l2_msg(1), t.MAX_BATCH_DEPTH))
    yield "empty-entry", t._batch(first, b"", t._signed_l2_msg(1))
    yield "truncated-tail", t._batch(first) + (999).to_bytes(8, "big") + b"\x04"
    yield "two-entries", t._batch(first, t._signed_l2_msg(1))
    to = TEMPLATES["eip1559"]["to"]
    auth = ACCOUNT.sign_authorization({"chainId": 4663, "address": to, "nonce": 12})
    raw = ACCOUNT.sign_transaction(
        {**TEMPLATES["eip1559"], "type": 4, "nonce": 11, "authorizationList": [auth]}
    ).raw_transaction
    yield "eip7702", bytes([t.L2_SIGNED_TX]) + bytes(raw)


if __name__ == "__main__":
    main()
