"""Dump what the Python baseline's intent decoders return, so the Rust port can be held to it.

    uv run --project ../robinhood-chain-sequencer-feed --extra dev python tests/golden_intents.py > tests/golden_intents.jsonl

Every call the baseline's own test suite decodes (recorded by wrapping `decode_call` and
`decode_intents`, then decoded again with the real table), plus every frame transaction.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
BASELINE = Path(os.environ.get("RHFEED_BASELINE", ROOT.parent / "robinhood-chain-sequencer-feed"))

import rhfeed  # noqa: E402
import rhfeed.cli  # noqa: E402
import rhfeed.intents as intents  # noqa: E402
from rhfeed import parse_frame  # noqa: E402
from rhfeed.cli import describe  # noqa: E402
from rhfeed.intents import Call  # noqa: E402

DECODE_CALL = intents.decode_call
DECODE_INTENTS = intents.decode_intents
calls: set = set()
txs: set = set()
# ~76,000 prefix calls, covered compactly by the prefix lines instead.
PREFIX_TEST = "test_truncated_calldata_never_raises"


class Tracker:
    test = ""

    def pytest_runtest_setup(self, item):
        Tracker.test = item.name


def recording_call(call, depth=0):
    if depth == 0 and Tracker.test != PREFIX_TEST:
        calls.add((call.to, call.value, bytes(call.data), call.actor, tuple(call.via)))
    return DECODE_CALL(call, depth)


def recording_intents(tx):
    txs.add((tx.to_bytes, tx.value, bytes(tx.data)))
    return DECODE_INTENTS(tx)


def hx(value: bytes | None) -> str | None:
    return None if value is None else "0x" + value.hex()


def intent_record(i) -> dict:
    return {
        "kind": i.kind,
        "actor": hx(i.actor),
        "via": [hx(v) for v in i.via],
        "payer": hx(i.payer),
        "token_in": hx(i.token_in),
        "token_out": hx(i.token_out),
        "amount_in": None if i.amount_in is None else str(i.amount_in),
        "amount_out": None if i.amount_out is None else str(i.amount_out),
        "exact_in": i.exact_in,
        "recipient": hx(i.recipient),
        "order_id": hx(i.order_id),
        "describe": describe(i),
    }


def fits(value) -> bool:
    return isinstance(value, int) and 0 <= value < 1 << 256


def sort_key(t: tuple):
    return repr(t)


def main() -> None:
    # Before collection, so the tests' `from ... import` lines get the recording versions.
    intents.decode_call = recording_call
    intents.decode_intents = rhfeed.decode_intents = rhfeed.cli.decode_intents = recording_intents
    with contextlib.redirect_stdout(sys.stderr):
        pytest.main([str(BASELINE / "tests"), "-q", "-p", "no:cacheprovider", "--rootdir", str(BASELINE)], plugins=[Tracker()])
    intents.decode_call = DECODE_CALL
    intents.decode_intents = rhfeed.decode_intents = rhfeed.cli.decode_intents = DECODE_INTENTS

    frame_txs = []
    for line in (ROOT / "tests" / "fixtures" / "frames.jsonl").read_text().splitlines():
        if line.strip():
            for msg in parse_frame(json.loads(line)):
                frame_txs.extend(msg.txs)
    covered = {(t.to_bytes, t.value, bytes(t.data)) for t in frame_txs}

    skipped = 0
    for to, value, data, actor, via in sorted(calls, key=sort_key):
        plain = actor is None and via == ((to,) if to is not None else ())
        if plain and (to, value, data) in covered:
            continue
        if not fits(value):
            skipped += 1
            continue
        out = DECODE_CALL(Call(to, value, data, actor, via))
        call = {"to": hx(to), "value": str(value), "data": hx(data), "actor": hx(actor), "via": [hx(v) for v in via]}
        print(json.dumps({"call": call, "intents": [intent_record(i) for i in out]}))
    for to, value, data in sorted(txs, key=sort_key):
        if (to, value, data) in covered:
            continue
        if not fits(value):
            skipped += 1
            continue
        out = DECODE_INTENTS(SimpleNamespace(to_bytes=to, value=value, data=data))
        tx = {"to": hx(to), "value": str(value), "data": hx(data)}
        print(json.dumps({"tx": tx, "intents": [intent_record(i) for i in out]}))
    for t in frame_txs:
        print(json.dumps({"hash": t.hash, "intents": [intent_record(i) for i in DECODE_INTENTS(t)]}))
    # Runs [first length, last length, intents] of prefixes that decode to something; every
    # other prefix must decode to nothing. Deploys are left out (empty `to` in via).
    for t in frame_txs:
        if t.to_bytes is None:
            continue
        found = []
        for n in range(len(t.data) + 1):
            out = DECODE_CALL(Call(t.to_bytes, t.value, t.data[:n], None, (t.to_bytes,)))
            if not out:
                continue
            record = [intent_record(i) for i in out]
            if found and found[-1][1] == n - 1 and found[-1][2] == record:
                found[-1][1] = n
            else:
                found.append([n, n, record])
        print(json.dumps({"prefixes": t.hash, "decoded": found}))
    print(f"{len(calls)} calls and {len(txs)} txs recorded, {skipped} skipped", file=sys.stderr)


if __name__ == "__main__":
    main()
