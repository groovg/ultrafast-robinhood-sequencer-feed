"""The Python half of the Python-vs-Rust comparison; `examples/bench.rs` is the other.

    uv run --project ../robinhood-chain-sequencer-feed python bench/bench.py [capture.jsonl]

Same rows, same method (best of N rounds, one warm-up), same capture. Frames are parsed
with orjson, as the consumer does.
"""

from __future__ import annotations

import base64
import sys
import time
from pathlib import Path

from coincurve import PublicKey
from eth_hash.auto import keccak
from orjson import loads

from rhfeed import MAINNET_CHAIN_ID, decode_transaction, parse_frame, recover_signer
from rhfeed.verify import signature_hash

ROOT = Path(__file__).resolve().parents[1]


def best_of(rounds: int, items: int, fn) -> float:
    fn()
    best = float("inf")
    for _ in range(rounds):
        started = time.perf_counter()
        fn()
        best = min(best, (time.perf_counter() - started) / items)
    return best * 1e6


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "tests" / "fixtures" / "frames.jsonl"
    lines = [line for line in path.read_text().splitlines() if line.strip()]
    frames = [loads(line) for line in lines]
    entries = [e for f in frames for e in (f.get("messages") or ()) if e.get("signatureV2")]
    messages = sum(len(f.get("messages") or ()) for f in frames)
    raws = [t.raw for f in frames for m in parse_frame(f) for t in m.txs]

    print(f"{len(lines)} frames, {messages} messages, {len(raws)} tx from {path}")
    print("recovery backend: coincurve (libsecp256k1)\n")
    print(f"{'per transaction':<44}{'us':>10}")

    def row(label, rounds, read):
        def run():
            for raw in raws:
                read(decode_transaction(raw))

        print(f"{label:<44}{best_of(rounds, len(raws), run):>10.3f}")

    row("to_bytes, selector, value, nonce, gas", 20, lambda t: (t.to_bytes, t.selector, t.value, t.nonce, t.gas))
    row("+ hash", 20, lambda t: (t.to_bytes, t.selector, t.hash))
    row("+ to (checksummed)", 20, lambda t: (t.to_bytes, t.selector, t.hash, t.to))
    row("+ sender", 5, lambda t: (t.to_bytes, t.selector, t.hash, t.to, t.sender))

    print(f"\n{'per message':<44}{'us':>10}")

    def frames_only():
        for line in lines:
            parse_frame(loads(line))

    print(f"{'frame JSON -> decoded txs':<44}{best_of(10, messages, frames_only):>10.3f}")

    def verify():
        for e in entries:
            recover_signer(e, MAINNET_CHAIN_ID)

    print(f"{'feed signature check':<44}{best_of(5, len(entries), verify):>10.3f}")

    def everything():
        for line in lines:
            frame = loads(line)
            for e, m in zip(frame.get("messages") or (), parse_frame(frame), strict=True):
                recover_signer(e, MAINNET_CHAIN_ID)
                for t in m.txs:
                    (t.hash, t.to, t.sender)

    print(f"{'all of it: frame, signature, every sender':<44}{best_of(3, messages, everything):>10.3f}")

    sigs = []
    for e in entries:
        sig = base64.b64decode(e["signatureV2"])
        sigs.append((signature_hash(e, MAINNET_CHAIN_ID), sig[:64] + bytes((sig[64] % 27,))))

    def recover():
        for digest, sig in sigs:
            key = PublicKey.from_signature_and_message(sig, digest, hasher=None)
            keccak(key.format(compressed=False)[1:])[-20:]

    print(f"\n{'ECDSA recover -> address':<44}{'us':>10}")
    print(f"{'coincurve (libsecp256k1)':<44}{best_of(20, len(sigs), recover):>10.3f}")

    def full():
        for raw in raws:
            decode_transaction(raw).sender

    print(f"\none core, full decode incl. sender: ~{1e6 / best_of(5, len(raws), full):,.0f} tx/s")


if __name__ == "__main__":
    main()
