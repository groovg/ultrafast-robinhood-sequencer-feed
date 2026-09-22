"""Record raw frames off a feed, one JSON frame per line, for the benchmarks.

    uv run --project ../robinhood-chain-sequencer-feed python bench/capture.py bench/capture.jsonl 60 [url]
"""

import asyncio
import sys
import time

import websockets


async def main(path: str, seconds: float, url: str) -> None:
    headers = {"Arbitrum-Feed-Client-Version": "2"}
    async with websockets.connect(
        url, additional_headers=headers, compression="deflate", max_size=2**24
    ) as ws:
        end = time.monotonic() + seconds
        with open(path, "w") as out:
            while (left := end - time.monotonic()) > 0:
                try:
                    frame = await asyncio.wait_for(ws.recv(), left)
                except TimeoutError:
                    break
                out.write(frame if isinstance(frame, str) else frame.decode())
                out.write("\n")


if __name__ == "__main__":
    url = sys.argv[3] if len(sys.argv) > 3 else "wss://feed.mainnet.chain.robinhood.com"
    asyncio.run(main(sys.argv[1], float(sys.argv[2]), url))
