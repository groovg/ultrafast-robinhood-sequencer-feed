# Benchmarks

Recorded on 2026-09-23 from 60 seconds of Robinhood Chain mainnet: 596 frames, 594
messages, 4,075 transactions. AMD Ryzen 9 9950X3D, Windows 11, single core. Each number
is the best of several rounds after a warm-up. Repeated runs came within 2% of each
other. The Rust columns were last updated on 2026-09-26.

## Time per message

"Feed path" is the work `Feed` does on each new message before you get it: parse the
JSON frame, check the sequencer's signature, decode the transactions. This is the delay
our code adds on top of the network.

| | Python | Rust + libsecp256k1 | Rust + ufsecp (clang-cl) |
|---|---:|---:|---:|
| **feed path, µs per message** | 111.6 | **28.8** | 30.3 |
| **per message, µs** | | | |
| frame JSON to decoded txs | 33.0 | 2.6 | 2.7 |
| signature check | 73.8 | **26.9** | 28.0 |
| signature check by recovering the signer | 73.8 | 47.8 | 37.4 |
| frame + signature + every sender | 543 | 301 | **225** |
| **per transaction, µs** | | | |
| to_bytes, selector, value, nonce, gas | 1.84 | 0.063 | 0.062 |
| + hash | 7.11 | 2.01 | 2.02 |
| + to (checksummed) | 12.3 | 2.32 | 2.33 |
| + sender | 63.9 | 37.2 | **27.0** |
| **ECDSA, µs** | | | |
| recover to address | 39.3 | 32.0 | **21.7** |
| verify against the known key (`FixedKey`) | | **12.2** | 12.7 |
| transactions/s on one core, sender included | 18.7k | 28.9k | **40.9k** |

Notes:

- The feed path is 3.9x faster than Python. What's left is mostly cryptography: about
  13 µs of keccak over the signed data (~10 KB on average) and about 12 µs for the
  ECDSA check.
- Every feed message is signed by the same key. `FixedKey` verifies against that key
  with precomputed tables (~370 KB each for the key and the generator) instead of
  recovering the signer: 12.2 µs against 32.0 µs. libsecp256k1 can only precompute
  for the generator, so it's built on k256's point arithmetic. A test checks it against
  libsecp256k1's verify.
- A verifier recovers the first message from a new signer and checks the later ones
  against its key. The mainnet key is built in.
- Senders still need recovery, one key each. UltrafastSecp256k1 built with clang is the
  fastest here (27.0 against 37.2 µs per transaction). The `secp256k1` crate 0.33 took
  recovery from 34.9 to 32.0 µs with MSVC.
- The parts that aren't cryptography got 10 to 30 times faster than Python. Some of that
  is just Rust vs Python. The rest is SIMD base64 (3.3x faster than the `base64` crate)
  and assembly keccak (1.2x faster than tiny-keccak).
- In absolute terms none of this is much. The feed sends about 10 messages and 70
  transactions per second. Network delays are measured in milliseconds, which is why
  racing connections (below) helps more than anything in this table.
- These numbers come from a tight loop, where everything stays in the CPU caches. In a
  live run messages are ~100 ms apart and every stage is slower. See "Live, stage by
  stage" below.

On Linux, `.github/workflows/bench.yml` (GitHub runner, AMD EPYC 7763, 4 vCPU, plain
`cargo build --release`, the 39-frame test fixture), 2026-09-26:

| µs | libsecp256k1 (gcc) | ufsecp (clang) |
|---|---:|---:|
| feed path | 34.7 | 34.7 |
| with 100 ms between messages (p50) | 76.0 | 81.5 |
| signature check against the known key | 32.7 | 32.6 |
| signature check by recovering the signer | 49.6 | 50.4 |
| ECDSA recover | 41.9 | 42.4 |
| `FixedKey` verify | 24.2 | 23.9 |

The feed path on this runner type was 55.2 µs before the known-key check. The known
key gains less here than on Windows (1.7x against 2.9x), where MSVC slows down
libsecp256k1.

The feed path starts after the WebSocket library has inflated the frame. The public feed
compresses every frame (permessage-deflate), and inflating one takes 8.9 µs with
zlib-rs, which we use, or 11.9 µs with miniz_oxide, yawc's default. Measured by
recompressing the recording the way the protocol does it, since the feed's own
compressed bytes aren't recorded. Tiny-message WebSocket benchmarks don't show this
cost, and at ~10 frames a second it's the only part of the WebSocket layer that
matters.

How the Rust feed path went from 61.0 µs to 28.8 µs (libsecp256k1, same recording):

| Change | Feed path |
|---|---:|
| straight port from Python | 61.0 µs |
| SIMD base64 (`base64-simd`) | 57.8 µs |
| assembly keccak (`keccak-asm`) | 55.4 µs |
| decode l2Msg once, hash the signed data as it's built | 54.3 µs |
| final run on 2026-09-23 | 52.4 µs |
| check the signature against the known key | 28.8 µs |

Borrowing the frame's strings instead of copying them (serde copies a `Cow<str>` inside
an `Option`) took the JSON parse from 1.3 to 1.0 µs, which is within the noise of the
whole path.

On this machine, differences smaller than about 0.3 µs are noise.

## Live, stage by stage

`rhfeed --feed mainnet --feed mainnet --seconds 60 --timing` on the same desktop,
2026-09-26. "Before" is from the start of that day. The other two ran back to back,
the last one with `--busy-poll`. p50 / p99 in µs:

| stage | before | after | after, busy poll |
|---|---:|---:|---:|
| TLS decrypt | 10.7 / 17.5 | 7.3 / 18.4 | 4.0 / 15.5 |
| WebSocket + inflate | 17.7 / 89.2 | 17.7 / 85.0 | 14.2 / 56.1 |
| JSON parse | 19.8 / 32.2 | 9.9 / 27.0 | 1.8 / 8.2 |
| signature check | 61.6 / 132.6 | 46.1 / 217.0 | 36.0 / 146.9 |
| decode transactions | 4.0 / 9.8 | 3.9 / 11.4 | 1.1 / 4.2 |
| dedup, queue | 1.6 / 3.0 | 1.1 / 3.0 | 1.0 / 2.2 |
| channel to `recv()` | 12.9 / 23.7 | 4.0 / 62.8 | 1.0 / 3.8 |
| **total, last socket read to `recv()`** | **128.7 / 251.5** | **94.9 / 332.7** | **60.9 / 219.0** |

- Live, every stage is several times slower than in the tight loop: the JSON parse
  takes 10 µs live and 1 µs in the loop. Frames come ~100 ms apart, and in between the
  caches go cold. `examples/bench.rs` reproduces this with a 100 ms sleep before each
  message: 67.6-70.4 µs against 29-30 µs in the loop.
- `busy_poll` keeps the thread awake and reruns the last frame every millisecond, so
  the JSON and decode rows drop to their tight-loop values. It also shortens the wait
  between a packet arriving and the task reading it, which the table doesn't include.
- The channel row dropped because the CLI now reads in a spawned task: waking main's
  own thread took 13.6 µs in a separate test, a spawned task 3.6 µs.
- Traffic differed between runs (4,532, 4,193 and 4,236 transactions), which moves the
  signature and decode rows.

## Senders for copy trading

A copy-trading bot needs the sender of each candidate transaction: one ECDSA recovery
each, about 7 per message. `recover_senders` spreads them over rayon's threads, which
takes 95-105 µs in a tight loop. Between feed messages rayon's threads fall asleep,
and after a 20 ms pause it took ~225 µs. `SenderPool` keeps its threads spinning and
warm.

| µs per message, p50 | `recover_senders` | `SenderPool`, 7 threads |
|---|---:|---:|
| `examples/bench.rs`, 20 ms before each message | 222.9-227.3 | 64.2-67.9 |
| live, `rhfeed --timing --sender ...`, 30 s | 273.0 (p99 540) | 56.4 (p99 194) |

With `FeedBuilder::senders` the feed does this on a pool while it checks the
signature. Live with `--busy-poll`, a message reached `recv()` with every sender known
78.2 µs after the last socket read (p50, p99 391). Before, that took about 370 µs.

## Which ECDSA library

Measured on 2026-09-23 with the `secp256k1` crate 0.31, before feed signatures were
checked against the known key, so the feed path figures here still include a recovery.
Recovery still matters for transaction senders.

Our first numbers said UltrafastSecp256k1 was 1.65x faster than libsecp256k1. It turned
out the comparison wasn't fair. On Windows, the `secp256k1` crate compiles libsecp256k1
with MSVC, which has no 128-bit integers, so libsecp256k1 falls back to slower code.
Compiled with clang, it's as fast as UltrafastSecp256k1.

Recovering a public key, µs:

| Machine | libsecp256k1 | UltrafastSecp256k1 |
|---|---:|---:|
| Ryzen 9 9950X3D, Windows, MSVC | 34.4 | 32.3 |
| Ryzen 9 9950X3D, Windows, clang-cl | 21.4 | 21.1 |
| EPYC 7763 (GitHub runner), Linux, gcc / clang | 45.0 | 42.5 |

On Linux, the feed path on that runner was 55.2 µs with libsecp256k1 and 52.7 µs with
UltrafastSecp256k1, about 5% apart. So on Linux the default build is fine, and ufsecp
buys a few percent. On Windows, build with clang either way. The Linux numbers come from
`.github/workflows/bench.yml`, which you can rerun with `gh workflow run bench`.

## Zen 4 in AWS, and what AVX-512 buys

c7a.large (AMD EPYC 9R14, Zen 4, Linux), same recording, µs per message unless noted,
2026-09-23 (before the known-key check, so the feed path includes a recovery).
"generic" is a plain `cargo build --release`, "native" adds `-C target-cpu=native`:

| | generic | native | native, scalar keccak | native + ufsecp |
|---|---:|---:|---:|---:|
| feed path | 68.7 | 66.6 | 67.6 | **62.9** |
| JSON parse (sonic-rs) | 2.40 | 1.71 | 1.70 | 1.78 |
| transaction hash, µs per tx | 3.26 | 3.13 | 3.25 | 3.13 |
| ECDSA recover, µs | 40.5 | 40.6 | 40.5 | 37.2 |
| every sender of a message, one by one | 307 | 305 | 306 | 280 |
| every sender of a message, `recover_senders` (2 cores) | 184 | 183 | 183 | 170 |

- `target-cpu=native` makes sonic-rs 29% faster. keccak-asm switches to OpenSSL's
  AVX-512 code, which is only 4% faster per hash here.
- ufsecp saves 8% on each ECDSA recovery.
- `recover_senders` spreads a message's senders across cores. Even with two cores it
  cuts the time by 40%. With more cores the gain grows with the number of transactions.
- We also tried [asmcrypto](https://crates.io/crates/asmcrypto), which recovers 8
  signatures at once with AVX-512 IFMA. It took 53.6 µs per signature here and 28.6 µs
  on the Zen 5 desktop, slower than libsecp256k1 on both (40.5 and 21.4 µs), so we
  removed it again.
- On Windows, forcing keccak-asm's AVX-512 variant made the benchmark hang. The
  cryptogams AVX-512 and AVX2 scripts it would use don't save the registers Windows
  requires a function to keep (xmm6 to xmm15), so they corrupt the caller's state. The
  default build on Windows uses the scalar code, which does.

## Two connections to the same feed

`rhfeed --feed mainnet --feed mainnet --seconds 30`, 2026-09-23, 292 messages:

| | first | second | average delay when second | worst delay |
|---|---:|---:|---:|---:|
| connection 1 | 144 | 148 | 30.2 ms | 88.8 ms |
| connection 2 | 148 | 144 | 30.9 ms | 108.3 ms |

Neither connection was faster overall. Each one lost about half the time, by about
30 ms on average. Taking the first copy of every message saves those 30 ms on half the
messages. That's roughly a thousand times more than the entire feed path above.

A third connection from the same IP was refused with HTTP 429.

## Where to run it

In September 2026 we recorded the feed at the same time from several AWS regions, with
clocks synced through Amazon Time Sync, and compared when each place got the same
message (`bench/regions.py`). Two rounds, 30 and 15 minutes, about 27,000 messages:

| Region | Median behind the fastest place |
|---|---:|
| us-east-1 (Virginia) | fastest in both rounds |
| ca-central-1 (Montreal) | ~12 ms |
| us-west-2 (Oregon) | ~18 ms |
| us-east-2 (Ohio) | ~31 ms |
| eu-central-1 (Frankfurt) | ~110 ms |

What we took from it:

- The feed is served through Cloudflare, so what counts is the route from your
  Cloudflare location to wherever the feed is served from. Distance to the sequencer
  doesn't predict it: Oregon was ahead of Ohio.
- Virginia was the best place to read the feed from.
- Machines in the same region can differ too. Two instances in Virginia were about
  10 ms apart. If you care about milliseconds, try a few and keep the fastest.
- Two connections from one machine usually trade places message by message, a few ms
  apart. Sometimes one gets stuck on a slower path for a long time, which is why
  `Feed` replaces a connection that keeps losing.

## Running the benchmarks yourself

```bash
# record 60 s of the feed (8.7 MB, not committed)
uv run --project ../robinhood-chain-sequencer-feed python bench/capture.py bench/capture.jsonl 60

# Python
uv run --project ../robinhood-chain-sequencer-feed python bench/bench.py bench/capture.jsonl

# Rust
cargo run --release --example bench -- bench/capture.jsonl

# where the time goes on the live feed, per stage
cargo run --release -- --feed mainnet --feed mainnet --seconds 60 --timing

# compare arrival times recorded in several places (seq<TAB>received_at per line)
python bench/regions.py place1=a.tsv place2=b.tsv
UFSECP_LIB_DIR=<ufsecp build dir> [CLANG_RT_DIR=<llvm>/lib/clang/22/lib/windows] \
  cargo run --release --example bench --features ufsecp -- bench/capture.jsonl
```

If you compare several ufsecp builds, give each one its own `CARGO_TARGET_DIR`.
Otherwise cargo won't relink when only `UFSECP_LIB_DIR` changes.
