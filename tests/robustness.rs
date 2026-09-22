//! The decoder reads untrusted bytes from the network, so no input may make it panic.
//!
//! We take real transactions, batches and frames from the recording, break them at
//! random (flip bits, cut them short, add junk, rewrite length prefixes) and read every
//! field, including the lazy ones. The random generator is seeded, so failures
//! reproduce. Set `RHFEED_ROUNDS` for a longer run than CI does. 500,000 rounds in
//! release mode passed on 2026-09-23.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;

use rhfeed::codec::decode_l2_message;
use rhfeed::{MAINNET_CHAIN_ID, decode_transaction, frame_from_slice, parse_frame, recover_signer};

/// xorshift64*: small, fast, and good enough to pick bytes to break.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn mutate(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    for _ in 0..=rng.below(4) {
        match rng.below(6) {
            0 if !out.is_empty() => {
                let i = rng.below(out.len());
                out[i] ^= 1 << rng.below(8);
            }
            1 if !out.is_empty() => {
                let i = rng.below(out.len());
                out[i] = rng.next() as u8;
            }
            2 => out.truncate(rng.below(out.len() + 1)),
            3 => out.extend((0..rng.below(64)).map(|_| rng.next() as u8)),
            // Length prefixes are where a decoder trusts the input most.
            4 if !out.is_empty() => {
                let i = rng.below(out.len());
                out[i] =
                    [0x00, 0x7f, 0x80, 0xb7, 0xb8, 0xbf, 0xc0, 0xf7, 0xf8, 0xff][rng.below(10)];
            }
            _ => {
                let i = rng.below(out.len() + 1);
                out.insert(i, rng.next() as u8);
            }
        }
    }
    out
}

fn touch(tx: &rhfeed::Tx) {
    let _ = (
        tx.hash_hex(),
        tx.to(),
        tx.sender(),
        tx.selector_hex(),
        tx.kind(),
    );
    let _ = (tx.value_dec(), tx.value_be(), tx.nonce, tx.gas, tx.data_len);
}

fn rounds() -> usize {
    std::env::var("RHFEED_ROUNDS")
        .ok()
        .and_then(|r| r.parse().ok())
        .unwrap_or(2_000)
}

fn capture() -> Vec<String> {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/frames.jsonl"),
    )
    .unwrap()
    .lines()
    .filter(|l| !l.trim().is_empty())
    .map(str::to_owned)
    .collect()
}

/// Every l2Msg in the capture, raw.
fn l2_messages(lines: &[String]) -> Vec<Vec<u8>> {
    lines
        .iter()
        .flat_map(|l| {
            let frame = frame_from_slice(l.as_bytes()).unwrap();
            frame
                .entries()
                .iter()
                .filter_map(|e| {
                    e.incoming()?
                        .l2_msg
                        .as_deref()
                        .map(|m| B64.decode(m).unwrap())
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn mutated_transactions_never_panic() {
    let lines = capture();
    let raws: Vec<Bytes> = lines
        .iter()
        .flat_map(|l| parse_frame(&frame_from_slice(l.as_bytes()).unwrap(), true))
        .flat_map(|m| m.txs)
        .map(|t| t.raw)
        .collect();
    let mut rng = Rng(0x5eed_0001);
    for _ in 0..rounds() {
        let raw = &raws[rng.below(raws.len())];
        if let Some(tx) = decode_transaction(Bytes::from(mutate(&mut rng, raw))) {
            touch(&tx);
        }
    }
}

#[test]
fn mutated_batches_never_panic() {
    let msgs = l2_messages(&capture());
    let mut rng = Rng(0x5eed_0002);
    for _ in 0..rounds() {
        let msg = &msgs[rng.below(msgs.len())];
        for tx in decode_l2_message(&Bytes::from(mutate(&mut rng, msg))) {
            touch(&tx);
        }
    }
}

#[test]
fn mutated_frames_never_panic() {
    let lines = capture();
    let mut rng = Rng(0x5eed_0003);
    for _ in 0..rounds() / 10 {
        let line = &lines[rng.below(lines.len())];
        let bytes = mutate(&mut rng, line.as_bytes());
        // Most mutations break the JSON; the ones that survive exercise the rest.
        let Ok(frame) = frame_from_slice(&bytes) else {
            continue;
        };
        for entry in frame.entries() {
            let _ = recover_signer(entry, MAINNET_CHAIN_ID);
        }
        for msg in parse_frame(&frame, true) {
            msg.txs.iter().for_each(touch);
        }
    }
}

#[test]
fn random_bytes_never_panic() {
    let mut rng = Rng(0x5eed_0004);
    for _ in 0..rounds() {
        let bytes: Vec<u8> = (0..rng.below(300)).map(|_| rng.next() as u8).collect();
        if let Some(tx) = decode_transaction(Bytes::from(bytes.clone())) {
            touch(&tx);
        }
        for tx in decode_l2_message(&Bytes::from(bytes)) {
            touch(&tx);
        }
    }
}
