//! No input may make the decoder panic. Real data broken at random, seeded so failures
//! reproduce. `RHFEED_ROUNDS` for a longer run.

use std::path::Path;

use bytes::Bytes;

use rhfeed::codec::decode_l2_message;
use rhfeed::{
    MAINNET_CHAIN_ID, MAINNET_SIGNER, MAINNET_VERIFIER, decode_transaction, frame_from_slice,
    parse_frame, recover_signer,
};

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
    rhfeed::decode_intents(tx).iter().for_each(touch_intent);
}

fn touch_intent(intent: &rhfeed::Intent) {
    let _ = (intent.describe(), sonic_rs::to_string(intent).unwrap());
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
                        .map(|m| rhfeed::codec::b64(m).unwrap())
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
        .flat_map(|l| parse_frame(&frame_from_slice(l.as_bytes()).unwrap(), None))
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
            // Whatever recovery attributes to the signer, the known-key check accepts.
            if recover_signer(entry, MAINNET_CHAIN_ID) == Some(MAINNET_SIGNER) {
                assert!(MAINNET_VERIFIER.accepts(entry));
            } else {
                let _ = MAINNET_VERIFIER.accepts(entry);
            }
        }
        for msg in parse_frame(&frame, None) {
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

/// ABI offset and length words are the favourite targets.
#[test]
fn mutated_calldata_never_panics() {
    use rhfeed::intents::{Call, Via, decode_call};

    let lines = capture();
    let mut datas: Vec<Vec<u8>> = lines
        .iter()
        .flat_map(|l| parse_frame(&frame_from_slice(l.as_bytes()).unwrap(), None))
        .flat_map(|m| m.txs)
        .map(|t| t.data().to_vec())
        .filter(|d| d.len() >= 4)
        .collect();
    let golden = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden_intents.jsonl"),
    )
    .unwrap();
    for line in golden.lines() {
        let r: serde_json::Value = serde_json::from_str(line).unwrap();
        if let Some(data) = r
            .get("call")
            .or(r.get("tx"))
            .and_then(|c| c["data"].as_str())
        {
            datas.push(hex::decode(&data[2..]).unwrap());
        }
    }
    let mut rng = Rng(0x5eed_0005);
    for _ in 0..rounds() * 5 {
        let source = &datas[rng.below(datas.len())];
        let mut data = mutate(&mut rng, source);
        if data.len() > 36 && rng.below(2) == 0 {
            let at = 4 + 32 * rng.below((data.len() - 4) / 32);
            let interesting: [u64; 6] = [
                0,
                32,
                64,
                data.len() as u64,
                (data.len() - 32) as u64,
                u64::MAX,
            ];
            let mut word = [0u8; 32];
            word[24..].copy_from_slice(&interesting[rng.below(6)].to_be_bytes());
            if rng.below(8) == 0 {
                word = [0xff; 32];
            }
            data[at..at + 32].copy_from_slice(&word);
        }
        let path: Vec<[u8; 20]> = (0..rng.below(4)).map(|_| [rng.next() as u8; 20]).collect();
        let call = Call {
            to: (rng.below(4) != 0).then(|| [rng.next() as u8; 20]),
            value: [rng.next() as u8; 32],
            data: &data,
            actor: (rng.below(2) == 0).then(|| [rng.next() as u8; 20]),
            via: Via::from_slice(&path).unwrap(),
            budget: &std::cell::Cell::new(rhfeed::intents::BUDGET),
        };
        let mut out = Vec::new();
        decode_call(&call, rng.below(10), &mut out);
        out.iter().for_each(touch_intent);
    }
}

#[test]
fn mutated_deposits_and_retryables_never_panic() {
    let golden =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden.jsonl"))
            .unwrap();
    let entries: Vec<String> = golden
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|g| g.get("parent").is_some() && !g["txs"].as_array().unwrap().is_empty())
        .map(|g| g["entry"].to_string())
        .collect();
    let mut rng = Rng(0x5eed_0006);
    for _ in 0..rounds() {
        let entry = &entries[rng.below(entries.len())];
        let json = format!(r#"{{"messages":[{entry}]}}"#);
        let frame = frame_from_slice(json.as_bytes()).unwrap();
        let e = &frame.entries()[0];
        let l2 = rhfeed::codec::l2_msg(e).unwrap().unwrap();
        let payload = mutate(&mut rng, &l2);
        if let Some(tx) =
            rhfeed::codec::decode_parent_chain_message(e.header().unwrap(), &payload, 4663)
        {
            touch(&tx);
            let _ = tx.data();
        }
    }
}
