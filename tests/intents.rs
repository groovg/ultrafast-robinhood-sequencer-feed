//! Field-by-field parity with the Python baseline's intent decoders.
//!
//! `tests/golden_intents.jsonl` is written by `tests/golden_intents.py` from the
//! baseline: every call its own test suite decodes, every transaction in
//! `tests/fixtures/frames.jsonl`, and every prefix of their calldata.

use std::collections::HashMap;
use std::path::Path;

use serde_json::Value;

use rhfeed::intents::{Call, Intent, Via, decode, decode_call};
use rhfeed::{codec::decimal, frame_from_slice, parse_frame};

fn hex20(v: &Value) -> Option<[u8; 20]> {
    v.as_str().map(|s| rhfeed::addr(s).unwrap())
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

/// A decimal string as a big-endian uint256.
fn uint256(v: &Value) -> [u8; 32] {
    let mut out = [0u8; 32];
    for digit in v.as_str().unwrap().bytes() {
        let mut carry = u32::from(digit - b'0');
        for b in out.iter_mut().rev() {
            let cur = u32::from(*b) * 10 + carry;
            *b = cur as u8;
            carry = cur >> 8;
        }
        assert_eq!(carry, 0, "over 256 bits");
    }
    out
}

fn hx(a: &Option<[u8; 20]>) -> Value {
    a.map_or(Value::Null, |a| format!("0x{}", hex::encode(a)).into())
}

fn amount(a: &Option<[u8; 32]>) -> Value {
    a.map_or(Value::Null, |a| decimal(&a).into())
}

fn check(got: &[Intent], want: &Value, what: &str) {
    let want = want.as_array().unwrap();
    assert_eq!(got.len(), want.len(), "{what}: intent count");
    for (g, w) in got.iter().zip(want) {
        let via: Vec<Value> = g.via.iter().map(|v| hx(&Some(*v))).collect();
        let fields = [
            ("kind", Value::from(g.kind.as_str())),
            ("actor", hx(&g.actor)),
            ("via", Value::from(via)),
            ("payer", hx(&g.payer)),
            ("token_in", hx(&g.token_in)),
            ("token_out", hx(&g.token_out)),
            ("amount_in", amount(&g.amount_in)),
            ("amount_out", amount(&g.amount_out)),
            ("exact_in", Value::from(g.exact_in)),
            ("recipient", hx(&g.recipient)),
            (
                "order_id",
                g.order_id
                    .map_or(Value::Null, |o| format!("0x{}", hex::encode(o)).into()),
            ),
            ("describe", Value::from(g.describe())),
        ];
        for (name, value) in fields {
            assert_eq!(value, w[name], "{what}: {name}");
        }
    }
}

#[test]
fn intents_match_the_python_baseline() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let frames = std::fs::read_to_string(root.join("tests/fixtures/frames.jsonl")).unwrap();
    let mut txs = HashMap::new();
    for line in frames.lines().filter(|l| !l.trim().is_empty()) {
        for msg in parse_frame(&frame_from_slice(line.as_bytes()).unwrap()) {
            for tx in msg.txs {
                txs.insert(tx.hash_hex(), tx);
            }
        }
    }

    let golden = std::fs::read_to_string(root.join("tests/golden_intents.jsonl")).unwrap();
    let mut counts = [0usize; 4];
    for (n, line) in golden.lines().enumerate() {
        let r: Value = serde_json::from_str(line).unwrap();
        let what = format!("line {}", n + 1);
        if let Some(c) = r.get("call") {
            let data = bytes(&c["data"]);
            let via: Vec<[u8; 20]> = c["via"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| hex20(v).unwrap())
                .collect();
            let call = Call {
                to: hex20(&c["to"]),
                value: uint256(&c["value"]),
                data: &data,
                actor: hex20(&c["actor"]),
                via: Via::from_slice(&via).unwrap(),
            };
            let mut out = Vec::new();
            decode_call(&call, 0, &mut out);
            check(&out, &r["intents"], &what);
            counts[0] += 1;
        } else if let Some(t) = r.get("tx") {
            let value = uint256(&t["value"]);
            check(
                &decode(hex20(&t["to"]), &value, &bytes(&t["data"])),
                &r["intents"],
                &what,
            );
            counts[1] += 1;
        } else if let Some(hash) = r.get("hash") {
            let tx = &txs[hash.as_str().unwrap()];
            check(&rhfeed::decode_intents(tx), &r["intents"], &what);
            counts[2] += 1;
        } else {
            let tx = &txs[r["prefixes"].as_str().unwrap()];
            let runs = r["decoded"].as_array().unwrap();
            let empty = Value::Array(Vec::new());
            let data = tx.data();
            for len in 0..=data.len() {
                let want = runs
                    .iter()
                    .find(|run| {
                        run[0].as_u64() <= Some(len as u64) && Some(len as u64) <= run[1].as_u64()
                    })
                    .map_or(&empty, |run| &run[2]);
                let to = tx.to_bytes.unwrap();
                let call = Call {
                    to: Some(to),
                    value: uint256(&tx.value_dec().into()),
                    data: &data[..len],
                    actor: None,
                    via: Via::from_slice(&[to]).unwrap(),
                };
                let mut out = Vec::new();
                decode_call(&call, 0, &mut out);
                check(&out, want, &format!("{what}, prefix {len}"));
            }
            counts[3] += 1;
        }
    }
    // Every kind of line is there, and every frame transaction was checked.
    assert!(counts[0] > 50 && counts[1] > 0, "{counts:?}");
    assert_eq!(counts[2], txs.len());
}

#[test]
fn json_matches_the_python_shape() {
    let mut data = vec![0x09, 0x5e, 0xa7, 0xb3];
    data.extend([0u8; 12]);
    data.extend([0x22; 20]);
    data.extend([0u8; 31]);
    data.push(7);
    let out = decode(Some([0x11; 20]), &[], &data);
    let json = sonic_rs::to_string(&out[0]).unwrap();
    assert_eq!(
        json,
        format!(
            r#"{{"kind":"approve","actor":null,"via":["{t}"],"payer":null,"token_in":"{t}","token_out":null,"amount_in":7,"amount_out":null,"exact_in":true,"recipient":"{r}","order_id":null}}"#,
            t = rhfeed::checksum(&[0x11; 20]),
            r = rhfeed::checksum(&[0x22; 20]),
        )
    );
}
