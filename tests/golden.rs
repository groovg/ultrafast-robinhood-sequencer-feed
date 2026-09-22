//! Hold the port to the Python baseline, field by field.
//!
//! `golden.jsonl` is what the baseline decodes from `tests/fixtures/frames.jsonl` plus envelopes
//! signed from its test templates, written by `golden.py`. The Python side is itself
//! cross-checked against eth-account, eth_utils and rlp, so matching it here inherits
//! those checks. Regenerate after changing the Python decoder:
//!
//!     uv run --project ../robinhood-chain-sequencer-feed --extra dev python tests/golden.py > tests/golden.jsonl

use std::path::Path;

use bytes::Bytes;
use serde_json::Value;

use rhfeed::codec::{Entry, Frame, L2_BATCH, L2_SIGNED_TX, MAX_BATCH_DEPTH, decode_l2_message};
use rhfeed::{
    FEED_PREFIX, MAINNET_CHAIN_ID, MAINNET_SIGNER, MAINNET_VERIFIER, Tx, Verifier,
    decode_transaction, parse_frame, recover_signer, signature_payload,
};

fn golden() -> Vec<Value> {
    let text =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden.jsonl"))
            .unwrap();
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn verified_message() -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/verified_message.json"),
    )
    .unwrap()
}

fn assert_tx(tx: &Tx, want: &Value, ctx: &str) {
    let hex_or_null = |v: Option<String>| v.map_or(Value::Null, Value::String);
    assert_eq!(
        hex::encode(&tx.raw),
        want["raw"].as_str().unwrap(),
        "{ctx}: raw"
    );
    assert_eq!(tx.hash_hex(), want["hash"], "{ctx}: hash");
    assert_eq!(tx.tx_type as u64, want["tx_type"], "{ctx}: tx_type");
    assert_eq!(hex_or_null(tx.to()), want["to"], "{ctx}: to");
    assert_eq!(
        hex_or_null(tx.selector_hex()),
        want["selector"],
        "{ctx}: selector"
    );
    assert_eq!(tx.nonce, want["nonce"], "{ctx}: nonce");
    assert_eq!(tx.gas, want["gas"], "{ctx}: gas");
    assert_eq!(
        tx.value_dec(),
        want["value"].as_str().unwrap(),
        "{ctx}: value"
    );
    assert_eq!(tx.data_len as u64, want["data_len"], "{ctx}: data_len");
    assert_eq!(tx.kind(), want["kind"], "{ctx}: kind");
    assert_eq!(hex_or_null(tx.sender()), want["sender"], "{ctx}: sender");
}

#[test]
fn every_captured_frame_decodes_exactly_as_python_does() {
    let mut txs = 0;
    for (i, line) in golden()
        .iter()
        .filter(|g| g.get("frame").is_some())
        .enumerate()
    {
        let frame: Frame = serde_json::from_str(line["frame"].as_str().unwrap()).unwrap();
        let got = parse_frame(&frame, true);
        let want = line["messages"].as_array().unwrap();
        assert_eq!(got.len(), want.len(), "frame {i}");
        for (m, w) in got.iter().zip(want) {
            let ctx = format!("frame {i} seq {}", m.seq);
            assert_eq!(m.seq, w["seq"], "{ctx}");
            assert_eq!(m.l1_kind, w["l1_kind"], "{ctx}");
            assert_eq!(m.l1_sender.as_deref(), w["l1_sender"].as_str(), "{ctx}");
            assert_eq!(m.timestamp, w["timestamp"], "{ctx}");
            assert_eq!(m.block_hash.as_deref(), w["block_hash"].as_str(), "{ctx}");
            assert_eq!(m.delayed_messages_read, w["delayed_messages_read"], "{ctx}");
            assert_eq!(m.l1_block_number, w["l1_block_number"], "{ctx}");
            let wtxs = w["txs"].as_array().unwrap();
            assert_eq!(m.txs.len(), wtxs.len(), "{ctx}: tx count");
            for (t, wt) in m.txs.iter().zip(wtxs) {
                assert_tx(t, wt, &ctx);
                txs += 1;
            }
        }
    }
    assert!(txs > 100, "capture decoded only {txs} transactions");
}

#[test]
fn every_signed_template_decodes_exactly_as_python_does() {
    let all = golden();
    let templates: Vec<&Value> = all.iter().filter(|g| g.get("template").is_some()).collect();
    assert_eq!(templates.len(), 5);
    for t in templates {
        let raw = hex::decode(t["tx"]["raw"].as_str().unwrap()).unwrap();
        let tx = decode_transaction(Bytes::from(raw)).unwrap();
        assert_tx(&tx, &t["tx"], t["template"].as_str().unwrap());
    }
}

fn signed_l2_msg() -> Vec<u8> {
    let eip1559 = golden()
        .into_iter()
        .find(|g| g["template"] == "eip1559")
        .unwrap();
    [
        vec![L2_SIGNED_TX],
        hex::decode(eip1559["tx"]["raw"].as_str().unwrap()).unwrap(),
    ]
    .concat()
}

fn nest(mut msg: Vec<u8>, times: usize) -> Bytes {
    for _ in 0..times {
        msg = [
            vec![L2_BATCH],
            (msg.len() as u64).to_be_bytes().to_vec(),
            msg,
        ]
        .concat();
    }
    Bytes::from(msg)
}

#[test]
fn batch_nesting_stops_exactly_at_the_arbos_cap() {
    assert_eq!(
        decode_l2_message(&nest(signed_l2_msg(), MAX_BATCH_DEPTH)).len(),
        1
    );
    assert!(decode_l2_message(&nest(signed_l2_msg(), MAX_BATCH_DEPTH + 1)).is_empty());
    // Untrusted input must not be able to exhaust the stack.
    assert!(decode_l2_message(&nest(signed_l2_msg(), 10_000)).is_empty());
}

// --------------------------------------------------------------------------- //
// feed signatures, against a message taken off mainnet
// --------------------------------------------------------------------------- //

fn with(field: &str, value: Value) -> String {
    let mut v: Value = serde_json::from_str(&verified_message()).unwrap();
    let header = &mut v["message"]["message"]["header"];
    if header.get(field).is_some() {
        header[field] = value;
    } else if v["message"].get(field).is_some() {
        v["message"][field] = value;
    } else {
        v[field] = value;
    }
    v.to_string()
}

fn entry(json: &str) -> Entry<'_> {
    serde_json::from_str(json).unwrap()
}

#[test]
fn a_real_message_recovers_the_batch_poster() {
    let json = verified_message();
    let e = entry(&json);
    assert_eq!(recover_signer(&e, MAINNET_CHAIN_ID), Some(MAINNET_SIGNER));
    assert!(MAINNET_VERIFIER.accepts(&e));
    assert!(
        signature_payload(&e, MAINNET_CHAIN_ID)
            .unwrap()
            .starts_with(FEED_PREFIX)
    );
    assert_ne!(recover_signer(&e, 42161), Some(MAINNET_SIGNER));
    // A verifier that does not accept the signer still says who it was.
    let someone_else = Verifier::new(MAINNET_CHAIN_ID, [[0u8; 20]]);
    assert!(!someone_else.accepts(&e));
    assert_eq!(someone_else.signer_of(&e), Some(MAINNET_SIGNER));
}

#[test]
fn the_preimage_traps_are_handled() {
    let base = signature_payload(&entry(&verified_message()), MAINNET_CHAIN_ID)
        .unwrap()
        .len();
    let len = |field: &str, v: Value| {
        signature_payload(&entry(&with(field, v)), MAINNET_CHAIN_ID)
            .unwrap()
            .len()
    };
    assert_eq!(len("baseFeeL1", Value::Null), base); // zero contributes no bytes
    assert_eq!(len("baseFeeL1", 1.into()), base + 1);
    assert_eq!(len("baseFeeL1", 256.into()), base + 2);
    assert_eq!(
        len("requestId", format!("0x{}", "00".repeat(32)).into()),
        base + 32
    );
    assert_eq!(len("blockMetadata", "AAAAAAAAAAAAAA==".into()), base + 10);
}

#[test]
fn changing_any_signed_field_breaks_verification() {
    for (field, value) in [
        ("sequenceNumber", Value::from(20839681)),
        ("blockHash", format!("0x{}", "11".repeat(32)).into()),
        ("delayedMessagesRead", 68505.into()),
        ("blockMetadata", "AAA=".into()),
        ("kind", 4.into()),
        (
            "sender",
            "0x000000000000000000000000000000000000dead".into(),
        ),
        ("blockNumber", 25625039.into()),
        ("timestamp", 1785166091.into()),
        ("baseFeeL1", 1.into()),
        ("requestId", format!("0x{}", "22".repeat(32)).into()),
    ] {
        assert!(
            !MAINNET_VERIFIER.accepts(&entry(&with(field, value))),
            "{field}"
        );
    }
}

#[test]
fn an_unusable_signature_is_not_accepted() {
    use base64::Engine;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    for sig in [
        Value::Null,
        "".into(),
        b64(&[1; 64]).into(),
        b64(&[1; 66]).into(),
        b64(&[[1u8; 64].as_slice(), &[9]].concat()).into(),
        "not base64 at all!!".into(),
    ] {
        let json = with("signatureV2", sig.clone());
        assert_eq!(
            recover_signer(&entry(&json), MAINNET_CHAIN_ID),
            None,
            "{sig}"
        );
    }
}
