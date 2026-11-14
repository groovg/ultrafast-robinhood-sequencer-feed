//! The decoder against the Python version's output, field by field. Regenerate with:
//!
//!     uv run --project ../robinhood-chain-sequencer-feed --extra dev python tests/golden.py > tests/golden.jsonl

use std::path::Path;

use bytes::Bytes;
use serde_json::Value;

use rhfeed::codec::{
    Entry, L2_BATCH, L2_SIGNED_TX, MAX_BATCH_DEPTH, MAX_L2_MESSAGE_SIZE, decode_l2_message,
};
use rhfeed::{
    FEED_PREFIX, MAINNET_CHAIN_ID, MAINNET_SIGNER, MAINNET_VERIFIER, SenderPool, Tx, Verifier,
    decode_transaction, frame_from_slice, parse_frame, recover_senders, recover_signer,
    signature_payload,
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

fn frames() -> Vec<String> {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/frames.jsonl"),
    )
    .unwrap()
    .lines()
    .filter(|l| !l.trim().is_empty())
    .map(str::to_owned)
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
    if let Some(raw) = want.get("raw") {
        assert_eq!(hex::encode(&tx.raw), raw.as_str().unwrap(), "{ctx}: raw");
    }
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
    let frames = frames();
    for line in golden().iter().filter(|g| g.get("line").is_some()) {
        let i = line["line"].as_u64().unwrap() as usize;
        let frame = frame_from_slice(frames[i].as_bytes()).unwrap();
        let got = parse_frame(&frame, None);
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
            assert_eq!(m.request_id.as_deref(), w["request_id"].as_str(), "{ctx}");
            assert_eq!(m.from_parent_chain(), w["from_parent_chain"], "{ctx}");
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
fn recovering_senders_in_bulk_matches_python() {
    let frames = frames();
    let mut pool = SenderPool::new(3);
    let (mut checked, mut pooled) = (0, 0);
    for line in golden().iter().filter(|g| g.get("line").is_some()) {
        let i = line["line"].as_u64().unwrap() as usize;
        let frame = frame_from_slice(frames[i].as_bytes()).unwrap();
        for (m, w) in parse_frame(&frame, None)
            .iter()
            .zip(line["messages"].as_array().unwrap())
        {
            if m.seq % 2 == 0 {
                recover_senders(&m.txs);
            } else {
                pool.recover(&m.txs);
                pooled += m.txs.len();
            }
            for (t, wt) in m.txs.iter().zip(w["txs"].as_array().unwrap()) {
                let got = t.sender().map_or(Value::Null, Value::String);
                assert_eq!(got, wt["sender"], "seq {}", m.seq);
                checked += 1;
            }
        }
    }
    assert!(checked > 100 && pooled > 50, "{checked} {pooled}");
}

#[test]
fn every_signed_template_decodes_exactly_as_python_does() {
    let all = golden();
    let templates: Vec<&Value> = all.iter().filter(|g| g.get("template").is_some()).collect();
    assert_eq!(templates.len(), 5);
    for t in templates {
        let raw = hex::decode(t["tx"]["raw"].as_str().unwrap()).unwrap();
        let name = t["template"].as_str().unwrap();
        let l2 = Bytes::from([&[L2_SIGNED_TX], raw.as_slice()].concat());
        assert_eq!(
            decode_l2_message(&l2).len() as u64,
            t["l2"],
            "{name} in an l2Msg"
        );
        let tx = decode_transaction(Bytes::from(raw)).unwrap();
        assert_tx(&tx, &t["tx"], name);
    }
}

#[test]
fn every_l2msg_arbos_refuses_is_voided_as_python_does() {
    let all = golden();
    let cases: Vec<&Value> = all.iter().filter(|g| g.get("l2msg").is_some()).collect();
    assert!(cases.len() >= 24, "{}", cases.len());
    for case in cases {
        let l2 = Bytes::from(hex::decode(case["hex"].as_str().unwrap()).unwrap());
        let got: Vec<String> = decode_l2_message(&l2).iter().map(Tx::hash_hex).collect();
        let want: Vec<&str> = case["hashes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h.as_str().unwrap())
            .collect();
        assert_eq!(got, want, "{}", case["l2msg"]);
    }
}

#[test]
fn an_l2msg_past_the_size_cap_is_ignored() {
    // A valid unsigned user tx (kind 0) padded with calldata up to the cap.
    let unsigned = |calldata: usize| {
        let word = |v: u64| [[0u8; 24].as_slice(), &v.to_be_bytes()].concat();
        let body = [word(21_000), word(100_000_000), word(3), word(0), word(0)].concat();
        [vec![0u8], body, vec![0; calldata]].concat()
    };
    let batch = |second: Vec<u8>| {
        let first = signed_l2_msg();
        let mut out = vec![L2_BATCH];
        for m in [first, second] {
            out.extend((m.len() as u64).to_be_bytes());
            out.extend(m);
        }
        Bytes::from(out)
    };
    let pad = MAX_L2_MESSAGE_SIZE - batch(unsigned(0)).len();
    assert_eq!(batch(unsigned(pad)).len(), MAX_L2_MESSAGE_SIZE);
    assert_eq!(decode_l2_message(&batch(unsigned(pad))).len(), 1);
    assert!(decode_l2_message(&batch(unsigned(pad + 1))).is_empty());
}

/// Rules geth enforces and Python doesn't, each broken in the first entry of a batch.
#[test]
fn an_envelope_geth_refuses_voids_its_siblings() {
    let raw = signed_l2_msg()[1..].to_vec(); // 0x02 || list of 12 fields
    let body = &raw[1..];
    let fields = rlp_items(body);
    let with = |k: usize, item: &[u8]| {
        let mut items = fields.clone();
        items[k] = item.to_vec();
        let content: Vec<u8> = items.concat();
        [vec![2u8], rlp_list_header(content.len()), content].concat()
    };
    let cases: [(&str, Vec<u8>); 7] = [
        ("nonce with a leading zero", with(1, &[0x82, 0x00, 0x09])),
        ("nonce as 0x00", with(1, &[0x00])),
        ("single byte in string form", with(1, &[0x81, 0x09])),
        (
            "nonce over 64 bits",
            with(1, &[[0x89u8].as_slice(), &[1; 9]].concat()),
        ),
        (
            "to of 19 bytes",
            with(5, &[[0x93u8].as_slice(), &[1; 19]].concat()),
        ),
        ("access list as a string", with(8, &[0x80])),
        ("data as a list", with(7, &[0xc0])),
    ];
    let second = signed_l2_msg();
    for (name, bad) in cases {
        let first = [vec![L2_SIGNED_TX], bad].concat();
        let mut l2 = vec![L2_BATCH];
        for m in [&first, &second] {
            l2.extend((m.len() as u64).to_be_bytes());
            l2.extend(m);
        }
        assert!(decode_l2_message(&Bytes::from(l2)).is_empty(), "{name}");
    }
    // The untouched envelope, re-encoded the same way, still decodes.
    let same = [vec![L2_SIGNED_TX], with(1, &fields[1])].concat();
    assert_eq!(decode_l2_message(&Bytes::from(same)).len(), 1);
}

fn rlp_items(list: &[u8]) -> Vec<Vec<u8>> {
    let (mut i, end) = match list[0] {
        h @ 0xc0..=0xf7 => (1, 1 + usize::from(h - 0xc0)),
        h => {
            let n = usize::from(h - 0xf7);
            let len = list[1..=n].iter().fold(0, |a, &b| a << 8 | usize::from(b));
            (1 + n, 1 + n + len)
        }
    };
    let mut out = Vec::new();
    while i < end {
        let len = match list[i] {
            ..=0x7f => 1,
            c @ 0x80..=0xb7 => 1 + usize::from(c - 0x80),
            c @ 0xb8..=0xbf => {
                let n = usize::from(c - 0xb7);
                1 + n
                    + list[i + 1..=i + n]
                        .iter()
                        .fold(0, |a, &b| a << 8 | usize::from(b))
            }
            c @ 0xc0..=0xf7 => 1 + usize::from(c - 0xc0),
            c => {
                let n = usize::from(c - 0xf7);
                1 + n
                    + list[i + 1..=i + n]
                        .iter()
                        .fold(0, |a, &b| a << 8 | usize::from(b))
            }
        };
        out.push(list[i..i + len].to_vec());
        i += len;
    }
    out
}

fn rlp_list_header(len: usize) -> Vec<u8> {
    if len < 56 {
        vec![0xc0 + len as u8]
    } else {
        let be = len.to_be_bytes();
        let skip = be.iter().take_while(|&&b| b == 0).count();
        [vec![0xf7 + (8 - skip) as u8], be[skip..].to_vec()].concat()
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
    sonic_rs::from_str(json).unwrap()
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
    assert_eq!(
        recover_signer(&e, someone_else.chain_id),
        Some(MAINNET_SIGNER)
    );
}

#[test]
fn a_verifier_learns_a_signer_key_and_forgets_it_with_the_signer() {
    let json = verified_message();
    let e = entry(&json);
    let forged = with("timestamp", 1785166091.into());
    let v = Verifier::new(MAINNET_CHAIN_ID, [MAINNET_SIGNER]);
    // First by recovering the signer, then against the key it learned.
    assert!(v.accepts(&e) && v.accepts(&e));
    assert!(!v.accepts(&entry(&forged)));
    // A clone shares what was learned, and removing the signer stops the key working.
    let mut clone = v.clone();
    clone.signers.clear();
    assert!(!clone.accepts(&e));
    assert!(v.accepts(&e));
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
    let b64 = |b: &[u8]| base64_turbo::STANDARD.encode(b);
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

/// Every signature in the capture and the fixtures, through both backends directly.
#[cfg(feature = "ufsecp")]
#[test]
fn ufsecp_and_libsecp256k1_recover_the_same_addresses() {
    use rhfeed::secp::{libsecp, ufsecp};
    let mut n = 0;
    let mut check = |digest: &[u8; 32], r: &[u8; 32], s: &[u8; 32]| {
        for recid in 0..4 {
            assert_eq!(
                libsecp::recover(digest, r, s, recid),
                ufsecp::recover(digest, r, s, recid)
            );
        }
        n += 1;
    };
    let digest = rhfeed::keccak(b"rhfeed");
    // Out of range: n itself, and all ones. libsecp256k1 rejects these; so must ufsecp.
    let order =
        hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap();
    check(&digest, order.as_slice().try_into().unwrap(), &[1; 32]);
    check(&digest, &[0xff; 32], &[1; 32]);
    check(&digest, &[1; 32], &[0xff; 32]);
    check(&digest, &[0; 32], &[1; 32]);
    for line in frames() {
        let frame = frame_from_slice(line.as_bytes()).unwrap();
        for e in frame.entries() {
            if let Some(sig) = e.signature_v2.as_deref() {
                let sig = base64_turbo::STANDARD.decode(sig).unwrap();
                let digest = rhfeed::keccak(&signature_payload(e, MAINNET_CHAIN_ID).unwrap());
                check(
                    &digest,
                    sig[..32].try_into().unwrap(),
                    sig[32..64].try_into().unwrap(),
                );
            }
        }
    }
    assert!(n >= 4);
}

#[test]
fn deposits_and_retryables_are_built_as_python_and_the_node_do() {
    let all = golden();
    let cases: Vec<&Value> = all.iter().filter(|g| g.get("parent").is_some()).collect();
    assert!(cases.len() >= 20, "{}", cases.len());
    let mut built = 0;
    for case in cases {
        let name = case["parent"].as_str().unwrap();
        let json = format!(r#"{{"messages":[{}]}}"#, case["entry"]);
        let frame = frame_from_slice(json.as_bytes()).unwrap();
        let msgs = parse_frame(&frame, case["chain_id"].as_u64());
        let msg = &msgs[0];
        let want = case["txs"].as_array().unwrap();
        assert_eq!(msg.txs.len(), want.len(), "{name}");
        for (tx, w) in msg.txs.iter().zip(want) {
            assert_tx(tx, w, name);
            assert_eq!(
                hex::encode(tx.data()),
                w["data"].as_str().unwrap(),
                "{name}: data"
            );
            built += 1;
        }
        assert!(msg.from_parent_chain(), "{name}");
    }
    assert_eq!(built, 7);
}

#[test]
fn a_parent_chain_payload_past_the_size_cap_is_refused() {
    let all = golden();
    for seq in ["18382979", "18382981"] {
        let case = all.iter().find(|g| g["parent"] == seq).unwrap();
        let mut entry = case["entry"].clone();
        let count = |entry: &Value| {
            let json = format!(r#"{{"messages":[{entry}]}}"#);
            let frame = frame_from_slice(json.as_bytes()).unwrap();
            parse_frame(&frame, case["chain_id"].as_u64())[0].txs.len()
        };
        assert_eq!(count(&entry), 1, "{seq}");
        let l2 = &mut entry["message"]["message"]["l2Msg"];
        let mut payload = base64_turbo::STANDARD
            .decode(l2.as_str().unwrap())
            .unwrap();
        payload.resize(MAX_L2_MESSAGE_SIZE + 1, 0);
        *l2 = Value::String(base64_turbo::STANDARD.encode(&payload));
        assert_eq!(count(&entry), 0, "{seq}");
    }
}

#[test]
fn a_7702_envelope_without_to_or_with_a_wide_integer_is_refused() {
    let all = golden();
    let case = all.iter().find(|g| g["l2msg"] == "eip7702").unwrap();
    let l2 = hex::decode(case["hex"].as_str().unwrap()).unwrap();
    let raw = &l2[1..]; // 0x04 || list
    let fields = rlp_items(&raw[1..]);
    let with = |k: usize, item: &[u8]| {
        let mut items = fields.clone();
        items[k] = item.to_vec();
        let content = items.concat();
        let env = [vec![4u8], rlp_list_header(content.len()), content].concat();
        decode_l2_message(&Bytes::from([vec![L2_SIGNED_TX], env].concat())).len()
    };
    assert_eq!(with(1, &fields[1]), 1, "re-encoded as is");
    assert_eq!(with(5, &[0x80]), 0, "no to");
    let wide = [[0xa1u8].as_slice(), &[1; 33]].concat();
    assert_eq!(with(2, &wide), 0, "a 33-byte tip");
    // The same envelope's list header in long form, although it would fit the short one.
    let content: Vec<u8> = fields.concat();
    if content.len() < 256 {
        let env = [vec![4u8, 0xf8, content.len() as u8], content.clone()].concat();
        let short_fits = content.len() < 56;
        let got = decode_l2_message(&Bytes::from([vec![L2_SIGNED_TX], env].concat())).len();
        assert_eq!(got, usize::from(!short_fits));
    }
    // Nine empty fields: legacy, 9 bytes, so the long form is refused.
    let short = [vec![L2_SIGNED_TX, 0xc9], vec![0x80; 9]].concat();
    let long = [vec![L2_SIGNED_TX, 0xf8, 9], vec![0x80; 9]].concat();
    assert_eq!(decode_l2_message(&Bytes::from(short)).len(), 1);
    assert!(decode_l2_message(&Bytes::from(long)).is_empty());
}
