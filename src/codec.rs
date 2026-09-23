//! Decode Nitro sequencer-feed frames into transactions. No I/O, just bytes in and
//! values out.
//!
//! Ported from the Python version's `src/rhfeed/codec.py`, whose docstring explains the
//! design. One difference: if a field can't fit the type geth would parse it into (a
//! nonce or gas over 64 bits, a value over 256 bits, a `to` that isn't empty or 20
//! bytes), we keep only the hash and raw bytes. Python passes the odd value through.
//! Nodes reject such transactions, so they never execute either way.

use std::borrow::Cow;
use std::sync::OnceLock;

use bytes::Bytes;
use keccak_asm::Keccak256;
use rayon::prelude::*;
use serde::Deserialize;

/// arbos/parse_l2.go: L2 message kinds. Only these two carry user transactions.
pub const L2_BATCH: u8 = 3;
pub const L2_SIGNED_TX: u8 = 4;

/// arbos rejects a batch at depth >= 16, so nothing nested deeper executes.
pub const MAX_BATCH_DEPTH: usize = 16;

pub const FILTER_PRECOMPILE: &str = "0x0000000000000000000000000000000000000074";
pub const IS_FILTERED_SELECTOR: &str = "0x85c733a4";

/// arbostypes: L1 message kinds. Anything but L2Message reached the chain through Ethereum.
pub fn l1_kind_name(kind: i64) -> Cow<'static, str> {
    Cow::Borrowed(match kind {
        3 => "L2Message",
        6 => "EndOfBlock",
        7 => "L2FundedByL1",
        8 => "RollupEvent",
        9 => "SubmitRetryable",
        10 => "BatchForGasEstimation",
        11 => "Initialize",
        12 => "EthDeposit",
        13 => "BatchPostingReport",
        0xFF => "Invalid",
        _ => return Cow::Owned(format!("kind{kind}")),
    })
}

// --------------------------------------------------------------------------- //
// helpers for building filters
// --------------------------------------------------------------------------- //

/// Standard base64 with padding, as Nitro writes it. SIMD: ~3x the `base64` crate.
pub(crate) fn b64(s: &str) -> Option<Vec<u8>> {
    base64_simd::STANDARD.decode_to_vec(s).ok()
}

/// Keccak-256 through XKCP's assembly, ~1.2x tiny-keccak. The same crate alloy uses.
pub fn keccak(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// 4-byte selector for a function signature: `selector_of("transfer(address,uint256)")`.
pub fn selector_of(signature: &str) -> [u8; 4] {
    keccak(signature.as_bytes())[..4].try_into().unwrap()
}

pub(crate) fn unhex(value: &str, what: &str) -> Result<Vec<u8>, String> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|_| format!("not a hex {what}: {value:?}"))
}

fn fixed<const N: usize>(value: &str, what: &str) -> Result<[u8; N], String> {
    let raw = unhex(value, what)?;
    let len = raw.len();
    raw.try_into()
        .map_err(|_| format!("not a {N}-byte {what}: {value:?} is {len} bytes"))
}

/// 4-byte selector from its hex form, with or without the 0x.
pub fn sel(hex_selector: &str) -> Result<[u8; 4], String> {
    fixed(hex_selector, "selector")
}

/// 20 raw bytes from a hex address, for membership tests against `Tx::to_bytes`.
pub fn addr(hex_address: &str) -> Result<[u8; 20], String> {
    fixed(hex_address, "address")
}

/// EIP-55 checksummed hex. Costs one keccak, which is why `Tx::to` is computed on demand.
pub fn checksum(address: &[u8]) -> String {
    let lower = hex::encode(address);
    let digest = keccak(lower.as_bytes());
    let mut out = String::with_capacity(2 + lower.len());
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (digest[i / 2] >> (4 - 4 * (i % 2))) & 0xF;
        out.push(if c > '9' && nibble > 7 {
            c.to_ascii_uppercase()
        } else {
            c
        });
    }
    out
}

// --------------------------------------------------------------------------- //
// RLP: a scanner, not a parser
// --------------------------------------------------------------------------- //

/// (item_start, payload_start, payload_end). `item_start` keeps the length prefix.
pub type Field = (usize, usize, usize);

/// Big-endian length of a long-form prefix, bounds-checked against `buf`.
fn long_len(buf: &[u8], start: usize, end: usize) -> Result<usize, &'static str> {
    let bytes = buf.get(start..end).ok_or("truncated RLP")?;
    Ok(bytes
        .iter()
        .fold(0usize, |acc, &b| acc << 8 | usize::from(b)))
}

/// Offsets of every item in the RLP list at the head of `buf`. Nested lists are skipped
/// over by length, not descended into.
pub fn scan_list(buf: &[u8]) -> Result<Vec<Field>, &'static str> {
    let &head = buf.first().ok_or("empty")?;
    if head < 0xC0 {
        return Err("not an RLP list");
    }
    let (mut i, end) = if head < 0xF8 {
        (1, 1 + usize::from(head - 0xC0))
    } else {
        let s = 1 + usize::from(head - 0xF7);
        (
            s,
            s.checked_add(long_len(buf, 1, s)?)
                .ok_or("RLP length overflow")?,
        )
    };
    if end > buf.len() {
        return Err("truncated RLP list");
    }

    let mut out = Vec::with_capacity(16);
    while i < end {
        let c = buf[i];
        let (s, e) = if c < 0x80 {
            (i, i + 1) // the byte is its own payload
        } else {
            // Strings and lists share a layout, offset by 0x40: short form under 56
            // bytes, long form above it with the length's length in the prefix.
            let short = usize::from(c - if c < 0xC0 { 0x80 } else { 0xC0 });
            if short < 56 {
                (i + 1, i + 1 + short)
            } else {
                let s = i + 1 + (short - 55);
                (
                    s,
                    s.checked_add(long_len(buf, i + 1, s)?)
                        .ok_or("RLP length overflow")?,
                )
            }
        };
        out.push((i, s, e));
        i = e;
    }
    if i != end {
        return Err("malformed RLP list");
    }
    Ok(out)
}

fn rlp_header(len: usize, offset: u8, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(offset + len as u8);
    } else {
        let be = len.to_be_bytes();
        let skip = (len.leading_zeros() / 8) as usize;
        out.push(offset + 55 + (be.len() - skip) as u8);
        out.extend_from_slice(&be[skip..]);
    }
}

pub fn rlp_uint(value: u128) -> Vec<u8> {
    let be = value.to_be_bytes();
    let body = &be[(value.leading_zeros() / 8) as usize..];
    match body {
        [] => vec![0x80],
        [b] if *b < 0x80 => vec![*b],
        _ => {
            let mut out = Vec::with_capacity(1 + body.len());
            rlp_header(body.len(), 0x80, &mut out);
            out.extend_from_slice(body);
            out
        }
    }
}

/// `prefix || rlp_list(content)`, built in one allocation.
pub fn rlp_list(prefix: &[u8], content: &[&[u8]]) -> Vec<u8> {
    let len: usize = content.iter().map(|c| c.len()).sum();
    let mut out = Vec::with_capacity(prefix.len() + 9 + len);
    out.extend_from_slice(prefix);
    rlp_header(len, 0xC0, &mut out);
    for c in content {
        out.extend_from_slice(c);
    }
    out
}

fn be_uint<const N: usize>(bytes: &[u8]) -> Option<u128> {
    (bytes.len() <= N).then(|| bytes.iter().fold(0u128, |acc, &b| acc << 8 | u128::from(b)))
}

fn pad32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    out
}

// --------------------------------------------------------------------------- //
// transactions
// --------------------------------------------------------------------------- //

/// Field positions per envelope type: (nonce, gas, to, value, data). The signature is
/// always the final three fields, found by counting back from the end.
fn layout(tx_type: u8) -> Option<[usize; 5]> {
    match tx_type {
        0 => Some([0, 2, 3, 4, 5]), // legacy: nonce gasPrice gas to value data v r s
        1 => Some([1, 3, 4, 5, 6]), // 2930:   +chainId, +accessList
        2..=4 => Some([1, 4, 5, 6, 7]), // 1559, blob, 7702: same first eight fields
        _ => None,
    }
}

/// One signed transaction as the sequencer ordered it, without its outcome.
///
/// Cheap and eager: `tx_type`, `nonce`, `gas`, `value_be`, `to_bytes`, `selector`.
/// Expensive and lazy: `hash` (cached), `to` (a keccak), `sender` (ECDSA, cached).
pub struct Tx {
    pub raw: Bytes,
    pub tx_type: u8,
    pub nonce: u64,
    pub gas: u64,
    pub to_bytes: Option<[u8; 20]>,
    pub selector: Option<[u8; 4]>,
    pub data_len: usize,
    value: (usize, usize),
    /// Empty for an envelope this does not model; offsets are into `raw[body..]`.
    fields: Vec<Field>,
    body: usize,
    hash: OnceLock<[u8; 32]>,
    sender: OnceLock<Option<[u8; 20]>>,
}

struct Modeled {
    nonce: u64,
    gas: u64,
    to_bytes: Option<[u8; 20]>,
    selector: Option<[u8; 4]>,
    data_len: usize,
    value: (usize, usize),
    fields: Vec<Field>,
}

fn model(body: &[u8], layout: [usize; 5]) -> Option<Modeled> {
    let fields = scan_list(body).ok()?;
    let [ni, gi, ti, vi, di] = layout;
    if fields.len() < di + 4 {
        return None; // payload fields plus v, r, s
    }
    let item = |k: usize| &body[fields[k].1..fields[k].2];
    let to_bytes = match item(ti) {
        [] => None,
        to => Some(to.try_into().ok()?),
    };
    let data = item(di);
    if item(vi).len() > 32 {
        return None;
    }
    Some(Modeled {
        nonce: be_uint::<8>(item(ni))? as u64,
        gas: be_uint::<8>(item(gi))? as u64,
        to_bytes,
        selector: data.get(..4).map(|s| s.try_into().unwrap()),
        data_len: data.len(),
        value: (fields[vi].1, fields[vi].2),
        fields,
    })
}

impl Tx {
    fn body(&self) -> &[u8] {
        &self.raw[self.body..]
    }

    /// keccak of the envelope. Cached.
    pub fn hash(&self) -> &[u8; 32] {
        self.hash.get_or_init(|| keccak(&self.raw))
    }

    pub fn hash_hex(&self) -> String {
        format!("0x{}", hex::encode(self.hash()))
    }

    /// Checksummed recipient. Costs a keccak; `to_bytes` does not.
    pub fn to(&self) -> Option<String> {
        self.to_bytes.as_ref().map(|t| checksum(t))
    }

    /// Recovers the sender with ECDSA, by far the most expensive thing here. Cached.
    pub fn sender_bytes(&self) -> Option<[u8; 20]> {
        *self.sender.get_or_init(|| self.recover())
    }

    pub fn sender(&self) -> Option<String> {
        self.sender_bytes().map(|s| checksum(&s))
    }

    /// Value in wei, big-endian and minimal as RLP stores it (empty for zero).
    pub fn value_be(&self) -> &[u8] {
        &self.body()[self.value.0..self.value.1]
    }

    /// Value in wei as a decimal string, since it can be bigger than any integer type.
    pub fn value_dec(&self) -> String {
        let mut n = self.value_be().to_vec();
        let mut digits = Vec::new();
        while n.iter().any(|&b| b != 0) {
            let mut rem = 0u32;
            for b in &mut n {
                let cur = rem * 256 + u32::from(*b);
                *b = (cur / 10) as u8;
                rem = cur % 10;
            }
            digits.push(b'0' + rem as u8);
        }
        if digits.is_empty() {
            return "0".into();
        }
        digits.reverse();
        String::from_utf8(digits).unwrap()
    }

    pub fn selector_hex(&self) -> Option<String> {
        self.selector.map(|s| format!("0x{}", hex::encode(s)))
    }

    pub fn kind(&self) -> &'static str {
        match (self.to_bytes, self.selector) {
            (None, _) => "deploy",
            (Some(_), Some(_)) => "call",
            (Some(_), None) => "transfer",
        }
    }

    fn recover(&self) -> Option<[u8; 20]> {
        let (body, f) = (self.body(), &self.fields);
        let n = f.len();
        if n < 4 {
            return None;
        }
        let item = |k: usize| &body[f[k].1..f[k].2];
        let v = be_uint::<16>(item(n - 3))?;
        let (r, s) = (item(n - 2), item(n - 1));
        if r.is_empty() || s.is_empty() || r.len() > 32 || s.len() > 32 {
            return None;
        }

        let (parity, payload) = if self.tx_type == 0 {
            // EIP-155 folds the chain id into v; pre-155 signatures use 27/28 and sign
            // only the first six fields.
            let unsigned = &body[f[0].0..f[5].2];
            if v >= 35 {
                let chain = rlp_uint((v - 35) >> 1);
                (
                    (v - 35) & 1,
                    rlp_list(&[], &[unsigned, &chain, b"\x80\x80"]),
                )
            } else if v == 27 || v == 28 {
                (v - 27, rlp_list(&[], &[unsigned]))
            } else {
                return None;
            }
        } else {
            // Typed envelopes sign type || rlp(everything but the signature).
            if v > 1 {
                return None;
            }
            (v, rlp_list(&[self.tx_type], &[&body[f[0].0..f[n - 4].2]]))
        };
        crate::secp::recover(&keccak(&payload), &pad32(r), &pad32(s), parity as u8)
    }
}

/// Recover the sender of every transaction in `txs` at once and cache it, so later
/// `sender()` calls are free. The transactions are spread over all cores, so a message's
/// worth of senders takes about as long as the slowest one, not the sum of them.
pub fn recover_senders<'a>(txs: impl IntoIterator<Item = &'a Tx>) {
    let txs: Vec<&Tx> = txs.into_iter().collect();
    // Each Tx caches its sender in a OnceLock, which is safe to fill from any thread.
    txs.par_iter().for_each(|t| {
        t.sender_bytes();
    });
}

impl std::fmt::Debug for Tx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<Tx {} type={} {}>",
            &self.hash_hex()[..12],
            self.tx_type,
            self.kind()
        )
    }
}

/// One signed transaction envelope: legacy, 2930, 1559, blob or 7702.
pub fn decode_transaction(raw: Bytes) -> Option<Tx> {
    let &head = raw.first()?;
    let typed = head < 0x80;
    let tx_type = if typed { head } else { 0 };
    let body = usize::from(typed);
    // A type we don't handle, or one that doesn't parse: keep just the hash and raw bytes.
    let m = layout(tx_type).and_then(|l| model(&raw[body..], l));
    let m = m.unwrap_or(Modeled {
        nonce: 0,
        gas: 0,
        to_bytes: None,
        selector: None,
        data_len: 0,
        value: (0, 0),
        fields: Vec::new(),
    });
    Some(Tx {
        raw,
        tx_type,
        nonce: m.nonce,
        gas: m.gas,
        to_bytes: m.to_bytes,
        selector: m.selector,
        data_len: m.data_len,
        value: m.value,
        fields: m.fields,
        body,
        hash: OnceLock::new(),
        sender: OnceLock::new(),
    })
}

/// Walk an l2Msg, flattening nested batches into the signed transactions inside.
pub fn decode_l2_message(payload: &Bytes) -> Vec<Tx> {
    let mut out = Vec::new();
    walk(payload, 0, &mut out);
    out
}

fn walk(payload: &Bytes, depth: usize, out: &mut Vec<Tx>) {
    match payload.first() {
        Some(&L2_SIGNED_TX) => out.extend(decode_transaction(payload.slice(1..))),
        // Past the cap arbos accepts, so nothing below here executes.
        Some(&L2_BATCH) if depth < MAX_BATCH_DEPTH => {
            // A Batch is repeated [8-byte big-endian length][nested L2 message].
            let mut offset = 1;
            while offset + 8 <= payload.len() {
                let len = u64::from_be_bytes(payload[offset..offset + 8].try_into().unwrap());
                offset += 8;
                if len == 0 || len > (payload.len() - offset) as u64 {
                    return;
                }
                let end = offset + len as usize;
                walk(&payload.slice(offset..end), depth + 1, out);
                offset = end;
            }
        }
        _ => {}
    }
}

// --------------------------------------------------------------------------- //
// frames
// --------------------------------------------------------------------------- //

/// A relay frame, `{"version":1,"messages":[...]}`, borrowing its strings from the
/// buffer it was parsed from. Every field is optional, like the Python version's `.get()` calls.
#[derive(Deserialize, Default, Clone)]
pub struct Frame<'a> {
    #[serde(borrow, default)]
    pub messages: Option<Vec<Entry<'a>>>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Entry<'a> {
    pub sequence_number: Option<i64>,
    #[serde(borrow)]
    pub message: Option<Wrapper<'a>>,
    #[serde(borrow)]
    pub block_hash: Option<Cow<'a, str>>,
    #[serde(borrow)]
    pub block_metadata: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "signatureV2")]
    pub signature_v2: Option<Cow<'a, str>>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Wrapper<'a> {
    #[serde(borrow)]
    pub message: Option<Incoming<'a>>,
    pub delayed_messages_read: Option<u64>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Incoming<'a> {
    #[serde(borrow)]
    pub header: Option<Header<'a>>,
    #[serde(borrow)]
    pub l2_msg: Option<Cow<'a, str>>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Header<'a> {
    pub kind: Option<i64>,
    #[serde(borrow)]
    pub sender: Option<Cow<'a, str>>,
    pub block_number: Option<u64>,
    pub timestamp: Option<u64>,
    #[serde(borrow)]
    pub request_id: Option<Cow<'a, str>>,
    #[serde(rename = "baseFeeL1")]
    pub base_fee_l1: Option<u128>,
}

/// Parse one relay frame, borrowing its strings from `json`. Uses sonic-rs, which is
/// about 1.3x faster than serde_json on these frames.
pub fn frame_from_slice(json: &[u8]) -> Result<Frame<'_>, sonic_rs::Error> {
    sonic_rs::from_slice(json)
}

impl<'a> Frame<'a> {
    pub fn entries(&self) -> &[Entry<'a>] {
        self.messages.as_deref().unwrap_or_default()
    }
}

impl<'a> Entry<'a> {
    pub fn incoming(&self) -> Option<&Incoming<'a>> {
        self.message.as_ref()?.message.as_ref()
    }

    pub fn header(&self) -> Option<&Header<'a>> {
        self.incoming()?.header.as_ref()
    }
}

/// One sequencer message. On this chain, `seq` equals the L2 block number. See
/// `FeedMessage` in codec.py for what `block_hash`, `delayed_messages_read` and
/// `l1_block_number` are good for.
#[derive(Debug)]
pub struct FeedMessage {
    pub seq: i64,
    pub l1_kind: i64,
    pub l1_sender: Option<String>,
    pub timestamp: u64,
    pub txs: Vec<Tx>,
    pub block_hash: Option<String>,
    pub delayed_messages_read: u64,
    pub l1_block_number: u64,
    /// Set by `Feed`; meaningless for a frame decoded straight off disk.
    pub live: bool,
    /// Unix seconds when the first copy of this message arrived, from any source.
    pub received_at: f64,
    /// This sequence number arrived before, carrying a different block hash.
    pub reorg: bool,
    /// Index into `Feed`'s sources of the one that delivered this message first.
    pub source: usize,
}

impl FeedMessage {
    pub fn l1_kind_name(&self) -> Cow<'static, str> {
        l1_kind_name(self.l1_kind)
    }

    /// Anything not an L2Message entered through Ethereum, not the sequencer.
    pub fn from_parent_chain(&self) -> bool {
        self.l1_kind != 3
    }
}

/// Every message in a frame, transactions decoded. One frame can carry several.
pub fn parse_frame(frame: &Frame) -> Vec<FeedMessage> {
    frame
        .entries()
        .iter()
        .map(|e| parse_entry_with(e, l2_msg(e).ok().flatten().as_ref()))
        .collect()
}

/// An entry's l2Msg, base64-decoded. Decode it once and pass it to both verification and
/// decoding.
/// `Ok(None)` when absent or empty.
pub fn l2_msg(entry: &Entry) -> Result<Option<Bytes>, base64_simd::Error> {
    match entry.incoming().and_then(|i| i.l2_msg.as_deref()) {
        Some(l2) if !l2.is_empty() => Ok(Some(base64_simd::STANDARD.decode_to_vec(l2)?.into())),
        _ => Ok(None),
    }
}

/// One entry of a frame, with its l2Msg already decoded by `l2_msg`. Transactions are
/// decoded only if `l2` is given, which is how the consumer skips decoding the backlog.
pub fn parse_entry_with(entry: &Entry, l2: Option<&Bytes>) -> FeedMessage {
    let header = entry.header();
    let txs = l2.map(decode_l2_message).unwrap_or_default();
    FeedMessage {
        seq: entry.sequence_number.unwrap_or(-1),
        l1_kind: header.and_then(|h| h.kind).unwrap_or(-1),
        l1_sender: header.and_then(|h| h.sender.as_deref()).map(str::to_owned),
        timestamp: header.and_then(|h| h.timestamp).unwrap_or(0),
        txs,
        block_hash: entry.block_hash.as_deref().map(str::to_owned),
        delayed_messages_read: entry
            .message
            .as_ref()
            .and_then(|w| w.delayed_messages_read)
            .unwrap_or(0),
        l1_block_number: header.and_then(|h| h.block_number).unwrap_or(0),
        live: true,
        received_at: 0.0,
        reorg: false,
        source: 0,
    }
}

// --------------------------------------------------------------------------- //
// compliance filtering
// --------------------------------------------------------------------------- //

/// eth_call body asking the filter precompile whether a hash is blocked. The hash is
/// checked here because a malformed one still encodes into a well-formed call that the
/// node would answer about the wrong slot. See `is_filtered_call` in codec.py.
pub fn is_filtered_call(tx_hash: &str) -> Result<serde_json::Value, String> {
    let raw: [u8; 32] = fixed(tx_hash, "transaction hash")?;
    Ok(serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [
            {"to": FILTER_PRECOMPILE, "data": format!("{IS_FILTERED_SELECTOR}{}", hex::encode(raw))},
            "latest",
        ],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_list_finds_every_field_and_keeps_prefixes() {
        // rlp([b"", b"\x01", b"\x7f", b"\x80", b"\xff"*55, b"\xab"*56])
        let items: Vec<Vec<u8>> = vec![
            vec![],
            vec![1],
            vec![0x7f],
            vec![0x80],
            vec![0xff; 55],
            vec![0xab; 56],
        ];
        let encoded: Vec<Vec<u8>> = items
            .iter()
            .map(|i| match i.as_slice() {
                [b] if *b < 0x80 => vec![*b],
                _ => {
                    let mut out = Vec::new();
                    rlp_header(i.len(), 0x80, &mut out);
                    out.extend_from_slice(i);
                    out
                }
            })
            .collect();
        let refs: Vec<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
        let list = rlp_list(&[], &refs);
        let scanned = scan_list(&list).unwrap();
        let got: Vec<&[u8]> = scanned.iter().map(|&(_, s, e)| &list[s..e]).collect();
        assert_eq!(got, items.iter().map(Vec::as_slice).collect::<Vec<_>>());
        assert_eq!(
            &list[scanned[0].0..scanned.last().unwrap().2],
            encoded.concat().as_slice()
        );
    }

    #[test]
    fn scan_list_skips_nested_lists() {
        // rlp([b"\x01", [[b"\x02", b"\x03"], [b"\x04"]], b"\x05"])
        let list = [0xc8, 0x01, 0xc5, 0xc2, 0x02, 0x03, 0xc1, 0x04, 0x05];
        let scanned = scan_list(&list).unwrap();
        assert_eq!(scanned.len(), 3);
        assert_eq!(&list[scanned[0].1..scanned[0].2], [1]);
        assert_eq!(&list[scanned[2].1..scanned[2].2], [5]);
    }

    #[test]
    fn scan_list_rejects_malformed_input() {
        for bad in [
            &b""[..],
            b"\x80",
            b"\xc4\x01\x02",
            b"\xf8\xff\x01",
            b"\xff\xff\xff\xff",
        ] {
            assert!(scan_list(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn rlp_uint_matches_the_encoding() {
        assert_eq!(rlp_uint(0), [0x80]);
        assert_eq!(rlp_uint(1), [0x01]);
        assert_eq!(rlp_uint(127), [0x7f]);
        assert_eq!(rlp_uint(128), [0x81, 0x80]);
        assert_eq!(rlp_uint(4663), [0x82, 0x12, 0x37]);
        assert_eq!(
            rlp_uint(u128::MAX),
            [[0x90].as_slice(), &[0xff; 16]].concat()
        );
    }

    #[test]
    fn rlp_list_header_uses_long_form_from_56() {
        assert_eq!(rlp_list(&[], &[&[0x2a; 55]])[0], 0xc0 + 55);
        assert_eq!(rlp_list(&[], &[&[0x2a; 56]])[..2], [0xf8, 56]);
        assert_eq!(
            rlp_list(&[], &[&[0x2a; 70_000]])[..4],
            [0xfa, 0x01, 0x11, 0x70]
        );
    }

    #[test]
    fn checksum_matches_eip55() {
        let a = addr("0xd0601ce157db5bdc3162bbac2a2c8af5320d9eec").unwrap();
        assert_eq!(checksum(&a), "0xd0601CE157Db5bdC3162BbaC2a2C8aF5320D9EEC");
        assert_eq!(
            checksum(&[0; 20]),
            "0x0000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn selector_helpers() {
        assert_eq!(
            selector_of("transfer(address,uint256)"),
            sel("0xa9059cbb").unwrap()
        );
        assert_eq!(
            selector_of("transferFrom(address,address,uint256)"),
            sel("23b872dd").unwrap()
        );
        assert!(sel("0xa9059c").unwrap_err().contains("4-byte"));
        assert!(
            addr("0xd0601ce1…")
                .unwrap_err()
                .contains("not a hex address")
        );
    }

    #[test]
    fn junk_does_not_panic() {
        for junk in [
            &b"\x02\xff\xff"[..],
            b"\x02",
            b"\xc0",
            b"\x02\xc0",
            b"\x7a\xc2\x01\x02",
        ] {
            let tx = decode_transaction(Bytes::copy_from_slice(junk)).unwrap();
            assert_eq!(tx.to_bytes, None);
            assert_eq!(tx.sender_bytes(), None);
        }
    }

    #[test]
    fn a_bad_filter_hash_is_refused() {
        assert!(is_filtered_call("0x1234").is_err());
        let call = is_filtered_call(&format!("0x{}", "ab".repeat(32))).unwrap();
        assert_eq!(
            call["params"][0]["data"],
            format!("0x85c733a4{}", "ab".repeat(32))
        );
    }
}
