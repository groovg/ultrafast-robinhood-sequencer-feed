//! Decode Nitro sequencer-feed frames into transactions. No I/O.

use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use keccak_asm::Keccak256;
use rayon::prelude::*;
use serde::Deserialize;

/// arbostypes: the L1 message kind whose l2Msg holds sequenced transactions.
pub const L1_L2_MESSAGE: i64 = 3;

/// arbos/parse_l2.go: L2 message kinds. 0 and 1 are unsigned delayed-inbox transactions;
/// arbos runs them, but they are not surfaced.
pub const L2_UNSIGNED_USER_TX: u8 = 0;
pub const L2_CONTRACT_TX: u8 = 1;
pub const L2_BATCH: u8 = 3;
pub const L2_SIGNED_TX: u8 = 4;

/// arbos rejects a batch at depth >= 16, and with it the whole l2Msg.
pub const MAX_BATCH_DEPTH: usize = 16;

/// arbostypes.MaxL2MessageSize. ParseL2Transactions ignores a longer l2Msg outright.
pub const MAX_L2_MESSAGE_SIZE: usize = 256 * 1024;

const FILTER_PRECOMPILE: &str = "0x0000000000000000000000000000000000000074";
const IS_FILTERED_SELECTOR: &str = "0x85c733a4";

/// Standard base64 with padding, as Nitro writes it. simdutf was the fastest decoder on
/// x86 and on ARM, where it beat base64-simd and base64-turbo by 1.5 to 1.8x.
pub fn b64(s: &str) -> Option<Vec<u8>> {
    use simdutf::{Base64Options, ErrorCode, LastChunkHandlingOptions};
    // SAFETY: `out` has room for the longest output simdutf says `s` can decode to, and
    // its length is set to what was written.
    unsafe {
        let mut out = Vec::with_capacity(simdutf::maximal_binary_length_from_base64(
            s.as_ptr(),
            s.len(),
        ));
        let r = simdutf::base64_to_binary(
            s.as_ptr(),
            s.len(),
            out.as_mut_ptr(),
            Base64Options::Default,
            LastChunkHandlingOptions::Strict,
        );
        if !matches!(r.error, ErrorCode::Success) {
            return None;
        }
        out.set_len(r.count);
        Some(out)
    }
}

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

/// 4-byte selector from hex, with or without the 0x.
pub fn sel(hex_selector: &str) -> Result<[u8; 4], String> {
    fixed(hex_selector, "selector")
}

/// 20 raw bytes from a hex address, to compare with `Tx::to_bytes`.
pub fn addr(hex_address: &str) -> Result<[u8; 20], String> {
    fixed(hex_address, "address")
}

/// EIP-55 checksummed hex. Costs one keccak.
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

/// (item_start, payload_start, payload_end). `item_start` keeps the length prefix.
type Field = (usize, usize, usize);

fn long_len(buf: &[u8], start: usize, end: usize) -> Result<usize, &'static str> {
    let bytes = buf.get(start..end).ok_or("truncated RLP")?;
    Ok(bytes
        .iter()
        .fold(0usize, |acc, &b| acc << 8 | usize::from(b)))
}

#[cfg(test)]
fn scan_list(buf: &[u8]) -> Result<Vec<Field>, &'static str> {
    scan(buf).map(|(fields, _)| fields)
}

/// What geth's decoder would object to in a list, noted during the scan so checking needs
/// no second pass. One bit per item for the first 32.
#[derive(Clone, Copy, Default)]
struct Shape {
    lists: u32,
    /// Payload starts with a zero byte: a non-canonical integer.
    zero_led: u32,
    /// Every length prefix is in its shortest form and the list ends where `buf` does.
    strict: bool,
}

/// Offsets of every item in the RLP list at the head of `buf`, without descending into
/// nested lists.
fn scan(buf: &[u8]) -> Result<(Vec<Field>, Shape), &'static str> {
    let &head = buf.first().ok_or("empty")?;
    if head < 0xC0 {
        return Err("not an RLP list");
    }
    let mut shape = Shape {
        strict: true,
        ..Shape::default()
    };
    let (mut i, end) = if head < 0xF8 {
        (1, 1 + usize::from(head - 0xC0))
    } else {
        let s = 1 + usize::from(head - 0xF7);
        let len = long_len(buf, 1, s)?;
        shape.strict = buf[1] != 0 && len >= 56;
        (s, s.checked_add(len).ok_or("RLP length overflow")?)
    };
    if end > buf.len() {
        return Err("truncated RLP list");
    }
    shape.strict &= end == buf.len();

    let mut out = Vec::with_capacity(16);
    while i < end {
        let c = buf[i];
        let (s, e) = if c < 0x80 {
            (i, i + 1)
        } else {
            let short = usize::from(c - if c < 0xC0 { 0x80 } else { 0xC0 });
            if short < 56 {
                // A byte under 0x80 must encode itself, not sit in a 1-byte string.
                shape.strict &= c != 0x81 || buf.get(i + 1).is_none_or(|&b| b >= 0x80);
                (i + 1, i + 1 + short)
            } else {
                let s = i + 1 + (short - 55);
                let len = long_len(buf, i + 1, s)?;
                shape.strict &= buf[i + 1] != 0 && len >= 56;
                (s, s.checked_add(len).ok_or("RLP length overflow")?)
            }
        };
        if let Some(bit) = 1u32.checked_shl(out.len() as u32) {
            if c >= 0xC0 {
                shape.lists |= bit;
            }
            if e > s && buf.get(s) == Some(&0) {
                shape.zero_led |= bit;
            }
        }
        out.push((i, s, e));
        i = e;
    }
    if i != end {
        return Err("malformed RLP list");
    }
    Ok((out, shape))
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

fn rlp_uint(value: u128) -> Vec<u8> {
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

fn rlp_list(prefix: &[u8], content: &[&[u8]]) -> Vec<u8> {
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

/// A big-endian unsigned integer of any length, in decimal.
pub fn decimal(be: &[u8]) -> String {
    let mut n = be.to_vec();
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

fn pad32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    out
}

/// Field positions per envelope type: (nonce, gas, to, value, data). The signature is
/// the last three fields.
fn layout(tx_type: u8) -> Option<[usize; 5]> {
    match tx_type {
        0 => Some([0, 2, 3, 4, 5]), // legacy: nonce gasPrice gas to value data v r s
        1 => Some([1, 3, 4, 5, 6]), // 2930:   +chainId, +accessList
        2..=4 => Some([1, 4, 5, 6, 7]), // 1559, blob, 7702: same first eight fields
        _ => None,
    }
}

/// One signed transaction as the sequencer ordered it, without its outcome. The public
/// fields are free; `hash`, `to` and `sender` cost a keccak or an ECDSA recovery.
pub struct Tx {
    pub raw: Bytes,
    pub tx_type: u8,
    pub nonce: u64,
    pub gas: u64,
    pub to_bytes: Option<[u8; 20]>,
    pub selector: Option<[u8; 4]>,
    pub data_len: usize,
    value: (usize, usize),
    data: (usize, usize),
    /// Calldata of a transaction built from a parent-chain message, not in its envelope.
    input: Option<Box<[u8]>>,
    /// Offsets into `raw[body..]`. Empty for an envelope this does not model.
    fields: Vec<Field>,
    body: usize,
    hash: OnceLock<[u8; 32]>,
    sender: OnceLock<Option<[u8; 20]>>,
}

#[derive(Default)]
struct Modeled {
    nonce: u64,
    gas: u64,
    to_bytes: Option<[u8; 20]>,
    selector: Option<[u8; 4]>,
    data_len: usize,
    value: (usize, usize),
    data: (usize, usize),
    fields: Vec<Field>,
    shape: Shape,
}

fn model(body: &[u8], layout: [usize; 5], uint256_value: bool) -> Option<Modeled> {
    let (fields, shape) = scan(body).ok()?;
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
    // Only blob and 7702 values are uint256 in geth; older types take a longer big.Int.
    if uint256_value && item(vi).len() > 32 {
        return None;
    }
    Some(Modeled {
        nonce: be_uint::<8>(item(ni))? as u64,
        gas: be_uint::<8>(item(gi))? as u64,
        to_bytes,
        selector: data.get(..4).map(|s| s.try_into().unwrap()),
        data_len: data.len(),
        value: (fields[vi].1, fields[vi].2),
        data: (fields[di].1, fields[di].2),
        fields,
        shape,
    })
}

impl Tx {
    fn body(&self) -> &[u8] {
        &self.raw[self.body..]
    }

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

    /// ECDSA recovery, by far the most expensive call here. Cached.
    pub fn sender_bytes(&self) -> Option<[u8; 20]> {
        *self.sender.get_or_init(|| self.recover())
    }

    pub fn sender(&self) -> Option<String> {
        self.sender_bytes().map(|s| checksum(&s))
    }

    /// Value in wei, minimal big-endian (empty for zero).
    pub fn value_be(&self) -> &[u8] {
        &self.body()[self.value.0..self.value.1]
    }

    pub fn value_dec(&self) -> String {
        decimal(self.value_be())
    }

    /// The calldata. Empty for an envelope this does not model.
    pub fn data(&self) -> &[u8] {
        match &self.input {
            Some(input) => input,
            None => &self.body()[self.data.0..self.data.1],
        }
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
            // EIP-155 folds the chain id into v; pre-155 uses 27/28 over six fields.
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
            if v > 1 {
                return None;
            }
            (v, rlp_list(&[self.tx_type], &[&body[f[0].0..f[n - 4].2]]))
        };
        crate::secp::recover(&keccak(&payload), &pad32(r), &pad32(s), parity as u8)
    }
}

/// Recover and cache every sender in `txs` on all cores (rayon). rayon's threads sleep
/// between messages and waking them costs most of the gain; `SenderPool` avoids that.
pub fn recover_senders<'a>(txs: impl IntoIterator<Item = &'a Tx>) {
    let txs: Vec<&Tx> = txs.into_iter().collect();
    txs.par_iter().for_each(|t| {
        t.sender_bytes();
    });
}

/// Threads that spin waiting for senders to recover, so they start at once with warm
/// caches. Each keeps a core at 100% while the pool exists.
pub struct SenderPool {
    epoch: Arc<AtomicU64>,
    job: Arc<Mutex<Option<Arc<Job>>>>,
    stop: Arc<AtomicBool>,
    sample: Arc<Mutex<Option<Bytes>>>,
}

struct Job {
    txs: Vec<*const Tx>,
    next: AtomicUsize,
    done: AtomicUsize,
}

// SAFETY: the pointers are only followed while `recover` still borrows the transactions
// (see `work`), and `Tx` is `Sync`.
unsafe impl Send for Job {}
unsafe impl Sync for Job {}

impl Job {
    fn work(&self) {
        loop {
            let i = self.next.fetch_add(1, Ordering::Relaxed);
            let Some(&tx) = self.txs.get(i) else {
                return;
            };
            // Counted even if recovery panics, so `recover_while` can't wait forever.
            let _done = Done(&self.done);
            // SAFETY: `recover_while` waits until every index handed out here is done, so
            // the transaction is still borrowed. An index past the end follows no pointer.
            unsafe { (*tx).sender_bytes() };
        }
    }
}

struct Done<'a>(&'a AtomicUsize);

impl Drop for Done<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Release);
    }
}

/// Waits for the other threads even while unwinding: they hold pointers to transactions
/// borrowed only for the call.
struct Finish<'a>(&'a Job);

impl Drop for Finish<'_> {
    fn drop(&mut self) {
        self.0.work();
        while self.0.done.load(Ordering::Acquire) < self.0.txs.len() {
            std::hint::spin_loop();
        }
    }
}

impl SenderPool {
    /// `threads` spinning threads; the calling thread works too.
    pub fn new(threads: usize) -> Self {
        let pool = Self {
            epoch: Arc::default(),
            job: Arc::default(),
            stop: Arc::default(),
            sample: Arc::default(),
        };
        for _ in 0..threads {
            let (epoch, job, stop) = (pool.epoch.clone(), pool.job.clone(), pool.stop.clone());
            let sample = pool.sample.clone();
            let mut next_warm = Instant::now();
            std::thread::Builder::new()
                .name("rhfeed-senders".into())
                .spawn(move || {
                    let mut seen = 0;
                    while !stop.load(Ordering::Relaxed) {
                        let now = epoch.load(Ordering::Acquire);
                        if now == seen {
                            // A sample every millisecond keeps code and tables in cache.
                            if Instant::now() >= next_warm {
                                let raw = sample.lock().unwrap_or_else(|e| e.into_inner()).clone();
                                if let Some(tx) = raw.and_then(decode_transaction) {
                                    std::hint::black_box(tx.sender_bytes());
                                }
                                next_warm = Instant::now() + Duration::from_millis(1);
                            }
                            std::hint::spin_loop();
                            continue;
                        }
                        seen = now;
                        let job = job.lock().unwrap_or_else(|e| e.into_inner()).clone();
                        if let Some(job) = job {
                            job.work();
                        }
                    }
                })
                .expect("cannot start a sender thread");
        }
        pool
    }

    pub fn recover<'a>(&mut self, txs: impl IntoIterator<Item = &'a Tx>) {
        self.recover_while(txs, || ());
    }

    /// `recover`, while this thread runs `f` first. Returns what `f` returns.
    pub fn recover_while<'a, R>(
        &mut self,
        txs: impl IntoIterator<Item = &'a Tx>,
        f: impl FnOnce() -> R,
    ) -> R {
        let job = Arc::new(Job {
            txs: txs.into_iter().map(std::ptr::from_ref).collect(),
            next: AtomicUsize::new(0),
            done: AtomicUsize::new(0),
        });
        let mut sample = self.sample.lock().unwrap_or_else(|e| e.into_inner());
        if sample.is_none() {
            // SAFETY: the transactions are borrowed for this whole call.
            *sample = job.txs.first().map(|&t| unsafe { (*t).raw.clone() });
        }
        drop(sample);
        *self.job.lock().unwrap_or_else(|e| e.into_inner()) = Some(job.clone());
        self.epoch.fetch_add(1, Ordering::Release);
        let finish = Finish(&job);
        let out = f();
        drop(finish);
        *self.job.lock().unwrap_or_else(|e| e.into_inner()) = None;
        out
    }
}

impl Drop for SenderPool {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
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

/// One signed envelope: legacy, 2930, 1559, blob or 7702. One that doesn't parse keeps
/// only its hash and raw bytes.
pub fn decode_transaction(raw: Bytes) -> Option<Tx> {
    decode_shaped(raw).map(|(tx, _)| tx)
}

fn decode_shaped(raw: Bytes) -> Option<(Tx, Shape)> {
    let &head = raw.first()?;
    let typed = head < 0x80;
    let tx_type = if typed { head } else { 0 };
    let body = usize::from(typed);
    let m = layout(tx_type).and_then(|l| model(&raw[body..], l, tx_type >= 3));
    let m = m.unwrap_or_default();
    let tx = Tx {
        raw,
        tx_type,
        nonce: m.nonce,
        gas: m.gas,
        to_bytes: m.to_bytes,
        selector: m.selector,
        data_len: m.data_len,
        value: m.value,
        data: m.data,
        input: None,
        fields: m.fields,
        body,
        hash: OnceLock::new(),
        sender: OnceLock::new(),
    };
    Some((tx, m.shape))
}

/// The signed transactions in an l2Msg, nested batches flattened. Anything
/// parseL2Message refuses anywhere voids the whole message, as in the block producer,
/// so the result is then empty.
pub fn decode_l2_message(payload: &Bytes) -> Vec<Tx> {
    let mut out = Vec::new();
    if payload.len() > MAX_L2_MESSAGE_SIZE || walk(payload, 0, &mut out).is_err() {
        out.clear();
    }
    out
}

struct Rejected;

fn walk(payload: &Bytes, depth: usize, out: &mut Vec<Tx>) -> Result<(), Rejected> {
    let &kind = payload.first().ok_or(Rejected)?;
    match kind {
        L2_SIGNED_TX => {
            let (tx, shape) = decode_shaped(payload.slice(1..)).ok_or(Rejected)?;
            if !geth_accepts(&tx, shape) {
                return Err(Rejected);
            }
            out.push(tx);
        }
        L2_BATCH if depth < MAX_BATCH_DEPTH => {
            // [8-byte length][message], repeated. As in util.BytestringFromReader, a
            // truncated entry ends the batch and keeps what came before.
            let mut offset = 1;
            while offset + 8 <= payload.len() {
                let len = u64::from_be_bytes(payload[offset..offset + 8].try_into().unwrap());
                offset += 8;
                if len > (payload.len() - offset) as u64 {
                    break;
                }
                let end = offset + len as usize;
                walk(&payload.slice(offset..end), depth + 1, out)?;
                offset = end;
            }
        }
        L2_UNSIGNED_USER_TX | L2_CONTRACT_TX => {
            // parseUnsignedTx: words for gas limit, max fee, nonce (kind 0), to, value.
            // Gas limit and nonce must fit a uint64.
            let words = if kind == L2_UNSIGNED_USER_TX { 5 } else { 4 };
            let body = &payload[1..];
            let high_zero = |at: usize| body[at..at + 24].iter().all(|&b| b == 0);
            if body.len() < 32 * words
                || !high_zero(0)
                || (kind == L2_UNSIGNED_USER_TX && !high_zero(64))
            {
                return Err(Rejected);
            }
        }
        // A batch past the cap, kinds 2 and 7 (unimplemented), 6 (heartbeat), unknown.
        _ => return Err(Rejected),
    }
    Ok(())
}

/// Whether geth's `UnmarshalBinary` decodes this envelope and arbos takes it: each field
/// matches its Go type (list or string, integers without a leading zero), prefixes are
/// canonical and nothing follows the list. `model` already bounded nonce, gas, `to` and a
/// 7702 value. parseL2Message refuses blob envelopes.
///
/// shortcut: items inside access and authorization lists aren't checked.
fn geth_accepts(tx: &Tx, shape: Shape) -> bool {
    // Field count, then one bit per field for lists and one for integers.
    let (count, lists, ints) = match tx.raw.first() {
        // nonce gasPrice gas to value data v r s
        Some(0xc0..) => (9, 0, 0b1_1101_0111),
        // chainId nonce gasPrice gas to value data accessList v r s
        Some(1) => (11, 1 << 7, 0b111_0010_1111),
        // chainId nonce tip feeCap gas to value data accessList v r s
        Some(2) => (12, 1 << 8, 0b1110_0101_1111),
        // + authorizationList; integers are uint256 and `to` can't be empty
        Some(4) => {
            let wide = |k: usize| INTS_7702 >> k & 1 != 0 && tx.fields[k].2 - tx.fields[k].1 > 32;
            if tx.fields.len() != 13 || (0..13).any(wide) || tx.to_bytes.is_none() {
                return false;
            }
            (13, 0b11 << 8, INTS_7702)
        }
        _ => return false,
    };
    shape.strict && tx.fields.len() == count && shape.lists == lists && shape.zero_led & ints == 0
}

const INTS_7702: u32 = 0b1_1100_0101_1111;

/// arbostypes: parent-chain kinds arbos turns into a transaction of its own type, whose
/// hash covers the chain id.
pub const L1_SUBMIT_RETRYABLE: i64 = 9;
pub const L1_ETH_DEPOSIT: i64 = 12;
pub const ARB_DEPOSIT_TX: u8 = 0x64;
pub const ARB_SUBMIT_RETRYABLE_TX: u8 = 0x69;
/// The ArbRetryableTx precompile a submit-retryable calls (go-ethereum arb_types.go).
const ARB_RETRYABLE_TX: [u8; 20] = {
    let mut a = [0; 20];
    a[19] = 0x6e;
    a
};
const SUBMIT_RETRYABLE_SELECTOR: [u8; 4] = [0xc9, 0xf9, 0x5d, 0x32];

fn rlp_bytes(value: &[u8]) -> Vec<u8> {
    match value {
        [b] if *b < 0x80 => vec![*b],
        _ => {
            let mut out = Vec::with_capacity(9 + value.len());
            rlp_header(value.len(), 0x80, &mut out);
            out.extend_from_slice(value);
            out
        }
    }
}

fn rlp_be(value: &[u8]) -> Vec<u8> {
    rlp_bytes(&value[value.iter().take_while(|&&b| b == 0).count()..])
}

fn header_bytes<const N: usize>(value: Option<&Cow<str>>) -> Option<[u8; N]> {
    unhex(value?, "").ok()?.try_into().ok()
}

/// The transaction arbos builds from a SubmitRetryable or EthDeposit message
/// (arbos/parse_l2.go, nitro v3.12.2), matching `eth_getTransactionByHash`. None if arbos
/// refuses the message. The auto-redeem (0x68) needs the block's base fee, which the feed
/// doesn't carry, so it isn't built.
pub fn decode_parent_chain_message(header: &Header, payload: &[u8], chain_id: u64) -> Option<Tx> {
    if payload.len() > MAX_L2_MESSAGE_SIZE {
        return None;
    }
    let request_id = header_bytes::<32>(header.request_id.as_ref())?;
    let poster = header_bytes::<20>(header.sender.as_ref())?;
    let chain = rlp_uint(chain_id.into());
    let word = |i: usize| -> &[u8; 32] { payload[32 * i..32 * i + 32].try_into().unwrap() };
    let address = |w: &[u8; 32]| -> [u8; 20] { w[12..].try_into().unwrap() };
    match header.kind? {
        L1_ETH_DEPOSIT => {
            let (to, value) = (payload.get(..20)?, payload.get(20..52)?);
            let envelope = rlp_list(
                &[ARB_DEPOSIT_TX],
                &[
                    &chain,
                    &rlp_bytes(&request_id),
                    &rlp_bytes(&poster),
                    &rlp_bytes(to),
                    &rlp_be(value),
                ],
            );
            // The value is the envelope's last field. Offsets are into the body.
            let value_len = 32 - value.iter().take_while(|&&b| b == 0).count();
            let end = envelope.len() - 1;
            let value = (end - value_len, end);
            Some(built(
                ARB_DEPOSIT_TX,
                envelope,
                to.try_into().ok()?,
                0,
                value,
                None,
                poster,
            ))
        }
        L1_SUBMIT_RETRYABLE => {
            if payload.len() < 9 * 32 {
                return None;
            }
            let (retry_to, call_value, deposit, max_submission_fee) =
                (word(0), word(1), word(2), word(3));
            let (fee_refund, beneficiary, gas_limit, max_fee, data_length) =
                (word(4), word(5), word(6), word(7), word(8));
            if gas_limit[..24].iter().any(|&b| b != 0) || data_length[..24].iter().any(|&b| b != 0)
            {
                return None;
            }
            let gas = u64::from_be_bytes(gas_limit[24..].try_into().unwrap());
            let length = u64::from_be_bytes(data_length[24..].try_into().unwrap()) as usize;
            if length > MAX_L2_MESSAGE_SIZE {
                return None;
            }
            // A plain Read, not ReadFull: a short tail is zero-padded, an empty one fails.
            let tail = &payload[9 * 32..];
            if length > 0 && tail.is_empty() {
                return None;
            }
            let mut retry_data = tail[..length.min(tail.len())].to_vec();
            retry_data.resize(length, 0);
            let l1_base_fee = header.base_fee_l1.unwrap_or(0).to_be_bytes();
            let to = address(retry_to);
            let envelope = rlp_list(
                &[ARB_SUBMIT_RETRYABLE_TX],
                &[
                    &chain,
                    &rlp_bytes(&request_id),
                    &rlp_bytes(&poster),
                    &rlp_be(&l1_base_fee),
                    &rlp_be(deposit),
                    &rlp_be(max_fee),
                    &rlp_uint(gas.into()),
                    // The zero address is encoded as nil.
                    &rlp_bytes(if to == [0; 20] { &[] } else { &to }),
                    &rlp_be(call_value),
                    &rlp_bytes(&address(beneficiary)),
                    &rlp_be(max_submission_fee),
                    &rlp_bytes(&address(fee_refund)),
                    &rlp_bytes(&retry_data),
                ],
            );
            // eth_getTransactionByHash's `input`, addresses re-padded from their low 20 bytes.
            let pad = |a: [u8; 20]| [[0u8; 12].as_slice(), &a].concat();
            let input = [
                &SUBMIT_RETRYABLE_SELECTOR[..],
                &request_id,
                &pad32(&l1_base_fee),
                deposit,
                call_value,
                max_fee,
                gas_limit,
                max_submission_fee,
                &pad(address(fee_refund)),
                &pad(address(beneficiary)),
                &pad(to),
                &pad32(&(32 * 11u32).to_be_bytes()),
                data_length,
                &retry_data,
                &vec![0; length.next_multiple_of(32) - length],
            ]
            .concat();
            Some(built(
                ARB_SUBMIT_RETRYABLE_TX,
                envelope,
                ARB_RETRYABLE_TX,
                gas,
                (0, 0),
                Some(input),
                poster,
            ))
        }
        _ => None,
    }
}

/// Unsigned: the sender is the message's poster.
fn built(
    tx_type: u8,
    envelope: Vec<u8>,
    to: [u8; 20],
    gas: u64,
    value: (usize, usize),
    input: Option<Vec<u8>>,
    sender: [u8; 20],
) -> Tx {
    let data_len = input.as_ref().map_or(0, Vec::len);
    let selector = input
        .as_ref()
        .and_then(|d| d.get(..4))
        .map(|s| s.try_into().unwrap());
    Tx {
        raw: envelope.into(),
        tx_type,
        nonce: 0,
        gas,
        to_bytes: Some(to),
        selector,
        data_len,
        value,
        data: (0, 0),
        input: input.map(Vec::into_boxed_slice),
        fields: Vec::new(),
        body: 1,
        hash: OnceLock::new(),
        sender: OnceLock::from(Some(sender)),
    }
}

/// serde copies a `Cow<str>` inside an `Option`; this borrows unless the string has escapes.
fn borrowed<'de: 'a, 'a, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Cow<'a, str>>, D::Error> {
    #[derive(Deserialize)]
    struct Borrowed<'a>(#[serde(borrow)] Cow<'a, str>);
    Ok(Option::<Borrowed>::deserialize(d)?.map(|b| b.0))
}

/// A relay frame, `{"version":1,"messages":[...]}`, borrowing its strings from the input.
#[derive(Deserialize)]
pub struct Frame<'a> {
    #[serde(borrow)]
    pub messages: Option<Vec<Entry<'a>>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry<'a> {
    pub sequence_number: Option<i64>,
    #[serde(borrow)]
    pub message: Option<Wrapper<'a>>,
    #[serde(borrow, default, deserialize_with = "borrowed")]
    pub block_hash: Option<Cow<'a, str>>,
    #[serde(borrow, default, deserialize_with = "borrowed")]
    pub block_metadata: Option<Cow<'a, str>>,
    #[serde(borrow, default, deserialize_with = "borrowed", rename = "signatureV2")]
    pub signature_v2: Option<Cow<'a, str>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Wrapper<'a> {
    #[serde(borrow)]
    pub message: Option<Incoming<'a>>,
    pub delayed_messages_read: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Incoming<'a> {
    #[serde(borrow)]
    pub header: Option<Header<'a>>,
    #[serde(borrow, default, deserialize_with = "borrowed")]
    pub l2_msg: Option<Cow<'a, str>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Header<'a> {
    pub kind: Option<i64>,
    #[serde(borrow, default, deserialize_with = "borrowed")]
    pub sender: Option<Cow<'a, str>>,
    pub block_number: Option<u64>,
    pub timestamp: Option<u64>,
    #[serde(borrow, default, deserialize_with = "borrowed")]
    pub request_id: Option<Cow<'a, str>>,
    #[serde(rename = "baseFeeL1")]
    pub base_fee_l1: Option<u128>,
}

/// Each entry as JSON text of its own, for a frame that `frame_from_slice` refuses because
/// one entry has a field of the wrong type. Slow; only for that case.
pub fn entry_texts(json: &[u8]) -> Option<Vec<String>> {
    use sonic_rs::{JsonContainerTrait, JsonValueTrait};
    let frame: sonic_rs::Value = sonic_rs::from_slice(json).ok()?;
    let messages = frame.get("messages")?.as_array()?;
    Some(messages.iter().map(|e| e.to_string()).collect())
}

/// Parse one relay frame, borrowing its strings from `json`.
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

/// When a message's frame finished each stage of `Feed`; the gap between neighbouring
/// fields is what that stage took.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// First socket read with bytes of this frame.
    pub first_read: Instant,
    /// Last socket read the frame needed.
    pub last_read: Instant,
    pub decrypted: Instant,
    /// The WebSocket layer returned the frame, inflated.
    pub inflated: Instant,
    pub parsed: Instant,
    /// With `FeedBuilder::senders`, also every sender recovered.
    pub verified: Instant,
    pub decoded: Instant,
    /// Just before the message went into the channel.
    pub sent: Instant,
}

/// One sequencer message. On this chain, `seq` equals the L2 block number.
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
    /// The delayed-inbox index; None on a message the sequencer built.
    pub request_id: Option<String>,
    /// Set by `Feed`.
    pub live: bool,
    /// Unix seconds when the first copy arrived.
    pub received_at: f64,
    /// This sequence number arrived before with a different block hash.
    pub reorg: bool,
    /// Index of the source that delivered this message first.
    pub source: usize,
    /// When each stage of `Feed` finished with this message.
    pub timing: Option<Timing>,
}

impl FeedMessage {
    /// arbostypes' name for the L1 message kind.
    pub fn l1_kind_name(&self) -> Cow<'static, str> {
        Cow::Borrowed(match self.l1_kind {
            L1_L2_MESSAGE => "L2Message",
            6 => "EndOfBlock",
            7 => "L2FundedByL1",
            8 => "RollupEvent",
            9 => "SubmitRetryable",
            10 => "BatchForGasEstimation",
            11 => "Initialize",
            12 => "EthDeposit",
            13 => "BatchPostingReport",
            0xFF => "Invalid",
            _ => return Cow::Owned(format!("kind{}", self.l1_kind)),
        })
    }

    /// Entered through Ethereum, not the sequencer. Nobody checked these `txs`: a node
    /// skips one whose signature, nonce or balance doesn't hold, without a receipt.
    pub fn from_parent_chain(&self) -> bool {
        self.request_id.is_some() || self.l1_kind != L1_L2_MESSAGE
    }
}

/// Every message in a frame, transactions decoded. With `chain_id`, SubmitRetryable and
/// EthDeposit messages carry the transaction arbos builds from them.
pub fn parse_frame(frame: &Frame, chain_id: Option<u64>) -> Vec<FeedMessage> {
    frame
        .entries()
        .iter()
        .map(|e| parse_entry_with(e, l2_msg(e).ok().flatten().as_ref(), chain_id))
        .collect()
}

/// An l2Msg that isn't valid base64.
#[derive(Debug)]
pub struct InvalidBase64;

/// An entry's l2Msg, base64-decoded once for both verification and decoding. `Ok(None)`
/// when absent or empty.
pub fn l2_msg(entry: &Entry) -> Result<Option<Bytes>, InvalidBase64> {
    match entry.incoming().and_then(|i| i.l2_msg.as_deref()) {
        Some(l2) if !l2.is_empty() => Ok(Some(b64(l2).ok_or(InvalidBase64)?.into())),
        _ => Ok(None),
    }
}

/// One entry, with its l2Msg from `l2_msg`. Transactions are decoded only if `l2` is
/// given. `chain_id` as in `parse_frame`.
pub fn parse_entry_with(entry: &Entry, l2: Option<&Bytes>, chain_id: Option<u64>) -> FeedMessage {
    let header = entry.header();
    let kind = header.and_then(|h| h.kind).unwrap_or(-1);
    // Only an L2Message holds signed transactions; arbos reads other kinds their own way.
    let txs = match (l2, header, chain_id) {
        (Some(l2), _, _) if kind == L1_L2_MESSAGE => decode_l2_message(l2),
        (Some(l2), Some(h), Some(chain)) => decode_parent_chain_message(h, l2, chain)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    };
    FeedMessage {
        seq: entry.sequence_number.unwrap_or(-1),
        l1_kind: kind,
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
        request_id: header
            .and_then(|h| h.request_id.as_deref())
            .map(str::to_owned),
        live: true,
        received_at: 0.0,
        reorg: false,
        source: 0,
        timing: None,
    }
}

/// eth_call body asking the compliance filter precompile whether a transaction is
/// blocked. A malformed hash would still make a well-formed call about the wrong slot,
/// so it's checked.
pub fn is_filtered_call(tx_hash: &str) -> Result<sonic_rs::Value, String> {
    let raw: [u8; 32] = fixed(tx_hash, "transaction hash")?;
    Ok(sonic_rs::json!({
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
    fn a_panic_in_recover_while_still_finishes_the_job() {
        let legacy = Bytes::from_static(b"\xc9\x80\x80\x80\x80\x80\x80\x80\x80\x80");
        let txs: Vec<Tx> = (0..4)
            .map(|_| decode_transaction(legacy.clone()).unwrap())
            .collect();
        let mut pool = SenderPool::new(0);
        let run = std::panic::AssertUnwindSafe(|| pool.recover_while(&txs, || panic!("boom")));
        assert!(std::panic::catch_unwind(run).is_err());
        // Every sender was worked out before the panic left recover_while.
        assert!(txs.iter().all(|t| t.sender.get().is_some()));
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
    fn only_an_l2_message_is_decoded_into_transactions() {
        // SignedTx marker and a legacy envelope of nine empty fields.
        let l2 = Bytes::from([[4u8, 0xc9].as_slice(), &[0x80; 9]].concat());
        let json = |kind: i64| {
            format!(
                r#"{{"messages":[{{"message":{{"message":{{"header":{{"kind":{kind}}}}}}}}}]}}"#
            )
        };
        for (kind, txs) in [(3, 1), (12, 0)] {
            let text = json(kind);
            let frame = frame_from_slice(text.as_bytes()).unwrap();
            let msg = parse_entry_with(&frame.entries()[0], Some(&l2), None);
            assert_eq!(msg.txs.len(), txs, "kind {kind}");
        }
    }

    #[test]
    fn strings_are_borrowed_from_the_frame() {
        let json = br#"{"messages":[{"sequenceNumber":1,"blockHash":null,
            "signatureV2":"a\/b","message":{"message":{"l2Msg":"BAAA"}}}]}"#;
        let frame = frame_from_slice(json).unwrap();
        let e = &frame.entries()[0];
        assert!(matches!(
            e.incoming().unwrap().l2_msg,
            Some(Cow::Borrowed("BAAA"))
        ));
        assert!(matches!(e.signature_v2.as_deref(), Some("a/b")));
        assert!(e.block_hash.is_none() && e.block_metadata.is_none());
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
