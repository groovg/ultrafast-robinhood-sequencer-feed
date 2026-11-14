//! Check that a feed message was signed by the chain's sequencer key.

use std::collections::HashSet;
use std::sync::{Arc, LazyLock, RwLock};

use keccak_asm::{Digest, Keccak256};

use crate::codec::{Entry, b64, l2_msg, unhex};
use crate::secp::{FixedKey, address, libsecp};

pub const FEED_PREFIX: &[u8] = b"Arbitrum Nitro Feed:";

pub const MAINNET_CHAIN_ID: u64 = 4663;

/// Confirmed as the batch poster by `isBatchPoster()` on the L1 SequencerInbox.
pub const MAINNET_SIGNER: [u8; 20] = [
    0xda, 0xa5, 0x26, 0x08, 0x67, 0x87, 0xd9, 0xde, 0xbe, 0x1d, 0x7f, 0x3f, 0xfd, 0xb1, 0xfe, 0x50,
    0xcf, 0x86, 0x87, 0xf4,
];

/// `MAINNET_SIGNER`'s compressed public key.
const MAINNET_KEY: &str = "02ea7d65f634219514fabe8121f77edf3b50d278af9b1783f2897ee5889473c828";

/// The bytes the sequencer signed (Nitro's `BroadcastFeedMessage.SignatureHash`).
pub fn signature_payload(entry: &Entry, chain_id: u64) -> Option<Vec<u8>> {
    let l2 = l2_msg(entry).ok()?;
    let mut out = Vec::new();
    preimage(entry, chain_id, l2.as_deref(), &mut |b| {
        out.extend_from_slice(b)
    })?;
    Some(out)
}

fn signature_hash(entry: &Entry, chain_id: u64, l2: Option<&[u8]>) -> Option<[u8; 32]> {
    let mut hasher = Keccak256::new();
    preimage(entry, chain_id, l2, &mut |b| hasher.update(b))?;
    Some(hasher.finalize().into())
}

fn preimage(
    entry: &Entry,
    chain_id: u64,
    l2: Option<&[u8]>,
    out: &mut impl FnMut(&[u8]),
) -> Option<()> {
    let wrapper = entry.message.as_ref();
    let header = entry.header();

    out(FEED_PREFIX);
    out(&chain_id.to_be_bytes());
    out(&u64::try_from(entry.sequence_number.unwrap_or(0))
        .ok()?
        .to_be_bytes());

    if let Some(hash) = entry.block_hash.as_deref().filter(|h| !h.is_empty()) {
        out(&unhex(hash, "block hash").ok()?);
    }
    // Timeboost's express-lane bitmap.
    if let Some(meta) = entry.block_metadata.as_deref().filter(|m| !m.is_empty()) {
        out(&b64(meta)?);
    }
    out(&wrapper
        .and_then(|w| w.delayed_messages_read)
        .unwrap_or(0)
        .to_be_bytes());

    out(&[u8::try_from(header.and_then(|h| h.kind).unwrap_or(0)).ok()?]);
    let sender = header.and_then(|h| h.sender.as_deref()).unwrap_or("");
    out(&unhex(sender, "sender").ok()?);
    out(&header
        .and_then(|h| h.block_number)
        .unwrap_or(0)
        .to_be_bytes());
    out(&header.and_then(|h| h.timestamp).unwrap_or(0).to_be_bytes());

    // Left out when null, and not zero-padded.
    if let Some(id) = header.and_then(|h| h.request_id.as_deref()) {
        out(&unhex(id, "request id").ok()?);
    }
    if let Some(fee) = header.and_then(|h| h.base_fee_l1) {
        // Go's big.Int.Bytes(): big-endian, no leading zeros, empty for zero.
        out(&fee.to_be_bytes()[(fee.leading_zeros() / 8) as usize..]);
    }

    if let Some(l2) = l2 {
        out(l2);
    }
    Some(())
}

/// The signer's address. A forged message still recovers some address: compare it.
pub fn recover_signer(entry: &Entry, chain_id: u64) -> Option<[u8; 20]> {
    let s = Signed::new(entry, chain_id, l2_msg(entry).ok()?.as_deref())?;
    crate::secp::recover(&s.digest, &s.r, &s.s, s.recid)
}

struct Signed {
    digest: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
    recid: u8,
}

impl Signed {
    fn new(entry: &Entry, chain_id: u64, l2: Option<&[u8]>) -> Option<Self> {
        let sig = b64(entry.signature_v2.as_deref()?)?;
        let sig: [u8; 65] = sig.try_into().ok()?;
        let recid = match sig[64] {
            v @ 27..=30 => v - 27,
            v @ 0..=3 => v,
            _ => return None,
        };
        Some(Self {
            digest: signature_hash(entry, chain_id, l2)?,
            r: sig[..32].try_into().unwrap(),
            s: sig[32..64].try_into().unwrap(),
            recid,
        })
    }
}

/// A chain id and the signers you accept for it. A fixed list, unlike Nitro's L1 lookup,
/// so a key rotation needs a new list. An accepted signer's key is kept with precomputed
/// tables, and later messages are checked against it. Clones share the keys.
#[derive(Clone, Debug)]
pub struct Verifier {
    pub chain_id: u64,
    pub signers: HashSet<[u8; 20]>,
    keys: Arc<RwLock<Vec<FixedKey>>>,
}

impl Verifier {
    pub fn new(chain_id: u64, signers: impl IntoIterator<Item = [u8; 20]>) -> Self {
        Self {
            chain_id,
            signers: signers.into_iter().collect(),
            keys: Arc::default(),
        }
    }

    /// A good signature from an allowed signer.
    pub fn accepts(&self, entry: &Entry) -> bool {
        l2_msg(entry).is_ok_and(|l2| self.accepts_with(entry, l2.as_deref()))
    }

    /// `accepts` with the entry's l2Msg already decoded (see `codec::l2_msg`).
    pub fn accepts_with(&self, entry: &Entry, l2: Option<&[u8]>) -> bool {
        let Some(s) = Signed::new(entry, self.chain_id, l2) else {
            return false;
        };
        let keys = self.keys.read().unwrap_or_else(|e| e.into_inner());
        // `signers` is public: a remembered key may have been removed since.
        let known = |k: &&FixedKey| self.signers.contains(&k.address);
        if keys
            .iter()
            .filter(known)
            .any(|k| k.verify(&s.digest, &s.r, &s.s))
        {
            return true;
        }
        drop(keys);
        // A new signer. Tables only for accepted ones: building them takes milliseconds.
        let Some(key) = libsecp::recover_key(&s.digest, &s.r, &s.s, s.recid) else {
            return false;
        };
        if !self
            .signers
            .contains(&address(&key.serialize_uncompressed()[1..]))
        {
            return false;
        }
        if let Some(key) = FixedKey::new(&key.serialize()) {
            self.remember(key);
        }
        true
    }

    fn remember(&self, key: FixedKey) {
        let mut keys = self.keys.write().unwrap_or_else(|e| e.into_inner());
        if !keys.iter().any(|k| k.address == key.address) {
            keys.push(key);
        }
    }
}

/// Robinhood Chain mainnet, with its key's tables built on first use.
pub static MAINNET_VERIFIER: LazyLock<Verifier> = LazyLock::new(|| {
    let v = Verifier::new(MAINNET_CHAIN_ID, [MAINNET_SIGNER]);
    let key: [u8; 33] = hex::decode(MAINNET_KEY).unwrap().try_into().unwrap();
    v.remember(FixedKey::new(&key).unwrap());
    v
});
