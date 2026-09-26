//! Check that a feed message was signed by the chain's sequencer key.
//!
//! Ported from the Python version's `src/rhfeed/verify.py`. Its docstring explains why
//! this is worth doing even over TLS or through your own relay. It also covers two
//! details that are easy to get wrong in the signed data: `requestId` and `baseFeeL1`
//! are left out entirely when null, and `baseFeeL1` is written as minimal big-endian
//! bytes, so a zero base fee adds nothing.

use std::collections::HashSet;
use std::sync::{Arc, LazyLock, RwLock};

use keccak_asm::{Digest, Keccak256};

use crate::codec::{Entry, b64, l2_msg, unhex};
use crate::secp::{FixedKey, address, libsecp};

/// Prefix on the signed data, so a feed signature can't be reused for anything else.
pub const FEED_PREFIX: &[u8] = b"Arbitrum Nitro Feed:";

pub const MAINNET_CHAIN_ID: u64 = 4663;

/// The key that signs mainnet feed messages, confirmed as this chain's batch poster by
/// `isBatchPoster()` on the L1 SequencerInbox (2026-07-27). See verify.py.
pub const MAINNET_SIGNER: [u8; 20] = [
    0xda, 0xa5, 0x26, 0x08, 0x67, 0x87, 0xd9, 0xde, 0xbe, 0x1d, 0x7f, 0x3f, 0xfd, 0xb1, 0xfe, 0x50,
    0xcf, 0x86, 0x87, 0xf4,
];

/// `MAINNET_SIGNER`'s public key, compressed, recovered from a mainnet feed signature.
const MAINNET_KEY: &str = "02ea7d65f634219514fabe8121f77edf3b50d278af9b1783f2897ee5889473c828";

/// The exact bytes the sequencer signed, rebuilt from one raw envelope. See Nitro's
/// `BroadcastFeedMessage.SignatureHash`. None when a field cannot be encoded at all.
pub fn signature_payload(entry: &Entry, chain_id: u64) -> Option<Vec<u8>> {
    let l2 = l2_msg(entry).ok()?;
    let mut out = Vec::new();
    preimage(entry, chain_id, l2.as_deref(), &mut |b| {
        out.extend_from_slice(b)
    })?;
    Some(out)
}

/// keccak of the preimage, hashed as it is produced rather than assembled first.
fn signature_hash(entry: &Entry, chain_id: u64, l2: Option<&[u8]>) -> Option<[u8; 32]> {
    let mut hasher = Keccak256::new();
    preimage(entry, chain_id, l2, &mut |b| hasher.update(b))?;
    Some(hasher.finalize().into())
}

/// Hand every piece of the preimage to `out`, in order, with the l2Msg pre-decoded.
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

    // Skipped when absent, per Nitro. Present in practice on this chain.
    if let Some(hash) = entry.block_hash.as_deref().filter(|h| !h.is_empty()) {
        out(&unhex(hash, "block hash").ok()?);
    }
    // Timeboost's express-lane bitmap. Robinhood Chain doesn't send it, Arbitrum One does.
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

    // Both are left out when null. They are not zero-padded.
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

/// The address that signed this message, or None if there's no usable signature. A
/// forged message still recovers some address, so compare the result, don't just check
/// for None.
pub fn recover_signer(entry: &Entry, chain_id: u64) -> Option<[u8; 20]> {
    recover_signer_with(entry, chain_id, l2_msg(entry).ok()?.as_deref())
}

/// `recover_signer` with the entry's l2Msg already decoded (see `codec::l2_msg`).
pub fn recover_signer_with(entry: &Entry, chain_id: u64, l2: Option<&[u8]>) -> Option<[u8; 20]> {
    let s = Signed::new(entry, chain_id, l2)?;
    crate::secp::recover(&s.digest, &s.r, &s.s, s.recid)
}

/// What a signature check needs from an entry: the digest and the signature's parts.
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
            v @ 27..=30 => v - 27, // a signer that normalised v the Ethereum way
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

/// A chain id and the signers you accept for it. Nitro looks the signer up on L1 at
/// runtime. We use a fixed list so checking works offline, which means a key rotation
/// needs a new list.
///
/// The first message from each accepted signer is checked by recovering its key, which
/// is then kept with precomputed tables (a few ms to build, ~370 KB). Its later messages
/// are checked against that key, about 3 times faster than recovering. Clones share
/// the keys.
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

    /// Who signed this message, whether or not you accept them.
    pub fn signer_of(&self, entry: &Entry) -> Option<[u8; 20]> {
        recover_signer(entry, self.chain_id)
    }

    /// A good signature from an allowed signer. False for an unsigned message too.
    pub fn accepts(&self, entry: &Entry) -> bool {
        l2_msg(entry).is_ok_and(|l2| self.accepts_with(entry, l2.as_deref()))
    }

    /// `accepts` with the entry's l2Msg already decoded (see `codec::l2_msg`).
    pub fn accepts_with(&self, entry: &Entry, l2: Option<&[u8]>) -> bool {
        let Some(s) = Signed::new(entry, self.chain_id, l2) else {
            return false;
        };
        let keys = self.keys.read().unwrap_or_else(|e| e.into_inner());
        // `signers` is public, so a key we remember may have been removed from it since.
        let known = |k: &&FixedKey| self.signers.contains(&k.address);
        if keys
            .iter()
            .filter(known)
            .any(|k| k.verify(&s.digest, &s.r, &s.s))
        {
            return true;
        }
        drop(keys);
        // A signer we haven't seen yet. Recover it, and if we accept it, keep its key so
        // its next messages take the path above. Tables only for accepted signers:
        // building them takes milliseconds.
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

/// Ready-made: Robinhood Chain mainnet, signed by its batch poster. Its key's tables
/// are built when this is first used, so the first message doesn't wait for them.
pub static MAINNET_VERIFIER: LazyLock<Verifier> = LazyLock::new(|| {
    let v = Verifier::new(MAINNET_CHAIN_ID, [MAINNET_SIGNER]);
    let key: [u8; 33] = hex::decode(MAINNET_KEY).unwrap().try_into().unwrap();
    v.remember(FixedKey::new(&key).unwrap());
    v
});
