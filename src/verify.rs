//! Check that a feed message was signed by the chain's sequencer key.
//!
//! Ported from the Python version's `src/rhfeed/verify.py`. Its docstring explains why
//! this is worth doing even over TLS or through your own relay. It also covers two
//! details that are easy to get wrong in the signed data: `requestId` and `baseFeeL1`
//! are left out entirely when null, and `baseFeeL1` is written as minimal big-endian
//! bytes, so a zero base fee adds nothing.

use std::collections::HashSet;
use std::sync::LazyLock;

use keccak_asm::{Digest, Keccak256};

use crate::codec::{Entry, b64, l2_msg};

/// Prefix on the signed data, so a feed signature can't be reused for anything else.
pub const FEED_PREFIX: &[u8] = b"Arbitrum Nitro Feed:";

pub const MAINNET_CHAIN_ID: u64 = 4663;

/// The key that signs mainnet feed messages, confirmed as this chain's batch poster by
/// `isBatchPoster()` on the L1 SequencerInbox (2026-07-27). See verify.py.
pub const MAINNET_SIGNER: [u8; 20] = [
    0xda, 0xa5, 0x26, 0x08, 0x67, 0x87, 0xd9, 0xde, 0xbe, 0x1d, 0x7f, 0x3f, 0xfd, 0xb1, 0xfe, 0x50,
    0xcf, 0x86, 0x87, 0xf4,
];

fn unhex(value: &str) -> Option<Vec<u8>> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value)).ok()
}

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
        out(&unhex(hash)?);
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
    out(&unhex(
        header.and_then(|h| h.sender.as_deref()).unwrap_or(""),
    )?);
    out(&header
        .and_then(|h| h.block_number)
        .unwrap_or(0)
        .to_be_bytes());
    out(&header.and_then(|h| h.timestamp).unwrap_or(0).to_be_bytes());

    // Both are left out when null. They are not zero-padded.
    if let Some(id) = header.and_then(|h| h.request_id.as_deref()) {
        out(&unhex(id)?);
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
    let sig = b64(entry.signature_v2.as_deref()?)?;
    let sig: [u8; 65] = sig.try_into().ok()?;
    let recid = match sig[64] {
        v @ 27..=30 => v - 27, // a signer that normalised v the Ethereum way
        v @ 0..=3 => v,
        _ => return None,
    };
    let digest = signature_hash(entry, chain_id, l2)?;
    crate::secp::recover(
        &digest,
        sig[..32].try_into().unwrap(),
        sig[32..64].try_into().unwrap(),
        recid,
    )
}

/// A chain id and the signers you accept for it. Nitro looks the signer up on L1 at
/// runtime. We use a fixed list so checking works offline, which means a key rotation
/// needs a new list.
#[derive(Clone, Debug)]
pub struct Verifier {
    pub chain_id: u64,
    pub signers: HashSet<[u8; 20]>,
}

impl Verifier {
    pub fn new(chain_id: u64, signers: impl IntoIterator<Item = [u8; 20]>) -> Self {
        Self {
            chain_id,
            signers: signers.into_iter().collect(),
        }
    }

    /// Who signed this message, whether or not you accept them.
    pub fn signer_of(&self, entry: &Entry) -> Option<[u8; 20]> {
        recover_signer(entry, self.chain_id)
    }

    /// A good signature from an allowed signer. False for an unsigned message too.
    pub fn accepts(&self, entry: &Entry) -> bool {
        self.signer_of(entry)
            .is_some_and(|s| self.signers.contains(&s))
    }

    /// `accepts` with the entry's l2Msg already decoded (see `codec::l2_msg`).
    pub fn accepts_with(&self, entry: &Entry, l2: Option<&[u8]>) -> bool {
        recover_signer_with(entry, self.chain_id, l2).is_some_and(|s| self.signers.contains(&s))
    }
}

/// Ready-made: Robinhood Chain mainnet, signed by its batch poster.
pub static MAINNET_VERIFIER: LazyLock<Verifier> =
    LazyLock::new(|| Verifier::new(MAINNET_CHAIN_ID, [MAINNET_SIGNER]));
