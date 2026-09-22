//! Check that a feed message really came from the chain's sequencer key.
//!
//! Port of upstream `src/rhfeed/verify.py`; its docstring explains why this matters even behind
//! TLS and a relay you run, and the two preimage traps (`requestId` and `baseFeeL1` are
//! skipped when null, and `baseFeeL1` is minimal big-endian, so zero adds no bytes).

use std::collections::HashSet;
use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::codec::{Entry, keccak};

/// Domain separator, so a feed signature cannot be replayed as one over anything else.
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

/// The exact bytes the sequencer hashed, rebuilt from one raw envelope — Nitro's
/// `BroadcastFeedMessage.SignatureHash`. None when a field cannot be encoded at all.
pub fn signature_payload(entry: &Entry, chain_id: u64) -> Option<Vec<u8>> {
    let wrapper = entry.message.as_ref();
    let incoming = entry.incoming();
    let header = entry.header();

    let mut out = FEED_PREFIX.to_vec();
    out.extend_from_slice(&chain_id.to_be_bytes());
    out.extend_from_slice(
        &u64::try_from(entry.sequence_number.unwrap_or(0))
            .ok()?
            .to_be_bytes(),
    );

    // Skipped when absent, per Nitro. Present in practice on this chain.
    if let Some(hash) = entry.block_hash.as_deref().filter(|h| !h.is_empty()) {
        out.extend(unhex(hash)?);
    }
    // Timeboost's express-lane bitmap: absent here, present on Arbitrum One, signed either way.
    if let Some(meta) = entry.block_metadata.as_deref().filter(|m| !m.is_empty()) {
        out.extend(B64.decode(meta).ok()?);
    }
    out.extend_from_slice(
        &wrapper
            .and_then(|w| w.delayed_messages_read)
            .unwrap_or(0)
            .to_be_bytes(),
    );

    out.push(u8::try_from(header.and_then(|h| h.kind).unwrap_or(0)).ok()?);
    out.extend(unhex(
        header.and_then(|h| h.sender.as_deref()).unwrap_or(""),
    )?);
    out.extend_from_slice(
        &header
            .and_then(|h| h.block_number)
            .unwrap_or(0)
            .to_be_bytes(),
    );
    out.extend_from_slice(&header.and_then(|h| h.timestamp).unwrap_or(0).to_be_bytes());

    // Both omitted when null rather than zero-padded.
    if let Some(id) = header.and_then(|h| h.request_id.as_deref()) {
        out.extend(unhex(id)?);
    }
    if let Some(fee) = header.and_then(|h| h.base_fee_l1) {
        // Go's big.Int.Bytes(): big-endian, no leading zeros, empty for zero.
        out.extend_from_slice(&fee.to_be_bytes()[(fee.leading_zeros() / 8) as usize..]);
    }

    if let Some(l2) = incoming
        .and_then(|i| i.l2_msg.as_deref())
        .filter(|m| !m.is_empty())
    {
        out.extend(B64.decode(l2).ok()?);
    }
    Some(out)
}

/// The address that signed this message, or None if that cannot be had. None means
/// unusable, not forged: a forged message recovers some address, just not one you accept.
pub fn recover_signer(entry: &Entry, chain_id: u64) -> Option<[u8; 20]> {
    let sig = B64.decode(entry.signature_v2.as_deref()?).ok()?;
    let sig: [u8; 65] = sig.try_into().ok()?;
    let recid = match sig[64] {
        v @ 27..=30 => v - 27, // a signer that normalised v the Ethereum way
        v @ 0..=3 => v,
        _ => return None,
    };
    let digest = keccak(&signature_payload(entry, chain_id)?);
    crate::secp::recover(
        &digest,
        sig[..32].try_into().unwrap(),
        sig[32..64].try_into().unwrap(),
        recid,
    )
}

/// A chain id and the signers you will accept for it. A fixed set rather than Nitro's
/// runtime L1 lookup, so verification stays offline; a key rotation needs a new set.
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
}

/// Ready-made: Robinhood Chain mainnet, signed by its batch poster.
pub static MAINNET_VERIFIER: LazyLock<Verifier> =
    LazyLock::new(|| Verifier::new(MAINNET_CHAIN_ID, [MAINNET_SIGNER]));
