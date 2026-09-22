//! ECDSA public-key recovery to an Ethereum address — the one expensive primitive in the
//! crate, used for both transaction senders and feed signatures.
//!
//! libsecp256k1, the same C library coincurve wraps on the Python side.

use crate::codec::keccak;

/// 20-byte address that produced (r, s, recid) over `digest`, or None if there is none.
pub fn recover(digest: &[u8; 32], r: &[u8; 32], s: &[u8; 32], recid: u8) -> Option<[u8; 20]> {
    libsecp::recover(digest, r, s, recid)
}

fn address(pubkey64: &[u8]) -> [u8; 20] {
    keccak(pubkey64)[12..].try_into().unwrap()
}

pub mod libsecp {
    use secp256k1::Message;
    use secp256k1::SECP256K1;
    use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};

    pub fn recover(digest: &[u8; 32], r: &[u8; 32], s: &[u8; 32], recid: u8) -> Option<[u8; 20]> {
        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(r);
        rs[32..].copy_from_slice(s);
        let id = RecoveryId::try_from(i32::from(recid)).ok()?;
        let sig = RecoverableSignature::from_compact(&rs, id).ok()?;
        let key = SECP256K1
            .recover_ecdsa(Message::from_digest(*digest), &sig)
            .ok()?;
        Some(super::address(&key.serialize_uncompressed()[1..]))
    }
}
