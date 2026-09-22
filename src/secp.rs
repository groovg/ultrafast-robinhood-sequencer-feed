//! ECDSA public-key recovery to an Ethereum address — the one expensive primitive in the
//! crate, used for both transaction senders and feed signatures.
//!
//! Two backends so they can be measured against each other: libsecp256k1 always, and
//! UltrafastSecp256k1 with the `ufsecp` feature, which then becomes the one `recover`
//! uses. Both must agree on every input; `tests/golden.rs` checks that they do.

use crate::codec::keccak;

/// 20-byte address that produced (r, s, recid) over `digest`, or None if there is none.
pub fn recover(digest: &[u8; 32], r: &[u8; 32], s: &[u8; 32], recid: u8) -> Option<[u8; 20]> {
    #[cfg(feature = "ufsecp")]
    return ufsecp::recover(digest, r, s, recid);
    #[cfg(not(feature = "ufsecp"))]
    return libsecp::recover(digest, r, s, recid);
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

#[cfg(feature = "ufsecp")]
pub mod ufsecp {
    use std::ffi::{c_int, c_void};

    // The four functions used from UltrafastSecp256k1's C ABI (include/ufsecp/ufsecp.h).
    // Declared here rather than through its `ufsecp-sys` crate, which is not published.
    unsafe extern "C" {
        fn ufsecp_ctx_create(ctx_out: *mut *mut c_void) -> c_int;
        fn ufsecp_eth_ecrecover(
            ctx: *mut c_void,
            msg32: *const u8,
            r: *const u8,
            s: *const u8,
            v: u64,
            addr20_out: *mut u8,
        ) -> c_int;
        fn ufsecp_ecdsa_recover(
            ctx: *mut c_void,
            msg32: *const u8,
            sig64: *const u8,
            recid: c_int,
            pubkey33_out: *mut u8,
        ) -> c_int;
        fn ufsecp_eth_address(ctx: *mut c_void, pubkey33: *const u8, addr20_out: *mut u8) -> c_int;
    }

    /// The curve order. Big-endian, so array comparison is numeric comparison.
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];

    thread_local! {
        // A context is single-threaded by the library's own rules, so one per thread.
        // Never destroyed: it lives as long as the thread that uses it.
        static CTX: *mut c_void = {
            let mut ctx = std::ptr::null_mut();
            unsafe { ufsecp_ctx_create(&mut ctx) };
            ctx
        };
    }

    pub fn recover(digest: &[u8; 32], r: &[u8; 32], s: &[u8; 32], recid: u8) -> Option<[u8; 20]> {
        // `ecrecover` reduces r and s mod n where libsecp256k1 rejects them, so an
        // out-of-range signature would recover here and not there. Reject it first.
        if *r >= N || *s >= N || recid > 3 {
            return None;
        }
        let mut out = [0u8; 20];
        let rc = CTX.with(|&ctx| unsafe {
            if recid < 2 {
                ufsecp_eth_ecrecover(
                    ctx,
                    digest.as_ptr(),
                    r.as_ptr(),
                    s.as_ptr(),
                    27 + u64::from(recid),
                    out.as_mut_ptr(),
                )
            } else {
                // `ecrecover` maps v through EIP-155 and cannot express recid 2 or 3.
                let mut rs = [0u8; 64];
                rs[..32].copy_from_slice(r);
                rs[32..].copy_from_slice(s);
                let mut key = [0u8; 33];
                match ufsecp_ecdsa_recover(
                    ctx,
                    digest.as_ptr(),
                    rs.as_ptr(),
                    c_int::from(recid),
                    key.as_mut_ptr(),
                ) {
                    0 => ufsecp_eth_address(ctx, key.as_ptr(), out.as_mut_ptr()),
                    err => err,
                }
            }
        });
        (rc == 0).then_some(out)
    }
}
