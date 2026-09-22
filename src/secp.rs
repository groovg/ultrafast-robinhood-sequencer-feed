//! ECDSA public-key recovery, returning an Ethereum address. This is the expensive part
//! of both sender recovery and feed signature checks.
//!
//! There are two implementations so we can compare them. libsecp256k1 is always built.
//! UltrafastSecp256k1 is used instead when the `ufsecp` feature is on. `tests/golden.rs`
//! checks that they return the same thing.
//!
//! `recover_many` does a whole batch at once, spread over all cores. With the
//! `asmcrypto` feature it also does 8 per core at a time with AVX-512 IFMA.

use rayon::prelude::*;

use crate::codec::keccak;

/// The curve order. Big-endian, so array comparison is numeric comparison.
#[cfg(any(feature = "ufsecp", feature = "asmcrypto"))]
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// A signature and the digest it signs, as recovery needs them.
#[derive(Clone, Debug)]
pub struct Signature {
    pub digest: [u8; 32],
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub recid: u8,
}

/// Recover every signature in `sigs`, in order, using all cores. `None` in, `None` out.
pub fn recover_many(sigs: &[Option<Signature>]) -> Vec<Option<[u8; 20]>> {
    #[cfg(feature = "asmcrypto")]
    return sigs
        .par_chunks(8)
        .flat_map_iter(asmcrypto::recover8)
        .collect();
    #[cfg(not(feature = "asmcrypto"))]
    sigs.par_iter()
        .map(|s| {
            s.as_ref()
                .and_then(|s| recover(&s.digest, &s.r, &s.s, s.recid))
        })
        .collect()
}

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

    use super::N;

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

#[cfg(feature = "asmcrypto")]
pub mod asmcrypto {
    use super::{N, Signature};

    /// Recover up to 8 signatures with one AVX-512 batch. Falls back to one at a time
    /// on CPUs without AVX-512 IFMA (the crate checks at runtime).
    pub fn recover8(chunk: &[Option<Signature>]) -> Vec<Option<[u8; 20]>> {
        // The batch takes recovery ids 0 and 1 only, and we don't rely on it to reject
        // r or s outside 1..n. Anything else goes through the scalar path, which does.
        let batchable =
            |s: &Signature| s.recid < 2 && s.r != [0; 32] && s.s != [0; 32] && s.r < N && s.s < N;
        let lanes: Vec<&Signature> = chunk.iter().flatten().filter(|s| batchable(s)).collect();
        let mut batch = [[0u8; 20]; 8];
        if let Some(&first) = lanes.first() {
            // Unused lanes repeat the first signature; their results are ignored.
            let lane = |i: usize| *lanes.get(i).unwrap_or(&first);
            batch = ::asmcrypto::recover_addresses_batch(
                std::array::from_fn(|i| &lane(i).digest),
                std::array::from_fn(|i| &lane(i).r),
                std::array::from_fn(|i| &lane(i).s),
                std::array::from_fn(|i| lane(i).recid),
            );
        }
        let mut next = 0;
        chunk
            .iter()
            .map(|sig| {
                let sig = sig.as_ref()?;
                if !batchable(sig) {
                    return super::recover(&sig.digest, &sig.r, &sig.s, sig.recid);
                }
                let addr = batch[next];
                next += 1;
                // The batch signals failure with an all-zero address.
                (addr != [0; 20]).then_some(addr)
            })
            .collect()
    }
}
