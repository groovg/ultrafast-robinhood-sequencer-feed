//! ECDSA public-key recovery, returning an Ethereum address. This is the expensive part
//! of both sender recovery and feed signature checks.
//!
//! There are two implementations so we can compare them. libsecp256k1 is always built.
//! UltrafastSecp256k1 is used instead when the `ufsecp` feature is on. `tests/golden.rs`
//! checks that they return the same thing.
//!
//! Feed signatures all come from one key, so for those `FixedKey` checks the signature
//! against the known key with precomputed tables instead of recovering it.

use std::ffi::c_int;
use std::sync::LazyLock;

use crate::codec::keccak;

/// 20-byte address that produced (r, s, recid) over `digest`, or None if there is none.
pub fn recover(digest: &[u8; 32], r: &[u8; 32], s: &[u8; 32], recid: u8) -> Option<[u8; 20]> {
    #[cfg(feature = "ufsecp")]
    return ufsecp::recover(digest, r, s, recid);
    #[cfg(not(feature = "ufsecp"))]
    return libsecp::recover(digest, r, s, recid);
}

/// The address of an uncompressed public key without its 0x04 prefix.
pub(crate) fn address(pubkey64: &[u8]) -> [u8; 20] {
    keccak(pubkey64)[12..].try_into().unwrap()
}

pub mod libsecp {
    use secp256k1::Message;
    use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};

    pub fn recover(digest: &[u8; 32], r: &[u8; 32], s: &[u8; 32], recid: u8) -> Option<[u8; 20]> {
        let key = recover_key(digest, r, s, recid)?;
        Some(super::address(&key.serialize_uncompressed()[1..]))
    }

    pub fn recover_key(
        digest: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
        recid: u8,
    ) -> Option<secp256k1::PublicKey> {
        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(r);
        rs[32..].copy_from_slice(s);
        let id = RecoveryId::try_from(i32::from(recid)).ok()?;
        let sig = RecoverableSignature::from_compact(&rs, id).ok()?;
        sig.recover_ecdsa(Message::from_digest(*digest)).ok()
    }
}

#[cfg(feature = "ufsecp")]
pub mod ufsecp {
    use std::ffi::{c_int, c_void};

    /// The curve order. Big-endian, so array comparison is numeric comparison.
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];

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

// --------------------------------------------------------------------------- //
// many signatures from one known key
// --------------------------------------------------------------------------- //

// csrc/fixedkey.c, on libsecp256k1's field, scalar and group code.
unsafe extern "C" {
    fn rhfeed_fixedkey_table_size() -> usize;
    fn rhfeed_fixedkey_build(table: *mut u64, compressed: *const u8) -> c_int;
    fn rhfeed_fixedkey_verify(
        g: *const u64,
        key: *const u64,
        digest: *const u8,
        r: *const u8,
        s: *const u8,
    ) -> c_int;
}

/// 1..128 times a point times 2^(8·row) for 33 rows (~270 KB): a multiplication is then
/// one addition per row and no doublings, which is what makes a known key cheap.
fn table(compressed: &[u8; 33]) -> Option<Box<[u64]>> {
    let mut t = vec![0u64; unsafe { rhfeed_fixedkey_table_size() } / 8].into_boxed_slice();
    (unsafe { rhfeed_fixedkey_build(t.as_mut_ptr(), compressed.as_ptr()) } == 1).then_some(t)
}

static G: LazyLock<Box<[u64]>> = LazyLock::new(|| {
    let g = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    table(&g.unwrap().try_into().unwrap()).unwrap()
});

/// A public key with precomputed tables, for checking many signatures from the same
/// signer. Checking one is several times cheaper than recovering the signer from it.
/// Building the tables takes a few milliseconds.
pub struct FixedKey {
    table: Box<[u64]>,
    pub address: [u8; 20],
}

impl std::fmt::Debug for FixedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FixedKey(0x{})", hex::encode(self.address))
    }
}

impl FixedKey {
    /// From a SEC1-compressed public key (33 bytes).
    pub fn new(compressed: &[u8; 33]) -> Option<Self> {
        let uncompressed = secp256k1::PublicKey::from_slice(compressed)
            .ok()?
            .serialize_uncompressed();
        LazyLock::force(&G);
        Some(Self {
            table: table(compressed)?,
            address: address(&uncompressed[1..]),
        })
    }

    /// Whether (r, s) is a valid ECDSA signature of `digest` by this key. Accepts what
    /// libsecp256k1's verify accepts, plus a high s, which recovery accepts too. It
    /// doesn't look at the recovery id: a signature with a wrong one still proves the
    /// key signed.
    pub fn verify(&self, digest: &[u8; 32], r: &[u8; 32], s: &[u8; 32]) -> bool {
        // SAFETY: both tables were filled by rhfeed_fixedkey_build and live as long as self.
        unsafe {
            rhfeed_fixedkey_verify(
                G.as_ptr(),
                self.table.as_ptr(),
                digest.as_ptr(),
                r.as_ptr(),
                s.as_ptr(),
            ) == 1
        }
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::ecdsa::{self, Signature};
    use secp256k1::{Message, PublicKey, SecretKey};

    use super::*;

    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];

    /// libsecp256k1's verdict, with s normalised the way recovery tolerates.
    fn reference(key: &PublicKey, digest: &[u8; 32], r: &[u8; 32], s: &[u8; 32]) -> bool {
        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(r);
        rs[32..].copy_from_slice(s);
        let Ok(mut sig) = Signature::from_compact(&rs) else {
            return false;
        };
        sig.normalize_s();
        ecdsa::verify(&sig, Message::from_digest(*digest), key).is_ok()
    }

    /// n - s, big-endian.
    fn negate(s: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = i16::from(ORDER[i]) - i16::from(s[i]) - borrow;
            borrow = i16::from(d < 0);
            out[i] = (d + 256 * borrow) as u8;
        }
        out
    }

    #[test]
    fn fixed_key_agrees_with_libsecp256k1() {
        let keys: Vec<SecretKey> = (0..3u8)
            .map(|i| SecretKey::from_secret_bytes(keccak(&[i])).unwrap())
            .collect();
        let fixed: Vec<FixedKey> = keys
            .iter()
            .map(|k| FixedKey::new(&PublicKey::from_secret_key(k).serialize()).unwrap())
            .collect();
        let mut checked = 0;
        for (i, sk) in keys.iter().enumerate() {
            let pk = PublicKey::from_secret_key(sk);
            assert_eq!(fixed[i].address, address(&pk.serialize_uncompressed()[1..]));
            for n in 0..40u32 {
                let digest = keccak(&n.to_be_bytes());
                let sig = ecdsa::sign(Message::from_digest(digest), sk).serialize_compact();
                let r: [u8; 32] = sig[..32].try_into().unwrap();
                let s: [u8; 32] = sig[32..].try_into().unwrap();
                let mut cases = vec![(digest, r, s, true), (digest, r, negate(&s), true)];
                for bit in [0, 7, 100, 255] {
                    let flip = |mut b: [u8; 32]| {
                        b[bit / 8] ^= 1 << (bit % 8);
                        b
                    };
                    cases.push((flip(digest), r, s, false));
                    cases.push((digest, flip(r), s, false));
                    cases.push((digest, r, flip(s), false));
                }
                for bad in [[0; 32], ORDER, [0xff; 32]] {
                    cases.push((digest, bad, s, false));
                    cases.push((digest, r, bad, false));
                }
                for (d, r, s, want) in cases {
                    let other = &fixed[(i + 1) % fixed.len()];
                    assert_eq!(fixed[i].verify(&d, &r, &s), want, "key {i} sig {n}");
                    assert_eq!(
                        reference(&pk, &d, &r, &s),
                        want,
                        "reference, key {i} sig {n}"
                    );
                    assert!(!other.verify(&d, &r, &s), "wrong key, key {i} sig {n}");
                    checked += 1;
                }
            }
        }
        assert!(checked > 2000);
    }
}
