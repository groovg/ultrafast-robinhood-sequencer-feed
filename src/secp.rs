//! ECDSA public-key recovery, returning an Ethereum address. This is the expensive part
//! of both sender recovery and feed signature checks.
//!
//! There are two implementations so we can compare them. libsecp256k1 is always built.
//! UltrafastSecp256k1 is used instead when the `ufsecp` feature is on. `tests/golden.rs`
//! checks that they return the same thing.
//!
//! Feed signatures all come from one key, so for those `FixedKey` checks the signature
//! against the known key with precomputed tables instead of recovering it.

use std::sync::LazyLock;

use k256::elliptic_curve::group::{Curve, GroupEncoding};
use k256::elliptic_curve::hazmat::FieldArithmetic;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::subtle::CtOption;
use k256::elliptic_curve::{Group, PrimeField};
use k256::{AffinePoint, ProjectivePoint, Scalar, U256};

use crate::codec::keccak;

/// The curve order. Big-endian, so array comparison is numeric comparison.
const N_BYTES: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

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

    use super::N_BYTES as N;

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

/// Window width in bits. Each point gets `ROWS` rows of `2^(W-1)` multiples (about
/// 330 KB), and a multiplication is one addition per row.
const W: usize = 8;
const ROWS: usize = 256 / W + 1;
const HALF: usize = 1 << (W - 1);

/// secp256k1's field element, through the trait k256 exposes it by.
type Fe = <k256::Secp256k1 as FieldArithmetic>::FieldElement;

/// p - n, big-endian: an r below it may also stand for the x coordinate r + n.
const P_MINUS_N: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4,
    0x40, 0x2d, 0xa1, 0x72, 0x2f, 0xc9, 0xba, 0xee,
];

/// A table point in affine coordinates.
#[derive(Clone, Copy)]
struct Ge {
    x: Fe,
    y: Fe,
}

/// The running sum in Jacobian coordinates (x/z², y/z³).
struct Gej {
    x: Fe,
    y: Fe,
    z: Fe,
    infinity: bool,
}

impl Gej {
    /// `self += b` with libsecp256k1's `gej_add_ge_var` formulas: 8 multiplications and
    /// 3 squarings, against about 12 multiplications for k256's complete formulas.
    /// Returns false in the one case they don't cover, `b` equal to `self`, which would
    /// need a doubling.
    // The operands go by reference: by value it measured ~1 µs slower per verify.
    #[allow(clippy::op_ref)]
    fn add(&mut self, b: &Ge) -> bool {
        if self.infinity {
            *self = Gej {
                x: b.x,
                y: b.y,
                z: Fe::ONE,
                infinity: false,
            };
            return true;
        }
        let z12 = self.z.square();
        let (u1, s1) = (self.x, self.y);
        let u2 = b.x * &z12;
        let s2 = b.y * &z12 * &self.z;
        let h = u1.negate(4) + &u2;
        let i = s2.negate(1) + &s1;
        if bool::from(h.normalizes_to_zero()) {
            if bool::from(i.normalizes_to_zero()) {
                return false;
            }
            self.infinity = true;
            return true;
        }
        self.z *= &h;
        let h2 = h.square().negate(1);
        let h3 = h2 * &h;
        let t = u1 * &h2;
        self.x = i.square() + &h3 + &t + &t;
        self.y = (t + self.x) * &i + (h3 * &s1);
        true
    }
}

/// P, 2P, ..., HALF·P, times 2^(W·row) for each row. A scalar split into signed W-bit
/// digits then multiplies with one addition per row and no doublings, which is what
/// makes a known key cheaper than recovering one.
struct Table(Vec<[Ge; HALF]>);

impl Table {
    fn new(point: ProjectivePoint) -> Self {
        let mut base = point;
        let rows = (0..ROWS)
            .map(|_| {
                let mut row = [base; HALF];
                for j in 1..HALF {
                    row[j] = row[j - 1] + base;
                }
                let mut affine = [AffinePoint::IDENTITY; HALF];
                ProjectivePoint::batch_normalize(&row, &mut affine);
                for _ in 0..W {
                    base = base.double();
                }
                // No multiple in a row is the identity, since n is prime.
                affine.map(|a| Ge {
                    x: Fe::from_bytes(&a.x()).unwrap(),
                    y: Fe::from_bytes(&a.y()).unwrap(),
                })
            })
            .collect();
        Self(rows)
    }

    /// `acc += k·P`, taking k's bytes as base-256 digits in -127..=128. False if an
    /// addition needed a doubling.
    fn mul_add(&self, acc: &mut Gej, k: &Scalar) -> bool {
        let bytes = k.to_bytes(); // big-endian
        let mut carry = 0;
        for (row, points) in self.0.iter().enumerate() {
            let byte = if row < 32 { bytes[31 - row] } else { 0 };
            let mut digit = carry + i32::from(byte);
            carry = 0;
            if digit > HALF as i32 {
                digit -= 1 << W;
                carry = 1;
            }
            let added = match digit {
                0 => true,
                d if d > 0 => acc.add(&points[d as usize - 1]),
                d => {
                    let p = points[(-d) as usize - 1];
                    acc.add(&Ge {
                        x: p.x,
                        y: p.y.negate(1),
                    })
                }
            };
            if !added {
                return false;
            }
        }
        true
    }
}

static G: LazyLock<Table> = LazyLock::new(|| Table::new(ProjectivePoint::GENERATOR));

/// A public key with precomputed tables, for checking many signatures from the same
/// signer. Checking one is several times cheaper than recovering the signer from it.
/// Building the tables takes a few milliseconds.
pub struct FixedKey {
    table: Table,
    point: AffinePoint,
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
        let point = Option::<AffinePoint>::from(AffinePoint::from_bytes(&(*compressed).into()))?;
        let uncompressed = secp256k1::PublicKey::from_slice(compressed)
            .ok()?
            .serialize_uncompressed();
        LazyLock::force(&G);
        Some(Self {
            table: Table::new(point.into()),
            point,
            address: address(&uncompressed[1..]),
        })
    }

    /// Whether (r, s) is a valid ECDSA signature of `digest` by this key. Accepts what
    /// libsecp256k1's verify accepts, plus a high s, which recovery accepts too. It
    /// doesn't look at the recovery id: a signature with a wrong one still proves the
    /// key signed.
    pub fn verify(&self, digest: &[u8; 32], r: &[u8; 32], s: &[u8; 32]) -> bool {
        let nonzero = |b: &[u8; 32]| {
            let k: CtOption<Scalar> = Scalar::from_repr((*b).into());
            Option::from(k).filter(|k: &Scalar| !bool::from(k.is_zero()))
        };
        let (Some(r_scalar), Some(s)) = (nonzero(r), nonzero(s)) else {
            return false;
        };
        let Some(s_inv) = Option::<Scalar>::from(s.invert_vartime()) else {
            return false;
        };
        let z = <Scalar as Reduce<U256>>::reduce(&U256::from_be_slice(digest));
        let (u1, u2) = (z * s_inv, r_scalar * s_inv);
        // R = u1·G + u2·Q, and the signature holds if R's x is r mod n.
        let mut acc = Gej {
            x: Fe::ZERO,
            y: Fe::ZERO,
            z: Fe::ZERO,
            infinity: true,
        };
        if !(G.mul_add(&mut acc, &u1) && self.table.mul_add(&mut acc, &u2)) {
            // A doubling came up, which happens with probability ~2^-128.
            let p = ProjectivePoint::GENERATOR * u1 + ProjectivePoint::from(self.point) * u2;
            if bool::from(p.is_identity()) {
                return false;
            }
            let x = p.to_affine().x();
            return <Scalar as Reduce<U256>>::reduce(&U256::from_be_slice(&x)) == r_scalar;
        }
        if acc.infinity {
            return false;
        }
        // x = X / Z², so compare X with r·Z², and with (r + n)·Z² when r + n < p.
        let zz = acc.z.square();
        let x_is = |c: Fe| bool::from(((c * zz).negate(1) + acc.x).normalizes_to_zero());
        let r_fe = Fe::from_bytes(&(*r).into()).unwrap(); // r < n < p
        if x_is(r_fe) {
            return true;
        }
        *r < P_MINUS_N && x_is(r_fe + Fe::from_bytes(&N_BYTES.into()).unwrap())
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
