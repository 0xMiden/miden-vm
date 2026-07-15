//! secp256k1 GLV endomorphism: scalar decomposition and the constants it needs.
//!
//! The endomorphism `φ(x, y) = (β·x mod p, y)` acts as multiplication by `λ` on the group
//! (`φ(P) = λ·P`), so any scalar multiplication `k·P` can be rewritten `k₁·P + k₂·φ(P)` with
//! `k₁, k₂` roughly half the bit-width of `k`. [`glv_decompose`] performs the split natively
//! (host side, untrusted advice); the in-circuit certificate binding `φ(P)` to `P` and the split
//! back to the original scalar is the caller's responsibility.

use ruint::Uint;

use crate::math::{k1_scalar::K1Scalar, uint::Limbs};

/// secp256k1 GLV endomorphism scalar `λ` (`λ³ ≡ 1 mod n`, `n` the curve order): `φ(P) = λ·P`.
pub const SECP256K1_LAMBDA: Limbs = [
    0x1b23bd72, 0xdf02967c, 0x20816678, 0x122e22ea, 0x8812645a, 0xa5261c02, 0xc05c30e0, 0x5363ad4c,
];

/// secp256k1 GLV base-field constant `β` (`β³ ≡ 1 mod p`, `p` the base field modulus):
/// `φ(x, y) = (β·x mod p, y)`.
pub const SECP256K1_BETA: Limbs = [
    0x719501ee, 0xc1396c28, 0x12f58995, 0x9cf04975, 0xac3434e9, 0x6e64479e, 0x657c0710, 0x7ae96a2b,
];

/// A magnitude type wide enough to hold every intermediate value the lattice reduction and Babai
/// rounding below produce, with ample headroom above the ~256-bit inputs (products of two
/// ~256-bit values stay under 512 bits; this doubles that margin again).
type Wide = Uint<1024, 16>;

fn wide_zero() -> Wide {
    Wide::from_limbs([0; 16])
}

fn wide_one() -> Wide {
    let mut limbs = [0u64; 16];
    limbs[0] = 1;
    Wide::from_limbs(limbs)
}

fn limbs_to_wide(limbs: Limbs) -> Wide {
    let mut u64_limbs = [0u64; 16];
    for i in 0..4 {
        u64_limbs[i] = (limbs[2 * i] as u64) | ((limbs[2 * i + 1] as u64) << 32);
    }
    Wide::from_limbs(u64_limbs)
}

/// Converts a reduced `Wide` value back to `Limbs`. Panics if the value doesn't actually fit in
/// 256 bits — every value this module ever converts back is a GLV magnitude bounded well under
/// the curve order, so a nonzero high limb indicates a bug in the reduction above, not a valid
/// (if merely suboptimal) result.
fn wide_to_limbs(v: Wide) -> Limbs {
    let u64_limbs = v.as_limbs();
    assert!(u64_limbs[4..].iter().all(|&l| l == 0), "GLV magnitude must fit in 256 bits");
    core::array::from_fn(|i| {
        let word = u64_limbs[i / 2];
        if i % 2 == 0 { word as u32 } else { (word >> 32) as u32 }
    })
}

/// A sign-magnitude integer over [`Wide`] — the GLV lattice arithmetic below needs signed
/// intermediate values (the extended-Euclid Bézout coefficients), while the moduli and remainders
/// stay unsigned.
#[derive(Clone, Copy)]
struct Signed {
    neg: bool,
    mag: Wide,
}

impl Signed {
    fn new(neg: bool, mag: Wide) -> Self {
        // Canonicalize the sign of zero so equality/negation stay simple.
        if mag == wide_zero() {
            Signed { neg: false, mag }
        } else {
            Signed { neg, mag }
        }
    }

    fn negate(self) -> Self {
        Signed::new(!self.neg, self.mag)
    }

    fn add(self, other: Self) -> Self {
        if self.neg == other.neg {
            Signed::new(self.neg, self.mag + other.mag)
        } else if self.mag >= other.mag {
            Signed::new(self.neg, self.mag - other.mag)
        } else {
            Signed::new(other.neg, other.mag - self.mag)
        }
    }

    fn sub(self, other: Self) -> Self {
        self.add(other.negate())
    }

    fn mul(self, other: Self) -> Self {
        Signed::new(self.neg != other.neg, self.mag * other.mag)
    }

    /// `round(self / n)` as a signed integer. Ties round up in magnitude; the exact tie-breaking
    /// rule is a performance choice, not a soundness one — the recompose relation this feeds
    /// holds for *any* integer quotient (see [`glv_decompose`]'s doc comment).
    fn div_round(self, n: Wide) -> Self {
        let q = self.mag / n;
        let r = self.mag % n;
        let q = if r + r >= n { q + wide_one() } else { q };
        Signed::new(self.neg, q)
    }
}

/// Splits `k` (implicitly reduced mod `n`, the secp256k1 scalar-field order) into a signed short
/// pair `[(neg_a, mag_a), (neg_b, mag_b)]` with `k ≡ (±mag_a) + λ·(±mag_b) (mod n)`, each
/// magnitude bounded well under `n` — typically close to half its bit-width — by a half
/// extended-Euclid shortest-lattice-vector reduction followed by one Babai rounding step
/// (Hankerson–Menezes–Vanstone, Algorithm 3.74).
///
/// The in-circuit certificate this decomposition feeds re-derives the same congruence from the
/// returned halves and accepts it unconditionally: a less-than-optimal rounding here only costs
/// the addition chain some extra bit-width, it can never make the certificate unsound.
pub fn glv_decompose(k: Limbs) -> [(bool, Limbs); 2] {
    let n = limbs_to_wide(K1Scalar::MODULUS);
    let lambda = limbs_to_wide(SECP256K1_LAMBDA);
    let k = limbs_to_wide(k);

    let below_sqrt_n = |r: Wide| r * r < n;
    let (mut r0, mut r1) = (n, lambda);
    let (mut t0, mut t1) = (Signed::new(false, wide_zero()), Signed::new(false, wide_one()));
    while !below_sqrt_n(r1) {
        let q = r0 / r1;
        let r2 = r0 - q * r1;
        let t2 = t0.sub(Signed::new(false, q).mul(t1));
        (r0, r1, t0, t1) = (r1, r2, t1, t2);
    }

    let (a1, b1) = (Signed::new(false, r1), t1.negate());
    let q = r0 / r1;
    let r2 = r0 - q * r1;
    let t2 = t0.sub(Signed::new(false, q).mul(t1));
    let norm = |r: Wide, t: Wide| r * r + t * t;
    let (a2, b2) = if norm(r0, t0.mag) <= norm(r2, t2.mag) {
        (Signed::new(false, r0), t0.negate())
    } else {
        (Signed::new(false, r2), t2.negate())
    };

    let k_s = Signed::new(false, k);
    let c1 = b2.mul(k_s).div_round(n);
    let c2 = b1.negate().mul(k_s).div_round(n);
    let k1 = k_s.sub(c1.mul(a1)).sub(c2.mul(a2));
    let k2 = c1.negate().mul(b1).sub(c2.mul(b2));

    [(k1.neg, wide_to_limbs(k1.mag)), (k2.neg, wide_to_limbs(k2.mag))]
}

/// Reduces `v` modulo the secp256k1 scalar-field order `n`.
pub fn reduce_mod_n(v: Limbs) -> Limbs {
    let n = limbs_to_wide(K1Scalar::MODULUS);
    wide_to_limbs(limbs_to_wide(v) % n)
}

/// Computes `a * b mod n`, the secp256k1 scalar-field order.
pub fn scalar_mul_mod_n(a: Limbs, b: Limbs) -> Limbs {
    let n = limbs_to_wide(K1Scalar::MODULUS);
    wide_to_limbs((limbs_to_wide(a) * limbs_to_wide(b)) % n)
}

/// Computes the multiplicative inverse of `a` modulo `n` (the secp256k1 scalar-field order) via
/// Fermat's little theorem (`n` is prime): `a^(n-2) mod n`. Panics if `a` is not reduced, or is
/// zero (which has no inverse).
pub fn scalar_inv_mod_n(a: Limbs) -> Limbs {
    let n = limbs_to_wide(K1Scalar::MODULUS);
    let a = limbs_to_wide(a);
    assert!(a != wide_zero(), "zero has no modular inverse");
    let two = wide_one() + wide_one();
    let exp = n - two;
    wide_to_limbs(mod_pow(a, exp, n))
}

/// Computes `base^exp mod modulus` via square-and-multiply.
fn mod_pow(base: Wide, exp: Wide, modulus: Wide) -> Wide {
    let two = wide_one() + wide_one();
    let mut result = wide_one();
    let mut base = base % modulus;
    let mut exp = exp;
    while exp != wide_zero() {
        if exp % two == wide_one() {
            result = (result * base) % modulus;
        }
        exp = exp / two;
        base = (base * base) % modulus;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limbs_from_u64(v: u64) -> Limbs {
        [v as u32, (v >> 32) as u32, 0, 0, 0, 0, 0, 0]
    }

    /// Recomposes a GLV split via wide (unreduced) arithmetic and checks it lands back on `k`
    /// modulo `n` — the property the in-circuit recompose certificate re-checks per signature.
    fn recompose(split: [(bool, Limbs); 2]) -> Wide {
        let n = limbs_to_wide(K1Scalar::MODULUS);
        let lambda = limbs_to_wide(SECP256K1_LAMBDA);
        let to_signed = |(neg, mag): (bool, Limbs)| Signed::new(neg, limbs_to_wide(mag));
        let a = to_signed(split[0]);
        let b = to_signed(split[1]);
        let term = Signed::new(false, lambda).mul(b);
        let sum = a.add(term);
        // Reduce the signed sum mod n into [0, n).
        let mag_mod_n = sum.mag % n;
        if sum.neg && mag_mod_n != wide_zero() {
            n - mag_mod_n
        } else {
            mag_mod_n
        }
    }

    #[test]
    fn glv_decompose_recomposes_small_scalars() {
        for k in [0u64, 1, 2, 12345, u64::MAX] {
            let split = glv_decompose(limbs_from_u64(k));
            assert_eq!(recompose(split), limbs_to_wide(limbs_from_u64(k)), "failed for k={k}");
        }
    }

    #[test]
    fn glv_decompose_recomposes_full_width_scalar() {
        let k: Limbs = [
            0x12345678, 0x9abcdef0, 0x0fedcba9, 0x87654321, 0x11223344, 0x55667788, 0x99aabbcc,
            0x00112233,
        ];
        let split = glv_decompose(k);
        assert_eq!(recompose(split), limbs_to_wide(k));
    }

    #[test]
    fn glv_decompose_halves_are_short() {
        // The shortest-vector reduction should keep both magnitudes comfortably under the full
        // 256-bit scalar width -- otherwise the split buys no ladder-height win at all.
        let k: Limbs = [
            0x12345678, 0x9abcdef0, 0x0fedcba9, 0x87654321, 0x11223344, 0x55667788, 0x99aabbcc,
            0x00112233,
        ];
        // 2^132: comfortably above the ~128-bit halves, comfortably below the full 256 bits.
        let mut bound_limbs = [0u32; 8];
        bound_limbs[4] = 0x10;
        let bound = limbs_to_wide(bound_limbs);
        for (_, mag) in glv_decompose(k) {
            assert!(limbs_to_wide(mag) < bound, "GLV half is not short: {mag:?}");
        }
    }

    #[test]
    fn scalar_inv_mod_n_round_trips() {
        for v in [1u64, 2, 3, 12345, u64::MAX] {
            let a = limbs_from_u64(v);
            let inv = scalar_inv_mod_n(a);
            assert_eq!(scalar_mul_mod_n(a, inv), limbs_from_u64(1));
        }
    }

    #[test]
    fn reduce_mod_n_is_identity_below_modulus() {
        let a = limbs_from_u64(12345);
        assert_eq!(reduce_mod_n(a), a);
    }

    #[test]
    fn reduce_mod_n_wraps_the_modulus() {
        let n = K1Scalar::MODULUS;
        assert_eq!(reduce_mod_n(n), limbs_from_u64(0));
    }
}
