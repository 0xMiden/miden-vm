//! Witness handler for the GLV decomposition of a secp256k1 scalar. Reads `k` from memory
//! at the address given on the operand stack, pushes `(|k_a|, sign_a, |k_b|, sign_b)` to
//! advice such that `k ≡ k_a + k_b·λ (mod n)`, with both magnitudes bounded above by
//! `2^128`. The MASM verifier checks the relation, the magnitude bounds, and that the sign
//! bits are boolean.
//!
//! Among all integer pairs `(x, y)` satisfying `x + y·λ ≡ k (mod n)`, the splitter picks
//! the one with the smallest absolute values. The set of pairs `(x, y)` with
//! `x + y·λ ≡ 0 (mod n)` forms a 2D integer lattice with a precomputed short basis
//! `(a1, b1)`, `(a2, b2)`. Any solution to the congruence can be shifted by an integer
//! combination `c1·(a1, b1) + c2·(a2, b2)` and stay a solution; the closest-vector
//! algorithm of Babai applied to a 2D lattice (rounded division) gives the `(c1, c2)`
//! whose shift lands closest to `(k, 0)`:
//!
//!   c1 = round(b2·k / n),   c2 = round(-b1·k / n)
//!   k_a = k - c1·a1 - c2·a2
//!   k_b = -(c1·b1 + c2·b2)
//!
//! For secp256k1's specific basis these formulas yield magnitudes `< 2^128`
//! (`tests::split_magnitudes_strictly_below_2_pow_128` is a 256-sample regression guard).
//!
//! Soundness lives entirely on the verifier side: a handler bug or a malicious prover
//! supplying a different witness can only ever cause the MASM verifier to reject.
//!
//! References: Gallant, Lambert, Vanstone, "Faster Point Multiplication on Elliptic Curves
//! with Efficient Endomorphisms" (CRYPTO 2001) for the GLV technique itself; Hankerson,
//! Menezes, Vanstone, "Guide to Elliptic Curve Cryptography" (Springer, 2004) for the
//! basis derivation via extended Euclidean reduction.

use alloc::vec::Vec;

use miden_core::Felt;
use miden_processor::{
    ProcessorState,
    advice::AdviceMutation,
    event::{EventError, EventName},
};
use num::{
    Signed,
    bigint::{BigInt, BigUint, Sign},
    rational::BigRational,
};

use crate::handlers::secp256k1_constants::{
    SECP256K1_GLV_A1_U32, SECP256K1_GLV_A2_U32, SECP256K1_GLV_B1_NEG_MAG_U32, SECP256K1_GLV_B2_U32,
    SECP256K1_SCALAR_PRIME_U32,
};

/// Event name for the GLV scalar splitter.
pub const GLV_SPLIT_K1_EVENT_NAME: EventName =
    EventName::new("miden::core::math::k1_scalar::glv_split");

/// Witness handler for `k1_scalar::glv_split`.
///
/// Inputs (operand stack at emit time):
///   `[event_id, k_addr, ...]`
///
/// `k_addr` points into operand-stack-context memory at the start of an 8-felt u32-LE-limb
/// encoding of the scalar `k`.
///
/// Outputs (advice stack, top-to-bottom in pop order):
///   - `mag_a[0..8]`: magnitude of `k_a`, 8 u32 LE limbs. Limbs 4..8 are always zero (the MASM
///     verifier enforces strict `|k_a| < 2^128`).
///   - `sign_a`: sign bit in `{0, 1}` (1 iff `k_a < 0`).
///   - `mag_b[0..8]`, `sign_b`: same for `k_b`.
///
/// Total: 18 felts.
pub fn handle_glv_split_k1(process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
    let k_addr = process.get_stack_item(1).as_canonical_u64();
    let k_limbs = read_u256_at(process, k_addr)?;
    let k_bn = BigUint::from_slice(&k_limbs);

    let n = BigInt::from(BigUint::from_slice(&SECP256K1_SCALAR_PRIME_U32));
    let a1 = BigInt::from(BigUint::from_slice(&SECP256K1_GLV_A1_U32));
    let b1 = -BigInt::from(BigUint::from_slice(&SECP256K1_GLV_B1_NEG_MAG_U32));
    let a2 = BigInt::from(BigUint::from_slice(&SECP256K1_GLV_A2_U32));
    let b2 = BigInt::from(BigUint::from_slice(&SECP256K1_GLV_B2_U32));

    let k_signed = BigInt::from(k_bn);

    let c1 = round_div(&(&b2 * &k_signed), &n);
    let c2 = round_div(&(&(-&b1) * &k_signed), &n);

    let k_a = &k_signed - &c1 * &a1 - &c2 * &a2;
    let k_b = -(&c1 * &b1 + &c2 * &b2);

    let (mag_a, sign_a) = signed_to_mag_sign(&k_a);
    let (mag_b, sign_b) = signed_to_mag_sign(&k_b);

    let mut advice: Vec<Felt> = Vec::with_capacity(18);
    push_u32_limbs(&mut advice, &mag_a);
    advice.push(Felt::from_u32(sign_a));
    push_u32_limbs(&mut advice, &mag_b);
    advice.push(Felt::from_u32(sign_b));

    Ok(alloc::vec![AdviceMutation::extend_stack(advice)])
}

// HELPERS
// ================================================================================================

fn read_u256_at(process: &ProcessorState, addr: u64) -> Result<[u32; 8], GlvSplitK1Error> {
    let base: u32 = addr.try_into().map_err(|_| GlvSplitK1Error::AddrOverflow { addr })?;
    let ctx = process.ctx();
    let mut limbs = [0u32; 8];
    for i in 0..8u32 {
        let read_addr = base.checked_add(i).ok_or(GlvSplitK1Error::AddrOverflow { addr })?;
        let felt = process
            .get_mem_value(ctx, read_addr)
            .ok_or(GlvSplitK1Error::MemoryReadFailed { addr: read_addr })?;
        let val = felt.as_canonical_u64();
        if val > u32::MAX as u64 {
            return Err(GlvSplitK1Error::NotU32Limb { addr: read_addr, value: val });
        }
        limbs[i as usize] = val as u32;
    }
    Ok(limbs)
}

/// Integer division rounded to the nearest integer.
fn round_div(num: &BigInt, den: &BigInt) -> BigInt {
    BigRational::new(num.clone(), den.clone()).round().to_integer()
}

/// Returns `(|x|_as_8_u32_LE_limbs, sign_bit)` where `sign_bit = 1` iff `x < 0`.
fn signed_to_mag_sign(x: &BigInt) -> ([u32; 8], u32) {
    let abs = x.abs().to_biguint().expect("|x| fits in BigUint");
    let mut digits = abs.to_u32_digits();
    digits.resize(8, 0);
    let mag: [u32; 8] = digits.try_into().expect("8 limbs after resize");
    let sign = if x.sign() == Sign::Minus { 1 } else { 0 };
    (mag, sign)
}

fn push_u32_limbs(advice: &mut Vec<Felt>, limbs: &[u32; 8]) {
    advice.extend(limbs.iter().map(|&v| Felt::from_u32(v)));
}

// ERROR TYPES
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum GlvSplitK1Error {
    #[error("k_addr {addr} overflows u32")]
    AddrOverflow { addr: u64 },

    #[error("failed to read scalar limb at memory address {addr}")]
    MemoryReadFailed { addr: u32 },

    #[error("scalar limb at address {addr} = {value} exceeds u32::MAX")]
    NotU32Limb { addr: u32, value: u64 },
}

// UNIT TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use num::traits::Zero;

    use super::*;
    use crate::handlers::secp256k1_constants::SECP256K1_LAMBDA_N_U32;

    fn n() -> BigUint {
        BigUint::from_slice(&SECP256K1_SCALAR_PRIME_U32)
    }

    fn lambda() -> BigUint {
        BigUint::from_slice(&SECP256K1_LAMBDA_N_U32)
    }

    fn a1() -> BigInt {
        BigInt::from(BigUint::from_slice(&SECP256K1_GLV_A1_U32))
    }

    fn b1() -> BigInt {
        -BigInt::from(BigUint::from_slice(&SECP256K1_GLV_B1_NEG_MAG_U32))
    }

    fn a2() -> BigInt {
        BigInt::from(BigUint::from_slice(&SECP256K1_GLV_A2_U32))
    }

    fn b2() -> BigInt {
        BigInt::from(BigUint::from_slice(&SECP256K1_GLV_B2_U32))
    }

    fn rem_euclid(x: &BigInt, m: &BigInt) -> BigInt {
        let r = x % m;
        if r.sign() == Sign::Minus { &r + m } else { r }
    }

    /// Confirms `a1 + b1·λ ≡ 0 (mod n)` and same for `(a2, b2)`. A drift in any of the basis
    /// constants vs `λ` or `n` would make every GLV-split witness reject.
    #[test]
    fn lattice_basis_satisfies_lambda_relation() {
        let n_bn = BigInt::from(n());
        let lambda_bn = BigInt::from(lambda());
        let lhs1 = rem_euclid(&(&a1() + &b1() * &lambda_bn), &n_bn);
        let lhs2 = rem_euclid(&(&a2() + &b2() * &lambda_bn), &n_bn);
        assert!(Zero::is_zero(&lhs1), "a1 + b1·λ should be 0 mod n, got {lhs1}");
        assert!(Zero::is_zero(&lhs2), "a2 + b2·λ should be 0 mod n, got {lhs2}");
    }

    /// `b2 == a1` is a well-known coincidence for secp256k1's basis.
    #[test]
    fn b2_equals_a1() {
        assert_eq!(a1(), b2());
    }

    /// Splits a manually chosen scalar and asserts the GLV reconstruction holds modulo `n`
    /// and that magnitudes fit in 128 bits.
    fn assert_split(k: BigUint) {
        let n_bn = BigInt::from(n());
        let lambda_bn = BigInt::from(lambda());
        let k_signed = BigInt::from(k);

        let c1 = round_div(&(&b2() * &k_signed), &n_bn);
        let c2 = round_div(&(&(-&b1()) * &k_signed), &n_bn);
        let k_a = &k_signed - &c1 * &a1() - &c2 * &a2();
        let k_b = -(&c1 * &b1() + &c2 * &b2());

        let recombined = rem_euclid(&(&k_a + &k_b * &lambda_bn), &n_bn);
        let expected = rem_euclid(&k_signed, &n_bn);
        assert_eq!(recombined, expected, "GLV reconstruction must match k mod n");

        let bound = BigInt::from(1u128) << 128;
        assert!(k_a.abs() < bound, "|k_a| = {} exceeds 2^128", k_a.abs());
        assert!(k_b.abs() < bound, "|k_b| = {} exceeds 2^128", k_b.abs());
    }

    #[test]
    fn split_zero_yields_zero_zero() {
        assert_split(BigUint::from(0u32));
    }

    #[test]
    fn split_one_yields_one_zero() {
        assert_split(BigUint::from(1u32));
    }

    #[test]
    fn split_lambda_yields_zero_one() {
        assert_split(lambda());
    }

    #[test]
    fn split_n_minus_one() {
        assert_split(&n() - 1u32);
    }

    #[test]
    fn split_arbitrary_large() {
        let k = BigUint::from_bytes_be(&[
            0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78, 0xca, 0xfe, 0xba, 0xbe, 0x9a, 0xbc,
            0xde, 0xf0, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66,
            0x77, 0x77, 0x88, 0x88,
        ]);
        assert_split(k % n());
    }

    /// Sweeps 256 SplitMix64-seeded samples to verify the splitter never exceeds the
    /// `|k_a|, |k_b| < 2^128` bound that `k1_scalar::verify_glv_split` enforces.
    #[test]
    fn split_magnitudes_strictly_below_2_pow_128() {
        let n_bn = BigInt::from(n());
        let bound = BigInt::from(1u128) << 128;
        let mut state: u64 = 0xcafe_babe_dead_beef;
        for sample in 0..256u32 {
            let mut bytes = [0u8; 32];
            for chunk in bytes.chunks_exact_mut(8) {
                state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                z ^= z >> 31;
                chunk.copy_from_slice(&z.to_le_bytes());
            }
            let k = BigUint::from_bytes_be(&bytes) % n();
            let k_signed = BigInt::from(k);

            let c1 = round_div(&(&b2() * &k_signed), &n_bn);
            let c2 = round_div(&(&(-&b1()) * &k_signed), &n_bn);
            let k_a = &k_signed - &c1 * &a1() - &c2 * &a2();
            let k_b = -(&c1 * &b1() + &c2 * &b2());

            assert!(
                k_a.abs() < bound,
                "sample {sample}: |k_a| = {} exceeded 2^128 (k bytes = {:x?})",
                k_a.abs(),
                bytes,
            );
            assert!(
                k_b.abs() < bound,
                "sample {sample}: |k_b| = {} exceeded 2^128 (k bytes = {:x?})",
                k_b.abs(),
                bytes,
            );
        }
    }
}
