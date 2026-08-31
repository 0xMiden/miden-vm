//! Pure little-endian 256-bit limb arithmetic used by the uint precompile.

use core::cmp::Ordering;

const ZERO_LIMBS: [u32; 8] = [0; 8];
const ONE_LIMBS: [u32; 8] = [1, 0, 0, 0, 0, 0, 0, 0];

/// Adds two little-endian 256-bit values modulo `2^256`.
pub(crate) fn wrapping_add(a: [u32; 8], b: [u32; 8]) -> [u32; 8] {
    add_raw(a, b).0
}

/// Subtracts two little-endian 256-bit values modulo `2^256`.
pub(crate) fn wrapping_sub(a: [u32; 8], b: [u32; 8]) -> [u32; 8] {
    sub_raw(a, b).0
}

/// Multiplies two little-endian 256-bit values modulo `2^256`.
pub(crate) fn wrapping_mul(a: [u32; 8], b: [u32; 8]) -> [u32; 8] {
    let wide = mul_wide(a, b);
    let mut out = [0u32; 8];
    out.copy_from_slice(&wide[..8]);
    out
}

/// Adds two canonical values modulo `modulus`.
pub(crate) fn add_mod(a: [u32; 8], b: [u32; 8], modulus: [u32; 8]) -> [u32; 8] {
    let (sum, carry) = add_raw(a, b);
    if carry != 0 || !cmp(&sum, &modulus).is_lt() {
        sub_raw(sum, modulus).0
    } else {
        sum
    }
}

/// Subtracts two canonical values modulo `modulus`.
pub(crate) fn sub_mod(a: [u32; 8], b: [u32; 8], modulus: [u32; 8]) -> [u32; 8] {
    let (diff, borrow) = sub_raw(a, b);
    if borrow != 0 { add_raw(diff, modulus).0 } else { diff }
}

// BARRETT REDUCTION
// ================================================================================================

/// Computes the Barrett constant `mu = floor(2^512 / modulus)` for a 256-bit modulus.
///
/// Returns `[0; 9]` for the `2^256` wrapping sentinel (`modulus == 0`), which never reaches the
/// Barrett path. Intended to be evaluated at compile time, once per fixed domain.
pub(crate) const fn barrett_mu(modulus: [u32; 8]) -> [u32; 9] {
    let mut nonzero = false;
    let mut i = 0;
    while i < 8 {
        if modulus[i] != 0 {
            nonzero = true;
        }
        i += 1;
    }
    if !nonzero {
        return [0; 9];
    }

    // Bit-by-bit long division of 2^512 by `modulus`. The quotient has at most 257 bits, so every
    // set bit lands within the nine quotient limbs.
    let mut quotient = [0u32; 9];
    let mut remainder = [0u32; 9];
    let mut bit: i32 = 512;
    while bit >= 0 {
        remainder = shl1_limbs9(remainder);
        if bit == 512 {
            remainder[0] |= 1;
        }
        if limbs9_ge_mod(&remainder, &modulus) {
            remainder = limbs9_sub_mod(remainder, &modulus);
            let b = bit as usize;
            if b < 288 {
                quotient[b / 32] |= 1u32 << (b % 32);
            }
        }
        bit -= 1;
    }
    quotient
}

/// Multiplies two canonical values modulo `modulus` using Barrett reduction.
///
/// `mu` must equal `barrett_mu(modulus)`; the modulus must occupy its full 256-bit width (nonzero
/// top limb), which holds for every fixed prime domain.
pub(crate) fn mul_mod_barrett(
    a: [u32; 8],
    b: [u32; 8],
    modulus: [u32; 8],
    mu: [u32; 9],
) -> [u32; 8] {
    if a == ZERO_LIMBS || b == ZERO_LIMBS {
        return ZERO_LIMBS;
    }
    if a == ONE_LIMBS {
        return b;
    }
    if b == ONE_LIMBS {
        return a;
    }

    reduce_barrett(mul_wide(a, b), modulus, mu)
}

/// Computes `value^-1 mod modulus` for nonzero values in a prime field, using Barrett reduction.
pub(crate) fn inv_mod_prime_barrett(
    value: [u32; 8],
    modulus: [u32; 8],
    mu: [u32; 9],
) -> Option<[u32; 8]> {
    if value == ZERO_LIMBS || modulus == ZERO_LIMBS {
        return None;
    }
    if value == ONE_LIMBS {
        return Some(ONE_LIMBS);
    }

    // Fermat's little theorem: a^(p - 2) is the multiplicative inverse modulo prime p.
    Some(pow_mod_barrett(value, sub_small(modulus, 2), modulus, mu))
}

/// Exponentiates `base^exponent mod modulus` using Barrett reduction.
fn pow_mod_barrett(
    mut base: [u32; 8],
    exponent: [u32; 8],
    modulus: [u32; 8],
    mu: [u32; 9],
) -> [u32; 8] {
    let mut result = ONE_LIMBS;
    for bit in 0..256 {
        if bit_is_set(&exponent, bit) {
            result = mul_mod_barrett(result, base, modulus, mu);
        }
        base = mul_mod_barrett(base, base, modulus, mu);
    }
    result
}

/// Reduces a 512-bit little-endian product modulo a 256-bit modulus (Barrett, HAC 14.42, base
/// `2^32`, `k = 8`). Requires `value < modulus^2 < 2^512`.
fn reduce_barrett(value: [u32; 16], modulus: [u32; 8], mu: [u32; 9]) -> [u32; 8] {
    // q1 = floor(value / 2^224): the top nine limbs of the product.
    let mut q1 = [0u32; 9];
    q1.copy_from_slice(&value[7..16]);

    // q3 = floor(q1 * mu / 2^288): drop the low nine limbs of the product.
    let mut q2 = [0u32; 18];
    mul_limbs(&q1, &mu, &mut q2);
    let mut q3 = [0u32; 9];
    q3.copy_from_slice(&q2[9..18]);

    // r = (value mod 2^288) - (q3 * modulus mod 2^288), taken modulo 2^288.
    let mut r1 = [0u32; 9];
    r1.copy_from_slice(&value[0..9]);
    let mut q3m = [0u32; 18];
    mul_limbs(&q3, &modulus, &mut q3m);
    let mut r2 = [0u32; 9];
    r2.copy_from_slice(&q3m[0..9]);
    let mut r = sub_limbs9(r1, r2);

    // The Barrett estimate leaves at most two extra multiples of the modulus.
    while limbs9_ge_mod(&r, &modulus) {
        r = limbs9_sub_mod(r, &modulus);
    }

    let mut out = [0u32; 8];
    out.copy_from_slice(&r[0..8]);
    out
}

/// Schoolbook multiply of little-endian limb slices into `out` (length `>= a.len() + b.len()`).
fn mul_limbs(a: &[u32], b: &[u32], out: &mut [u32]) {
    for slot in out.iter_mut() {
        *slot = 0;
    }
    for (i, &a_limb) in a.iter().enumerate() {
        let mut carry = 0u64;
        for (j, &b_limb) in b.iter().enumerate() {
            let idx = i + j;
            let cur = out[idx] as u64 + a_limb as u64 * b_limb as u64 + carry;
            out[idx] = cur as u32;
            carry = cur >> 32;
        }
        let mut idx = i + b.len();
        while carry != 0 {
            let cur = out[idx] as u64 + carry;
            out[idx] = cur as u32;
            carry = cur >> 32;
            idx += 1;
        }
    }
}

/// Shifts a nine-limb little-endian value left by one bit.
const fn shl1_limbs9(mut limbs: [u32; 9]) -> [u32; 9] {
    let mut carry = 0u32;
    let mut i = 0;
    while i < 9 {
        let next_carry = limbs[i] >> 31;
        limbs[i] = (limbs[i] << 1) | carry;
        carry = next_carry;
        i += 1;
    }
    limbs
}

/// Compares a nine-limb value against an eight-limb modulus (zero-extended), returning `r >=
/// modulus`.
const fn limbs9_ge_mod(r: &[u32; 9], modulus: &[u32; 8]) -> bool {
    if r[8] != 0 {
        return true;
    }
    let mut i = 8;
    while i > 0 {
        i -= 1;
        if r[i] != modulus[i] {
            return r[i] > modulus[i];
        }
    }
    true
}

/// Subtracts an eight-limb modulus (zero-extended) from a nine-limb value, wrapping modulo 2^288.
const fn limbs9_sub_mod(mut r: [u32; 9], modulus: &[u32; 8]) -> [u32; 9] {
    let mut borrow = 0u64;
    let mut i = 0;
    while i < 9 {
        let modulus_limb = if i < 8 { modulus[i] as u64 } else { 0 };
        let subtrahend = modulus_limb + borrow;
        let diff = (r[i] as u64).wrapping_sub(subtrahend);
        borrow = ((r[i] as u64) < subtrahend) as u64;
        r[i] = diff as u32;
        i += 1;
    }
    r
}

/// Subtracts two nine-limb values, wrapping modulo 2^288.
fn sub_limbs9(a: [u32; 9], b: [u32; 9]) -> [u32; 9] {
    let mut out = [0u32; 9];
    let mut borrow = 0u64;
    for i in 0..9 {
        let subtrahend = b[i] as u64 + borrow;
        out[i] = (a[i] as u64).wrapping_sub(subtrahend) as u32;
        borrow = u64::from((a[i] as u64) < subtrahend);
    }
    out
}

/// Multiplies two 256-bit values into a 512-bit little-endian result.
pub(crate) fn mul_wide(a: [u32; 8], b: [u32; 8]) -> [u32; 16] {
    let mut out = [0u32; 16];
    for (i, a_limb) in a.iter().enumerate() {
        let mut carry = 0u64;
        for (j, b_limb) in b.iter().enumerate() {
            let idx = i + j;
            let cur = out[idx] as u64 + *a_limb as u64 * *b_limb as u64 + carry;
            out[idx] = cur as u32;
            carry = cur >> 32;
        }

        let mut idx = i + 8;
        while carry != 0 {
            let cur = out[idx] as u64 + carry;
            out[idx] = cur as u32;
            carry = cur >> 32;
            idx += 1;
        }
    }
    out
}

/// Subtracts a small integer from a little-endian 256-bit value.
pub(crate) fn sub_small(value: [u32; 8], rhs: u32) -> [u32; 8] {
    let mut out = value;
    let mut borrow = rhs as u64;
    for limb in &mut out {
        if borrow == 0 {
            break;
        }
        let original = *limb as u64;
        *limb = limb.wrapping_sub(borrow as u32);
        borrow = u64::from(original < borrow);
    }
    out
}

/// Compares two little-endian 256-bit values.
pub(crate) fn cmp(a: &[u32; 8], b: &[u32; 8]) -> Ordering {
    for i in (0..8).rev() {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => {},
            ordering => return ordering,
        }
    }
    Ordering::Equal
}

/// Returns whether bit `bit` is set in a little-endian limb array.
pub(crate) fn bit_is_set<const N: usize>(limbs: &[u32; N], bit: usize) -> bool {
    ((limbs[bit / 32] >> (bit % 32)) & 1) == 1
}

fn add_raw(a: [u32; 8], b: [u32; 8]) -> ([u32; 8], u32) {
    let mut out = [0u32; 8];
    let mut carry = 0u64;
    for i in 0..8 {
        let sum = a[i] as u64 + b[i] as u64 + carry;
        out[i] = sum as u32;
        carry = sum >> 32;
    }
    (out, carry as u32)
}

fn sub_raw(a: [u32; 8], b: [u32; 8]) -> ([u32; 8], u32) {
    let mut out = [0u32; 8];
    let mut borrow = 0u64;
    for i in 0..8 {
        let subtrahend = b[i] as u64 + borrow;
        out[i] = a[i].wrapping_sub(subtrahend as u32);
        borrow = u64::from((a[i] as u64) < subtrahend);
    }
    (out, borrow as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::{k1_base::K1Base, k1_scalar::K1Scalar, uint::UintSpec};

    /// Reference path retained as a differential oracle for the Barrett implementation.
    fn mul_mod(lhs: [u32; 8], rhs: [u32; 8], modulus: [u32; 8]) -> [u32; 8] {
        reduce_wide(mul_wide(lhs, rhs), modulus)
    }

    /// Reference path retained as a differential oracle for the Barrett implementation.
    fn inv_mod_prime(value: [u32; 8], modulus: [u32; 8]) -> Option<[u32; 8]> {
        if value == ZERO_LIMBS || modulus == ZERO_LIMBS {
            return None;
        }

        // Fermat's little theorem: a^(p - 2) is the multiplicative inverse modulo prime p.
        Some(pow_mod(value, sub_small(modulus, 2), modulus))
    }

    fn pow_mod(mut base: [u32; 8], exponent: [u32; 8], modulus: [u32; 8]) -> [u32; 8] {
        let mut result = ONE_LIMBS;
        for bit in 0..256 {
            if bit_is_set(&exponent, bit) {
                result = mul_mod(result, base, modulus);
            }
            base = mul_mod(base, base, modulus);
        }
        result
    }

    fn reduce_wide(value: [u32; 16], modulus: [u32; 8]) -> [u32; 8] {
        let mut remainder = [0u32; 8];
        for bit in (0..512).rev() {
            let overflow = shl1(&mut remainder);
            if bit_is_set(&value, bit) {
                remainder[0] |= 1;
            }
            if overflow != 0 || !cmp(&remainder, &modulus).is_lt() {
                remainder = sub_raw(remainder, modulus).0;
            }
        }
        remainder
    }

    /// Shifts a little-endian 256-bit value left by one bit and returns the overflow bit. Used by
    /// the reference reduction path.
    fn shl1(limbs: &mut [u32; 8]) -> u32 {
        let mut carry = 0u32;
        for limb in limbs.iter_mut() {
            let next_carry = *limb >> 31;
            *limb = (*limb << 1) | carry;
            carry = next_carry;
        }
        carry
    }

    #[test]
    fn wrapping_add_overflows() {
        assert_eq!(wrapping_add([u32::MAX; 8], [1, 0, 0, 0, 0, 0, 0, 0]), [0; 8]);
    }

    #[test]
    fn wrapping_sub_underflows() {
        assert_eq!(wrapping_sub([0; 8], [1, 0, 0, 0, 0, 0, 0, 0]), [u32::MAX; 8]);
    }

    #[test]
    fn wrapping_mul_keeps_low_256_bits() {
        assert_eq!(
            wrapping_mul([u32::MAX, 0, 0, 0, 0, 0, 0, 0], [2, 0, 0, 0, 0, 0, 0, 0]),
            [u32::MAX - 1, 1, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn modular_add_wraps_at_modulus() {
        let modulus = [5, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(add_mod([4, 0, 0, 0, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0, 0, 0], modulus), [0; 8]);
    }

    #[test]
    fn modular_sub_wraps_at_modulus() {
        let modulus = [5, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            sub_mod([0, 0, 0, 0, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0, 0, 0], modulus),
            [4, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn modular_mul_reduces() {
        let modulus = [5, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            mul_mod([4, 0, 0, 0, 0, 0, 0, 0], [4, 0, 0, 0, 0, 0, 0, 0], modulus),
            [1, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn modular_inverse_handles_zero_one_and_two() {
        assert_eq!(inv_mod_prime([0; 8], K1Base::MODULUS), None);
        assert_eq!(
            inv_mod_prime([1, 0, 0, 0, 0, 0, 0, 0], K1Base::MODULUS),
            Some([1, 0, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(inv_mod_prime([2, 0, 0, 0, 0, 0, 0, 0], K1Base::MODULUS), K1Base::half());
    }

    #[test]
    fn modular_inverse_uses_prime_field_exponentiation() {
        let modulus = [5, 0, 0, 0, 0, 0, 0, 0];
        let two = [2, 0, 0, 0, 0, 0, 0, 0];
        let three = [3, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(inv_mod_prime(two, modulus), Some(three));
        assert_eq!(
            mul_mod(two, inv_mod_prime(two, modulus).unwrap(), modulus),
            [1, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(inv_mod_prime([0; 8], modulus), None);
    }

    #[test]
    fn barrett_matches_reference_over_prime_fields() {
        fn next_u32(state: &mut u64) -> u32 {
            *state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (*state >> 32) as u32
        }

        fn rand_reduced(state: &mut u64, modulus: [u32; 8]) -> [u32; 8] {
            let mut wide = [0u32; 16];
            for limb in wide.iter_mut().take(8) {
                *limb = next_u32(state);
            }
            reduce_wide(wide, modulus)
        }

        let moduli = [K1Base::MODULUS, K1Scalar::MODULUS];

        let mut state: u64 = 0x1234_5678_9abc_def0;
        for modulus in moduli {
            let mu = barrett_mu(modulus);
            let max = sub_small(modulus, 1);

            // Edge cases: zero, one, and the largest canonical value.
            let edges = [ZERO_LIMBS, ONE_LIMBS, max];
            for a in edges {
                for b in edges {
                    assert_eq!(mul_mod_barrett(a, b, modulus, mu), mul_mod(a, b, modulus));
                }
            }

            for _ in 0..4000 {
                let a = rand_reduced(&mut state, modulus);
                let b = rand_reduced(&mut state, modulus);
                assert_eq!(
                    mul_mod_barrett(a, b, modulus, mu),
                    mul_mod(a, b, modulus),
                    "barrett mul mismatch"
                );
            }

            for _ in 0..400 {
                let value = rand_reduced(&mut state, modulus);
                assert_eq!(
                    inv_mod_prime_barrett(value, modulus, mu),
                    inv_mod_prime(value, modulus),
                    "barrett inverse mismatch"
                );
            }
        }
    }
}
