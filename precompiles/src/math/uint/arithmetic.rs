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

/// Multiplies two canonical values modulo `modulus`.
pub(crate) fn mul_mod(a: [u32; 8], b: [u32; 8], modulus: [u32; 8]) -> [u32; 8] {
    if a == ZERO_LIMBS || b == ZERO_LIMBS {
        return ZERO_LIMBS;
    }
    if a == ONE_LIMBS {
        return b;
    }
    if b == ONE_LIMBS {
        return a;
    }

    reduce_wide(mul_wide(a, b), modulus)
}

/// Exponentiates `base^exponent mod modulus` with little-endian exponent limbs.
pub(crate) fn pow_mod(mut base: [u32; 8], exponent: [u32; 8], modulus: [u32; 8]) -> [u32; 8] {
    let mut result = [0u32; 8];
    result[0] = 1;

    for bit in 0..256 {
        if bit_is_set(&exponent, bit) {
            result = mul_mod(result, base, modulus);
        }
        base = mul_mod(base, base, modulus);
    }

    result
}

/// Computes `value^-1 mod modulus` for nonzero values in a prime field.
pub(crate) fn inv_mod_prime(value: [u32; 8], modulus: [u32; 8]) -> Option<[u32; 8]> {
    if value == ZERO_LIMBS || modulus == ZERO_LIMBS {
        return None;
    }
    if value == ONE_LIMBS {
        return Some(ONE_LIMBS);
    }

    // Fermat's little theorem: a^(p - 2) is the multiplicative inverse modulo prime p.
    Some(pow_mod(value, sub_small(modulus, 2), modulus))
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

/// Reduces a 512-bit little-endian value modulo a concrete 256-bit modulus.
pub(crate) fn reduce_wide(value: [u32; 16], modulus: [u32; 8]) -> [u32; 8] {
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

/// Shifts a little-endian 256-bit value left by one bit and returns the overflow bit.
pub(crate) fn shl1(limbs: &mut [u32; 8]) -> u32 {
    let mut carry = 0u32;
    for limb in limbs.iter_mut() {
        let next_carry = *limb >> 31;
        *limb = (*limb << 1) | carry;
        carry = next_carry;
    }
    carry
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
        use crate::math::{k1_base::K1Base, uint::UintSpec};

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
}
