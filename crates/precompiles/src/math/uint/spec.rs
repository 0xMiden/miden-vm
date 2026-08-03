//! Fixed uint arithmetic specs shared by deferred evaluation and generated MASM support.

use core::cmp::Ordering;

use miden_core::Felt;

use super::arithmetic::{
    add_mod, barrett_mu, cmp, inv_mod_prime_barrett, mul_mod_barrett, sub_mod, sub_small,
    wrapping_add, wrapping_mul, wrapping_sub,
};

/// Little-endian 256-bit value represented as eight `u32` limbs.
pub type Limbs = [u32; 8];

/// The canonical zero value in every supported uint domain.
pub const ZERO_LIMBS: Limbs = [0; 8];

/// The canonical one value in every supported uint domain.
pub const ONE_LIMBS: Limbs = [1, 0, 0, 0, 0, 0, 0, 0];

/// The canonical two value in every supported uint domain.
pub const TWO_LIMBS: Limbs = [2, 0, 0, 0, 0, 0, 0, 0];

/// Spec for one fixed uint arithmetic domain.
pub trait UintSpec: 'static {
    /// Stable local domain selector retained for host-side metadata.
    const ID: Felt;

    /// Encoded modulus limbs. `[0; 8]` is the `2^256` wrapping-domain sentinel.
    const ENCODED_MODULUS: Limbs;

    /// Barrett constant `floor(2^512 / modulus)` derived from [`Self::ENCODED_MODULUS`]. Unused by
    /// the `2^256` wrapping sentinel, for which it is `[0; 9]`.
    const BARRETT_MU: [u32; 9] = barrett_mu(Self::ENCODED_MODULUS);

    /// Whether this domain supports prime-field helpers such as inversion.
    const IS_PRIME_FIELD: bool = false;

    /// Returns whether `value` is canonical for this domain.
    fn is_canonical(value: &Limbs) -> bool {
        if Self::ENCODED_MODULUS == ZERO_LIMBS {
            true
        } else {
            cmp(value, &Self::ENCODED_MODULUS) == Ordering::Less
        }
    }

    /// Adds two canonical values in this domain.
    fn add(lhs: Limbs, rhs: Limbs) -> Limbs {
        if Self::ENCODED_MODULUS == ZERO_LIMBS {
            wrapping_add(lhs, rhs)
        } else {
            add_mod(lhs, rhs, Self::ENCODED_MODULUS)
        }
    }

    /// Subtracts two canonical values in this domain.
    fn sub(lhs: Limbs, rhs: Limbs) -> Limbs {
        if Self::ENCODED_MODULUS == ZERO_LIMBS {
            wrapping_sub(lhs, rhs)
        } else {
            sub_mod(lhs, rhs, Self::ENCODED_MODULUS)
        }
    }

    /// Multiplies two canonical values in this domain.
    fn mul(lhs: Limbs, rhs: Limbs) -> Limbs {
        if Self::ENCODED_MODULUS == ZERO_LIMBS {
            wrapping_mul(lhs, rhs)
        } else {
            mul_mod_barrett(lhs, rhs, Self::ENCODED_MODULUS, Self::BARRETT_MU)
        }
    }

    /// Returns the multiplicative inverse of `value` for declared prime-field domains.
    fn inv(value: Limbs) -> Option<Limbs> {
        if Self::IS_PRIME_FIELD && Self::ENCODED_MODULUS != ZERO_LIMBS {
            inv_mod_prime_barrett(value, Self::ENCODED_MODULUS, Self::BARRETT_MU)
        } else {
            None
        }
    }

    /// Returns the canonical value `modulus - 1`, or `2^256 - 1` for U256.
    fn minus_one() -> Limbs {
        if Self::ENCODED_MODULUS == ZERO_LIMBS {
            [u32::MAX; 8]
        } else {
            sub_small(Self::ENCODED_MODULUS, 1)
        }
    }

    /// Returns the field constant `1 / 2`, if this is a declared prime-field domain.
    fn half() -> Option<Limbs> {
        Self::inv(TWO_LIMBS)
    }

    /// Returns `2^exponent` reduced into this prime-field domain.
    fn pow2_mod(exponent: usize) -> Option<Limbs> {
        if !Self::IS_PRIME_FIELD || Self::ENCODED_MODULUS == ZERO_LIMBS {
            return None;
        }

        let mut value = ONE_LIMBS;
        for _ in 0..exponent {
            value = Self::add(value, value);
        }
        Some(value)
    }
}
