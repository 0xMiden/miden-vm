//! Fixed uint domains and spec defaults.

use core::cmp::Ordering;

use miden_core::Felt;

use super::arithmetic::{
    add_mod, cmp, inv_mod_prime, mul_mod, sub_mod, sub_small, wrapping_add, wrapping_mul,
    wrapping_sub,
};
use crate::math::{
    ed25519_base::Ed25519Base, ed25519_scalar::Ed25519Scalar, k1_base::K1Base, k1_scalar::K1Scalar,
    r1_base::R1Base, r1_scalar::R1Scalar, u256::U256,
};

/// Little-endian 256-bit value represented as eight `u32` limbs.
pub type Limbs = [u32; 8];

pub(crate) const ZERO_LIMBS: Limbs = [0; 8];
pub(crate) const ONE_LIMBS: Limbs = [1, 0, 0, 0, 0, 0, 0, 0];
pub(crate) const TWO_LIMBS: Limbs = [2, 0, 0, 0, 0, 0, 0, 0];

/// Spec for one fixed uint arithmetic domain.
///
/// The default methods intentionally use slow generic limb arithmetic. Concrete domains can
/// override individual methods later without changing precompile dispatch.
pub trait UintSpec: 'static {
    /// Stable local domain selector carried in uint precompile tags.
    const ID: Felt;

    /// Encoded modulus limbs. `[0; 8]` is the `2^256` wrapping-domain sentinel.
    const ENCODED_MODULUS: Limbs;

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
            mul_mod(lhs, rhs, Self::ENCODED_MODULUS)
        }
    }

    /// Returns the multiplicative inverse of `value` for declared prime-field domains.
    fn inv(value: Limbs) -> Option<Limbs> {
        if Self::IS_PRIME_FIELD && Self::ENCODED_MODULUS != ZERO_LIMBS {
            inv_mod_prime(value, Self::ENCODED_MODULUS)
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

/// Fixed uint arithmetic domains supported by the native uint precompile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UintDomain {
    /// Arithmetic modulo `2^256`.
    U256,
    /// secp256k1 base field.
    K1Base,
    /// secp256k1 scalar field.
    K1Scalar,
    /// secp256r1 base field.
    R1Base,
    /// secp256r1 scalar field.
    R1Scalar,
    /// Ed25519 base field.
    Ed25519Base,
    /// Ed25519 scalar field.
    Ed25519Scalar,
}

impl UintDomain {
    /// All fixed domains in deterministic precompile initialization order.
    pub const ALL: [Self; 7] = [
        Self::U256,
        Self::K1Base,
        Self::K1Scalar,
        Self::R1Base,
        Self::R1Scalar,
        Self::Ed25519Base,
        Self::Ed25519Scalar,
    ];

    /// Returns the supported domain for a tag-local id.
    pub fn from_id(id: Felt) -> Option<Self> {
        match id {
            id if id == <U256 as UintSpec>::ID => Some(Self::U256),
            id if id == <K1Base as UintSpec>::ID => Some(Self::K1Base),
            id if id == <K1Scalar as UintSpec>::ID => Some(Self::K1Scalar),
            id if id == <R1Base as UintSpec>::ID => Some(Self::R1Base),
            id if id == <R1Scalar as UintSpec>::ID => Some(Self::R1Scalar),
            id if id == <Ed25519Base as UintSpec>::ID => Some(Self::Ed25519Base),
            id if id == <Ed25519Scalar as UintSpec>::ID => Some(Self::Ed25519Scalar),
            _ => None,
        }
    }

    /// Returns the stable local domain selector used in uint tags.
    pub fn id(self) -> Felt {
        match self {
            Self::U256 => <U256 as UintSpec>::ID,
            Self::K1Base => <K1Base as UintSpec>::ID,
            Self::K1Scalar => <K1Scalar as UintSpec>::ID,
            Self::R1Base => <R1Base as UintSpec>::ID,
            Self::R1Scalar => <R1Scalar as UintSpec>::ID,
            Self::Ed25519Base => <Ed25519Base as UintSpec>::ID,
            Self::Ed25519Scalar => <Ed25519Scalar as UintSpec>::ID,
        }
    }

    /// Returns the encoded modulus limbs. `[0; 8]` is the `2^256` sentinel.
    pub fn encoded_modulus(self) -> Limbs {
        match self {
            Self::U256 => <U256 as UintSpec>::ENCODED_MODULUS,
            Self::K1Base => <K1Base as UintSpec>::ENCODED_MODULUS,
            Self::K1Scalar => <K1Scalar as UintSpec>::ENCODED_MODULUS,
            Self::R1Base => <R1Base as UintSpec>::ENCODED_MODULUS,
            Self::R1Scalar => <R1Scalar as UintSpec>::ENCODED_MODULUS,
            Self::Ed25519Base => <Ed25519Base as UintSpec>::ENCODED_MODULUS,
            Self::Ed25519Scalar => <Ed25519Scalar as UintSpec>::ENCODED_MODULUS,
        }
    }

    /// Returns whether this domain is declared to be a prime field.
    pub fn is_prime_field(self) -> bool {
        match self {
            Self::U256 => <U256 as UintSpec>::IS_PRIME_FIELD,
            Self::K1Base => <K1Base as UintSpec>::IS_PRIME_FIELD,
            Self::K1Scalar => <K1Scalar as UintSpec>::IS_PRIME_FIELD,
            Self::R1Base => <R1Base as UintSpec>::IS_PRIME_FIELD,
            Self::R1Scalar => <R1Scalar as UintSpec>::IS_PRIME_FIELD,
            Self::Ed25519Base => <Ed25519Base as UintSpec>::IS_PRIME_FIELD,
            Self::Ed25519Scalar => <Ed25519Scalar as UintSpec>::IS_PRIME_FIELD,
        }
    }

    /// Returns whether `value` is canonical for this domain.
    pub fn is_canonical(self, value: &Limbs) -> bool {
        match self {
            Self::U256 => U256::is_canonical(value),
            Self::K1Base => K1Base::is_canonical(value),
            Self::K1Scalar => K1Scalar::is_canonical(value),
            Self::R1Base => R1Base::is_canonical(value),
            Self::R1Scalar => R1Scalar::is_canonical(value),
            Self::Ed25519Base => Ed25519Base::is_canonical(value),
            Self::Ed25519Scalar => Ed25519Scalar::is_canonical(value),
        }
    }

    /// Adds two canonical values in this domain.
    pub fn add(self, lhs: Limbs, rhs: Limbs) -> Limbs {
        match self {
            Self::U256 => U256::add(lhs, rhs),
            Self::K1Base => K1Base::add(lhs, rhs),
            Self::K1Scalar => K1Scalar::add(lhs, rhs),
            Self::R1Base => R1Base::add(lhs, rhs),
            Self::R1Scalar => R1Scalar::add(lhs, rhs),
            Self::Ed25519Base => Ed25519Base::add(lhs, rhs),
            Self::Ed25519Scalar => Ed25519Scalar::add(lhs, rhs),
        }
    }

    /// Subtracts two canonical values in this domain.
    pub fn sub(self, lhs: Limbs, rhs: Limbs) -> Limbs {
        match self {
            Self::U256 => U256::sub(lhs, rhs),
            Self::K1Base => K1Base::sub(lhs, rhs),
            Self::K1Scalar => K1Scalar::sub(lhs, rhs),
            Self::R1Base => R1Base::sub(lhs, rhs),
            Self::R1Scalar => R1Scalar::sub(lhs, rhs),
            Self::Ed25519Base => Ed25519Base::sub(lhs, rhs),
            Self::Ed25519Scalar => Ed25519Scalar::sub(lhs, rhs),
        }
    }

    /// Multiplies two canonical values in this domain.
    pub fn mul(self, lhs: Limbs, rhs: Limbs) -> Limbs {
        match self {
            Self::U256 => U256::mul(lhs, rhs),
            Self::K1Base => K1Base::mul(lhs, rhs),
            Self::K1Scalar => K1Scalar::mul(lhs, rhs),
            Self::R1Base => R1Base::mul(lhs, rhs),
            Self::R1Scalar => R1Scalar::mul(lhs, rhs),
            Self::Ed25519Base => Ed25519Base::mul(lhs, rhs),
            Self::Ed25519Scalar => Ed25519Scalar::mul(lhs, rhs),
        }
    }

    /// Returns the multiplicative inverse of `value` for declared prime-field domains.
    pub fn inv(self, value: Limbs) -> Option<Limbs> {
        match self {
            Self::U256 => U256::inv(value),
            Self::K1Base => K1Base::inv(value),
            Self::K1Scalar => K1Scalar::inv(value),
            Self::R1Base => R1Base::inv(value),
            Self::R1Scalar => R1Scalar::inv(value),
            Self::Ed25519Base => Ed25519Base::inv(value),
            Self::Ed25519Scalar => Ed25519Scalar::inv(value),
        }
    }

    /// Returns the maximum canonical value for U256.
    pub fn max(self) -> Option<Limbs> {
        match self {
            Self::U256 => Some(U256::MAX),
            _ => None,
        }
    }

    /// Returns the canonical value `modulus - 1`, or `2^256 - 1` for U256.
    pub fn minus_one(self) -> Limbs {
        match self {
            Self::U256 => U256::minus_one(),
            Self::K1Base => K1Base::minus_one(),
            Self::K1Scalar => K1Scalar::minus_one(),
            Self::R1Base => R1Base::minus_one(),
            Self::R1Scalar => R1Scalar::minus_one(),
            Self::Ed25519Base => Ed25519Base::minus_one(),
            Self::Ed25519Scalar => Ed25519Scalar::minus_one(),
        }
    }

    /// Returns the field constant `1 / 2`, if this is a declared prime-field domain.
    pub fn half(self) -> Option<Limbs> {
        match self {
            Self::U256 => U256::half(),
            Self::K1Base => K1Base::half(),
            Self::K1Scalar => K1Scalar::half(),
            Self::R1Base => R1Base::half(),
            Self::R1Scalar => R1Scalar::half(),
            Self::Ed25519Base => Ed25519Base::half(),
            Self::Ed25519Scalar => Ed25519Scalar::half(),
        }
    }

    /// Returns `2^exponent` reduced into this prime-field domain.
    pub fn pow2_mod(self, exponent: usize) -> Option<Limbs> {
        match self {
            Self::U256 => U256::pow2_mod(exponent),
            Self::K1Base => K1Base::pow2_mod(exponent),
            Self::K1Scalar => K1Scalar::pow2_mod(exponent),
            Self::R1Base => R1Base::pow2_mod(exponent),
            Self::R1Scalar => R1Scalar::pow2_mod(exponent),
            Self::Ed25519Base => Ed25519Base::pow2_mod(exponent),
            Self::Ed25519Scalar => Ed25519Scalar::pow2_mod(exponent),
        }
    }

    pub(crate) fn field_constants(self) -> Option<[Limbs; 5]> {
        if self.is_prime_field() {
            Some([
                self.minus_one(),
                self.half()?,
                self.pow2_mod(128)?,
                self.pow2_mod(256)?,
                self.pow2_mod(384)?,
            ])
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use miden_core::ZERO;

    use super::*;

    #[test]
    fn fixed_domains_round_trip_ids() {
        for domain in UintDomain::ALL {
            assert_eq!(UintDomain::from_id(domain.id()), Some(domain));
        }
        assert_eq!(UintDomain::from_id(Felt::new_unchecked(99)), None);
    }

    #[test]
    fn fixed_domain_constants_are_canonical() {
        for domain in UintDomain::ALL {
            assert!(domain.is_canonical(&ZERO_LIMBS));
            assert!(domain.is_canonical(&ONE_LIMBS));
            assert!(domain.is_canonical(&TWO_LIMBS));
            if let Some(max) = domain.max() {
                assert_eq!(domain, UintDomain::U256);
                assert!(domain.is_canonical(&max));
            }
            if let Some(constants) = domain.field_constants() {
                assert!(domain.is_prime_field());
                for constant in constants {
                    assert!(domain.is_canonical(&constant));
                }
            }
        }
    }

    #[test]
    fn u256_is_the_only_zero_modulus_domain() {
        for domain in UintDomain::ALL {
            assert_eq!(domain.encoded_modulus() == ZERO_LIMBS, domain == UintDomain::U256);
            assert_eq!(domain.id() == ZERO, domain == UintDomain::U256);
        }
    }
}
