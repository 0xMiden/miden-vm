//! Fixed uint domains supported by deferred evaluation and MASM codegen.

use miden_core::Felt;

use super::spec::{Limbs, UintSpec};
use crate::math::{k1_base::K1Base, k1_scalar::K1Scalar, u256::U256};

/// VM-owned store pointer for the U256 wrapping-domain bound (`2^256 - 1`).
pub const U256_BOUND_PTR: u32 = 1;
/// VM-owned store pointer for the secp256k1 base-field bound (`p - 1`).
pub const K1_BASE_BOUND_PTR: u32 = 2;
/// VM-owned store pointer for the secp256k1 scalar-field bound (`n - 1`).
pub const K1_SCALAR_BOUND_PTR: u32 = 3;

/// Fixed uint arithmetic domains supported by the native uint precompile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UintDomain {
    /// Arithmetic modulo `2^256`.
    U256,
    /// secp256k1 base field.
    K1Base,
    /// secp256k1 scalar field.
    K1Scalar,
}

impl UintDomain {
    /// All fixed domains in deterministic precompile initialization order.
    pub const ALL: [Self; 3] = [Self::U256, Self::K1Base, Self::K1Scalar];

    /// Returns the supported domain for a tag-local id.
    pub fn from_id(id: Felt) -> Option<Self> {
        match id {
            id if id == <U256 as UintSpec>::ID => Some(Self::U256),
            id if id == <K1Base as UintSpec>::ID => Some(Self::K1Base),
            id if id == <K1Scalar as UintSpec>::ID => Some(Self::K1Scalar),
            _ => None,
        }
    }

    /// Returns the stable local domain selector retained for host-side metadata.
    pub fn id(self) -> Felt {
        match self {
            Self::U256 => <U256 as UintSpec>::ID,
            Self::K1Base => <K1Base as UintSpec>::ID,
            Self::K1Scalar => <K1Scalar as UintSpec>::ID,
        }
    }

    /// Returns the VM-owned bound pointer carried in uint `VALUE` tags.
    pub const fn bound_ptr(self) -> u32 {
        match self {
            Self::U256 => U256_BOUND_PTR,
            Self::K1Base => K1_BASE_BOUND_PTR,
            Self::K1Scalar => K1_SCALAR_BOUND_PTR,
        }
    }

    /// Returns the supported domain for a VM-owned bound pointer.
    pub const fn from_bound_ptr(ptr: u32) -> Option<Self> {
        match ptr {
            U256_BOUND_PTR => Some(Self::U256),
            K1_BASE_BOUND_PTR => Some(Self::K1Base),
            K1_SCALAR_BOUND_PTR => Some(Self::K1Scalar),
            _ => None,
        }
    }

    /// Returns the encoded modulus limbs. `[0; 8]` is the `2^256` sentinel.
    pub fn encoded_modulus(self) -> Limbs {
        match self {
            Self::U256 => <U256 as UintSpec>::ENCODED_MODULUS,
            Self::K1Base => <K1Base as UintSpec>::ENCODED_MODULUS,
            Self::K1Scalar => <K1Scalar as UintSpec>::ENCODED_MODULUS,
        }
    }

    /// Returns whether this domain is declared to be a prime field.
    pub fn is_prime_field(self) -> bool {
        match self {
            Self::U256 => <U256 as UintSpec>::IS_PRIME_FIELD,
            Self::K1Base => <K1Base as UintSpec>::IS_PRIME_FIELD,
            Self::K1Scalar => <K1Scalar as UintSpec>::IS_PRIME_FIELD,
        }
    }

    /// Returns whether `value` is canonical for this domain.
    pub fn is_canonical(self, value: &Limbs) -> bool {
        match self {
            Self::U256 => U256::is_canonical(value),
            Self::K1Base => K1Base::is_canonical(value),
            Self::K1Scalar => K1Scalar::is_canonical(value),
        }
    }

    /// Adds two canonical values in this domain.
    pub fn add(self, lhs: Limbs, rhs: Limbs) -> Limbs {
        match self {
            Self::U256 => U256::add(lhs, rhs),
            Self::K1Base => K1Base::add(lhs, rhs),
            Self::K1Scalar => K1Scalar::add(lhs, rhs),
        }
    }

    /// Subtracts two canonical values in this domain.
    pub fn sub(self, lhs: Limbs, rhs: Limbs) -> Limbs {
        match self {
            Self::U256 => U256::sub(lhs, rhs),
            Self::K1Base => K1Base::sub(lhs, rhs),
            Self::K1Scalar => K1Scalar::sub(lhs, rhs),
        }
    }

    /// Multiplies two canonical values in this domain.
    pub fn mul(self, lhs: Limbs, rhs: Limbs) -> Limbs {
        match self {
            Self::U256 => U256::mul(lhs, rhs),
            Self::K1Base => K1Base::mul(lhs, rhs),
            Self::K1Scalar => K1Scalar::mul(lhs, rhs),
        }
    }

    /// Returns the multiplicative inverse of `value` for declared prime-field domains.
    pub fn inv(self, value: Limbs) -> Option<Limbs> {
        match self {
            Self::U256 => U256::inv(value),
            Self::K1Base => K1Base::inv(value),
            Self::K1Scalar => K1Scalar::inv(value),
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
        }
    }

    /// Returns the field constant `1 / 2`, if this is a declared prime-field domain.
    pub fn half(self) -> Option<Limbs> {
        match self {
            Self::U256 => U256::half(),
            Self::K1Base => K1Base::half(),
            Self::K1Scalar => K1Scalar::half(),
        }
    }

    /// Returns `2^exponent` reduced into this prime-field domain.
    pub fn pow2_mod(self, exponent: usize) -> Option<Limbs> {
        match self {
            Self::U256 => U256::pow2_mod(exponent),
            Self::K1Base => K1Base::pow2_mod(exponent),
            Self::K1Scalar => K1Scalar::pow2_mod(exponent),
        }
    }

    /// Returns the generated field constants for prime-field domains.
    pub fn field_constants(self) -> Option<[Limbs; 5]> {
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
