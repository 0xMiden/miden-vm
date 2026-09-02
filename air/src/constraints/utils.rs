//! Utility extension traits for constraint code.

use miden_core::field::PrimeCharacteristicRing;

use crate::{
    Felt,
    constraints::constants::{TWO_POW_8, TWO_POW_16, TWO_POW_24},
};

/// Extension trait adding `.not()` for boolean negation (`1 - self`).
pub trait BoolNot: PrimeCharacteristicRing {
    fn not(&self) -> Self {
        Self::ONE - self.clone()
    }
}

impl<T: PrimeCharacteristicRing> BoolNot for T {}

/// Aggregate bits into a value (little-endian) using Horner's method: `sum(2^i * limbs[i])`.
///
/// Evaluates as `((limbs[N-1]*2 + limbs[N-2])*2 + ...)*2 + limbs[0]`.
#[inline]
pub fn horner_eval_bits<const N: usize, T: Clone + Into<E>, E: PrimeCharacteristicRing>(
    limbs: &[T; N],
) -> E {
    const {
        assert! { N >= 1};
    }
    limbs
        .iter()
        .rev()
        .cloned()
        .map(Into::into)
        .reduce(|acc, bit| acc.double() + bit)
        .expect("non-empty array")
}

/// Packs four little-endian byte limbs into a u32 field expression.
#[inline]
pub fn pack_u32_bytes_le<T, E>(bytes: [T; 4]) -> E
where
    T: Into<E>,
    E: PrimeCharacteristicRing,
    Felt: Into<E>,
{
    let [b0, b1, b2, b3] = bytes.map(Into::into);
    let shift8: E = TWO_POW_8.into();
    let shift16: E = TWO_POW_16.into();
    let shift24: E = TWO_POW_24.into();

    b0 + shift8 * b1 + shift16 * b2 + shift24 * b3
}
