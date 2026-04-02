//! Utility extension traits for constraint code.

use miden_core::field::PrimeCharacteristicRing;

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
