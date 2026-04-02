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
pub fn horner_eval_bits<const N: usize, E: PrimeCharacteristicRing>(limbs: &[E; N]) -> E {
    const {
        assert! { N >= 1};
    }
    limbs
        .iter()
        .rev()
        .cloned()
        .reduce(|acc, bit| acc.double() + bit)
        .expect("non-empty array")
}

/// Computes binary OR: `a + b - a * b`
///
/// Assumes both a and b are binary (0 or 1).
/// Returns 1 if either a=1 or b=1.
#[inline]
pub fn binary_or<E: PrimeCharacteristicRing>(a: E, b: E) -> E {
    a.clone() + b.clone() - a * b
}
