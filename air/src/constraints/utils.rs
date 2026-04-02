//! Utility extension traits for constraint code.

use miden_core::field::PrimeCharacteristicRing;

/// Extension trait adding `.not()` for boolean negation (`1 - self`).
pub trait BoolNot: PrimeCharacteristicRing {
    fn not(&self) -> Self {
        Self::ONE - self.clone()
    }
}

impl<T: PrimeCharacteristicRing> BoolNot for T {}
