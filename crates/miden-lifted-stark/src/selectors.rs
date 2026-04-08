//! Selector container for constraint folding.
//!
//! The [`Selectors`] struct is a plain container holding selector values.
//! Computation is done via [`LiftedCoset`](crate::coset::LiftedCoset) methods:
//! - [`LiftedCoset::selectors`](crate::coset::LiftedCoset::selectors) for coset evaluation (prover)
//! - [`LiftedCoset::selectors_at`](crate::coset::LiftedCoset::selectors_at) for lifted OOD point
//!   evaluation (verifier)

use alloc::vec::Vec;

use p3_field::{PackedField, TwoAdicField};

/// Selector values for constraint evaluation.
///
/// Plain container for selector values. Use [`LiftedCoset`](crate::coset::LiftedCoset) methods
/// to compute selectors.
///
/// Generic over `T` to support:
/// - `EF` for single-point OOD evaluation (verifier)
/// - `Vec<F>` for coset evaluation (prover)
#[derive(Clone, Debug)]
pub struct Selectors<T> {
    pub is_first_row: T,
    pub is_last_row: T,
    pub is_transition: T,
}

impl<F: TwoAdicField> Selectors<Vec<F>> {
    /// Get packed selectors for indices `i..i + P::WIDTH`.
    ///
    /// Returns selector values for consecutive coset points in natural order.
    #[inline]
    pub fn packed_at<P>(&self, i: usize) -> Selectors<P>
    where
        P: PackedField<Scalar = F>,
    {
        Selectors {
            is_first_row: *P::from_slice(&self.is_first_row[i..i + P::WIDTH]),
            is_last_row: *P::from_slice(&self.is_last_row[i..i + P::WIDTH]),
            is_transition: *P::from_slice(&self.is_transition[i..i + P::WIDTH]),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::{
        coset::LiftedCoset,
        testing::configs::goldilocks_poseidon2::{Felt, QuadFelt},
    };

    #[test]
    fn test_selectors_at_point() {
        let log_n = 4;
        let coset = LiftedCoset::unlifted(log_n, 0);

        // Sample a point outside the domain
        let z = QuadFelt::from(Felt::from_u32(12345));

        let _sels = coset.selectors_at::<Felt, _>(z);

        // Verify vanishing_at matches manual computation
        let vanishing = coset.vanishing_at::<Felt, _>(z);
        let n = 1usize << log_n;
        let expected = z.exp_u64(n as u64) - QuadFelt::ONE;
        assert_eq!(vanishing, expected);
    }

    #[test]
    fn test_selectors_on_coset() {
        let log_trace = 3;
        let log_blowup = 2; // 4x blowup
        let coset = LiftedCoset::unlifted(log_trace, log_blowup);

        let sels: Selectors<Vec<Felt>> = coset.selectors();

        // Check lengths
        let coset_size = 1 << (log_trace + log_blowup);
        assert_eq!(sels.is_first_row.len(), coset_size);
        assert_eq!(sels.is_last_row.len(), coset_size);
        assert_eq!(sels.is_transition.len(), coset_size);
    }
}
