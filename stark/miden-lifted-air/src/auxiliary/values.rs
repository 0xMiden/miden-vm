//! Types for auxiliary trace value reduction and cross-AIR identity checking.
//!
//! Each AIR's aux trace has associated aux values (extension field scalars),
//! sent via the transcript by the prover. The verifier calls
//! [`LiftedAir::reduced_aux_values`](crate::LiftedAir::reduced_aux_values)
//! on each AIR to compute a [`ReducedAuxValues`] contribution, then checks that
//! the global combination is identity (prod=1, sum=0).

use p3_field::{Field, PrimeCharacteristicRing};

/// Accumulated contribution from reducing aux values across one or more AIRs.
///
/// The global identity check requires:
/// - `prod == 1` (multiset buses: all ratios multiply to 1)
/// - `sum == 0` (logup buses: all differences sum to 0)
#[derive(Clone, Debug)]
pub struct ReducedAuxValues<EF> {
    /// Accumulated product for multiset buses.
    pub prod: EF,
    /// Accumulated sum for logup buses.
    pub sum: EF,
}

impl<EF: PrimeCharacteristicRing> ReducedAuxValues<EF> {
    /// The identity contribution (no buses): prod=1, sum=0.
    pub fn identity() -> Self {
        Self { prod: EF::ONE, sum: EF::ZERO }
    }

    /// Combine another contribution into this one.
    pub fn combine_in_place(&mut self, other: &Self) {
        self.prod *= other.prod.clone();
        self.sum += other.sum.clone();
    }

    /// Combine two contributions, returning a new one.
    pub fn combine(mut self, other: &Self) -> Self {
        self.combine_in_place(other);
        self
    }
}

impl<EF: Field> ReducedAuxValues<EF> {
    /// Check whether this contribution is the identity (all buses satisfied).
    pub fn is_identity(&self) -> bool {
        self.prod == EF::ONE && self.sum == EF::ZERO
    }
}
