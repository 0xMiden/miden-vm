//! Reduction of VM LogUp boundary interactions into their external correction.

use miden_core::{Felt, field::ExtensionField};
use miden_lifted_stark::air::ReductionError;

use crate::lookup::{BoundaryBuilder, Challenges, LookupMessage};

// REDUCED-AUX BOUNDARY BUILDER
// ================================================================================================

/// `BoundaryBuilder` impl that reduces each emitted interaction to its LogUp denominator
/// contribution `multiplicity / encode(msg)` and sums them into a running `EF` accumulator.
///
/// Boundary correction is computed from the structured boundary messages emitted by each AIR.
///
/// Denominators are `alpha + sum_i beta^i * field_i` with random `alpha, beta`; on any
/// legitimate proof they are non-zero with overwhelming probability. A malformed proof can still
/// drive a denominator to zero, so the reducer captures the first failure and surfaces it as a
/// [`ReductionError`] to the verifier rather than panicking.
pub(super) struct ReduceBoundaryBuilder<'a, EF: ExtensionField<Felt>> {
    pub(super) challenges: &'a Challenges<EF>,
    pub(super) var_len_public_inputs: &'a [&'a [Felt]],
    pub(super) sum: EF,
    pub(super) error: Option<ReductionError>,
}

impl<'a, EF: ExtensionField<Felt>> ReduceBoundaryBuilder<'a, EF> {
    pub(super) fn finalize(self) -> Result<EF, ReductionError> {
        match self.error {
            Some(err) => Err(err),
            None => Ok(self.sum),
        }
    }
}

impl<'a, EF: ExtensionField<Felt>> BoundaryBuilder for ReduceBoundaryBuilder<'a, EF> {
    type F = Felt;
    type EF = EF;

    fn var_len_public_inputs(&self) -> &[&[Felt]] {
        self.var_len_public_inputs
    }

    fn insert<M>(&mut self, _name: &'static str, multiplicity: Felt, msg: M)
    where
        M: LookupMessage<Felt, EF>,
    {
        if self.error.is_some() {
            return;
        }
        match msg.encode(self.challenges).try_inverse() {
            Some(inv) => self.sum += inv * multiplicity,
            None => {
                self.error = Some("LogUp boundary denominator was zero".into());
            },
        }
    }
}
