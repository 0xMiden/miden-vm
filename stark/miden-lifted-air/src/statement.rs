//! Validated multi-AIR statements.
//!
//! - [`Statement`]: validated per-proof inputs over a [`MultiAir`] — `air_inputs`, `aux_inputs`.
//!   Construction via [`Statement::new`] runs the inputs-class validation; the type itself encodes
//!   the invariant.
//! - [`ProverStatement`]: validated prover-side companion — a [`Statement`] plus per-AIR main
//!   traces. Construction via [`ProverStatement::new`] runs the trace-shape validation.

use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_challenger::CanObserve;
use p3_field::{ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    air::{MultiAir, ReductionError},
    validate::{InstanceError, validate_inputs, validate_prover_traces},
};

// ============================================================================
// Statement
// ============================================================================

/// Validated per-proof inputs over a [`MultiAir`].
///
/// Holding a `Statement` is a type-level guarantee that the inputs-class
/// validation passed: per-AIR `num_public_values == air_inputs.len()` and
/// `aux_inputs.len() <= MultiAir::max_aux_inputs`.
pub struct Statement<F, EF, MA>
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    multi_air: MA,
    air_inputs: Vec<F>,
    aux_inputs: Vec<F>,
    _ef: PhantomData<EF>,
}

impl<F, EF, MA> Statement<F, EF, MA>
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    /// Construct a [`Statement`] after validating the inputs against `multi_air`.
    ///
    /// Returns [`InstanceError::PublicValuesLengthMismatch`] if any AIR's
    /// `num_public_values()` does not match `air_inputs.len()`, or
    /// [`InstanceError::AuxInputsTooLong`] if `aux_inputs.len()` exceeds
    /// `multi_air.max_aux_inputs()`.
    pub fn new(
        multi_air: MA,
        air_inputs: Vec<F>,
        aux_inputs: Vec<F>,
    ) -> Result<Self, InstanceError> {
        validate_inputs::<F, EF, MA>(&multi_air, &air_inputs, &aux_inputs)?;
        Ok(Self::new_unchecked(multi_air, air_inputs, aux_inputs))
    }

    /// Construct without validating. Use only when the inputs are already known to be valid
    /// (replay, deserialization of trusted state).
    pub fn new_unchecked(multi_air: MA, air_inputs: Vec<F>, aux_inputs: Vec<F>) -> Self {
        Self {
            multi_air,
            air_inputs,
            aux_inputs,
            _ef: PhantomData,
        }
    }

    pub fn multi_air(&self) -> &MA {
        &self.multi_air
    }

    pub fn airs(&self) -> &[MA::Air] {
        self.multi_air.airs()
    }

    pub fn air_inputs(&self) -> &[F] {
        &self.air_inputs
    }

    pub fn aux_inputs(&self) -> &[F] {
        &self.aux_inputs
    }

    /// Evaluate the cross-AIR external assertions via [`MultiAir::eval_external`].
    pub fn eval_external(
        &self,
        challenges: &[EF],
        aux_values: &[&[EF]],
        log_trace_heights: &[u8],
    ) -> Result<Vec<EF>, ReductionError> {
        self.multi_air.eval_external(
            challenges,
            &self.air_inputs,
            &self.aux_inputs,
            aux_values,
            log_trace_heights,
        )
    }

    /// Absorb this statement into the Fiat-Shamir challenger via [`MultiAir::observe`].
    pub fn observe<C: CanObserve<F>>(&self, challenger: &mut C, log_trace_heights: &[u8]) {
        self.multi_air
            .observe(challenger, &self.air_inputs, &self.aux_inputs, log_trace_heights);
    }
}

// ============================================================================
// ProverStatement
// ============================================================================

/// Validated prover-side companion: a [`Statement`] plus per-AIR main traces.
///
/// Holding a `ProverStatement` is a type-level guarantee that the
/// trace-shape validation passed: counts match, heights are powers of two
/// (and ≤ `u8::MAX + 1` instances), widths match each AIR, and per-AIR
/// height ≥ the AIR's max periodic column length.
pub struct ProverStatement<F, EF, MA>
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    statement: Statement<F, EF, MA>,
    traces: Vec<RowMajorMatrix<F>>,
}

impl<F, EF, MA> ProverStatement<F, EF, MA>
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    /// Construct after validating the trace shape against `statement`.
    pub fn new(
        statement: Statement<F, EF, MA>,
        traces: Vec<RowMajorMatrix<F>>,
    ) -> Result<Self, InstanceError> {
        validate_prover_traces::<F, EF, MA>(&statement, &traces)?;
        Ok(Self::new_unchecked(statement, traces))
    }

    /// Construct without validating.
    pub fn new_unchecked(statement: Statement<F, EF, MA>, traces: Vec<RowMajorMatrix<F>>) -> Self {
        Self { statement, traces }
    }

    pub fn statement(&self) -> &Statement<F, EF, MA> {
        &self.statement
    }

    pub fn traces(&self) -> &[RowMajorMatrix<F>] {
        &self.traces
    }

    /// Build every AIR's aux trace + aux values via [`MultiAir::build_aux_traces`].
    pub fn build_aux_traces(&self, challenges: &[EF]) -> (Vec<RowMajorMatrix<EF>>, Vec<Vec<EF>>) {
        let trace_refs: Vec<&RowMajorMatrix<F>> = self.traces.iter().collect();
        self.statement.multi_air.build_aux_traces(
            &trace_refs,
            &self.statement.air_inputs,
            &self.statement.aux_inputs,
            challenges,
        )
    }
}
