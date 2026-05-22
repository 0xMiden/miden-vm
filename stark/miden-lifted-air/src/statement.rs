//! Validated multi-AIR statements: [`Statement`] (per-proof inputs over a
//! [`MultiAir`]) and [`ProverStatement`] (a `Statement` plus per-AIR main
//! traces). Both validate their inputs on construction.

use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_challenger::CanObserve;
use p3_field::{ExtensionField, Field};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use thiserror::Error;

use crate::{
    BaseAir, LiftedAir,
    air::{MultiAir, ReductionError},
};

// ============================================================================
// Statement
// ============================================================================

/// Validated per-proof inputs over a [`MultiAir`]: `air_inputs` and `aux_inputs`.
///
/// Holding one guarantees the input-length checks in [`Statement::new`] passed.
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
    /// Construct a [`Statement`], validating `air_inputs` and `aux_inputs` lengths
    /// against `multi_air`.
    pub fn new(
        multi_air: MA,
        air_inputs: Vec<F>,
        aux_inputs: Vec<F>,
    ) -> Result<Self, InstanceError> {
        let expected = multi_air.num_air_inputs();
        if expected != air_inputs.len() {
            return Err(InstanceError::PublicValuesLengthMismatch {
                expected,
                actual: air_inputs.len(),
            });
        }
        let max = multi_air.max_aux_inputs();
        if aux_inputs.len() > max {
            return Err(InstanceError::AuxInputsTooLong { actual: aux_inputs.len(), max });
        }
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

/// A [`Statement`] plus per-AIR main traces.
///
/// Holding one guarantees the trace-shape checks in [`ProverStatement::new`] passed.
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
    /// Construct a [`ProverStatement`], validating each trace's count, height, and
    /// width against its AIR.
    pub fn new(
        statement: Statement<F, EF, MA>,
        traces: Vec<RowMajorMatrix<F>>,
    ) -> Result<Self, InstanceError> {
        let max_instances = u8::MAX as usize + 1;
        if traces.len() > max_instances {
            return Err(InstanceError::TooManyInstances { count: traces.len() });
        }
        let airs = statement.airs();
        if airs.len() != traces.len() {
            return Err(InstanceError::TraceCountMismatch {
                airs: airs.len(),
                traces: traces.len(),
            });
        }
        for (idx, trace) in traces.iter().enumerate() {
            let h = trace.height();
            if !h.is_power_of_two() {
                return Err(InstanceError::TraceHeightNotPowerOfTwo { air: idx, height: h });
            }
        }
        for (idx, (air, trace)) in airs.iter().zip(traces.iter()).enumerate() {
            let trace_height = trace.height();
            let max_period = air.max_periodic_length();
            if trace_height < max_period {
                return Err(InstanceError::TraceHeightBelowPeriod {
                    air: idx,
                    trace_height,
                    max_period,
                });
            }
            if trace.width() != air.width() {
                return Err(InstanceError::TraceWidthMismatch {
                    air: idx,
                    expected: air.width(),
                    actual: trace.width(),
                });
            }
        }
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

// ============================================================================
// InstanceError
// ============================================================================

/// Errors from constructing a [`Statement`] / [`ProverStatement`] — the runtime
/// trust boundary on caller-supplied inputs.
#[derive(Debug, Error)]
pub enum InstanceError {
    #[error("num_air_inputs() = {expected}, but air_inputs().len() = {actual}")]
    PublicValuesLengthMismatch { expected: usize, actual: usize },

    #[error("aux_inputs().len() = {actual} exceeds max_aux_inputs() = {max}")]
    AuxInputsTooLong { actual: usize, max: usize },

    #[error("airs().len() = {airs} does not match traces().len() = {traces}")]
    TraceCountMismatch { airs: usize, traces: usize },

    #[error(
        "too many instances ({count}); the per-proof limit is {max} = u8::MAX + 1",
        max = u8::MAX as usize + 1
    )]
    TooManyInstances { count: usize },

    #[error("AIR {air}: trace width = {actual}, but air.width() = {expected}")]
    TraceWidthMismatch {
        air: usize,
        expected: usize,
        actual: usize,
    },

    #[error("AIR {air}: trace height = {height} is not a power of two")]
    TraceHeightNotPowerOfTwo { air: usize, height: usize },

    #[error(
        "AIR {air}: trace height = {trace_height} is less than max periodic column \
         length {max_period}"
    )]
    TraceHeightBelowPeriod {
        air: usize,
        trace_height: usize,
        max_period: usize,
    },
}
