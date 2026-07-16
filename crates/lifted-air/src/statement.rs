//! Validated runtime inputs for trusted multi-AIR definitions: [`Statement`]
//! holds per-proof caller inputs, and [`ProverStatement`] adds per-AIR main
//! traces.

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
/// Holding one guarantees the caller-input length checks in [`Statement::new`] passed.
/// The `MultiAir` itself is trusted application code; run
/// [`crate::debug::assert_multi_air_valid`] in tests/setup to check structural
/// invariants such as non-empty `airs()`, shared public-value counts, and
/// periodic-column shape.
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
    /// Construct a [`Statement`], validating caller-supplied input lengths
    /// against `multi_air`.
    ///
    /// This assumes `multi_air` satisfies the structural contract checked by
    /// [`crate::debug::assert_multi_air_valid`]; malformed AIR definitions (for
    /// example an empty [`MultiAir::airs`] collection) may panic in trusted
    /// helper methods such as [`MultiAir::num_air_inputs`].
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
        Ok(Self {
            multi_air,
            air_inputs,
            aux_inputs,
            _ef: PhantomData,
        })
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

    /// Evaluate cross-AIR assertions via [`MultiAir::eval_external`].
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

    /// Absorb statement-owned data into the Fiat-Shamir challenger via [`MultiAir::observe`].
    ///
    /// The protocol separately observes the instance count and
    /// `log_trace_heights` in instance order after this call. Heights are passed
    /// here only so custom `MultiAir` bindings can include height-dependent
    /// statement data.
    ///
    /// The default [`MultiAir::observe`] implementation absorbs, in order, the
    /// `air_inputs` length, `air_inputs`, [`MultiAir::max_aux_inputs`], the
    /// `aux_inputs` length, and `aux_inputs`.
    ///
    /// # Examples
    ///
    /// ```
    /// use miden_field::Felt;
    /// use miden_lifted_air::{BaseAir, LiftedAir, LiftedAirBuilder, MultiAir, Statement};
    /// use p3_challenger::CanObserve;
    /// use p3_matrix::{Matrix, dense::RowMajorMatrix};
    ///
    /// #[derive(Clone)]
    /// struct ExampleAir;
    ///
    /// impl BaseAir<Felt> for ExampleAir {
    ///     fn width(&self) -> usize {
    ///         1
    ///     }
    ///
    ///     fn num_public_values(&self) -> usize {
    ///         2
    ///     }
    /// }
    ///
    /// impl LiftedAir<Felt, Felt> for ExampleAir {
    ///     fn num_randomness(&self) -> usize {
    ///         0
    ///     }
    ///
    ///     fn aux_width(&self) -> usize {
    ///         1
    ///     }
    ///
    ///     fn num_aux_values(&self) -> usize {
    ///         0
    ///     }
    ///
    ///     fn build_aux_trace(
    ///         &self,
    ///         main: &RowMajorMatrix<Felt>,
    ///         _air_inputs: &[Felt],
    ///         _aux_inputs: &[Felt],
    ///         _challenges: &[Felt],
    ///     ) -> (RowMajorMatrix<Felt>, Vec<Felt>) {
    ///         (RowMajorMatrix::new(vec![Felt::ZERO; main.height()], 1), Vec::new())
    ///     }
    ///
    ///     fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, _builder: &mut AB) {}
    /// }
    ///
    /// struct ExampleMultiAir {
    ///     airs: [ExampleAir; 1],
    /// }
    ///
    /// impl MultiAir<Felt, Felt> for ExampleMultiAir {
    ///     type Air = ExampleAir;
    ///
    ///     fn airs(&self) -> &[Self::Air] {
    ///         &self.airs
    ///     }
    ///
    ///     fn max_aux_inputs(&self) -> usize {
    ///         3
    ///     }
    /// }
    ///
    /// #[derive(Default)]
    /// struct RecordingChallenger(Vec<Felt>);
    ///
    /// impl CanObserve<Felt> for RecordingChallenger {
    ///     fn observe(&mut self, value: Felt) {
    ///         self.0.push(value);
    ///     }
    /// }
    ///
    /// let statement = Statement::<Felt, Felt, _>::new(
    ///     ExampleMultiAir { airs: [ExampleAir] },
    ///     vec![Felt::new_unchecked(10), Felt::new_unchecked(11)],
    ///     vec![Felt::new_unchecked(20), Felt::new_unchecked(21)],
    /// )
    /// .unwrap();
    ///
    /// let mut challenger = RecordingChallenger::default();
    /// statement.observe(&mut challenger, &[3]);
    ///
    /// assert_eq!(
    ///     challenger.0,
    ///     vec![
    ///         Felt::new_unchecked(2),
    ///         Felt::new_unchecked(10),
    ///         Felt::new_unchecked(11),
    ///         Felt::new_unchecked(3),
    ///         Felt::new_unchecked(2),
    ///         Felt::new_unchecked(20),
    ///         Felt::new_unchecked(21),
    ///     ],
    /// );
    /// ```
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
    ///
    /// This assumes the underlying [`MultiAir`] satisfies the structural contract
    /// checked by [`crate::debug::assert_multi_air_valid`].
    pub fn new(
        statement: Statement<F, EF, MA>,
        traces: Vec<RowMajorMatrix<F>>,
    ) -> Result<Self, InstanceError> {
        // TraceOrder stores instance indices as u8, so it can represent 256
        // instances: indices 0 through u8::MAX.
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
            if h < 2 {
                return Err(InstanceError::TraceHeightTooSmall { air: idx, height: h });
            }
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
        Ok(Self { statement, traces })
    }

    pub fn statement(&self) -> &Statement<F, EF, MA> {
        &self.statement
    }

    pub fn traces(&self) -> &[RowMajorMatrix<F>] {
        &self.traces
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

    #[error("AIR {air}: trace height = {height} is too small; expected at least 2 rows")]
    TraceHeightTooSmall { air: usize, height: usize },

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
