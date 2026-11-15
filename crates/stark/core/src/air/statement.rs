//! Validated runtime inputs for trusted multi-AIR definitions: [`Statement`]
//! holds per-proof caller inputs, and [`ProverStatement`] adds per-AIR main
//! traces.

use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_challenger::CanObserve;
use p3_field::{ExtensionField, Field};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use thiserror::Error;

use crate::air::{MultiAir, ReductionError, native::AirKernel};

// ============================================================================
// Statement
// ============================================================================

/// Validated per-proof inputs over a [`MultiAir`]: `air_inputs` and `aux_inputs`.
///
/// Holding one guarantees the caller-input length checks in [`Statement::new`] passed.
/// The `MultiAir` itself is trusted application code; run
/// [`crate::air::debug::assert_multi_air_valid`] in tests/setup to check structural
/// invariants such as non-empty `airs()` and periodic-column shape.
pub struct Statement<F, EF, MA>
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    multi_air: MA,
    air_inputs: Vec<Vec<F>>,
    aux_inputs: Vec<F>,
    _ef: PhantomData<EF>,
}

impl<F, EF, MA> Statement<F, EF, MA>
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    /// Construct a [`Statement`] from `(AIR instance index, public inputs)` entries.
    ///
    /// Entries may appear in any order. Only AIRs with no public inputs may be omitted.
    /// Duplicate indices, indices outside `multi_air.airs()`, and entries whose lengths
    /// differ from the AIR's declaration are rejected.
    ///
    /// This assumes `multi_air` satisfies the structural contract checked by
    /// [`crate::air::debug::assert_multi_air_valid`]; malformed AIR definitions (for
    /// example an empty [`MultiAir::airs`] collection) may panic.
    pub fn new(
        multi_air: MA,
        air_inputs: Vec<(usize, Vec<F>)>,
        aux_inputs: Vec<F>,
    ) -> Result<Self, InstanceError> {
        let airs = multi_air.airs();
        assert!(!airs.is_empty(), "a MultiAir must carry at least one AIR");
        let mut inputs: Vec<_> = (0..airs.len()).map(|_| None).collect();
        for (air_index, values) in air_inputs {
            let slot = inputs.get_mut(air_index).ok_or(InstanceError::InvalidPublicInputs)?;
            if slot.is_some() {
                return Err(InstanceError::InvalidPublicInputs);
            }
            *slot = Some(values);
        }
        let air_inputs = inputs
            .into_iter()
            .zip(airs)
            .map(|(values, air)| {
                let values = values.unwrap_or_default();
                let expected = air.descriptor().spec().num_public_values;
                if values.len() != expected {
                    return Err(InstanceError::PublicValuesLengthMismatch {
                        expected,
                        actual: values.len(),
                    });
                }
                Ok(values)
            })
            .collect::<Result<_, _>>()?;
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

    /// Public inputs for every AIR in instance order, including empty slices for omitted AIRs.
    pub fn air_inputs(&self) -> &[Vec<F>] {
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
    /// total public-input count, public inputs flattened in instance order,
    /// [`MultiAir::max_aux_inputs`], the
    /// `aux_inputs` length, and `aux_inputs`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::borrow::Cow;
    /// use miden_crypto::Felt;
    /// use miden_stark::air::{MultiAir, Statement, native};
    /// use p3_challenger::CanObserve;
    ///
    /// struct ExampleAir;
    ///
    /// impl native::LiftedAir for ExampleAir {
    ///     type F = Felt;
    ///
    ///     fn spec(&self) -> native::AirSpec<'_, Felt> {
    ///         native::AirSpec {
    ///             main_width: 1, aux_width: 1, num_public_values: 2,
    ///             num_challenges: 0, num_exports: 0, preprocessed: None,
    ///             periodic_columns: Cow::Borrowed(&[]),
    ///         }
    ///     }
    ///
    ///     fn eval<B: native::LiftedAirBuilder<F = Felt>>(
    ///         &self, _frame: &native::Frame<'_, B>, _inputs: native::Inputs<'_, B>,
    ///         _sink: &mut B,
    ///     ) {}
    /// }
    ///
    /// struct ExampleMultiAir {
    ///     airs: [native::DirectKernel<ExampleAir>; 1],
    /// }
    ///
    /// impl MultiAir<Felt, Felt> for ExampleMultiAir {
    ///     type Air = native::DirectKernel<ExampleAir>;
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
    ///     ExampleMultiAir { airs: [native::DirectKernel::new(ExampleAir).unwrap()] },
    ///     vec![(0, vec![Felt::new_unchecked(10), Felt::new_unchecked(11)])],
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
    /// checked by [`crate::air::debug::assert_multi_air_valid`].
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
        for (idx, (air, trace)) in airs.iter().zip(&traces).enumerate() {
            let spec = air.descriptor().spec();
            let width = trace.width();
            if width != spec.main_width {
                return Err(InstanceError::TraceWidthMismatch {
                    air: idx,
                    expected: spec.main_width,
                    actual: width,
                });
            }
            // Descriptor main width is positive. Validate raw rows before Matrix::height divides.
            if !trace.values.len().is_multiple_of(width) {
                return Err(InstanceError::TraceStorageMismatch {
                    air: idx,
                    width,
                    elements: trace.values.len(),
                });
            }
            let h = trace.values.len() / width;
            if h < 2 {
                return Err(InstanceError::TraceHeightTooSmall { air: idx, height: h });
            }
            if !h.is_power_of_two() {
                return Err(InstanceError::TraceHeightNotPowerOfTwo { air: idx, height: h });
            }
            let trace_height = h;
            let max_period = spec.max_periodic_length();
            if trace_height < max_period {
                return Err(InstanceError::TraceHeightBelowPeriod {
                    air: idx,
                    trace_height,
                    max_period,
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

    /// Split this value into the verifier-side statement and owned main traces.
    pub fn into_parts(self) -> (Statement<F, EF, MA>, Vec<RowMajorMatrix<F>>) {
        (self.statement, self.traces)
    }
}

// ============================================================================
// InstanceError
// ============================================================================

/// Errors from constructing a [`Statement`] / [`ProverStatement`] — the runtime
/// trust boundary on caller-supplied inputs.
#[derive(Debug, Error)]
pub enum InstanceError {
    #[error("expected {expected} public inputs, but got {actual}")]
    PublicValuesLengthMismatch { expected: usize, actual: usize },

    #[error("invalid public inputs")]
    InvalidPublicInputs,

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

    #[error("AIR {air}: {elements} trace elements do not form complete rows of width {width}")]
    TraceStorageMismatch {
        air: usize,
        width: usize,
        elements: usize,
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
