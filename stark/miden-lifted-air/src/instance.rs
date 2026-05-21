//! Multi-AIR statement description.
//!
//! - [`MultiAir`]: the circuit — the AIR collection (`airs`) plus the cross-AIR `eval_external`
//!   reduction, the aux-trace builder, and the Fiat-Shamir `observe` hook. Because it owns the AIRs
//!   it is constructed per proof; impls carry the AIRs (and any shared parameters) on `&self`.
//! - [`Statement`]: validated per-proof inputs over a `MultiAir` — `air_inputs`, `aux_inputs`.
//!   Construction via [`Statement::new`] runs the inputs-class validation; the type itself encodes
//!   the invariant.
//! - [`ProverStatement`]: validated prover-side companion — a [`Statement`] plus per-AIR main
//!   traces. Construction via [`ProverStatement::new`] runs the trace-shape validation.

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use core::marker::PhantomData;

use p3_challenger::CanObserve;
use p3_field::{ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    LiftedAir,
    validate::{InstanceError, validate_inputs, validate_prover_traces},
};

/// Boxed error returned by [`MultiAir::eval_external`].
pub type ReductionError = Box<dyn core::error::Error + Send + Sync>;

// ============================================================================
// MultiAir trait
// ============================================================================

/// The circuit for a multi-AIR statement: the AIR collection plus the
/// cross-AIR behavior that operates on it.
///
/// Methods take `&self` so an impl can carry the AIRs and any protocol-level
/// state (closures, lookup tables, shared parameters). Because the AIRs are
/// owned here, a `MultiAir` is constructed per proof.
///
/// The framework defines instance order as the position of an AIR within
/// [`Self::airs`]. Every per-AIR slice elsewhere on [`Statement`] /
/// [`ProverStatement`] uses the same ordering.
pub trait MultiAir<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// AIR type. Heterogeneous AIRs are expressed via caller-defined enum
    /// wrappers, exactly as before.
    type Air: LiftedAir<F, EF>;

    /// The AIRs in instance order — the single source of that ordering.
    fn airs(&self) -> &[Self::Air];

    /// Upper bound on `aux_inputs().len()` accepted by [`Self::eval_external`].
    ///
    /// Validated by [`Statement::new`] before any cryptographic work. Default
    /// `0`; implementations that consume `aux_inputs` must override so the
    /// budget matches the schema their `eval_external` decodes.
    fn max_aux_inputs(&self) -> usize {
        0
    }

    /// Cross-AIR external assertions.
    ///
    /// Returns a flat vector of extension-field values, each of which must
    /// equal zero for the proof to be accepted.
    ///
    /// # Arguments
    /// - `challenges`: shared extension-field challenge pool; each AIR consumes the prefix of
    ///   length `air.num_randomness()`.
    /// - `air_inputs`, `aux_inputs`: the inputs from the [`Statement`].
    /// - `aux_values`: per-AIR aux values in instance order. `aux_values[i]` belongs to
    ///   `self.airs()[i]`.
    /// - `log_trace_heights`: per-AIR log₂ trace heights in instance order.
    ///
    /// Default: refuses to be called with non-empty `aux_inputs`; otherwise
    /// emits no assertions.
    fn eval_external(
        &self,
        challenges: &[EF],
        air_inputs: &[F],
        aux_inputs: &[F],
        aux_values: &[&[EF]],
        log_trace_heights: &[u8],
    ) -> Result<Vec<EF>, ReductionError> {
        if !aux_inputs.is_empty() {
            return Err("default `eval_external` received non-empty `aux_inputs` — override \
                 `eval_external` to consume them"
                .into());
        }
        let _ = (challenges, air_inputs, aux_values, log_trace_heights);
        Ok(Vec::new())
    }

    /// Build every AIR's auxiliary trace and aux values.
    ///
    /// # Arguments
    /// - `traces`, `air_inputs`, `aux_inputs`: instance-order slices owned by the
    ///   [`ProverStatement`] / [`Statement`].
    /// - `challenges`: sized to the maximum `num_randomness()` across AIRs; each AIR consumes the
    ///   prefix matching its own `num_randomness()`.
    ///
    /// # Returns
    /// `(aux_traces, aux_values)` in instance order — one entry per AIR.
    /// `aux_traces[i]` has width `self.airs()[i].aux_width()` and height matching
    /// `traces[i]`; `aux_values[i]` has length `self.airs()[i].num_aux_values()`.
    fn build_aux_traces(
        &self,
        traces: &[&RowMajorMatrix<F>],
        air_inputs: &[F],
        aux_inputs: &[F],
        challenges: &[EF],
    ) -> (Vec<RowMajorMatrix<EF>>, Vec<Vec<EF>>);

    /// Absorb per-proof state into the Fiat-Shamir challenger.
    ///
    /// Default order: `air_inputs`, then `aux_inputs`, then each log trace
    /// height in instance order. Overrides must preserve this ordering unless
    /// they account for the change on both prover and verifier.
    ///
    /// # Soundness gap (TODO)
    ///
    /// The default binds inputs and trace heights but does NOT canonically
    /// bind the `MultiAir` itself — neither its AIR collection nor
    /// `eval_external` — into Fiat-Shamir. Until the symbolic-graph binding
    /// lands (tracked in <https://github.com/0xMiden/crypto/issues/970>),
    /// callers MUST observe the `MultiAir`'s AIR configurations into the
    /// challenger before calling the prover or verifier.
    fn observe<C: CanObserve<F>>(
        &self,
        challenger: &mut C,
        air_inputs: &[F],
        aux_inputs: &[F],
        log_trace_heights: &[u8],
    ) {
        for &v in air_inputs {
            challenger.observe(v);
        }
        for &v in aux_inputs {
            challenger.observe(v);
        }
        for &h in log_trace_heights {
            challenger.observe(F::from_u8(h));
        }
    }
}

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
