//! Authored relations, concrete auxiliary witnesses, and trusted AIR collections.

use alloc::{boxed::Box, vec::Vec};

use p3_challenger::CanObserve;
use p3_field::{ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;

use super::{AirSpec, Frame, Inputs, LiftedAirBuilder};

/// An authored relation, independent of witness construction and prepared execution.
///
/// Source configuration must remain immutable while its analyzed form is reused. `Sync` alone
/// does not establish this: dimensions, equation structure, assertion class/order and addressing
/// must depend only on configuration, never on input values or the selected expression backend.
pub trait LiftedAir: Sync {
    type F: Field;

    fn spec(&self) -> AirSpec<'_, Self::F>;

    /// Construct the fixed matrix declared by [`Self::spec`] for setup ownership.
    ///
    /// Setup validates presence and dimensions and caches the result. Capture, descriptor
    /// construction, verification and row evaluation must not invoke this factory.
    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Self::F>> {
        None
    }

    fn eval<B: LiftedAirBuilder<F = Self::F>>(
        &self,
        frame: &Frame<'_, B>,
        inputs: Inputs<'_, B>,
        sink: &mut B,
    );
}

/// Caller-owned inputs for one concrete auxiliary-witness construction.
///
/// Public values, statement inputs and the shared challenge prefix retain instance order. The
/// optional preprocessed matrix is borrowed from setup's cache; it is not rebuilt by the witness.
#[derive(Debug)]
pub struct AuxTraceInputs<'a, F, EF> {
    pub main: &'a RowMajorMatrix<F>,
    pub preprocessed: Option<&'a RowMajorMatrix<F>>,
    pub public_values: &'a [F],
    pub statement: &'a [F],
    pub challenges: &'a [EF],
}

impl<F, EF> Copy for AuxTraceInputs<'_, F, EF> {}

impl<F, EF> Clone for AuxTraceInputs<'_, F, EF> {
    fn clone(&self) -> Self {
        *self
    }
}

/// Constructed auxiliary columns and exported boundary values, in source-declared order.
#[derive(Debug)]
pub struct AuxTrace<EF> {
    pub columns: RowMajorMatrix<EF>,
    pub exports: Vec<EF>,
}

/// Concrete fallible witness construction, required by proving but not source inspection.
pub trait ProverAir<EF: ExtensionField<Self::F>>: LiftedAir {
    type Error: core::error::Error + Send + Sync + 'static;

    /// Build the declared auxiliary matrix and exports from the exact supplied inputs.
    ///
    /// Source-specific recoverable construction failures are returned as errors. Lookup arithmetic
    /// assumes nonzero divisors. Successful output dimensions and export ordering are trusted
    /// construction invariants checked by the caller.
    fn build_aux_trace(
        &self,
        inputs: AuxTraceInputs<'_, Self::F, EF>,
    ) -> Result<AuxTrace<EF>, Self::Error>;
}

// Borrowed local/debug consumers retain the original source and its witness capability. These
// forwards neither capture a descriptor nor construct any data on their own.
impl<A: LiftedAir + ?Sized> LiftedAir for &A {
    type F = A::F;

    fn spec(&self) -> AirSpec<'_, Self::F> {
        A::spec(self)
    }

    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Self::F>> {
        A::build_preprocessed_trace(self)
    }

    fn eval<B: LiftedAirBuilder<F = Self::F>>(
        &self,
        frame: &Frame<'_, B>,
        inputs: Inputs<'_, B>,
        sink: &mut B,
    ) {
        A::eval(self, frame, inputs, sink);
    }
}

impl<A, EF> ProverAir<EF> for &A
where
    A: ProverAir<EF> + ?Sized,
    EF: ExtensionField<A::F>,
{
    type Error = A::Error;

    fn build_aux_trace(
        &self,
        inputs: AuxTraceInputs<'_, Self::F, EF>,
    ) -> Result<AuxTrace<EF>, Self::Error> {
        A::build_aux_trace(self, inputs)
    }
}

/// Boxed error returned by [`MultiAir::eval_external`].
pub type ReductionError = Box<dyn core::error::Error + Send + Sync>;

// ============================================================================
// MultiAir trait
// ============================================================================

/// Trusted statement definition for a multi-AIR proof.
///
/// A `MultiAir` owns the AIR instances and defines the cross-AIR assertions and
/// Fiat-Shamir binding hook for the statement.
///
/// Methods take `&self` so an impl can carry the AIRs and any protocol-level
/// state (closures, lookup tables, shared parameters). Because the AIRs are
/// owned here, a `MultiAir` is constructed per proof.
///
/// The framework defines instance order as the position of an AIR within
/// [`Self::airs`]. Every per-AIR slice elsewhere on [`Statement`](crate::air::Statement) /
/// [`ProverStatement`](crate::air::ProverStatement) uses the same ordering.
///
/// # Structural contract
///
/// Prover/verifier hot paths assume the structural invariants checked by
/// [`crate::air::debug::assert_multi_air_valid`]. In particular, `airs()` must be
/// non-empty and each AIR's dimensions and periodic columns must be well-formed.
/// Public inputs are stored in instance order, with each AIR's slice sized
/// by each kernel descriptor's `num_public_values`.
pub trait MultiAir<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// AIR type. Heterogeneous AIRs are expressed via caller-defined enum wrappers.
    type Air: crate::air::AirKernel<F = F>;

    /// The AIRs in instance order — the single source of that ordering.
    fn airs(&self) -> &[Self::Air];

    /// Upper bound on the extra statement inputs accepted by
    /// [`Self::eval_external`].
    ///
    /// These inputs are public/verifier-visible, but are separate from each AIR's
    /// `air_inputs` and are unrelated to aux trace columns. They are
    /// available only to the statement-level cross-AIR assertions. Validated by
    /// [`Statement::new`](crate::air::Statement::new) before any cryptographic work.
    /// Default `0`; implementations that consume `aux_inputs` must override so
    /// the budget matches the schema their `eval_external` decodes.
    fn max_aux_inputs(&self) -> usize {
        0
    }

    /// Evaluate statement-level cross-AIR assertions.
    ///
    /// Returns one value per assertion expression. Each expression is expected
    /// to vanish for a valid statement; the prover/verifier accept only if every
    /// returned value is zero. Implementations should return `Ok(Vec::new())`
    /// when the statement has no cross-AIR assertions.
    ///
    /// An implementation could perform zero checks internally, but returning
    /// assertion expression values keeps this hook close to the AIR constraint
    /// model: build the algebraic expression for each assertion, then let the
    /// protocol batch or individually assert those expressions equal zero. This
    /// also keeps the logic usable by a future symbolic-expression pipeline that
    /// extracts the assertion polynomials.
    ///
    /// # Arguments
    /// - `challenges`: shared extension-field challenge pool; each AIR consumes the prefix of
    ///   length `air.num_randomness()`.
    /// - `air_inputs`: public inputs per AIR in instance order, with lengths validated by
    ///   [`Statement::new`](crate::air::Statement::new).
    /// - `aux_inputs`: the extra inputs from the [`Statement`](crate::air::Statement).
    /// - `aux_values`, `log_trace_heights`: parallel per-AIR slices in instance order.
    ///   `aux_values[i]` and `log_trace_heights[i]` both describe `self.airs()[i]`. The protocol
    ///   derives proof order by stable-sorting instance indices by `(log_trace_height,
    ///   instance_index)`.
    ///
    /// Default: refuses to be called with non-empty `aux_inputs`; otherwise
    /// emits no assertions.
    fn eval_external(
        &self,
        challenges: &[EF],
        air_inputs: &[Vec<F>],
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

    /// Absorb statement-owned public inputs into the Fiat-Shamir challenger.
    ///
    /// The default order is the total public-input count, public inputs flattened in instance
    /// order, `max_aux_inputs()`, `aux_inputs.len()`, then `aux_inputs`. The protocol
    /// observes the instance count and `log_trace_heights` separately after this
    /// hook, but passes the heights here so custom bindings can include AIR
    /// metadata that depends on the prover-chosen trace ordering or heights.
    /// See [`Statement::observe`](crate::air::Statement::observe) for a runnable
    /// example of the default binding sequence.
    ///
    /// # Soundness gap (TODO)
    ///
    /// The default binds inputs but does NOT canonically bind the `MultiAir`
    /// itself — neither its AIR collection nor `eval_external` logic — into
    /// Fiat-Shamir. Until the symbolic-graph binding lands (tracked in
    /// <https://github.com/0xMiden/crypto/issues/970>), callers MUST observe the
    /// `MultiAir`'s AIR configurations into the challenger before calling the
    /// prover or verifier.
    fn observe<C: CanObserve<F>>(
        &self,
        challenger: &mut C,
        air_inputs: &[Vec<F>],
        aux_inputs: &[F],
        log_trace_heights: &[u8],
    ) {
        crate::air::StatementEncoding {
            num_public_values: air_inputs.iter().map(Vec::len).sum(),
            max_aux_inputs: self.max_aux_inputs(),
            num_aux_inputs: aux_inputs.len(),
            num_airs: self.airs().len(),
        }
        .observe(challenger, air_inputs.iter().flatten().copied(), aux_inputs);
        let _ = log_trace_heights;
    }
}
