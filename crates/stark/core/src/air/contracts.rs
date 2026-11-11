//! AIR traits for the lifted STARK system: [`LiftedAir`] (a single AIR) and
//! [`MultiAir`] (the AIR collection plus the cross-AIR behavior on it).

use alloc::{boxed::Box, vec::Vec};

use p3_air::BaseAir;
use p3_challenger::CanObserve;
use p3_field::{Algebra, ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;

use crate::air::{
    LiftedAirBuilder,
    symbolic::{
        AirLayout, SymbolicAirBuilder, SymbolicExpression, SymbolicExpressionExt, eval_air,
    },
};

/// Inputs that stay fixed throughout one AIR evaluation pass.
///
/// Values use the evaluator's base and extension expression types. Symbolic callers supply
/// expressions, while concrete callers supply scalar or packed field values.
pub struct EvalInputs<'a, B, E> {
    /// This AIR's public inputs, in the order returned by `builder.public_values()`.
    pub public_values: &'a [B],
    /// Auxiliary-trace challenges, in the order returned by `builder.permutation_randomness()`.
    pub challenges: &'a [E],
    /// Auxiliary boundary values returned by `builder.permutation_values()`.
    pub aux_values: &'a [E],
}

/// Super-trait for AIR definitions used by the lifted STARK prover/verifier.
///
/// Inherits from upstream traits for width and public values.
/// Adds Miden-specific auxiliary trace support and periodic column data.
/// Every `LiftedAir` must provide an auxiliary trace (even if it is a minimal
/// 1-column dummy).
///
/// # Evaluation
///
/// Constraint structure and input indexing must depend only on the AIR configuration and declared
/// dimensions. Preparation and evaluation must preserve the constraints and their order across
/// scalar, packed, and symbolic expression types. Symbolic preparation must retain input
/// dependencies in its expressions so degree analysis and constraint capture see the complete
/// relation.
///
/// The default [`constraint_degree`](Self::constraint_degree) evaluates symbolically with the
/// declared dimensions. Use [`crate::air::debug::check_builder_shape`] to check that a concrete
/// builder has matching dimensions before evaluation.
///
/// # Type Parameters
/// - `F`: Base field
/// - `EF`: Extension field (for aux trace challenges and aux values)
pub trait LiftedAir<F: Field, EF>: Sync + BaseAir<F> {
    /// Data shared by row evaluations with the same inputs. Use `()` when no preparation is needed.
    type EvalData<B: Algebra<F>, E: Algebra<B>>: Default;

    /// Fixed native height of this AIR's preprocessed matrix, or `None` if it has none.
    ///
    /// Return `None` when [`BaseAir::preprocessed_width`] is zero. Otherwise return
    /// `Some(height)`, where `height` is a power of two, is at least 2, and equals the height of
    /// the matrix returned by [`BaseAir::preprocessed_trace`].
    /// Shape validation requires this AIR's main trace to have this height before deriving
    /// the committed table order. Return the height without constructing the matrix.
    fn preprocessed_height(&self) -> Option<usize> {
        None
    }

    /// Maximum periodic-column length, or `0` if there are none. A trace's height
    /// must be at least this, so it is the per-AIR lower bound on trace height.
    ///
    /// The default derives it from [`periodic_columns`](BaseAir::periodic_columns),
    /// asserting each column is a non-empty power of two. Override to return it
    /// directly when known statically; the override is cross-checked by
    /// [`crate::air::debug::assert_multi_air_valid`].
    fn max_periodic_length(&self) -> usize {
        self.periodic_columns()
            .iter()
            .map(|col| {
                assert!(
                    !col.is_empty() && col.len().is_power_of_two(),
                    "periodic column length must be a positive power of two, got {}",
                    col.len(),
                );
                col.len()
            })
            .max()
            .unwrap_or(0)
    }

    /// Number of extension-field challenges required for the auxiliary trace.
    fn num_randomness(&self) -> usize;

    /// Number of extension-field columns in the auxiliary trace.
    fn aux_width(&self) -> usize;

    /// Number of extension-field aux values committed to the Fiat-Shamir transcript.
    ///
    /// Returned by [`build_aux_trace`](Self::build_aux_trace) alongside the aux trace
    /// matrix; the count is independent of [`aux_width`](Self::aux_width) (the number
    /// of aux trace columns). Exposed to constraints as *permutation values* via
    /// [`PermutationAirBuilder::permutation_values`](crate::air::PermutationAirBuilder::permutation_values).
    fn num_aux_values(&self) -> usize;

    /// Build this AIR's auxiliary trace and aux values.
    ///
    /// `air_inputs` is this AIR's public-input slice; `aux_inputs` contains the
    /// statement-level inputs. `challenges` contains exactly
    /// [`num_randomness`](Self::num_randomness) extension-field elements for this AIR. The
    /// returned `aux_trace` has width [`aux_width`](Self::aux_width) and the same height as
    /// `main`; `aux_values` has length [`num_aux_values`](Self::num_aux_values). The default
    /// [`build_aux_trace_with_preprocessed`](Self::build_aux_trace_with_preprocessed)
    /// delegates to this method.
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<F>,
        air_inputs: &[F],
        aux_inputs: &[F],
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>);

    /// Build the auxiliary trace using the cached preprocessed trace when present.
    ///
    /// The prover supplies the preprocessed trace cached in its setup bundle:
    /// `Some` exactly when this AIR declares preprocessed columns. AIRs that
    /// do not need it can use the default implementation.
    fn build_aux_trace_with_preprocessed(
        &self,
        main: &RowMajorMatrix<F>,
        _preprocessed: Option<&RowMajorMatrix<F>>,
        air_inputs: &[F],
        aux_inputs: &[F],
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        self.build_aux_trace(main, air_inputs, aux_inputs, challenges)
    }

    /// Return the [`AirLayout`] describing this AIR's dimensions.
    ///
    /// This is the single source of truth for building symbolic or layout builders.
    fn air_layout(&self) -> AirLayout {
        AirLayout {
            preprocessed_width: self.preprocessed_width(),
            main_width: self.width(),
            num_public_values: self.num_public_values(),
            permutation_width: self.aux_width(),
            num_permutation_challenges: self.num_randomness(),
            num_permutation_values: self.num_aux_values(),
            num_periodic_columns: self.periodic_columns().len(),
        }
    }

    /// Prepare data for a pass over this AIR's constraints.
    ///
    /// The input lengths are [`num_public_values`](BaseAir::num_public_values),
    /// [`num_randomness`](Self::num_randomness), and [`num_aux_values`](Self::num_aux_values).
    /// Call once per evaluation batch, using the same expression types as its builders. The data
    /// can be reused while the AIR configuration and all input values remain unchanged.
    /// The parallel prover requires its packed `EvalData` to be `Sync`.
    fn prepare<B: Algebra<F>, E: Algebra<B>>(
        &self,
        _inputs: EvalInputs<'_, B, E>,
    ) -> Self::EvalData<B, E> {
        Default::default()
    }

    /// Evaluate all constraints using data from [`prepare`](Self::prepare).
    ///
    /// The data must have been prepared for this AIR configuration and the public values,
    /// auxiliary challenges, and auxiliary values exposed by `builder`.
    fn eval<AB: LiftedAirBuilder<F = F>>(
        &self,
        builder: &mut AB,
        data: &Self::EvalData<AB::Expr, AB::ExprEF>,
    );

    /// Symbolic constraint degree multiples, split into base-field and
    /// extension-field maxima (see [`ConstraintDegrees`]).
    ///
    /// The split lets callers report base and extension constraint degree maxima
    /// separately; STARK prover/verifier code derives quotient degrees from these
    /// raw symbolic bounds later. Override this when the split is known statically
    /// so a per-AIR bound can be sharp without redoing the symbolic pass.
    fn constraint_degree(&self) -> ConstraintDegrees
    where
        Self: Sized,
    {
        ConstraintDegrees::from_air::<F, EF, Self>(self)
    }
}

/// Symbolic constraint degree multiples, split by constraint kind.
///
/// `base` is the maximum degree multiple over the base-field constraints and
/// `ext` over the extension-field constraints (each `0` if the AIR has none of
/// that kind). Consumers that need a single value take [`max`](Self::max).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ConstraintDegrees {
    /// Max degree multiple over base-field constraints (`0` if there are none).
    pub base: usize,
    /// Max degree multiple over extension-field constraints (`0` if there are none).
    pub ext: usize,
}

impl ConstraintDegrees {
    /// Compute symbolic constraint degree multiples from an AIR.
    pub fn from_air<F, EF, A>(air: &A) -> Self
    where
        F: Field,
        A: LiftedAir<F, EF>,
    {
        let mut builder = SymbolicAirBuilder::<F>::new(air.air_layout());
        eval_air(air, &mut builder);

        let base = builder
            .base_constraints()
            .iter()
            .map(SymbolicExpression::degree_multiple)
            .max()
            .unwrap_or(0);
        let ext = builder
            .extension_constraints()
            .iter()
            .map(SymbolicExpressionExt::degree_multiple)
            .max()
            .unwrap_or(0);
        Self { base, ext }
    }

    /// The combined degree multiple: the larger of [`base`](Self::base) and
    /// [`ext`](Self::ext).
    pub fn max(&self) -> usize {
        self.base.max(self.ext)
    }
}

/// Symbolic constraint counts, split by constraint kind.
///
/// Soundness of the constraint-batching round scales with how many constraints are folded into the
/// composition polynomial, so a security estimate needs the count alongside
/// [`ConstraintDegrees`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ConstraintCounts {
    /// Number of base-field constraints.
    pub base: usize,
    /// Number of extension-field constraints.
    pub ext: usize,
}

impl ConstraintCounts {
    /// Compute symbolic constraint counts from an AIR.
    pub fn from_air<F, EF, A>(air: &A) -> Self
    where
        F: Field,
        A: LiftedAir<F, EF>,
    {
        let mut builder = SymbolicAirBuilder::<F>::new(air.air_layout());
        eval_air(air, &mut builder);

        Self {
            base: builder.base_constraints().len(),
            ext: builder.extension_constraints().len(),
        }
    }

    /// Total number of constraints folded into the composition polynomial.
    pub fn total(&self) -> usize {
        self.base + self.ext
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
/// by [`BaseAir::num_public_values`].
pub trait MultiAir<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// AIR type. Heterogeneous AIRs are expressed via caller-defined enum wrappers.
    type Air: LiftedAir<F, EF>;

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
