//! Debug helpers for lifted AIRs.
//!
//! Two flavours of helpers live here:
//!
//! - **Structural assertion** ([`assert_prover_setup`]) — a panic-based check over
//!   [`miden_lifted_air::debug::assert_multi_air_valid`]. Call it from tests / setup; the prover
//!   and verifier hot paths trust the AIR's structural contract.
//! - **Constraint checker** ([`check_constraints`]) — evaluates AIR constraints row-by-row on
//!   concrete trace values and panics on the first nonzero constraint. It derives deterministic
//!   debug challenges; it does not replay the prover transcript.

extern crate alloc;

use alloc::vec::Vec;

use miden_lifted_air::{
    AirBuilder, ExtensionBuilder, LiftedAir, MultiAir, PermutationAirBuilder, ProverStatement,
    RowWindow, debug::assert_multi_air_valid,
};
use p3_challenger::{CanObserve, CanSample};
use p3_field::{ExtensionField, Field};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::order::TraceOrder;

// ============================================================================
// Structural assertions (over miden_lifted_air::debug)
// ============================================================================

/// Assert the AIR's structural contract via [`assert_multi_air_valid`].
///
/// Only the *trusted* structural contract is asserted here. The AIR ↔ PCS
/// compatibility bound (`log_quotient_degree <= log_blowup`) is a validated
/// runtime input — prover and verifier surface it as
/// [`DomainError::ConstraintDegreeTooHigh`](crate::DomainError) — so it is not
/// re-checked here.
///
/// The preprocessed bundle's shape (tree presence, per-trace width, per-AIR
/// height) is validated at [`ProverInstance::new`](crate::ProverInstance::new)
/// construction time, so it is not re-checked here.
pub fn assert_prover_setup<F, EF, MA>(prover_statement: &ProverStatement<F, EF, MA>)
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    assert_multi_air_valid::<F, EF, MA>(prover_statement.statement().multi_air());
}

// ============================================================================
// Public API
// ============================================================================

/// Evaluate AIR constraints against concrete trace values and panic on failure.
///
/// Constraints are checked row-by-row using the trace + aux trace built by
/// [`ProverStatement`]. All AIRs see the same `air_inputs` from `statement`.
///
/// Derives auxiliary-trace challenges from the supplied challenger using only
/// statement-owned data plus the instance count and log trace heights. This is
/// a local constraint debugger: it intentionally skips protocol commitments
/// (including any preprocessed setup commitment), so sampled challenges need
/// not match a full proof transcript produced by
/// [`ProverInstance::prove`](crate::ProverInstance::prove).
///
/// # Panics
///
/// - If trace dimensions don't match their AIR
/// - If any constraint evaluates to nonzero on any row
pub fn check_constraints<F, EF, MA, Ch>(
    prover_statement: &ProverStatement<F, EF, MA>,
    mut challenger: Ch,
) where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
    Ch: CanObserve<F> + CanSample<F>,
{
    let statement = prover_statement.statement();
    let airs = statement.airs();
    let traces = prover_statement.traces();
    let air_inputs = statement.air_inputs();
    let aux_inputs = statement.aux_inputs();
    assert!(!airs.is_empty(), "no instances provided");
    assert_eq!(airs.len(), traces.len(), "airs and traces counts must match");

    // Seed deterministic debug challenges from statement/height observations only.
    // Do not observe setup/trace commitments or replay the prover transcript here.
    let trace_heights: Vec<usize> = traces.iter().map(Matrix::height).collect();
    let trace_order = TraceOrder::from_trace_heights::<F, EF, _>(airs, &trace_heights)
        .expect("ProverStatement::new should reject malformed heights");
    statement.observe(&mut challenger, trace_order.log_heights());
    trace_order.observe_shape::<F, _>(&mut challenger);
    let max_num_randomness = airs.iter().map(LiftedAir::num_randomness).max().unwrap_or(0);
    let challenges: Vec<EF> = (0..max_num_randomness)
        .map(|_| EF::from_basis_coefficients_fn(|_| challenger.sample()))
        .collect();

    let mut aux_traces = Vec::with_capacity(airs.len());
    let mut aux_values_per_air = Vec::with_capacity(airs.len());
    for (air, main) in airs.iter().zip(traces.iter()) {
        let num_randomness = air.num_randomness();
        let (aux_trace, aux_values) =
            air.build_aux_trace(main, air_inputs, aux_inputs, &challenges[..num_randomness]);
        aux_traces.push(aux_trace);
        aux_values_per_air.push(aux_values);
    }

    // Mirror the verifier's external-assertion check: the cross-AIR
    // interactions must hold for these aux values and public inputs. Each
    // assertion is a concrete value, so a zero-check is exact.
    let aux_views: Vec<&[EF]> = aux_values_per_air.iter().map(Vec::as_slice).collect();
    let assertions = statement
        .eval_external(&challenges, &aux_views, trace_order.log_heights())
        .expect("eval_external failed during check_constraints");
    for (k, assertion) in assertions.iter().enumerate() {
        assert_eq!(*assertion, EF::ZERO, "external assertion {k} is non-zero");
    }

    for (i, ((air, main), (aux_trace, aux_values))) in airs
        .iter()
        .zip(traces.iter())
        .zip(aux_traces.iter().zip(aux_values_per_air.iter()))
        .enumerate()
    {
        // `check_builder_shape` validates row-window widths per row, but aux trace
        // height is invisible to a single row window — check it here so a short aux
        // trace fails cleanly rather than via an opaque row-slice panic.
        assert_eq!(
            aux_trace.height(),
            main.height(),
            "instance {i}: aux trace height mismatch: expected {}, got {}",
            main.height(),
            aux_trace.height()
        );

        check_single_trace(air, main, aux_trace, aux_values, air_inputs, &challenges, i);
    }
}

/// Check constraints for one instance's traces row by row.
#[allow(clippy::too_many_arguments)]
fn check_single_trace<F, EF, A>(
    air: &A,
    main: &RowMajorMatrix<F>,
    aux_trace: &RowMajorMatrix<EF>,
    aux_values: &[EF],
    public_values: &[F],
    challenges: &[EF],
    instance_index: usize,
) where
    F: Field,
    EF: ExtensionField<F>,
    A: LiftedAir<F, EF>,
{
    let height = main.height();

    // Preprocessed matrix comes straight off the AIR (debug-only; this
    // re-materialises `BaseAir::preprocessed_trace`). Its height must match the main
    // trace; width is checked per row by `check_builder_shape`.
    let preprocessed = air.preprocessed_trace();
    if let Some(preproc) = &preprocessed {
        assert_eq!(
            preproc.height(),
            height,
            "instance {instance_index}: preprocessed trace height mismatch: expected {height}, got {}",
            preproc.height()
        );
    }

    let periodic_matrix = air.periodic_columns_matrix();
    for row in 0..height {
        let next_row = (row + 1) % height;

        // Main trace rows.
        let main_current = main.row_slice(row).unwrap();
        let main_next = main.row_slice(next_row).unwrap();

        // Aux trace rows.
        let aux_current = aux_trace.row_slice(row).unwrap();
        let aux_next = aux_trace.row_slice(next_row).unwrap();

        // Periodic values for this row via modulo indexing into the periodic table.
        let periodic_row = periodic_matrix.as_ref().map(|m| m.row_slice(row % m.height()).unwrap());
        let periodic_values: &[F] = periodic_row.as_deref().unwrap_or(&[]);

        // Preprocessed rows (empty window when the AIR declares none).
        let preprocessed_current = preprocessed.as_ref().map(|m| m.row_slice(row).unwrap());
        let preprocessed_next = preprocessed.as_ref().map(|m| m.row_slice(next_row).unwrap());

        let mut builder = DebugConstraintBuilder {
            main: RowWindow::from_two_rows(&main_current, &main_next),
            preprocessed: RowWindow::from_two_rows(
                preprocessed_current.as_deref().unwrap_or(&[]),
                preprocessed_next.as_deref().unwrap_or(&[]),
            ),
            permutation: RowWindow::from_two_rows(&aux_current, &aux_next),
            randomness: &challenges[..air.num_randomness()],
            public_values,
            periodic_values,
            permutation_values: aux_values,
            is_first_row: F::from_bool(row == 0),
            is_last_row: F::from_bool(row == height - 1),
            is_transition: F::from_bool(row != height - 1),
            instance_index,
            row_index: row,
        };

        #[cfg(debug_assertions)]
        miden_lifted_air::debug::check_builder_shape(air, &builder);

        air.eval(&mut builder);
    }
}

// ============================================================================
// DebugConstraintBuilder
// ============================================================================

/// Lightweight constraint builder that checks constraints against concrete trace values.
///
/// Evaluates constraints row-by-row and panics immediately on the first nonzero constraint.
/// Uses base field `F` for the main trace and extension field `EF` for the auxiliary
/// (permutation) trace, matching the actual field layout of lifted STARK traces.
struct DebugConstraintBuilder<'a, F: Field, EF: ExtensionField<F>> {
    main: RowWindow<'a, F>,
    preprocessed: RowWindow<'a, F>,
    permutation: RowWindow<'a, EF>,
    randomness: &'a [EF],
    public_values: &'a [F],
    periodic_values: &'a [F],
    permutation_values: &'a [EF],
    is_first_row: F,
    is_last_row: F,
    is_transition: F,
    instance_index: usize,
    row_index: usize,
}

impl<'a, F, EF> AirBuilder for DebugConstraintBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type F = F;
    type Expr = F;
    type Var = F;
    type PreprocessedWindow = RowWindow<'a, F>;
    type MainWindow = RowWindow<'a, F>;
    type PublicVar = F;
    type PeriodicVar = F;

    fn main(&self) -> Self::MainWindow {
        self.main
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row
    }

    fn is_transition(&self) -> Self::Expr {
        self.is_transition
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        assert_eq!(
            x.into(),
            F::ZERO,
            "constraint not satisfied at instance {}, row {}",
            self.instance_index,
            self.row_index
        );
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.periodic_values
    }
}

impl<F, EF> ExtensionBuilder for DebugConstraintBuilder<'_, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type EF = EF;
    type ExprEF = EF;
    type VarEF = EF;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        assert_eq!(
            x.into(),
            EF::ZERO,
            "ext constraint not satisfied at instance {}, row {}",
            self.instance_index,
            self.row_index
        );
    }
}

impl<'a, F, EF> PermutationAirBuilder for DebugConstraintBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type MP = RowWindow<'a, EF>;
    type RandomVar = EF;
    type PermutationVar = EF;

    fn permutation(&self) -> Self::MP {
        self.permutation
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.randomness
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        self.permutation_values
    }
}
