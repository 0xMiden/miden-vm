//! Debug helpers for lifted AIRs.
//!
//! Two flavours of helpers live here:
//!
//! - **Structural assertions** ([`assert_airs_valid`], [`assert_valid`], [`assert_prover_valid`],
//!   [`assert_compatible`], [`assert_prover_setup`], [`assert_aux_traces_shape`]) — thin wrappers
//!   over [`miden_lifted_air::debug`] and [`crate::setup::validate_compatible`] that panic with a
//!   `BUG:` prefix on contract violation. Call them from tests / setup; the prover and verifier hot
//!   paths trust their inputs.
//! - **Constraint checker** ([`check_constraints`]) — evaluates the AIR constraints row-by-row on
//!   concrete trace values and panics on the first nonzero constraint. Avoids the full STARK
//!   pipeline so failures surface immediately.

extern crate alloc;

use alloc::vec::Vec;

use miden_lifted_air::{
    AirBuilder, BaseAir, EmptyWindow, ExtensionBuilder, Instance, LiftedAir, PeriodicAirBuilder,
    PermutationAirBuilder, RowWindow,
};
use p3_challenger::{CanObserve, CanSample};
use p3_field::{ExtensionField, Field};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{ProverInstance, pcs::params::PcsParams, setup::validate_compatible};

// ============================================================================
// Structural assertions (thin wrappers over miden_lifted_air::debug + setup)
// ============================================================================

/// Assert every AIR in `airs` satisfies the structural contract.
pub fn assert_airs_valid<F, EF, A>(airs: &[&A])
where
    F: Field,
    EF: ExtensionField<F>,
    A: LiftedAir<F, EF>,
{
    miden_lifted_air::debug::assert_airs_valid::<F, EF, A>(airs);
}

/// Assert `instance` is valid: runtime instance contract + AIR structural
/// contract.
pub fn assert_valid<F, EF, I>(instance: &I)
where
    F: Field,
    EF: ExtensionField<F>,
    I: Instance<F, EF>,
{
    miden_lifted_air::debug::assert_valid::<F, EF, I>(instance);
}

/// Prover-side analogue of [`assert_valid`]: validates trace shape too.
pub fn assert_prover_valid<F, EF, P>(pi: &P)
where
    F: Field,
    EF: ExtensionField<F>,
    P: ProverInstance<F, EF>,
{
    miden_lifted_air::debug::assert_prover_valid::<F, EF, P>(pi);
}

/// Assert per-AIR `log_quotient_degree <= params.log_blowup()`.
pub fn assert_compatible<F, EF, A>(airs: &[&A], params: &PcsParams)
where
    F: Field,
    EF: ExtensionField<F>,
    A: LiftedAir<F, EF>,
{
    validate_compatible::<F, EF, A>(airs, params).expect("BUG: AIR ↔ PCS compatibility");
}

/// One-shot prover-setup check: bundles [`assert_prover_valid`] and
/// [`assert_compatible`].
///
/// TODO(adr1anh/preprocessed): also call `assert_preprocessed(pi)` once the
/// preprocessed branch lands.
pub fn assert_prover_setup<F, EF, P>(pi: &P, params: &PcsParams)
where
    F: Field,
    EF: ExtensionField<F>,
    P: ProverInstance<F, EF>,
{
    assert_prover_valid::<F, EF, P>(pi);
    assert_compatible::<F, EF, <P::Instance as Instance<F, EF>>::Air>(pi.instance().airs(), params);
}

/// Drive [`ProverInstance::build_aux_traces`] and assert the returned
/// shapes match the AIR contract.
///
/// This contract is **trusted** by [`crate::prover::prove`] — the prover
/// will silently consume malformed aux traces and panic deep inside the
/// LDE pipeline (or produce an unsound proof). Call this helper from
/// tests to surface the contract violation up-front.
///
/// Fiat-Shamir seeding mirrors [`check_constraints`] so the returned aux
/// values match what `prove` would derive for the same instance.
pub fn assert_aux_traces_shape<F, EF, P, Ch>(prover_instance: &P, mut challenger: Ch)
where
    F: Field,
    EF: ExtensionField<F>,
    P: ProverInstance<F, EF>,
    Ch: CanObserve<F> + CanSample<F>,
{
    let instance = prover_instance.instance();
    let airs = instance.airs();
    let traces = prover_instance.traces();
    assert_eq!(
        airs.len(),
        traces.len(),
        "BUG: airs.len() = {} but traces.len() = {}",
        airs.len(),
        traces.len(),
    );

    let log_heights: Vec<u8> = traces.iter().map(|t| log_height(t.height())).collect();
    instance.observe(&mut challenger, &log_heights);
    let max_num_randomness = airs.iter().map(|a| a.num_randomness()).max().unwrap_or(0);
    let challenges: Vec<EF> = (0..max_num_randomness)
        .map(|_| EF::from_basis_coefficients_fn(|_| challenger.sample()))
        .collect();

    let (aux_traces, aux_values) = prover_instance.build_aux_traces(&challenges);
    assert_eq!(
        aux_traces.len(),
        airs.len(),
        "BUG: build_aux_traces returned {} aux traces, expected {}",
        aux_traces.len(),
        airs.len(),
    );
    assert_eq!(
        aux_values.len(),
        airs.len(),
        "BUG: build_aux_traces returned {} aux value vectors, expected {}",
        aux_values.len(),
        airs.len(),
    );

    for (i, ((air, main), (aux_trace, aux_vals))) in airs
        .iter()
        .copied()
        .zip(traces.iter().copied())
        .zip(aux_traces.iter().zip(aux_values.iter()))
        .enumerate()
    {
        assert_eq!(
            aux_trace.width(),
            air.aux_width(),
            "BUG: AIR {i}: aux trace width = {}, but air.aux_width() = {}",
            aux_trace.width(),
            air.aux_width(),
        );
        assert_eq!(
            aux_trace.height(),
            main.height(),
            "BUG: AIR {i}: aux trace height = {}, but main trace height = {}",
            aux_trace.height(),
            main.height(),
        );
        assert_eq!(
            aux_vals.len(),
            air.num_aux_values(),
            "BUG: AIR {i}: aux_values.len() = {}, but air.num_aux_values() = {}",
            aux_vals.len(),
            air.num_aux_values(),
        );
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Evaluate AIR constraints against concrete trace values and panic on failure.
///
/// Constraints are checked row-by-row using the trace + aux trace built by
/// [`ProverInstance`]. All AIRs see the same `air_inputs` from `instance`.
///
/// Derives auxiliary-trace challenges from the supplied challenger by
/// observing the instance first, mirroring how the prover's challenger is
/// seeded — so tests don't need to keep a separate RNG handle in sync.
///
/// # Panics
///
/// - If trace dimensions don't match their AIR
/// - If any constraint evaluates to nonzero on any row
pub fn check_constraints<F, EF, P, Ch>(prover_instance: &P, mut challenger: Ch)
where
    F: Field,
    EF: ExtensionField<F>,
    P: ProverInstance<F, EF>,
    Ch: CanObserve<F> + CanSample<F>,
{
    let instance = prover_instance.instance();
    let airs = instance.airs();
    let traces = prover_instance.traces();
    let air_inputs = instance.air_inputs();
    assert!(!airs.is_empty(), "no instances provided");
    assert_eq!(airs.len(), traces.len(), "airs and traces counts must match");

    // Mirror the prover's Fiat-Shamir seeding so challenges line up with what
    // `prove` would produce for the same instance.
    let log_heights: Vec<u8> = traces.iter().map(|t| log_height(t.height())).collect();
    instance.observe(&mut challenger, &log_heights);
    let max_num_randomness = airs.iter().map(|a| a.num_randomness()).max().unwrap_or(0);
    let challenges: Vec<EF> = (0..max_num_randomness)
        .map(|_| EF::from_basis_coefficients_fn(|_| challenger.sample()))
        .collect();

    let (aux_traces, aux_values_per_air) = prover_instance.build_aux_traces(&challenges);
    assert_eq!(aux_traces.len(), airs.len(), "build_aux_traces returned wrong number of traces");
    assert_eq!(
        aux_values_per_air.len(),
        airs.len(),
        "build_aux_traces returned wrong number of aux values"
    );

    for (i, ((air, main), (aux_trace, aux_values))) in airs
        .iter()
        .copied()
        .zip(traces.iter().copied())
        .zip(aux_traces.iter().zip(aux_values_per_air.iter()))
        .enumerate()
    {
        let height = main.height();
        assert!(
            height.is_power_of_two(),
            "instance {i}: trace height {height} is not a power of two"
        );
        assert_eq!(
            main.width,
            air.width(),
            "instance {i}: main trace width mismatch: expected {}, got {}",
            air.width(),
            main.width
        );
        assert_eq!(
            air_inputs.len(),
            air.num_public_values(),
            "instance {i}: public values length mismatch: expected {}, got {}",
            air.num_public_values(),
            air_inputs.len()
        );
        assert_eq!(
            aux_trace.height(),
            height,
            "instance {i}: aux trace height mismatch: expected {height}, got {}",
            aux_trace.height()
        );
        assert_eq!(
            aux_trace.width,
            air.aux_width(),
            "instance {i}: aux trace width mismatch: expected {}, got {}",
            air.aux_width(),
            aux_trace.width
        );
        assert_eq!(
            aux_values.len(),
            air.num_aux_values(),
            "instance {i}: aux values count mismatch: expected {}, got {}",
            air.num_aux_values(),
            aux_values.len()
        );

        check_single_trace(air, main, aux_trace, aux_values, air_inputs, &challenges, i);
    }
}

fn log_height(h: usize) -> u8 {
    assert!(h.is_power_of_two(), "trace height {h} is not a power of two");
    h.trailing_zeros() as u8
}

/// Check constraints for one instance's traces row by row.
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

        let mut builder = DebugConstraintBuilder {
            main: RowWindow::from_two_rows(&main_current, &main_next),
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

        debug_assert!(air.is_valid_builder(&builder).is_ok());

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
    type PreprocessedWindow = EmptyWindow<F>;
    type MainWindow = RowWindow<'a, F>;
    type PublicVar = F;

    fn main(&self) -> Self::MainWindow {
        self.main
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        EmptyWindow::empty_ref()
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert!(size <= 2, "only two-row windows are supported, got {size}");
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

impl<F, EF> PeriodicAirBuilder for DebugConstraintBuilder<'_, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type PeriodicVar = F;

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.periodic_values
    }
}
