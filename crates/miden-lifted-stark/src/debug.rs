//! Debug constraint checker for lifted AIRs.
//!
//! Evaluates constraints row-by-row on concrete trace values and panics if any constraint
//! is nonzero. This avoids the full STARK pipeline (DFT, commitment, FRI) and provides
//! immediate feedback on constraint violations during development.
//!
//! # Usage
//!
//! ```ignore
//! use miden_lifted_air::AirWitness;
//!
//! // Single instance
//! let witness = AirWitness::new(&trace, &public_values, &[]);
//! check_constraints(&air, &witness, &aux_builder, &challenges);
//!
//! // Multiple instances (ascending height order)
//! check_constraints_multi(
//!     &[(&air_a, witness_a, &builder_a), (&air_b, witness_b, &builder_b)],
//!     &challenges,
//! );
//! ```

use miden_lifted_air::{
    AirBuilder, AirWitness, AuxBuilder, EmptyWindow, ExtensionBuilder, LiftedAir,
    PeriodicAirBuilder, PermutationAirBuilder, RowWindow,
};
use p3_field::{ExtensionField, Field};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

// ============================================================================
// Public API
// ============================================================================

/// Evaluate every AIR constraint against a concrete trace and panic on failure.
///
/// Convenience wrapper around [`check_constraints_multi`] for a single instance.
///
/// # Panics
///
/// - If the AIR fails validation
/// - If trace dimensions don't match the AIR
/// - If challenges are insufficient
/// - If any constraint evaluates to nonzero on any row
pub fn check_constraints<F, EF, A, B>(
    air: &A,
    witness: AirWitness<'_, F>,
    aux_builder: &B,
    challenges: &[EF],
) where
    F: Field,
    EF: ExtensionField<F>,
    A: LiftedAir<F, EF>,
    B: AuxBuilder<F, EF>,
{
    check_constraints_multi(&[(air, witness, aux_builder)], challenges);
}

/// Evaluate constraints for multiple AIR instances and panic on failure.
///
/// Each instance is a tuple of `(air, witness, aux_builder)`. Instances must be in
/// ascending trace height order, matching the protocol's multi-trace convention.
///
/// Builds the auxiliary trace for each instance and checks constraints row by row.
/// Uses shared challenges across all instances (caller samples from RNG in test code).
///
/// # Panics
///
/// - If any AIR fails validation
/// - If trace dimensions don't match their AIR
/// - If instances are not in ascending height order
/// - If challenges are insufficient
/// - If any constraint evaluates to nonzero on any row
pub fn check_constraints_multi<F, EF, A, B>(
    instances: &[(&A, AirWitness<'_, F>, &B)],
    challenges: &[EF],
) where
    F: Field,
    EF: ExtensionField<F>,
    A: LiftedAir<F, EF>,
    B: AuxBuilder<F, EF>,
{
    assert!(!instances.is_empty(), "no instances provided");

    let mut prev_height = 0usize;

    for (i, &(air, ref witness, aux_builder)) in instances.iter().enumerate() {
        air.validate()
            .unwrap_or_else(|e| panic!("AIR validation failed for instance {i}: {e}"));

        let main = witness.trace;
        let height = main.height();

        // Ascending height order.
        assert!(
            height >= prev_height,
            "instances not in ascending height order: instance {i} has height {height} \
             but previous had {prev_height}"
        );
        prev_height = height;

        // Main trace dimensions.
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
            witness.public_values.len(),
            air.num_public_values(),
            "instance {i}: public values length mismatch: expected {}, got {}",
            air.num_public_values(),
            witness.public_values.len()
        );
        assert_eq!(
            witness.var_len_public_inputs.len(),
            air.num_var_len_public_inputs(),
            "instance {i}: var-len public inputs count mismatch: expected {}, got {}",
            air.num_var_len_public_inputs(),
            witness.var_len_public_inputs.len()
        );
        assert!(
            challenges.len() >= air.num_randomness(),
            "instance {i}: not enough challenges: need {}, got {}",
            air.num_randomness(),
            challenges.len()
        );

        // Build auxiliary trace.
        let (aux_trace, aux_values) =
            aux_builder.build_aux_trace(main, &challenges[..air.num_randomness()]);

        // Auxiliary trace dimensions.
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

        check_single_trace(
            air,
            main,
            &aux_trace,
            &aux_values,
            witness.public_values,
            challenges,
            i,
        );
    }
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
