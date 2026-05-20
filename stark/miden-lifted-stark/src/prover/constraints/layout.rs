//! Constraint layout: maps global constraint indices to base/ext streams.
//!
//! Also provides [`ConstraintLayoutBuilder`], a lightweight AIR builder that discovers
//! constraint types without building symbolic expression trees.

use alloc::{vec, vec::Vec};

use miden_lifted_air::{
    AirBuilder, EmptyWindow, ExtensionBuilder, LiftedAir, PeriodicAirBuilder,
    PermutationAirBuilder,
    symbolic::{AirLayout, ConstraintLayout},
};
use p3_field::{ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;
use tracing::instrument;

// ============================================================================
// Constraint Layout Builder (lightweight, no symbolic expressions)
// ============================================================================

/// Evaluate the AIR on a lightweight builder and return the constraint layout.
///
/// Runs `air.eval()` on a [`ConstraintLayoutBuilder`] that uses concrete field zeros
/// for all variables. This discovers which constraints are base-field vs extension-field
/// without building symbolic expression trees — only the emission order matters.
#[instrument(name = "compute constraint layout", skip_all, level = "debug")]
pub fn get_constraint_layout<F, EF, A>(air: &A) -> ConstraintLayout
where
    F: Field,
    EF: ExtensionField<F>,
    A: LiftedAir<F, EF>,
{
    let mut builder = ConstraintLayoutBuilder::<F>::new(air.air_layout());
    #[cfg(debug_assertions)]
    miden_lifted_air::debug::check_builder_shape(0, air, &builder);
    air.eval(&mut builder);
    builder.into_layout()
}

/// Lightweight AIR builder that only tracks constraint types (base vs extension).
///
/// Uses concrete field zeros for all variables — no symbolic expression trees, no degree
/// tracking, no `Arc` allocations. Builds a [`ConstraintLayout`] directly by recording
/// which `assert_*` method is called for each constraint.
///
/// Uses `RowMajorMatrix<F>` as `MainWindow` because the builder owns its trace data.
/// `RowWindow` cannot be used here — it borrows, but the associated type can't
/// capture the `&self` lifetime from `main()`.
struct ConstraintLayoutBuilder<F: Field> {
    main: RowMajorMatrix<F>,
    public_values: Vec<F>,
    periodic_values: Vec<F>,
    permutation: RowMajorMatrix<F>,
    permutation_challenges: Vec<F>,
    permutation_values: Vec<F>,
    layout: ConstraintLayout,
    constraint_count: usize,
}

impl<F: Field> ConstraintLayoutBuilder<F> {
    fn new(layout: AirLayout) -> Self {
        let AirLayout {
            main_width,
            num_public_values,
            permutation_width,
            num_permutation_challenges,
            num_permutation_values,
            num_periodic_columns,
            ..
        } = layout;
        Self {
            main: RowMajorMatrix::new(vec![F::ZERO; 2 * main_width], main_width),
            public_values: vec![F::ZERO; num_public_values],
            periodic_values: vec![F::ZERO; num_periodic_columns],
            permutation: RowMajorMatrix::new(
                vec![F::ZERO; 2 * permutation_width],
                permutation_width,
            ),
            permutation_challenges: vec![F::ZERO; num_permutation_challenges],
            permutation_values: vec![F::ZERO; num_permutation_values],
            layout: ConstraintLayout::default(),
            constraint_count: 0,
        }
    }

    fn into_layout(self) -> ConstraintLayout {
        self.layout
    }
}

impl<F: Field> AirBuilder for ConstraintLayoutBuilder<F> {
    type F = F;
    type Expr = F;
    type Var = F;
    type PreprocessedWindow = EmptyWindow<F>;
    type MainWindow = RowMajorMatrix<F>;
    type PublicVar = F;

    fn main(&self) -> Self::MainWindow {
        self.main.clone()
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        EmptyWindow::empty_ref()
    }

    fn is_first_row(&self) -> Self::Expr {
        F::ZERO
    }

    fn is_last_row(&self) -> Self::Expr {
        F::ZERO
    }

    fn is_transition_window(&self, _size: usize) -> Self::Expr {
        F::ZERO
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, _x: I) {
        self.layout.base_indices.push(self.constraint_count);
        self.constraint_count += 1;
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        &self.public_values
    }
}

impl<F: Field> ExtensionBuilder for ConstraintLayoutBuilder<F> {
    type EF = F;
    type ExprEF = F;
    type VarEF = F;

    fn assert_zero_ext<I>(&mut self, _x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.layout.ext_indices.push(self.constraint_count);
        self.constraint_count += 1;
    }
}

impl<F: Field> PermutationAirBuilder for ConstraintLayoutBuilder<F> {
    type MP = RowMajorMatrix<F>;
    type RandomVar = F;
    type PermutationVar = F;

    fn permutation(&self) -> Self::MP {
        self.permutation.clone()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        &self.permutation_challenges
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        &self.permutation_values
    }
}

impl<F: Field> PeriodicAirBuilder for ConstraintLayoutBuilder<F> {
    type PeriodicVar = F;

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        &self.periodic_values
    }
}
