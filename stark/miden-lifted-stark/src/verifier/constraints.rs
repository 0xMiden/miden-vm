//! Constraint evaluation for the verifier.
//!
//! Provides [`ConstraintFolder`], a minimal EF-only folder evaluating the AIR's
//! constraints at a single OOD extension-field point.

use core::marker::PhantomData;

use miden_lifted_air::{
    AirBuilder, EmptyWindow, ExtensionBuilder, PeriodicAirBuilder, PermutationAirBuilder, RowWindow,
};
use p3_field::{ExtensionField, Field};

use crate::selectors::Selectors;

// ============================================================================
// ConstraintFolder
// ============================================================================

/// Minimal constraint folder for verifier OOD evaluation.
///
/// Implements the AIR builder traits needed to evaluate constraints at an out-of-domain
/// point. Uses the extension field throughout since the verifier only evaluates at a
/// single EF point (z).
///
/// The verifier folds constraints on the fly using Horner:
///
/// acc = acc·α + Cₖ(z).
///
/// This matches the prover's random linear combination
/// `Σₖ α^{K−1−k}·Cₖ(z)`, but is cheaper for a single-point evaluation.
/// The prover computes an equivalent fold over the whole quotient domain, optimized
/// with base-field SIMD where possible.
pub struct ConstraintFolder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    pub main: RowWindow<'a, EF>,
    pub aux: RowWindow<'a, EF>,
    pub randomness: &'a [EF],
    pub public_values: &'a [F],
    pub periodic_values: &'a [EF],
    pub permutation_values: &'a [EF],
    pub selectors: Selectors<EF>,
    pub alpha: EF,
    pub accumulator: EF,
    pub _phantom: PhantomData<F>,
}

impl<'a, F, EF> AirBuilder for ConstraintFolder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type F = F;
    type Expr = EF;
    type Var = EF;
    type PreprocessedWindow = EmptyWindow<EF>;
    type MainWindow = RowWindow<'a, EF>;
    type PublicVar = F;

    fn main(&self) -> Self::MainWindow {
        self.main
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        EmptyWindow::empty_ref()
    }

    fn is_first_row(&self) -> Self::Expr {
        self.selectors.is_first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.selectors.is_last_row
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        debug_assert_eq!(size, 2, "BUG: AIR uses window size {size}; only 2 supported");
        self.selectors.is_transition
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.accumulator = self.accumulator * self.alpha + x.into();
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl<'a, F, EF> ExtensionBuilder for ConstraintFolder<'a, F, EF>
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
        self.accumulator = self.accumulator * self.alpha + x.into();
    }
}

impl<'a, F, EF> PermutationAirBuilder for ConstraintFolder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type MP = RowWindow<'a, EF>;
    type RandomVar = EF;
    type PermutationVar = EF;

    fn permutation(&self) -> Self::MP {
        self.aux
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.randomness
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        self.permutation_values
    }
}

impl<'a, F, EF> PeriodicAirBuilder for ConstraintFolder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type PeriodicVar = EF;

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.periodic_values
    }
}
