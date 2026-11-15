//! Constraint evaluation for the verifier.
//!
//! Provides [`ConstraintFolder`], a minimal EF-only folder evaluating the AIR's
//! constraints at a single OOD extension-field point.

use core::marker::PhantomData;

use p3_field::{ExtensionField, Field};

use crate::{
    air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, RowWindow, native},
    selectors::Selectors,
};

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
pub(super) struct ConstraintFolder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    pub main: RowWindow<'a, EF>,
    pub preprocessed: RowWindow<'a, EF>,
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

impl<F: Field, EF: ExtensionField<F>> ConstraintFolder<'_, F, EF> {
    fn fold(&mut self, value: EF) {
        self.accumulator = self.accumulator * self.alpha + value;
    }
}

impl<F: Field, EF: ExtensionField<F>> native::LiftedAirBuilder for ConstraintFolder<'_, F, EF> {
    type F = F;
    type Expr = EF;
    type ExtExpr = EF;

    fn emit_base(&mut self, value: EF, _meta: native::ConstraintMeta<'_>) {
        self.fold(value);
    }

    fn emit_ext(&mut self, value: EF, _meta: native::ConstraintMeta<'_>) {
        self.fold(value);
    }
}

impl<'a, F, EF> AirBuilder for ConstraintFolder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type F = F;
    type Expr = EF;
    type Var = EF;
    type PreprocessedWindow = RowWindow<'a, EF>;
    type MainWindow = RowWindow<'a, EF>;
    type PublicVar = F;
    type PeriodicVar = EF;

    fn main(&self) -> Self::MainWindow {
        self.main
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed
    }

    fn is_first_row(&self) -> Self::Expr {
        self.selectors.is_first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.selectors.is_last_row
    }

    fn is_transition(&self) -> Self::Expr {
        self.selectors.is_transition
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.fold(x.into());
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.periodic_values
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
        self.fold(x.into());
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

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::testing::configs::{Felt, QuadFelt};

    fn folder(alpha: QuadFelt) -> ConstraintFolder<'static, Felt, QuadFelt> {
        ConstraintFolder {
            main: RowWindow::from_two_rows(&[], &[]),
            preprocessed: RowWindow::from_two_rows(&[], &[]),
            aux: RowWindow::from_two_rows(&[], &[]),
            randomness: &[],
            public_values: &[],
            periodic_values: &[],
            permutation_values: &[],
            selectors: Selectors {
                is_first_row: QuadFelt::ZERO,
                is_last_row: QuadFelt::ZERO,
                is_transition: QuadFelt::ZERO,
            },
            alpha,
            accumulator: QuadFelt::ZERO,
            _phantom: PhantomData,
        }
    }

    #[test]
    fn native_scalar_folder_keeps_zero_and_repeated_interleaved_emissions() {
        let alpha = QuadFelt::new([Felt::from_u32(7), Felt::from_u32(11)]);
        let first = QuadFelt::from_u32(13);
        let repeated = QuadFelt::new([Felt::from_u32(17), Felt::from_u32(19)]);
        let last = QuadFelt::from_u32(23);
        let mut legacy = folder(alpha);
        AirBuilder::assert_zero(&mut legacy, first);
        ExtensionBuilder::assert_zero_ext(&mut legacy, QuadFelt::ZERO);
        AirBuilder::assert_zero(&mut legacy, repeated);
        ExtensionBuilder::assert_zero_ext(&mut legacy, repeated);
        AirBuilder::assert_zero(&mut legacy, last);

        let mut native_folder = folder(alpha);
        native::LiftedAirBuilder::assert_zero(&mut native_folder, first);
        native::LiftedAirBuilder::assert_zero_ext(
            &mut native::LiftedAirBuilder::when(&mut native_folder, QuadFelt::ZERO),
            repeated,
        );
        native::LiftedAirBuilder::assert_zero(&mut native_folder, repeated);
        native::LiftedAirBuilder::assert_zero_ext(&mut native_folder, repeated);
        native::LiftedAirBuilder::assert_zero(&mut native_folder, last);

        // Five emissions assign descending powers 4 through 0, including the zero-gated emission.
        let expected =
            first * alpha.exp_u64(4) + repeated * alpha.square() + repeated * alpha + last;
        assert_eq!(legacy.accumulator, expected);
        assert_eq!(native_folder.accumulator, expected);
    }
}
