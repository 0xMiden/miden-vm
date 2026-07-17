//! SIMD-optimized constraint folder for prover evaluation.
//!
//! [`ProverConstraintFolder`] collects base and extension constraints during `air.eval()`,
//! then combines them via [`Self::finalize_constraints`] using decomposed alpha powers
//! and batched linear combinations.

use alloc::vec::Vec;
use core::marker::PhantomData;

use miden_lifted_air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, RowWindow};
use p3_field::{Algebra, BasedVectorSpace, ExtensionField, Field, PackedField};

use crate::selectors::Selectors;

/// Packed constraint folder for SIMD-optimized prover evaluation.
///
/// Uses packed types to evaluate constraints on multiple domain points simultaneously:
/// - `P`: Packed base field (e.g., `PackedGoldilocks`)
/// - `PE`: Packed extension field - must be `Algebra<EF> + Algebra<P> + BasedVectorSpace<P>`
///
/// Collects constraints during `air.eval()` into separate base/ext vectors, then
/// combines them in [`Self::finalize_constraints`] using decomposed alpha powers and
/// `Algebra::batched_linear_combination` for efficient SIMD accumulation.
///
/// # Type Parameters
/// - `F`: Base field scalar
/// - `EF`: Extension field scalar
/// - `P`: Packed base field (with `P::Scalar = F`)
/// - `PE`: Packed extension field (must implement appropriate algebra traits)
pub(super) struct ProverConstraintFolder<'a, F, EF, P, PE>
where
    F: Field,
    EF: ExtensionField<F>,
    P: PackedField<Scalar = F>,
    PE: Algebra<EF> + Algebra<P> + BasedVectorSpace<P> + Copy + Send + Sync,
{
    /// Main trace two-row window (packed base field)
    pub main: RowWindow<'a, P>,
    /// Preprocessed trace two-row window (packed base field); empty when the
    /// AIR declares no preprocessed columns.
    pub preprocessed: RowWindow<'a, P>,
    /// Aux/permutation trace two-row window (packed extension field)
    pub aux: RowWindow<'a, PE>,
    /// Randomness for aux trace (packed extension field)
    pub packed_randomness: &'a [PE],
    /// Public values (base field scalars)
    pub public_values: &'a [F],
    /// Periodic column values (packed base field)
    pub periodic_values: &'a [P],
    /// Permutation values (packed extension field)
    pub permutation_values: &'a [PE],
    /// Constraint selectors (packed base field)
    pub selectors: Selectors<P>,
    /// Base-field alpha powers, reordered to match base constraint emission order.
    /// `base_alpha_powers[d][j]` = d-th basis coefficient of alpha power for j-th base constraint.
    pub base_alpha_powers: &'a [Vec<F>],
    /// Extension-field alpha powers, reordered to match ext constraint emission order.
    pub ext_alpha_powers: &'a [EF],
    /// Current constraint index (debug-only bookkeeping)
    pub constraint_index: usize,
    /// Total expected constraint count (debug-only bookkeeping)
    pub constraint_count: usize,
    /// Collected base-field constraints for this row
    pub base_constraints: Vec<P>,
    /// Collected extension-field constraints for this row
    pub ext_constraints: Vec<PE>,
    pub _phantom: PhantomData<EF>,
}

impl<'a, F, EF, P, PE> ProverConstraintFolder<'a, F, EF, P, PE>
where
    F: Field,
    EF: ExtensionField<F>,
    P: PackedField<Scalar = F>,
    PE: Algebra<EF> + Algebra<P> + BasedVectorSpace<P> + Copy + Send + Sync,
{
    /// Combine all collected constraints with their pre-computed alpha powers.
    ///
    /// Base constraints use `Algebra::batched_linear_combination` per basis dimension,
    /// decomposing the extension-field multiply into D base-field SIMD dot products.
    /// Extension constraints use the same batched combination with scalar EF coefficients.
    ///
    /// We keep base and extension constraints separate because the base constraints can
    /// stay in the base field and use packed SIMD arithmetic. Decomposing EF powers of
    /// `alpha` into base-field coordinates turns the base-field fold into a small number
    /// of packed dot-products, avoiding repeated cross-field promotions.
    #[inline]
    pub fn finalize_constraints(self) -> PE {
        debug_assert_eq!(self.constraint_index, self.constraint_count);
        debug_assert_eq!(
            self.base_constraints.len(),
            self.base_alpha_powers.first().map_or(0, Vec::len)
        );
        debug_assert_eq!(self.ext_constraints.len(), self.ext_alpha_powers.len());

        // Base constraints: D independent base-field dot products
        let base = &self.base_constraints;
        let base_powers = self.base_alpha_powers;
        let acc = PE::from_basis_coefficients_fn(|d| {
            P::batched_linear_combination(base, &base_powers[d])
        });

        // Extension constraints: EF-coefficient dot product
        acc + PE::batched_linear_combination(&self.ext_constraints, self.ext_alpha_powers)
    }
}

impl<'a, F, EF, P, PE> AirBuilder for ProverConstraintFolder<'a, F, EF, P, PE>
where
    F: Field,
    EF: ExtensionField<F>,
    P: PackedField<Scalar = F>,
    PE: Algebra<EF> + Algebra<P> + BasedVectorSpace<P> + Copy + Send + Sync,
{
    type F = F;
    type Expr = P;
    type Var = P;
    type PreprocessedWindow = RowWindow<'a, P>;
    type MainWindow = RowWindow<'a, P>;
    type PublicVar = F;
    type PeriodicVar = P;

    #[inline]
    fn main(&self) -> Self::MainWindow {
        self.main
    }

    #[inline]
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed
    }

    #[inline]
    fn is_first_row(&self) -> Self::Expr {
        self.selectors.is_first_row
    }

    #[inline]
    fn is_last_row(&self) -> Self::Expr {
        self.selectors.is_last_row
    }

    #[inline]
    fn is_transition(&self) -> Self::Expr {
        self.selectors.is_transition
    }

    #[inline]
    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.base_constraints.push(x.into());
        self.constraint_index += 1;
    }

    #[inline]
    fn assert_zeros<const N: usize, I: Into<Self::Expr>>(&mut self, array: [I; N]) {
        let expr_array = array.map(Into::into);
        self.base_constraints.extend(expr_array);
        self.constraint_index += N;
    }

    #[inline]
    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }

    #[inline]
    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.periodic_values
    }
}

impl<'a, F, EF, P, PE> ExtensionBuilder for ProverConstraintFolder<'a, F, EF, P, PE>
where
    F: Field,
    EF: ExtensionField<F>,
    P: PackedField<Scalar = F>,
    PE: Algebra<EF> + Algebra<P> + BasedVectorSpace<P> + Copy + Send + Sync,
{
    type EF = EF;
    type ExprEF = PE;
    type VarEF = PE;

    #[inline]
    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.ext_constraints.push(x.into());
        self.constraint_index += 1;
    }
}

impl<'a, F, EF, P, PE> PermutationAirBuilder for ProverConstraintFolder<'a, F, EF, P, PE>
where
    F: Field,
    EF: ExtensionField<F>,
    P: PackedField<Scalar = F>,
    PE: Algebra<EF> + Algebra<P> + BasedVectorSpace<P> + Copy + Send + Sync,
{
    type MP = RowWindow<'a, PE>;
    type RandomVar = PE;
    type PermutationVar = PE;

    #[inline]
    fn permutation(&self) -> Self::MP {
        self.aux
    }

    #[inline]
    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.packed_randomness
    }

    #[inline]
    fn permutation_values(&self) -> &[Self::PermutationVar] {
        self.permutation_values
    }
}
