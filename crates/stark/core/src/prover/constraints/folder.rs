//! SIMD-optimized constraint folder for prover evaluation.
//!
//! [`ProverConstraintFolder`] collects base and extension constraints during `air.eval()`,
//! then combines them via [`Self::finalize_constraints`] using decomposed alpha powers
//! and batched linear combinations.

use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_field::{Algebra, BasedVectorSpace, ExtensionField, Field, PackedField};

use crate::air;

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
    #[inline]
    fn record_base(&mut self, value: P) {
        self.base_constraints.push(value);
        self.constraint_index += 1;
    }

    #[inline]
    fn record_bases<const N: usize>(&mut self, values: [P; N]) {
        self.base_constraints.extend(values);
        self.constraint_index += N;
    }

    #[inline]
    fn record_ext(&mut self, value: PE) {
        self.ext_constraints.push(value);
        self.constraint_index += 1;
    }

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

impl<F, EF, P, PE> air::LiftedAirBuilder for ProverConstraintFolder<'_, F, EF, P, PE>
where
    F: Field,
    EF: ExtensionField<F>,
    P: PackedField<Scalar = F>,
    PE: Algebra<EF> + Algebra<P> + BasedVectorSpace<P> + Copy + Send + Sync,
{
    type F = F;
    type Expr = P;
    type ExtExpr = PE;

    #[inline]
    fn emit_base(&mut self, value: P, _meta: air::ConstraintMeta<'_>) {
        self.record_base(value);
    }

    #[inline]
    fn emit_ext(&mut self, value: PE, _meta: air::ConstraintMeta<'_>) {
        self.record_ext(value);
    }

    #[inline]
    fn assert_zeros<const N: usize, I: Into<P>>(&mut self, values: [I; N]) {
        self.record_bases(values.map(Into::into));
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_field::{PackedValue, PrimeCharacteristicRing};

    use super::*;
    use crate::testing::configs::{Felt, PackedFelt, PackedQuadFelt, QuadFelt};

    type Folder<'a> = ProverConstraintFolder<'a, Felt, QuadFelt, PackedFelt, PackedQuadFelt>;

    fn folder<'a>(base: &'a [Vec<Felt>], ext: &'a [QuadFelt]) -> Folder<'a> {
        // Evaluation borrows its frame and uniform inputs separately from this assertion sink.
        ProverConstraintFolder {
            base_alpha_powers: base,
            ext_alpha_powers: ext,
            constraint_index: 0,
            constraint_count: base.first().map_or(0, Vec::len) + ext.len(),
            base_constraints: Vec::new(),
            ext_constraints: Vec::new(),
            _phantom: PhantomData,
        }
    }

    fn pack_extension(value: impl Fn(usize) -> QuadFelt) -> PackedQuadFelt {
        <PackedQuadFelt as BasedVectorSpace<PackedFelt>>::from_basis_coefficients_fn(
            |coefficient| {
                PackedFelt::from_fn(|lane| value(lane).as_basis_coefficients_slice()[coefficient])
            },
        )
    }

    fn extension_lane(value: PackedQuadFelt, lane: usize) -> QuadFelt {
        let coefficients: &[PackedFelt] = value.as_basis_coefficients_slice();
        QuadFelt::from_basis_coefficients_fn(|coefficient| {
            coefficients[coefficient].as_slice()[lane]
        })
    }

    #[test]
    fn native_packed_fold_preserves_interleaved_classes_zeros_and_repeats() {
        let layout = air::ConstraintLayout::new(vec![1, 2, 4, 6], vec![0, 3, 5, 7]).unwrap();
        let alpha = QuadFelt::new([Felt::from_u64(17), Felt::from_u64(19)]);
        let (base_weights, ext_weights) = layout.decompose_alpha(alpha);
        let base0 = PackedFelt::from_fn(|lane| Felt::from_usize(3 + lane));
        let base1 = PackedFelt::from_fn(|lane| Felt::from_usize(7 + 3 * lane));
        let ext0 = pack_extension(|lane| {
            QuadFelt::new([Felt::from_usize(2 + lane), Felt::from_usize(5 + 2 * lane)])
        });
        let ext1 = pack_extension(|lane| {
            QuadFelt::new([Felt::from_usize(11 + lane), Felt::from_usize(13 + lane)])
        });
        let mut native = folder(&base_weights, &ext_weights);
        air::LiftedAirBuilder::emit_ext(&mut native, ext0, air::ConstraintMeta::default());
        air::LiftedAirBuilder::assert_zeros(&mut native, [base0, PackedFelt::ZERO]);
        air::LiftedAirBuilder::emit_ext(&mut native, ext0, air::ConstraintMeta::default());
        air::LiftedAirBuilder::emit_base(&mut native, base0, air::ConstraintMeta::default());
        air::LiftedAirBuilder::emit_ext(
            &mut native,
            PackedQuadFelt::ZERO,
            air::ConstraintMeta::default(),
        );
        air::LiftedAirBuilder::emit_base(&mut native, base1, air::ConstraintMeta::default());
        air::LiftedAirBuilder::emit_ext(&mut native, ext1, air::ConstraintMeta::default());

        assert_eq!(native.constraint_index, 8);
        assert_eq!(native.base_constraints.len(), 4);
        assert_eq!(native.ext_constraints.len(), 4);
        let actual = native.finalize_constraints();
        for lane in 0..PackedFelt::WIDTH {
            // Global weights descend from alpha^7 to alpha^0; zeros still occupy their slots.
            let expected = extension_lane(ext0, lane) * (alpha.exp_u64(7) + alpha.exp_u64(4))
                + QuadFelt::from(base0.as_slice()[lane]) * (alpha.exp_u64(6) + alpha.exp_u64(3))
                + QuadFelt::from(base1.as_slice()[lane]) * alpha
                + extension_lane(ext1, lane);
            assert_eq!(extension_lane(actual, lane), expected);
        }
    }
}
