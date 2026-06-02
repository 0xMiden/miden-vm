//! FRI folding via polynomial interpolation.
//!
//! FRI (Fast Reed-Solomon IOP of Proximity) folds evaluations on a coset into a
//! lower-degree polynomial value parameterized by a challenge `β`. Each row fold
//! returns the folded value `g(s^r)` for its coset `s·⟨ω_r⟩` (and when `deg f < r`,
//! this equals `f(β)`). This module provides a struct-based abstraction for FRI
//! folding at different arities.
//!
//! ## Arity
//!
//! The **arity** determines how many evaluations are folded together in each round:
//! - **Arity 2**: Fold pairs `{f(s), f(-s)}` using even-odd decomposition
//! - **Arity 4**: Fold quadruples `{f(s), f(-s), f(is), f(-is)}` using inverse FFT
//! - **Arity 8**: Fold octuples using size-8 inverse FFT
//!
//! Higher arity reduces the number of FRI rounds but increases per-round work.

mod arity2;
mod arity4;
mod arity8;

use alloc::vec::Vec;

use p3_field::{ExtensionField, PackedValue, TwoAdicField};
use p3_matrix::{Matrix, dense::RowMajorMatrixView};
use p3_maybe_rayon::prelude::*;

use crate::util::packing::PackedFieldExtensionExt;

/// FRI folding strategy.
///
/// This struct encapsulates different folding arities (2, 4, 8).
#[derive(Clone, Copy, Debug)]
pub struct FriFold {
    pub(crate) log_arity: u8,
}

impl FriFold {
    /// Create a new folder for a supported log-arity (currently only 1, 2, 3).
    pub const fn new(log_arity: u8) -> Option<Self> {
        if log_arity == 1 || log_arity == 2 || log_arity == 3 {
            Some(Self { log_arity })
        } else {
            None
        }
    }

    #[inline]
    pub const fn arity(self) -> usize {
        1 << self.log_arity as usize
    }

    #[inline]
    pub const fn log_arity(self) -> u8 {
        self.log_arity
    }

    /// Fold evaluations from a slice of extension field elements.
    ///
    /// The slice must have exactly `arity()` elements.
    /// Used by the verifier in scalar mode.
    ///
    /// Folding is the core FRI step: it turns `arity` evaluations of `f` on a coset
    /// `s·⟨ω⟩` into a single evaluation of a new polynomial `g` on the folded domain.
    ///
    /// Conceptually, write `f(X)` as `Σⱼ Xʲ·fⱼ(X^arity)`. The fold interpolates the
    /// `fⱼ` values from the row (an iFFT on the coset) and then takes a random linear
    /// combination with challenge `β` to obtain `g(s^arity)`. The resulting `g` has
    /// degree reduced by a factor of `arity`. If `deg(f) < arity`, folding recovers
    /// `f(β)` exactly.
    #[inline]
    pub fn fold_evals<F: TwoAdicField, EF: ExtensionField<F>>(
        self,
        evals: &[EF],
        s_inv: F,
        beta: EF,
    ) -> EF {
        match self.log_arity {
            1 => arity2::fold_evals::<F, F, EF>(evals, s_inv, beta),
            2 => arity4::fold_evals::<F, F, EF>(evals, s_inv, beta),
            3 => arity8::fold_evals::<F, F, EF>(evals, s_inv, beta),
            _ => unreachable!("unsupported arity"),
        }
    }

    /// Packed (SIMD) version of `fold_evals`.
    #[inline]
    fn fold_evals_packed<F: TwoAdicField, EF: ExtensionField<F>>(
        self,
        evals: &[EF::ExtensionPacking],
        s_inv: F::Packing,
        beta: EF,
    ) -> EF::ExtensionPacking {
        let beta_packed: EF::ExtensionPacking = beta.into();
        match self.log_arity {
            1 => {
                arity2::fold_evals::<F, F::Packing, EF::ExtensionPacking>(evals, s_inv, beta_packed)
            },
            2 => {
                arity4::fold_evals::<F, F::Packing, EF::ExtensionPacking>(evals, s_inv, beta_packed)
            },
            3 => {
                arity8::fold_evals::<F, F::Packing, EF::ExtensionPacking>(evals, s_inv, beta_packed)
            },
            _ => unreachable!("unsupported arity"),
        }
    }

    /// Fold a matrix of coset evaluations using the challenge `beta`.
    ///
    /// Each row contains evaluations on a coset `s·⟨ω⟩`. Returns folded
    /// evaluations, one per row, maintaining bit-reversed order.
    ///
    /// Automatically dispatches to scalar or packed implementation based on matrix size.
    pub fn fold_matrix<F: TwoAdicField, EF: ExtensionField<F>>(
        self,
        input: RowMajorMatrixView<'_, EF>,
        s_invs: &[F],
        beta: EF,
    ) -> Vec<EF> {
        let width = F::Packing::WIDTH;
        if input.height() < width || width == 1 {
            // Scalar path
            let arity = self.arity();
            assert_eq!(input.width, arity);
            input
                .values
                .par_chunks(arity)
                .zip(s_invs.par_iter())
                .map(|(evals, &s_inv)| self.fold_evals(evals, s_inv, beta))
                .collect()
        } else {
            match self.log_arity {
                1 => self.fold_matrix_packed_impl::<2, F, EF>(input, s_invs, beta),
                2 => self.fold_matrix_packed_impl::<4, F, EF>(input, s_invs, beta),
                3 => self.fold_matrix_packed_impl::<8, F, EF>(input, s_invs, beta),
                _ => unreachable!("unsupported arity"),
            }
        }
    }

    fn fold_matrix_packed_impl<const ARITY: usize, F, EF>(
        self,
        input: RowMajorMatrixView<'_, EF>,
        s_invs: &[F],
        beta: EF,
    ) -> Vec<EF>
    where
        F: TwoAdicField,
        EF: ExtensionField<F>,
    {
        assert_eq!(input.width, ARITY);
        assert_eq!(input.values.len() % ARITY, 0);
        let evals: &[[EF; ARITY]] = unsafe {
            // SAFETY: the slice length is checked above to be a multiple of `ARITY`, and
            // `[EF; ARITY]` is laid out contiguously like `ARITY` adjacent `EF` values.
            core::slice::from_raw_parts(input.values.as_ptr().cast(), input.values.len() / ARITY)
        };
        let width = F::Packing::WIDTH;
        assert_eq!(evals.len() % width, 0);

        let mut new_evals = EF::zero_vec(evals.len());

        new_evals
            .par_chunks_exact_mut(width)
            .zip(evals.par_chunks_exact(width))
            .zip(s_invs.par_chunks_exact(width))
            .for_each(|((new_evals_chunk, evals_chunk), s_inv_chunk)| {
                let evals_packed =
                    <EF::ExtensionPacking as PackedFieldExtensionExt<F, EF>>::pack_ext_columns::<
                        ARITY,
                    >(evals_chunk);
                let s_invs_packed = F::Packing::from_slice(s_inv_chunk);
                let new_evals_packed =
                    self.fold_evals_packed::<F, EF>(&evals_packed, *s_invs_packed, beta);
                <EF::ExtensionPacking as PackedFieldExtensionExt<F, EF>>::to_ext_slice(
                    &new_evals_packed,
                    new_evals_chunk,
                );
            });
        new_evals
    }
}

// ============================================================================
// Shared Test Utilities
// ============================================================================

#[cfg(test)]
pub mod tests {
    use alloc::vec::Vec;

    use p3_dft::{NaiveDft, Radix2DFTSmallBatch, TwoAdicSubgroupDft};
    use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, TwoAdicField};
    use p3_matrix::dense::RowMajorMatrix;
    use p3_util::reverse_slice_index_bits;
    use rand::{
        RngExt, SeedableRng,
        distr::{Distribution, StandardUniform},
        prelude::SmallRng,
    };

    use super::*;
    use crate::{
        domain::{Coset, TwoAdicSubgroup},
        testing::{
            configs::goldilocks_poseidon2::{Felt, QuadFelt},
            params::{FRI_FOLD_ARITY_2, FRI_FOLD_ARITY_4, FRI_FOLD_ARITY_8},
        },
        util::horner::horner,
    };

    // Type alias for tests using packed fields
    type Pf = <Felt as Field>::Packing;

    /// Test fold_evals against NaiveDft coset evaluations for a specific arity.
    ///
    /// Generates a random polynomial, computes evaluations on a coset using NaiveDft,
    /// then verifies fold_evals correctly recovers f(β).
    fn test_fold_evals_naive_dft(fold: FriFold) {
        let mut rng = SmallRng::seed_from_u64(42);
        let arity = fold.arity();

        // Polynomial of degree arity-1
        let coeffs: Vec<QuadFelt> = (0..arity).map(|_| rng.sample(StandardUniform)).collect();

        // Coset generator
        let s: Felt = rng.sample(StandardUniform);
        let s_inv = s.inverse();

        // Compute evaluations using NaiveDft on coset s·⟨ω⟩
        let mut coeffs_padded = coeffs.clone();
        coeffs_padded.resize(arity, QuadFelt::ZERO);
        let coeffs_matrix = RowMajorMatrix::new(coeffs_padded, 1);
        let evals_matrix = NaiveDft.coset_dft_batch(coeffs_matrix, QuadFelt::from(s));
        let mut evals: Vec<QuadFelt> = evals_matrix.values;
        reverse_slice_index_bits(&mut evals);

        // Fold with random beta
        let beta: QuadFelt = rng.sample(StandardUniform);
        let result = fold.fold_evals(&evals, s_inv, beta);

        // Expected: direct Horner evaluation at beta
        let expected = horner(beta, coeffs.iter().rev().copied());
        assert_eq!(result, expected, "fold_evals mismatch for arity {arity}");
    }

    /// Test FRI folding correctness for a specific arity.
    ///
    /// Creates a random polynomial of degree `arity - 1`, evaluates it on a coset
    /// of size `arity`, then verifies that `fold_evals` correctly recovers `f(β)`.
    fn test_fold_correctness<Base, Ext>(fold: FriFold)
    where
        Base: TwoAdicField,
        Ext: ExtensionField<Base>,
        StandardUniform: Distribution<Ext> + Distribution<Base>,
    {
        let rng = &mut SmallRng::seed_from_u64(1);
        let beta: Ext = rng.sample(StandardUniform);
        let arity = fold.arity();
        let log_arity = fold.log_arity();

        // Random polynomial of degree arity - 1
        let poly: Vec<Ext> = (0..arity).map(|_| rng.sample(StandardUniform)).collect();

        // Roots of unity in bit-reversed order for this arity.
        let roots: Vec<Base> = TwoAdicSubgroup::<Base>::new(log_arity).bit_reversed_points();

        let s: Base = rng.sample(StandardUniform);
        let s_inv = s.inverse();

        // Evaluate polynomial at coset points: [f(s·root) for root in roots]
        let evals: Vec<Ext> =
            roots.iter().map(|&root| horner(root * s, poly.iter().rev().copied())).collect();

        // Expected: f(beta)
        let expected = horner(beta, poly.iter().rev().copied());

        // Test fold_evals
        let result = fold.fold_evals(&evals, s_inv, beta);
        assert_eq!(result, expected);
    }

    /// Test that `fold_matrix` scalar and packed paths produce identical results.
    ///
    /// Creates a matrix large enough to trigger the packed path, then verifies
    /// the result matches row-by-row scalar `fold_evals` computation.
    fn test_fold_matrix_scalar_packed_equivalence(fold: FriFold) {
        let rng = &mut SmallRng::seed_from_u64(42);
        let arity = fold.arity();

        // Create input matrix with height = multiple of packing width (triggers packed path)
        let height = Pf::WIDTH * 4;
        let values: Vec<QuadFelt> =
            (0..height * arity).map(|_| rng.sample(StandardUniform)).collect();
        let input = RowMajorMatrix::new(values.clone(), arity);

        // Generate random coset generators and their inverses
        let s_values: Vec<Felt> =
            (0..height).map(|_| rng.sample::<Felt, _>(StandardUniform)).collect();
        let s_invs: Vec<Felt> = s_values.iter().map(Field::inverse).collect();

        let beta: QuadFelt = rng.sample(StandardUniform);

        // Scalar path: compute fold_evals for each row
        let scalar_result: Vec<QuadFelt> = values
            .chunks(arity)
            .zip(s_invs.iter())
            .map(|(evals, &s_inv)| fold.fold_evals(evals, s_inv, beta))
            .collect();

        // Packed path: call fold_matrix (uses packed impl for large matrices)
        let packed_result = fold.fold_matrix(input.as_view(), &s_invs, beta);

        assert_eq!(scalar_result, packed_result, "Scalar vs packed mismatch for arity {arity}");
    }

    /// Test that folding preserves low-degree structure.
    ///
    /// After folding a degree-d polynomial, the result should have degree d/arity.
    /// Verifies by checking that high coefficients are zero after IDFT.
    fn test_folding_preserves_low_degree(fold: FriFold) {
        let rng = &mut SmallRng::seed_from_u64(42);
        let arity = fold.arity();
        let log_arity: u8 = fold.log_arity();

        let log_blowup: u8 = 2;
        let log_poly_degree: u8 = 4; // degree 16 polynomial
        let poly_degree = 1usize << log_poly_degree;
        let log_lde_size: u8 = log_poly_degree + log_blowup;
        let lde_size = 1usize << log_lde_size;

        // Generate random low-degree polynomial
        let coeffs: Vec<QuadFelt> = (0..poly_degree).map(|_| rng.sample(StandardUniform)).collect();

        // Compute LDE in bit-reversed order
        let mut full_coeffs = coeffs;
        full_coeffs.resize(lde_size, QuadFelt::ZERO);
        let dft = Radix2DFTSmallBatch::<QuadFelt>::default();
        let mut evals = dft.dft_algebra(full_coeffs);
        reverse_slice_index_bits(&mut evals);

        // Compute s_invs
        let log_num_cosets = log_lde_size - log_arity;
        let num_cosets = 1usize << log_num_cosets;
        let g_inv = TwoAdicSubgroup::<Felt>::new(log_lde_size).generator_inverse();
        let mut s_invs: Vec<Felt> = g_inv.powers().take(num_cosets).collect();
        reverse_slice_index_bits(&mut s_invs);

        // Fold with random beta
        let beta: QuadFelt = rng.sample(StandardUniform);
        let matrix = RowMajorMatrix::new(evals, arity);
        let folded = fold.fold_matrix(matrix.as_view(), &s_invs, beta);

        // IDFT the result to get coefficients
        let mut folded_for_idft = folded;
        reverse_slice_index_bits(&mut folded_for_idft);
        let folded_coeffs = dft.idft_algebra(folded_for_idft);

        // Check that all coefficients beyond degree/arity are zero
        let expected_degree = poly_degree / arity;
        for (i, coeff) in folded_coeffs.iter().enumerate().skip(expected_degree) {
            assert_eq!(
                *coeff,
                QuadFelt::ZERO,
                "Arity {arity}: High coefficient c[{i}] should be zero but was {coeff:?}"
            );
        }
    }

    #[test]
    fn test_fold() {
        test_fold_correctness::<Felt, QuadFelt>(FRI_FOLD_ARITY_2);
        test_fold_correctness::<Felt, QuadFelt>(FRI_FOLD_ARITY_4);
        test_fold_correctness::<Felt, QuadFelt>(FRI_FOLD_ARITY_8);
    }

    #[test]
    fn test_fold_evals_against_naive_dft() {
        test_fold_evals_naive_dft(FRI_FOLD_ARITY_2);
        test_fold_evals_naive_dft(FRI_FOLD_ARITY_4);
        test_fold_evals_naive_dft(FRI_FOLD_ARITY_8);
    }

    #[test]
    fn test_fold_matrix() {
        test_fold_matrix_scalar_packed_equivalence(FRI_FOLD_ARITY_2);
        test_fold_matrix_scalar_packed_equivalence(FRI_FOLD_ARITY_4);
        test_fold_matrix_scalar_packed_equivalence(FRI_FOLD_ARITY_8);
    }

    #[test]
    fn test_fold_low_degree() {
        test_folding_preserves_low_degree(FRI_FOLD_ARITY_2);
        test_folding_preserves_low_degree(FRI_FOLD_ARITY_4);
        test_folding_preserves_low_degree(FRI_FOLD_ARITY_8);
    }
}
