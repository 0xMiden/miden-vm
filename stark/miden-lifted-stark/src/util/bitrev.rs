//! Bit-reversal helpers and a stopgap [`BitReversibleMatrix`] trait.
//!
//! # Temporary stopgap
//!
//! The upstream `BitReversibleMatrix` trait in `p3-matrix` is only implemented for
//! [`DenseMatrix`], not for [`FlatMatrixView`]. This module provides an identical
//! trait with impls for all matrix types used by the LMCS and FRI.
//!
//! Once an upstream impl is available, this trait (and `materialize_bitrev`) can
//! be removed and all uses replaced with `p3_matrix::bitrev::BitReversibleMatrix`.

use alloc::vec::Vec;

use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_matrix::{
    Matrix,
    bitrev::{BitReversalPerm, BitReversedMatrixView},
    dense::{DenseMatrix, DenseStorage, RowMajorMatrix},
    extension::FlatMatrixView,
};
use p3_util::reverse_slice_index_bits;

/// A matrix that supports bit-reversed row reordering.
///
/// Local copy of `p3_matrix::bitrev::BitReversibleMatrix` extended with impls for
/// [`FlatMatrixView`].
pub trait BitReversibleMatrix<T: Send + Sync + Clone>: Matrix<T> {
    /// The type returned when this matrix is viewed in bit-reversed order.
    type BitRev: BitReversibleMatrix<T>;

    /// Return a version of the matrix with its row order reversed by bit index.
    fn bit_reverse_rows(self) -> Self::BitRev;
}

// ============================================================================
// DenseMatrix impls (mirrors upstream)
// ============================================================================

impl<T, S> BitReversibleMatrix<T> for DenseMatrix<T, S>
where
    T: Clone + Send + Sync,
    S: DenseStorage<T>,
{
    type BitRev = BitReversedMatrixView<Self>;

    fn bit_reverse_rows(self) -> Self::BitRev {
        BitReversalPerm::new_view(self)
    }
}

impl<T, S> BitReversibleMatrix<T> for BitReversedMatrixView<DenseMatrix<T, S>>
where
    T: Clone + Send + Sync,
    S: DenseStorage<T>,
{
    type BitRev = DenseMatrix<T, S>;

    fn bit_reverse_rows(self) -> Self::BitRev {
        self.inner
    }
}

// ============================================================================
// FlatMatrixView impls (not available upstream)
// ============================================================================

impl<F, EF, Inner> BitReversibleMatrix<F> for FlatMatrixView<F, EF, Inner>
where
    F: Field,
    EF: ExtensionField<F>,
    Inner: Matrix<EF>,
{
    type BitRev = BitReversedMatrixView<Self>;

    fn bit_reverse_rows(self) -> Self::BitRev {
        BitReversalPerm::new_view(self)
    }
}

impl<F, EF, Inner> BitReversibleMatrix<F> for BitReversedMatrixView<FlatMatrixView<F, EF, Inner>>
where
    F: Field,
    EF: ExtensionField<F>,
    Inner: Matrix<EF>,
{
    type BitRev = FlatMatrixView<F, EF, Inner>;

    fn bit_reverse_rows(self) -> Self::BitRev {
        self.inner
    }
}

/// Materialize a matrix into domain-ordered `BitReversedMatrixView<RowMajorMatrix<T>>`.
///
/// Temporary adapter for types that implement the upstream
/// [`p3_matrix::bitrev::BitReversibleMatrix`] but not this crate's local copy.
/// The returned type implements both traits and can be passed directly to
/// [`Lmcs::build_tree`](crate::lmcs::Lmcs::build_tree) /
/// [`Lmcs::build_aligned_tree`](crate::lmcs::Lmcs::build_aligned_tree).
///
/// Remove alongside [`BitReversibleMatrix`] when upstream impls cover all DFT output types.
pub fn materialize_bitrev<T: Clone + Send + Sync>(
    evals: impl p3_matrix::bitrev::BitReversibleMatrix<T>,
) -> BitReversedMatrixView<RowMajorMatrix<T>> {
    BitReversalPerm::new_view(evals.bit_reverse_rows().to_row_major_matrix())
}

/// Coset points `gK` in bit-reversed order.
///
/// Note: the coset shift `g` is fixed to `F::GENERATOR` by convention in this PCS.
///
/// Bit-reversal gives two properties essential for lifting:
/// - **Adjacent negation**: `gK[2i+1] = -gK[2i]`, so both square to the same value
/// - **Squaring gives prefix**: `(gK[2i])² = (gK)²[i]` — the even-indexed elements, when squared,
///   form the half-size sub-coset. Generalizes to r-th powers.
///
/// Together these enable iterative weight folding in barycentric evaluation.
///
/// # Panics
/// Panics if the two-adic coset construction fails (e.g., `log_n` exceeds the field's
/// two-adicity), since this unwraps `TwoAdicMultiplicativeCoset::new`.
pub fn bit_reversed_coset_points<F: TwoAdicField>(log_n: u8) -> Vec<F> {
    let coset =
        p3_field::coset::TwoAdicMultiplicativeCoset::new(F::GENERATOR, log_n as usize).unwrap();
    let mut pts: Vec<F> = coset.iter().collect();
    reverse_slice_index_bits(&mut pts);
    pts
}
