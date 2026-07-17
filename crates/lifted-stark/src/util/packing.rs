//! Packing / column-transpose helpers for SIMD operations on packed values
//! and packed extension-field elements.

use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};

/// Reconstitute EF elements from opened base field polynomial evaluations.
///
/// When an EF polynomial is committed, it becomes DIM base field polynomials.
/// Opening at EF point z gives DIM EF values (F-polys evaluated at EF point).
/// Reconstruct each EF element: `vᵢ = Σⱼ basisⱼ·row[i·DIM + j]`.
///
/// Returns `None` if `row.len()` is not a multiple of `EF::DIMENSION`.
pub(crate) fn row_to_packed_ext<F, EF>(row: &[EF]) -> Option<Vec<EF>>
where
    F: Field,
    EF: ExtensionField<F>,
{
    if !row.len().is_multiple_of(EF::DIMENSION) {
        return None;
    }
    Some(
        row.chunks_exact(EF::DIMENSION)
            .map(|chunk| EF::from_ext_basis_coefficients(chunk).unwrap())
            .collect(),
    )
}
