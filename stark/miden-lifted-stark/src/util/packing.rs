//! Packing / column-transpose helpers for SIMD operations on packed values
//! and packed extension-field elements.

use alloc::vec::Vec;
use core::array;

use p3_field::{ExtensionField, Field, PackedFieldExtension, PackedValue};

/// Extension trait for [`PackedValue`] providing columnar pack/unpack operations.
///
/// These methods perform transpose operations on packed data, useful for
/// SIMD-parallelized Merkle tree construction.
pub trait PackedValueExt: PackedValue {
    /// Pack columns from `WIDTH` rows of scalar values.
    ///
    /// Given `WIDTH` rows of `N` scalar values, extract each column and pack it
    /// into a single packed value. This performs a transpose operation.
    #[inline]
    #[must_use]
    fn pack_columns<const N: usize>(rows: &[[Self::Value; N]]) -> [Self; N] {
        assert_eq!(rows.len(), Self::WIDTH);
        array::from_fn(|col| Self::from_fn(|lane| rows[lane][col]))
    }
}

impl<T: PackedValue> PackedValueExt for T {}

/// Extension trait for [`PackedFieldExtension`] adding `pack_ext_columns` and
/// `to_ext_slice` methods for column-wise SIMD operations on extension field elements.
pub trait PackedFieldExtensionExt<
    BaseField: Field,
    ExtField: ExtensionField<BaseField, ExtensionPacking = Self>,
>: PackedFieldExtension<BaseField, ExtField>
{
    /// Pack N columns from WIDTH rows into N packed extension field elements.
    ///
    /// Input: `rows[lane][col]` - WIDTH rows, each with N extension field elements.
    /// Output: `result[col]` - N packed values, where each packs WIDTH lanes.
    fn pack_ext_columns<const N: usize>(rows: &[[ExtField; N]]) -> [Self; N] {
        let width = BaseField::Packing::WIDTH;
        debug_assert_eq!(rows.len(), width);
        array::from_fn(|col| {
            let col_elems: Vec<ExtField> = (0..width).map(|lane| rows[lane][col]).collect();
            Self::from_ext_slice(&col_elems)
        })
    }

    /// Extract all lanes to an output slice.
    fn to_ext_slice(&self, out: &mut [ExtField]) {
        let width = BaseField::Packing::WIDTH;
        for (lane, slot) in out.iter_mut().enumerate().take(width) {
            *slot = self.extract(lane);
        }
    }
}

impl<
    BaseField: Field,
    ExtField: ExtensionField<BaseField, ExtensionPacking = P>,
    P: PackedFieldExtension<BaseField, ExtField>,
> PackedFieldExtensionExt<BaseField, ExtField> for P
{
}

/// Reconstitute EF elements from opened base field polynomial evaluations.
///
/// When an EF polynomial is committed, it becomes DIM base field polynomials.
/// Opening at EF point z gives DIM EF values (F-polys evaluated at EF point).
/// Reconstruct each EF element: `vᵢ = Σⱼ basisⱼ·row[i·DIM + j]`.
///
/// Returns `None` if `row.len()` is not a multiple of `EF::DIMENSION`.
pub fn row_to_packed_ext<F, EF>(row: &[EF]) -> Option<Vec<EF>>
where
    F: Field,
    EF: ExtensionField<F>,
{
    if !row.len().is_multiple_of(EF::DIMENSION) {
        return None;
    }
    Some(
        row.chunks_exact(EF::DIMENSION)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .map(|(j, &c)| EF::ith_basis_element(j).unwrap() * c)
                    .sum()
            })
            .collect(),
    )
}
