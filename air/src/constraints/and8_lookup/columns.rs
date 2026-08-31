//! Column layout for the MVM byte-pair lookup table AIR.

use alloc::vec::Vec;
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use miden_core::{Felt, utils::RowMajorMatrix};

use super::eidos::{self, BytePairRelation, Rotation};

const BITS_PER_BYTE: usize = u8::BITS as usize;

/// Number of byte-pair rows per lookup relation.
pub const BYTE_PAIR_ROWS: usize = 1 << (2 * BITS_PER_BYTE);

/// Number of normalized byte-pair relations represented in the table.
pub const BYTE_PAIR_RELATION_COUNT: usize = eidos::NUM_RELATIONS;

/// Dynamic multiplicity column used by 16-bit range-check table inserts.
pub const RANGE_CHECK_LOOKUP_COL: usize = BYTE_PAIR_RELATION_COUNT;

/// Number of dynamic multiplicity columns in the byte-pair lookup AIR.
pub const BYTE_LOOKUP_COLUMN_COUNT: usize = BYTE_PAIR_RELATION_COUNT + 1;

/// Number of real byte-pair table rows.
pub const AND8_TABLE_ROWS: usize = BYTE_PAIR_ROWS;

/// Offset in the consumer count vector where range-check multiplicities start.
pub const RANGE_CHECK_COUNT_OFFSET: usize = BYTE_PAIR_ROWS * BYTE_PAIR_RELATION_COUNT;

/// Number of dynamic multiplicity counters filled by consumers.
pub const BYTE_LOOKUP_COUNT_LEN: usize = BYTE_PAIR_ROWS * BYTE_LOOKUP_COLUMN_COUNT;

/// Row occupied by `(lhs, rhs)` in the verifier-known byte-pair table.
pub const fn byte_pair_row(lhs: u8, rhs: u8) -> usize {
    (lhs as usize) << BITS_PER_BYTE | rhs as usize
}

/// Flat consumer-count index for a normalized relation and byte pair.
pub const fn byte_pair_count_index(relation: BytePairRelation, lhs: u8, rhs: u8) -> usize {
    relation.index() * BYTE_PAIR_ROWS + byte_pair_row(lhs, rhs)
}

/// Log2 of [`AND8_LOOKUP_TRACE_HEIGHT`].
pub const LOG_AND8_LOOKUP_TRACE_HEIGHT: u8 = (2 * BITS_PER_BYTE) as u8;

/// Physical trace height for the byte-pair lookup AIR.
///
/// This AIR uses the wrapped LogUp accumulator, so the last row may carry the real
/// `(255, 255)` byte-pair entry instead of an idle padding row.
pub const AND8_LOOKUP_TRACE_HEIGHT: usize = 1 << LOG_AND8_LOOKUP_TRACE_HEIGHT;

/// Dynamic byte-pair table columns.
///
/// The six relation multiplicities follow
/// [`BytePairRelation`](crate::trace::and8_lookup::BytePairRelation)'s discriminant order. The
/// final column serves the `RangeCheck` bus by interpreting `(a, b)` as `256 * a + b`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct And8LookupCols<T> {
    pub relation_multiplicities: [T; BYTE_PAIR_RELATION_COUNT],
    pub range_multiplicity: T,
}

/// Number of dynamic columns in the byte-pair table AIR.
pub const NUM_AND8_LOOKUP_COLS: usize = size_of::<And8LookupCols<u8>>();

impl<T> Borrow<And8LookupCols<T>> for [T] {
    fn borrow(&self) -> &And8LookupCols<T> {
        debug_assert_eq!(self.len(), NUM_AND8_LOOKUP_COLS);
        // SAFETY: `And8LookupCols<T>` is `repr(C)` and contains only `T` values. Its size is
        // statically reflected by `NUM_AND8_LOOKUP_COLS`, and the checked slice has the same
        // alignment and valid bit patterns.
        let (prefix, cols, suffix) = unsafe { self.align_to::<And8LookupCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && cols.len() == 1);
        &cols[0]
    }
}

impl<T> BorrowMut<And8LookupCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut And8LookupCols<T> {
        debug_assert_eq!(self.len(), NUM_AND8_LOOKUP_COLS);
        // SAFETY: as above, the `repr(C)` struct is exactly a contiguous sequence of
        // `NUM_AND8_LOOKUP_COLS` values of `T`; the exclusive slice borrow preserves aliasing.
        let (prefix, cols, suffix) = unsafe { self.align_to_mut::<And8LookupCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && cols.len() == 1);
        &mut cols[0]
    }
}

/// Fixed `[a, b, x, W12(x), W7(x)]` byte-pair table columns, where `x = a xor b`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct And8LookupPreprocessedCols<T> {
    pub a: T,
    pub b: T,
    pub xor: T,
    pub wrap12: T,
    pub wrap7: T,
}

/// Number of preprocessed columns in the byte-pair table AIR.
pub const NUM_AND8_LOOKUP_PREPROCESSED_COLS: usize = size_of::<And8LookupPreprocessedCols<u8>>();

impl<T> Borrow<And8LookupPreprocessedCols<T>> for [T] {
    fn borrow(&self) -> &And8LookupPreprocessedCols<T> {
        debug_assert_eq!(self.len(), NUM_AND8_LOOKUP_PREPROCESSED_COLS);
        // SAFETY: `And8LookupPreprocessedCols<T>` is `repr(C)` and contains only `T` fields. The
        // checked slice length, alignment, and valid bit patterns therefore match the struct.
        let (prefix, cols, suffix) = unsafe { self.align_to::<And8LookupPreprocessedCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && cols.len() == 1);
        &cols[0]
    }
}

impl And8LookupPreprocessedCols<Felt> {
    /// Builds the verifier-known byte-pair table in `(a << 8) + b` row order.
    pub fn preprocessed_trace() -> RowMajorMatrix<Felt> {
        let mut values =
            Vec::with_capacity(AND8_LOOKUP_TRACE_HEIGHT * NUM_AND8_LOOKUP_PREPROCESSED_COLS);
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                let a = a as u8;
                let b = b as u8;
                let x = a ^ b;
                values.extend([
                    Felt::from(a),
                    Felt::from(b),
                    Felt::from(x),
                    Felt::from(eidos::contribution(Rotation::Rot12, 1, a, b)),
                    Felt::from(eidos::contribution(Rotation::Rot7, 0, a, b)),
                ]);
            }
        }
        debug_assert_eq!(
            values.len(),
            AND8_LOOKUP_TRACE_HEIGHT * NUM_AND8_LOOKUP_PREPROCESSED_COLS
        );
        RowMajorMatrix::new(values, NUM_AND8_LOOKUP_PREPROCESSED_COLS)
    }
}

const _: () = {
    assert!(NUM_AND8_LOOKUP_COLS == 7);
    assert!(NUM_AND8_LOOKUP_COLS == BYTE_LOOKUP_COLUMN_COUNT);
    assert!(NUM_AND8_LOOKUP_PREPROCESSED_COLS == 5);
};

#[cfg(test)]
mod tests {
    use miden_core::utils::Matrix;

    use super::*;

    #[test]
    fn preprocessed_trace_enumerates_byte_pairs() {
        let trace = And8LookupPreprocessedCols::<Felt>::preprocessed_trace();
        assert_eq!(trace.height(), AND8_LOOKUP_TRACE_HEIGHT);
        assert_eq!(trace.width(), NUM_AND8_LOOKUP_PREPROCESSED_COLS);

        for row in 0..BYTE_PAIR_ROWS {
            let a = (row >> 8) as u8;
            let b = (row & 0xff) as u8;
            let x = a ^ b;
            let values = trace.row_slice(row).expect("real byte-pair row is present");
            assert_eq!(row, byte_pair_row(a, b));
            assert_eq!(
                &*values,
                &[
                    Felt::from(a),
                    Felt::from(b),
                    Felt::from(x),
                    Felt::from((u32::from(x) << 8).rotate_right(12)),
                    Felt::from(u32::from(x).rotate_right(7)),
                ],
            );
        }
    }
}
