//! Column layout for the byte-AND lookup table AIR.

use alloc::vec::Vec;
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use miden_core::{Felt, utils::RowMajorMatrix};

/// Number of rows in the byte-AND table.
pub const AND8_TABLE_HEIGHT: usize = 1 << 16;

/// Log2 of [`AND8_TABLE_HEIGHT`].
pub const LOG_AND8_TABLE_HEIGHT: u8 = 16;

/// Dynamic byte-AND table columns.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct And8LookupCols<T> {
    /// Number of consumers of this `(a, b, a & b)` row.
    pub multiplicity: T,
}

/// Number of dynamic columns in the byte-AND table AIR.
pub const NUM_AND8_LOOKUP_COLS: usize = size_of::<And8LookupCols<u8>>();

impl<T> Borrow<And8LookupCols<T>> for [T] {
    fn borrow(&self) -> &And8LookupCols<T> {
        debug_assert_eq!(self.len(), NUM_AND8_LOOKUP_COLS);
        let (prefix, cols, suffix) = unsafe { self.align_to::<And8LookupCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && cols.len() == 1);
        &cols[0]
    }
}

impl<T> BorrowMut<And8LookupCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut And8LookupCols<T> {
        debug_assert_eq!(self.len(), NUM_AND8_LOOKUP_COLS);
        let (prefix, cols, suffix) = unsafe { self.align_to_mut::<And8LookupCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && cols.len() == 1);
        &mut cols[0]
    }
}

/// Fixed byte-AND table columns.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct And8LookupPreprocessedCols<T> {
    pub a: T,
    pub b: T,
    pub result: T,
}

/// Number of preprocessed columns in the byte-AND table AIR.
pub const NUM_AND8_LOOKUP_PREPROCESSED_COLS: usize = size_of::<And8LookupPreprocessedCols<u8>>();

impl<T> Borrow<And8LookupPreprocessedCols<T>> for [T] {
    fn borrow(&self) -> &And8LookupPreprocessedCols<T> {
        debug_assert_eq!(self.len(), NUM_AND8_LOOKUP_PREPROCESSED_COLS);
        let (prefix, cols, suffix) = unsafe { self.align_to::<And8LookupPreprocessedCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && cols.len() == 1);
        &cols[0]
    }
}

/// Builds the fixed `(a, b, a & b)` table in row order `(a << 8) | b`.
pub fn preprocessed_trace() -> RowMajorMatrix<Felt> {
    let mut values = Vec::with_capacity(AND8_TABLE_HEIGHT * NUM_AND8_LOOKUP_PREPROCESSED_COLS);
    for a in 0u32..=255 {
        for b in 0u32..=255 {
            values.push(Felt::from_u32(a));
            values.push(Felt::from_u32(b));
            values.push(Felt::from_u32(a & b));
        }
    }
    RowMajorMatrix::new(values, NUM_AND8_LOOKUP_PREPROCESSED_COLS)
}

const _: () = {
    assert!(NUM_AND8_LOOKUP_COLS == 1);
    assert!(NUM_AND8_LOOKUP_PREPROCESSED_COLS == 3);
};
