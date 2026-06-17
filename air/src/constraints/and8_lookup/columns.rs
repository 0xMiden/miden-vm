//! Column layout for the byte-pair lookup table AIR.

use alloc::vec::Vec;
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use miden_core::{Felt, utils::RowMajorMatrix};

const BITS_PER_BYTE: usize = u8::BITS as usize;
const BYTE_LOOKUP_ROTATION_POSITIONS: usize = 4;
const BYTE_LOOKUP_BASE_PREPROCESSED_COLS: usize = 3;

/// Number of byte-pair rows per lookup kind.
pub const BYTE_PAIR_ROWS: usize = 1 << (2 * BITS_PER_BYTE);

/// Ordinary `a & b` lookup kind.
pub const BYTE_LOOKUP_KIND_AND8: usize = 0;

/// BlakeG rot12 contribution lookup kind for byte position 0.
pub const BYTE_LOOKUP_KIND_BLAKEG_ROT12_POS0: usize = 1;
/// BlakeG rot12 contribution lookup kind for byte position 1.
pub const BYTE_LOOKUP_KIND_BLAKEG_ROT12_POS1: usize = 2;
/// BlakeG rot12 contribution lookup kind for byte position 2.
pub const BYTE_LOOKUP_KIND_BLAKEG_ROT12_POS2: usize = 3;
/// BlakeG rot12 contribution lookup kind for byte position 3.
pub const BYTE_LOOKUP_KIND_BLAKEG_ROT12_POS3: usize = 4;

/// BlakeG rot7 contribution lookup kind for byte position 0.
pub const BYTE_LOOKUP_KIND_BLAKEG_ROT7_POS0: usize = 5;
/// BlakeG rot7 contribution lookup kind for byte position 1.
pub const BYTE_LOOKUP_KIND_BLAKEG_ROT7_POS1: usize = 6;
/// BlakeG rot7 contribution lookup kind for byte position 2.
pub const BYTE_LOOKUP_KIND_BLAKEG_ROT7_POS2: usize = 7;
/// BlakeG rot7 contribution lookup kind for byte position 3.
pub const BYTE_LOOKUP_KIND_BLAKEG_ROT7_POS3: usize = 8;

/// BlakeG rot12 contribution lookup kinds by byte position.
pub const BYTE_LOOKUP_KIND_BLAKEG_ROT12: [usize; BYTE_LOOKUP_ROTATION_POSITIONS] = [
    BYTE_LOOKUP_KIND_BLAKEG_ROT12_POS0,
    BYTE_LOOKUP_KIND_BLAKEG_ROT12_POS1,
    BYTE_LOOKUP_KIND_BLAKEG_ROT12_POS2,
    BYTE_LOOKUP_KIND_BLAKEG_ROT12_POS3,
];

/// BlakeG rot7 contribution lookup kinds by byte position.
pub const BYTE_LOOKUP_KIND_BLAKEG_ROT7: [usize; BYTE_LOOKUP_ROTATION_POSITIONS] = [
    BYTE_LOOKUP_KIND_BLAKEG_ROT7_POS0,
    BYTE_LOOKUP_KIND_BLAKEG_ROT7_POS1,
    BYTE_LOOKUP_KIND_BLAKEG_ROT7_POS2,
    BYTE_LOOKUP_KIND_BLAKEG_ROT7_POS3,
];

/// Number of byte-pair lookup kinds represented in the table.
pub const BYTE_LOOKUP_KIND_COUNT: usize = 1 + 2 * BYTE_LOOKUP_ROTATION_POSITIONS;

/// Dynamic multiplicity column used by 16-bit range-check table inserts.
pub const RANGE_CHECK_LOOKUP_COL: usize = BYTE_LOOKUP_KIND_COUNT;

/// Number of dynamic multiplicity columns in the byte-pair lookup AIR.
pub const BYTE_LOOKUP_COLUMN_COUNT: usize = BYTE_LOOKUP_KIND_COUNT + 1;

/// Number of real byte-pair table rows.
pub const AND8_TABLE_ROWS: usize = BYTE_PAIR_ROWS;

/// Offset in the consumer count vector where range-check multiplicities start.
pub const RANGE_CHECK_COUNT_OFFSET: usize = BYTE_PAIR_ROWS * BYTE_LOOKUP_KIND_COUNT;

/// Number of dynamic multiplicity counters filled by consumers.
pub const BYTE_LOOKUP_COUNT_LEN: usize = BYTE_PAIR_ROWS * BYTE_LOOKUP_COLUMN_COUNT;

/// Log2 of [`AND8_LOOKUP_TRACE_HEIGHT`].
pub const LOG_AND8_LOOKUP_TRACE_HEIGHT: u8 = (2 * BITS_PER_BYTE) as u8;

/// Physical trace height for the byte-pair lookup AIR.
///
/// This AIR uses the wrapped LogUp accumulator, so the last row may carry the real
/// `(255, 255)` byte-pair entry instead of an idle padding row.
pub const AND8_LOOKUP_TRACE_HEIGHT: usize = 1 << LOG_AND8_LOOKUP_TRACE_HEIGHT;

/// Dynamic byte-pair table columns.
///
/// Multiplicities are filled by consumers of the table. A zero-multiplicity row remains a valid
/// table row; it just contributes nothing to the lookup bus. The final column serves the
/// `RangeCheck` bus by interpreting the fixed `(a, b)` row as the 16-bit value `256 * a + b`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct And8LookupCols<T> {
    pub and_multiplicity: T,
    pub rot12_pos0_multiplicity: T,
    pub rot12_pos1_multiplicity: T,
    pub rot12_pos2_multiplicity: T,
    pub rot12_pos3_multiplicity: T,
    pub rot7_pos0_multiplicity: T,
    pub rot7_pos1_multiplicity: T,
    pub rot7_pos2_multiplicity: T,
    pub rot7_pos3_multiplicity: T,
    pub range_multiplicity: T,
}

/// Number of dynamic columns in the byte-pair table AIR.
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

/// Fixed byte-pair table columns.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct And8LookupPreprocessedCols<T> {
    pub a: T,
    pub b: T,
    pub and: T,
    pub rot12_pos0: T,
    pub rot12_pos1: T,
    pub rot12_pos2: T,
    pub rot12_pos3: T,
    pub rot7_pos0: T,
    pub rot7_pos1: T,
    pub rot7_pos2: T,
    pub rot7_pos3: T,
}

/// Number of preprocessed columns in the byte-pair table AIR.
pub const NUM_AND8_LOOKUP_PREPROCESSED_COLS: usize = size_of::<And8LookupPreprocessedCols<u8>>();

impl<T> Borrow<And8LookupPreprocessedCols<T>> for [T] {
    fn borrow(&self) -> &And8LookupPreprocessedCols<T> {
        debug_assert_eq!(self.len(), NUM_AND8_LOOKUP_PREPROCESSED_COLS);
        let (prefix, cols, suffix) = unsafe { self.align_to::<And8LookupPreprocessedCols<T>>() };
        debug_assert!(prefix.is_empty() && suffix.is_empty() && cols.len() == 1);
        &cols[0]
    }
}

impl And8LookupPreprocessedCols<Felt> {
    /// Builds the fixed byte-pair table.
    ///
    /// The row order is `(a << 8) + b`. Each row serves ordinary byte AND, the
    /// eight BlakeG rotation-contribution buses, and the range-check table side for
    /// `value = 256 * a + b`. A rotation contribution is the u32 value obtained by placing
    /// `(a xor b)` at one byte position and rotating the word by 12 or 7 bits.
    pub fn preprocessed_trace() -> RowMajorMatrix<Felt> {
        let mut values =
            Vec::with_capacity(AND8_LOOKUP_TRACE_HEIGHT * NUM_AND8_LOOKUP_PREPROCESSED_COLS);
        for a in 0u32..=255 {
            for b in 0u32..=255 {
                let and = a & b;
                values.push(Felt::from_u32(a));
                values.push(Felt::from_u32(b));
                values.push(Felt::from_u32(and));
                for kind in BYTE_LOOKUP_KIND_BLAKEG_ROT12 {
                    values.push(Felt::from_u32(byte_lookup_result(kind, a as u8, b as u8)));
                }
                for kind in BYTE_LOOKUP_KIND_BLAKEG_ROT7 {
                    values.push(Felt::from_u32(byte_lookup_result(kind, a as u8, b as u8)));
                }
            }
        }
        debug_assert_eq!(
            values.len(),
            AND8_LOOKUP_TRACE_HEIGHT * NUM_AND8_LOOKUP_PREPROCESSED_COLS
        );
        RowMajorMatrix::new(values, NUM_AND8_LOOKUP_PREPROCESSED_COLS)
    }
}

/// Returns the byte-pair table output for `kind`.
#[inline]
pub const fn byte_lookup_result(kind: usize, a: u8, b: u8) -> u32 {
    match kind {
        BYTE_LOOKUP_KIND_AND8 => (a & b) as u32,
        BYTE_LOOKUP_KIND_BLAKEG_ROT12_POS0 => byte_rotation_contribution(a, b, 0, 12),
        BYTE_LOOKUP_KIND_BLAKEG_ROT12_POS1 => byte_rotation_contribution(a, b, 1, 12),
        BYTE_LOOKUP_KIND_BLAKEG_ROT12_POS2 => byte_rotation_contribution(a, b, 2, 12),
        BYTE_LOOKUP_KIND_BLAKEG_ROT12_POS3 => byte_rotation_contribution(a, b, 3, 12),
        BYTE_LOOKUP_KIND_BLAKEG_ROT7_POS0 => byte_rotation_contribution(a, b, 0, 7),
        BYTE_LOOKUP_KIND_BLAKEG_ROT7_POS1 => byte_rotation_contribution(a, b, 1, 7),
        BYTE_LOOKUP_KIND_BLAKEG_ROT7_POS2 => byte_rotation_contribution(a, b, 2, 7),
        BYTE_LOOKUP_KIND_BLAKEG_ROT7_POS3 => byte_rotation_contribution(a, b, 3, 7),
        _ => panic!("byte lookup kind is out of range"),
    }
}

#[inline]
const fn byte_rotation_contribution(a: u8, b: u8, byte_pos: usize, rot: u32) -> u32 {
    if byte_pos >= 4 {
        panic!("byte position must be in 0..4");
    }
    let word = ((a ^ b) as u32) << (BITS_PER_BYTE * byte_pos);
    word.rotate_right(rot)
}

const _: () = {
    assert!(NUM_AND8_LOOKUP_COLS == BYTE_LOOKUP_COLUMN_COUNT);
    assert!(
        NUM_AND8_LOOKUP_PREPROCESSED_COLS
            == BYTE_LOOKUP_BASE_PREPROCESSED_COLS + 2 * BYTE_LOOKUP_ROTATION_POSITIONS
    );
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

        for row in [0, 1, 255, 256, BYTE_PAIR_ROWS - 1] {
            let a = (row >> 8) as u32;
            let b = (row & 0xff) as u32;
            let and = a & b;
            let values = trace.row_slice(row).expect("real byte-pair row is present");
            let mut expected =
                alloc::vec![Felt::from_u32(a), Felt::from_u32(b), Felt::from_u32(and),];
            for kind in BYTE_LOOKUP_KIND_BLAKEG_ROT12 {
                expected.push(Felt::from_u32(byte_lookup_result(kind, a as u8, b as u8)));
            }
            for kind in BYTE_LOOKUP_KIND_BLAKEG_ROT7 {
                expected.push(Felt::from_u32(byte_lookup_result(kind, a as u8, b as u8)));
            }
            assert_eq!(&*values, expected.as_slice());
        }
    }

    #[test]
    fn rotation_contributions_sum_to_rotated_byte_xor_word() {
        for (a, b) in [(0u8, 0u8), (0xf0, 0x0f), (0x53, 0xa9), (0xff, 0x80)] {
            let rot12 = BYTE_LOOKUP_KIND_BLAKEG_ROT12
                .into_iter()
                .map(|kind| byte_lookup_result(kind, a, b))
                .sum::<u32>();
            let rot7 = BYTE_LOOKUP_KIND_BLAKEG_ROT7
                .into_iter()
                .map(|kind| byte_lookup_result(kind, a, b))
                .sum::<u32>();
            let xor = a as u32 ^ b as u32;
            assert_eq!(rot12, ((xor) | (xor << 8) | (xor << 16) | (xor << 24)).rotate_right(12));
            assert_eq!(rot7, ((xor) | (xor << 8) | (xor << 16) | (xor << 24)).rotate_right(7));
        }
    }
}
