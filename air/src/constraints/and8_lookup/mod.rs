//! Byte-pair lookup table AIR.
//!
//! The fixed preprocessed trace enumerates one row per byte pair. The row serves
//! ten lookup domains: ordinary `(a, b, a & b)`, one BlakeG rotation-contribution
//! domain for each `(rotation, byte-position)` pair, and `RangeCheck` for the
//! 16-bit value `256 * a + b`. The dynamic main trace carries one multiplicity
//! column per domain.

use miden_core::{Felt, utils::RowMajorMatrix};

pub mod columns;

/// Builds the fixed byte-pair table used by the AND8 lookup AIR.
pub fn preprocessed_trace() -> RowMajorMatrix<Felt> {
    columns::And8LookupPreprocessedCols::<Felt>::preprocessed_trace()
}
