//! Byte-pair lookup table AIR.
//!
//! The fixed preprocessed trace enumerates one row per byte pair. The row serves canonical XOR,
//! five normalized Eidos rotation domains, and `RangeCheck` for `256 * a + b`. Ordinary AND and
//! three non-wrapping rotations map affinely to canonical XOR. The seven simultaneous table
//! interactions use four LogUp auxiliary columns with shape `[1, 2, 2, 2]`.

use miden_core::{Felt, utils::RowMajorMatrix};

pub mod columns;
pub(crate) mod eidos;

/// Builds the fixed byte-pair table used by the AND8 lookup AIR.
pub fn preprocessed_trace() -> RowMajorMatrix<Felt> {
    columns::And8LookupPreprocessedCols::<Felt>::preprocessed_trace()
}
