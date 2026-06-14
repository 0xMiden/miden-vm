//! Byte-pair lookup table AIR.
//!
//! The fixed preprocessed trace enumerates one row per byte pair. The row serves
//! nine semantic buses: ordinary `(a, b, a & b)` plus one BlakeG
//! rotation-contribution bus for each `(rotation, byte-position)` pair. The
//! dynamic main trace carries one multiplicity column per bus.

use miden_core::{Felt, utils::RowMajorMatrix};

pub mod columns;

/// Builds the fixed byte-pair table used by the AND8 lookup AIR.
pub fn preprocessed_trace() -> RowMajorMatrix<Felt> {
    columns::And8LookupPreprocessedCols::<Felt>::preprocessed_trace()
}
