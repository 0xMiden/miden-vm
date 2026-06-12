//! Byte-AND lookup table AIR.
//!
//! The fixed preprocessed trace enumerates every `(a, b, a & b)` byte tuple. The dynamic main
//! trace carries one multiplicity column. Consumers balance this table by removing the same tuple
//! from the `And8Lookup` bus.

use miden_core::utils::RowMajorMatrix;

use crate::Felt;

pub mod columns;

/// Build the fixed byte-AND table trace.
pub fn preprocessed_trace() -> RowMajorMatrix<Felt> {
    columns::preprocessed_trace()
}
