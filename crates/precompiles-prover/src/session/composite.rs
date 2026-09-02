//! Trace composition for the fixed byte-pair and And8 tables.

use miden_core::{Felt, utils::RowMajorMatrix};

use crate::{
    composite::concatenate_bands, primitives::byte_pair_lut::TRACE_HEIGHT as BPL_TRACE_HEIGHT,
};

/// Concatenate the two byte tables, requiring their fixed row ranges to match exactly.
pub(crate) fn byte_pair_and8_trace(
    bpl: RowMajorMatrix<Felt>,
    and8: RowMajorMatrix<Felt>,
) -> RowMajorMatrix<Felt> {
    assert_eq!(bpl.values.len() / bpl.width, BPL_TRACE_HEIGHT);
    assert_eq!(and8.values.len() / and8.width, BPL_TRACE_HEIGHT);
    concatenate_bands(&bpl, &and8)
}
