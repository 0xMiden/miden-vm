use alloc::vec::Vec;

use miden_air::trace::and8_lookup::{
    AND8_LOOKUP_TRACE_HEIGHT, BYTE_LOOKUP_COUNT_LEN, BYTE_LOOKUP_KIND_COUNT, BYTE_PAIR_ROWS,
    NUM_AND8_LOOKUP_COLS, RANGE_CHECK_COUNT_OFFSET, RANGE_CHECK_LOOKUP_COL,
};
use miden_core::{Felt, field::PrimeCharacteristicRing};

/// Builds the dynamic byte-pair lookup trace from accumulated BlakeG and stream counts.
pub(crate) fn build_and8_lookup_trace(counts: &[u64]) -> Vec<Felt> {
    debug_assert_eq!(counts.len(), BYTE_LOOKUP_COUNT_LEN);
    let mut trace = Felt::zero_vec(AND8_LOOKUP_TRACE_HEIGHT * NUM_AND8_LOOKUP_COLS);
    for pair in 0..BYTE_PAIR_ROWS {
        for kind in 0..BYTE_LOOKUP_KIND_COUNT {
            trace[pair * NUM_AND8_LOOKUP_COLS + kind] =
                Felt::new_unchecked(counts[kind * BYTE_PAIR_ROWS + pair]);
        }
        trace[pair * NUM_AND8_LOOKUP_COLS + RANGE_CHECK_LOOKUP_COL] =
            Felt::new_unchecked(counts[RANGE_CHECK_COUNT_OFFSET + pair]);
    }
    trace
}
