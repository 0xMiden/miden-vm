use alloc::vec::Vec;

use miden_air::trace::and8_lookup::{
    AND8_LOOKUP_TRACE_HEIGHT, BYTE_LOOKUP_COUNT_LEN, BYTE_PAIR_RELATION_COUNT, BYTE_PAIR_ROWS,
    NUM_AND8_LOOKUP_COLS, RANGE_CHECK_COUNT_OFFSET, RANGE_CHECK_LOOKUP_COL,
};
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, PrimeField64},
};

/// Builds the dynamic byte-pair lookup trace from accumulated byte-pair and range-check consumer
/// multiplicities.
pub(crate) fn build_and8_lookup_trace(counts: &[u64]) -> Vec<Felt> {
    debug_assert_eq!(counts.len(), BYTE_LOOKUP_COUNT_LEN);
    let mut trace = Felt::zero_vec(AND8_LOOKUP_TRACE_HEIGHT * NUM_AND8_LOOKUP_COLS);
    for pair in 0..BYTE_PAIR_ROWS {
        for relation in 0..BYTE_PAIR_RELATION_COUNT {
            let count = counts[relation * BYTE_PAIR_ROWS + pair];
            assert!(count < Felt::ORDER_U64, "byte lookup multiplicity must be canonical");
            trace[pair * NUM_AND8_LOOKUP_COLS + relation] = Felt::new_unchecked(count);
        }
        let count = counts[RANGE_CHECK_COUNT_OFFSET + pair];
        assert!(count < Felt::ORDER_U64, "range lookup multiplicity must be canonical");
        trace[pair * NUM_AND8_LOOKUP_COLS + RANGE_CHECK_LOOKUP_COL] = Felt::new_unchecked(count);
    }
    trace
}
