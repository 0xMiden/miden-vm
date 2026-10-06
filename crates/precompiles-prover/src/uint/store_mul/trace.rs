//! Trace generation for [`super::UintStoreMulAir`].
//!
//! Store and mul materialize their standalone layouts in disjoint column ranges through
//! `crate::uint::trace::generate_trace_padded_to` and
//! [`crate::uint::mul::trace::generate_trace`]. Mul runs first because it records its store-bus
//! demand. Store then uses at least `mul_main.height() / STORE_PERIOD` blocks. If store's natural
//! height is larger, the inactive all-zero mul tail extends to match it. The two column ranges are
//! concatenated row by row.

use alloc::vec::Vec;

use miden_core::{
    Felt,
    utils::{Matrix, RowMajorMatrix},
};

use super::{NUM_MAIN_COLS, STORE_NUM_MAIN_COLS, STORE_PERIOD};
use crate::{
    primitives::byte_pair_lut::BytePairLutRequires,
    uint::{
        mul::{
            NUM_MAIN_COLS as MUL_NUM_MAIN_COLS,
            trace::{UintMulRequires, generate_trace as mul_trace},
        },
        trace::{UintStoreRequires, generate_trace_padded_to as store_trace_padded_to},
    },
};

pub fn generate_trace(
    store: UintStoreRequires,
    mul: UintMulRequires,
    bpl: &mut BytePairLutRequires,
) -> RowMajorMatrix<Felt> {
    let mut store = store;
    let mul_main = mul_trace(mul, &mut store, bpl);

    // `mul_main.height()` is a power of two and `STORE_PERIOD` divides it
    // (both are powers of two), so this floor is too —
    // `generate_trace_padded_to` needs that to stay a valid power-of-two
    // block count.
    let store_min_blocks = mul_main.height() / STORE_PERIOD;
    let store_main = store_trace_padded_to(store, bpl, store_min_blocks);
    let h_merged = store_main.height();

    let mut mul_vals = mul_main.values;
    mul_vals.resize(h_merged * MUL_NUM_MAIN_COLS, Felt::ZERO);

    let mut vals = Vec::with_capacity(h_merged * NUM_MAIN_COLS);
    for r in 0..h_merged {
        vals.extend_from_slice(
            &store_main.values[r * STORE_NUM_MAIN_COLS..(r + 1) * STORE_NUM_MAIN_COLS],
        );
        vals.extend_from_slice(&mul_vals[r * MUL_NUM_MAIN_COLS..(r + 1) * MUL_NUM_MAIN_COLS]);
    }
    RowMajorMatrix::new(vals, NUM_MAIN_COLS)
}
