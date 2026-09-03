//! Trace generation for [`UintStoreMulAir`](crate::uint::store_mul::UintStoreMulAir).
//!
//! Store and mul each lay their own rows via their standalone trace-gen
//! (`crate::uint::trace::generate_trace_padded_to`,
//! [`crate::uint::mul::trace::generate_trace`]) — same block content,
//! same native padding mechanism (store's self-referential zero blocks,
//! mul's `act = 0` blocks). Mul routes its store demand first (as the
//! original dependency order required), producing its own natively
//! padded height; store is then generated with a block-count floor
//! matching that height, so it comes out at `max(store's natural
//! height, mul's natural height)` directly; if mul's own height was the
//! smaller one, it's zero-extended to match (mul's padding is already
//! all-zero, so more of it is exactly more native padding). The two
//! column ranges are then concatenated per row.

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
