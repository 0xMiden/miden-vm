//! Trace generation for the merged chunk + keccak-node chiplet.

use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::QuadFelt,
    utils::{Matrix, RowMajorMatrix},
};

use crate::{
    hash::{
        chunk::{
            self,
            trace::{ChunkRequires, generate_trace_padded_to as chunk_trace},
        },
        chunk_node::{ChunkNodeAir, NODE_COL_OFFSET, NUM_MAIN_COLS},
        keccak::node::{
            self as node,
            trace::{KeccakNodeRequires, generate_trace as node_trace},
        },
    },
    logup::build_logup_aux_trace,
};

/// Build the merged chunk + keccak-node main trace. Both sides run on
/// the same row range in disjoint column ranges (see the module doc),
/// so the shared height is `max` of what each side natively needs — the
/// keccak-node trace is computed first (its own padding is `act`-gated,
/// so zero-extending it is always sound), then chunk's own trace is
/// padded up to at least that height (chunk's `chunk_seq_id` /
/// `perm_seq_id` chains are unconditional, so it needs its own
/// continuation logic — see [`generate_trace_padded_to`](chunk::trace::generate_trace_padded_to)).
pub fn generate_trace(chunk: ChunkRequires, node: KeccakNodeRequires) -> RowMajorMatrix<Felt> {
    let mut node_main = node_trace(node);
    let node_height = node_main.height();
    let chunk_main = chunk_trace(chunk, node_height);
    let height = chunk_main.height();
    node_main.values.resize(height * node::NUM_MAIN_COLS, Felt::ZERO);

    let mut vals = Vec::with_capacity(height * NUM_MAIN_COLS);
    for r in 0..height {
        vals.extend_from_slice(
            &chunk_main.values[r * chunk::NUM_MAIN_COLS..(r + 1) * chunk::NUM_MAIN_COLS],
        );
        vals.extend_from_slice(
            &node_main.values[r * node::NUM_MAIN_COLS..(r + 1) * node::NUM_MAIN_COLS],
        );
    }
    debug_assert_eq!(vals.len(), height * NUM_MAIN_COLS);
    debug_assert_eq!(NODE_COL_OFFSET, chunk::NUM_MAIN_COLS);

    RowMajorMatrix::new(vals, NUM_MAIN_COLS)
}

/// Build the merged chiplet's aux trace via the generic
/// [`build_logup_aux_trace`] driver.
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    build_logup_aux_trace(&ChunkNodeAir, main, challenges)
}
