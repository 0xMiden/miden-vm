//! Trace generation for the merged chunk + keccak-node + keccak-sponge
//! chiplet.

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
        chunk_node_sponge::{ChunkNodeSpongeAir, NUM_MAIN_COLS},
        keccak::{
            node::{
                self as node,
                trace::{KeccakNodeRequires, generate_trace as node_trace},
            },
            sponge::{
                self as sponge,
                trace::{SpongeRequires, generate_trace_padded_to as sponge_trace},
            },
        },
    },
    logup::build_logup_aux_trace,
};

/// Build the merged main trace at the largest component height. Node rows
/// can be zero-extended because they are activity-gated; chunk and sponge
/// use their own padding generators to preserve unconditional chains.
pub fn generate_trace(
    chunk: ChunkRequires,
    node: KeccakNodeRequires,
    sponge: SpongeRequires,
) -> RowMajorMatrix<Felt> {
    let mut node_main = node_trace(node);
    let node_height = node_main.height();
    let sponge_main = sponge_trace(sponge, node_height);
    let chunk_main = chunk_trace(chunk, sponge_main.height());
    let height = chunk_main.height();
    // The sponge uses at least 32 rows per invocation and therefore
    // dominates the chunk trace's ceil(len / 32) rows.
    assert_eq!(
        height,
        sponge_main.height(),
        "the sponge band's height must dominate the chunk band's"
    );
    node_main.values.resize(height * node::NUM_MAIN_COLS, Felt::ZERO);

    let mut vals = Vec::with_capacity(height * NUM_MAIN_COLS);
    for r in 0..height {
        vals.extend_from_slice(
            &chunk_main.values[r * chunk::NUM_MAIN_COLS..(r + 1) * chunk::NUM_MAIN_COLS],
        );
        vals.extend_from_slice(
            &node_main.values[r * node::NUM_MAIN_COLS..(r + 1) * node::NUM_MAIN_COLS],
        );
        vals.extend_from_slice(
            &sponge_main.values[r * sponge::NUM_MAIN_COLS..(r + 1) * sponge::NUM_MAIN_COLS],
        );
    }
    debug_assert_eq!(vals.len(), height * NUM_MAIN_COLS);

    RowMajorMatrix::new(vals, NUM_MAIN_COLS)
}

/// Build the merged chiplet's LogUp trace.
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    build_logup_aux_trace(&ChunkNodeSpongeAir, main, challenges)
}
