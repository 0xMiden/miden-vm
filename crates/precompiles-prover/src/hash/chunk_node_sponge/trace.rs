//! Trace generation for chunk and node records sharing idle sponge cells.

use alloc::vec::Vec;

use miden_core::{
    Felt,
    utils::{Matrix, RowMajorMatrix},
};
use miden_precompiles_air::hash::chunk_node as layout;

use crate::hash::{
    chunk::trace::{ChunkRequires, generate_trace_padded_to as chunk_trace},
    chunk_node_sponge::NUM_MAIN_COLS,
    keccak::{
        node::{
            self,
            trace::{KeccakNodeRequires, generate_trace as node_trace},
        },
        sponge::{
            self,
            trace::{SpongeRequires, generate_trace_padded_to as sponge_trace},
        },
    },
};

/// Serialize one node and seven chunks into each 32-row sponge period.
///
/// Session allocation provides at least one sponge period per node. For input length `n`,
/// `max(1, ceil(n / 32)) <= 5 * (floor(n / 136) + 1)`, so seven chunk slots per period
/// suffice without increasing the sponge height. Independent accumulators must satisfy these
/// capacities too; inconsistent counts panic before the composite trace is allocated.
pub fn generate_trace(
    chunk: ChunkRequires,
    node: KeccakNodeRequires,
    sponge: SpongeRequires,
) -> RowMajorMatrix<Felt> {
    let node_count = node.total_rows() as usize;
    let chunk_count = chunk.total_chunks() as usize;
    let sponge_main = sponge_trace(sponge, 0);
    let height = sponge_main.height();
    let periods = height / sponge::SPONGE_PERIOD;
    assert!(node_count <= periods, "one node slot is available per sponge period");
    let chunk_slots = periods * layout::CHUNK_ROWS.len();
    assert!(chunk_count <= chunk_slots, "seven chunk slots are available per sponge period");
    let node_main = node_trace(node);
    let chunk_main = chunk_trace(chunk, chunk_slots.next_power_of_two());

    let mut values = Vec::with_capacity(height * NUM_MAIN_COLS);
    let mut sponge_head = Felt::ZERO;
    let mut chunk_head = Felt::ZERO;
    let mut chunk_seq = 0usize;
    // The first chunk has no predecessor in the logical ChunkAir trace. Before its slot,
    // this value makes the increment check valid even when the first chunk is inactive.
    let mut chunk_id = chunk_main.values[1] - Felt::ONE;
    let mut chunk_act = chunk_main.values[2];
    let empty_node = [Felt::ZERO; node::NUM_MAIN_COLS];

    for row in 0..height {
        let period = row / sponge::SPONGE_PERIOD;
        let phase = row % sponge::SPONGE_PERIOD;
        let n = if period < node_count {
            &node_main.values[period * node::NUM_MAIN_COLS..(period + 1) * node::NUM_MAIN_COLS]
        } else {
            &empty_node
        };
        let mut output = [Felt::ZERO; NUM_MAIN_COLS];
        output[..sponge::NUM_MAIN_COLS].copy_from_slice(
            &sponge_main.values[row * sponge::NUM_MAIN_COLS..(row + 1) * sponge::NUM_MAIN_COLS],
        );
        output[layout::COL_NODE_ACT] = n[node::COL_ACT];
        output[layout::COL_SPONGE_HEAD] = sponge_head;
        output[layout::COL_CHUNK_HEAD] = chunk_head;

        if (layout::NODE_ROW_START..layout::NODE_ROW_START + 7).contains(&phase) {
            let step = phase - layout::NODE_ROW_START;
            output[layout::COL_NODE_PERMS] = if step < 4 {
                n[node::COL_N_SPONGE_PERMS]
            } else {
                n[node::COL_ABSORPTION_ID_KECCAK]
            };
            output[layout::COL_NODE_CHUNKS] = n[node::COL_N_CHUNKS];
            output[layout::COL_INPUT_ID] = if step < 5 {
                n[node::COL_ABSORPTION_ID_CHUNKS]
            } else if step == 6 {
                n[node::COL_OUT_MULT]
            } else {
                Felt::ZERO
            };
            output[layout::COL_LEN] = n[node::COL_LEN_BYTES];
            output[layout::COL_DIGEST_ID] = n[node::COL_ABSORPTION_ID_DIGEST_CHUNKS];
            let payload = match step {
                0 => {
                    [n[node::COL_LAST_CHUNK_REM], n[node::COL_N_CHUNKS_INV], Felt::ZERO, Felt::ZERO]
                },
                1 => [Felt::ZERO; 4],
                2 => n[node::COL_D_BEGIN..node::COL_D_BEGIN + 4].try_into().unwrap(),
                3 => n[node::COL_D_BEGIN + 4..node::COL_D_END].try_into().unwrap(),
                4 => n[node::COL_H_INPUT_CHUNKS_BEGIN..node::COL_H_INPUT_CHUNKS_END]
                    .try_into()
                    .unwrap(),
                5 => n[node::COL_H_DIGEST_CHUNKS_BEGIN..node::COL_H_DIGEST_CHUNKS_END]
                    .try_into()
                    .unwrap(),
                6 => n[node::COL_H_KECCAK_BEGIN..node::COL_H_KECCAK_END].try_into().unwrap(),
                _ => unreachable!(),
            };
            for (column, value) in layout::PAYLOAD.into_iter().zip(payload) {
                output[column] = value;
            }
            if step == 3 {
                sponge_head += n[node::COL_N_SPONGE_PERMS] * Felt::from(32u8);
            }
            if step == 6 {
                chunk_head += n[node::COL_N_CHUNKS];
            }
        }

        let is_chunk = layout::CHUNK_ROWS.contains(&phase);
        if is_chunk {
            let source = &chunk_main.values[chunk_seq * 12..(chunk_seq + 1) * 12];
            let columns = if phase == 24 {
                layout::CHUNK_CAPACITY_COLUMNS
            } else {
                layout::CHUNK_LATE_COLUMNS
            };
            for (column, &value) in columns.into_iter().zip(source) {
                output[column] = value;
            }
            chunk_id = source[1];
            chunk_act = source[2];
        }
        output[layout::COL_CHUNK_SEQ] =
            Felt::new(chunk_seq as u64).expect("chunk sequence fits the field");
        output[layout::COL_CHUNK_ID] = chunk_id;
        output[layout::COL_CHUNK_ACT] = chunk_act;
        values.extend(output);
        if is_chunk {
            chunk_seq += 1;
        }
    }
    RowMajorMatrix::new(values, NUM_MAIN_COLS)
}
