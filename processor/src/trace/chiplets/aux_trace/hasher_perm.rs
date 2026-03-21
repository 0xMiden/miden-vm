//! Hasher perm-link bus builder.
//!
//! Builds the LogUp running-sum that links hasher controller rows (dispatch) to hasher
//! permutation segment rows (compute). Each controller input/output row adds +1/msg,
//! and each permutation cycle boundary subtracts -m/msg (where m = multiplicity from
//! memoization).
//!
//! The running sum is merged into the shared v_wiring auxiliary column.

use alloc::vec::Vec;

use miden_air::trace::{
    Challenges, MainTrace, RowIndex,
    chiplets::hasher::{HASH_CYCLE_LEN, STATE_WIDTH},
};
use miden_core::{Felt, field::ExtensionField};

/// Labels for domain-separating input vs output perm-link messages.
///
/// TODO: These naive labels (0 and 1) risk collisions with other messages on the shared
/// v_wiring column (ACE wiring and memory range checks). Revisit when refactoring the buses.
const LABEL_IN: Felt = Felt::ZERO;
const LABEL_OUT: Felt = Felt::ONE;

/// Builds the hasher perm-link running sum as a prefix array.
///
/// The result is a vector of the same length as the main trace, where each entry
/// is the cumulative LogUp contribution from hasher perm-link messages up to that row.
pub fn build_perm_link_running_sum<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    challenges: &Challenges<E>,
) -> Vec<E> {
    let num_rows = main_trace.num_rows();
    let mut running_sum = vec![E::ZERO; num_rows];

    for row_idx in 0..(num_rows - 1) {
        let row: RowIndex = (row_idx as u32).into();

        if !main_trace.is_hash_row(row) {
            running_sum[row_idx + 1] = running_sum[row_idx];
            continue;
        }

        let perm_seg = main_trace.chiplet_perm_seg(row);
        let hs0 = main_trace.chiplet_selector_1(row);
        let hs1 = main_trace.chiplet_selector_2(row);

        if perm_seg == Felt::ZERO {
            // Controller region
            if hs0 == Felt::ONE {
                // Controller input row: +1/msg_in
                let msg_in = encode_perm_link_message(main_trace, row, challenges, LABEL_IN);
                running_sum[row_idx + 1] = running_sum[row_idx] + msg_in.inverse();
            } else if hs0 == Felt::ZERO && hs1 == Felt::ZERO {
                // Controller output row (RETURN_HASH or RETURN_STATE with s0=0, s1=0): +1/msg_out
                let msg_out = encode_perm_link_message(main_trace, row, challenges, LABEL_OUT);
                running_sum[row_idx + 1] = running_sum[row_idx] + msg_out.inverse();
            } else {
                running_sum[row_idx + 1] = running_sum[row_idx];
            }
        } else {
            // Permutation segment.
            // This works because the hasher is always the first chiplet (rows start at 0)
            // and the controller region is padded to a HASH_CYCLE_LEN boundary, so perm
            // cycles are aligned to global row indices.
            let cycle_pos = row_idx % HASH_CYCLE_LEN;

            if cycle_pos == 0 {
                // Perm row 0: -m/msg_in
                let m: E = main_trace.chiplet_node_index(row).into();
                let msg_in = encode_perm_link_message(main_trace, row, challenges, LABEL_IN);
                running_sum[row_idx + 1] = running_sum[row_idx] - m * msg_in.inverse();
            } else if cycle_pos == HASH_CYCLE_LEN - 1 {
                // Perm row 31: -m/msg_out
                let m: E = main_trace.chiplet_node_index(row).into();
                let msg_out = encode_perm_link_message(main_trace, row, challenges, LABEL_OUT);
                running_sum[row_idx + 1] = running_sum[row_idx] - m * msg_out.inverse();
            } else {
                running_sum[row_idx + 1] = running_sum[row_idx];
            }
        }
    }

    // The running sum should balance to zero (all requests matched by responses).
    assert!(
        running_sum[num_rows - 1] == E::ZERO,
        "hasher perm-link running sum did not balance to zero: {:?}",
        running_sum[num_rows - 1]
    );

    running_sum
}

/// Encodes a perm-link message: `challenges.encode([label, h0, h1, ..., h11])`.
///
/// The message includes a domain-separation label and the full 12-element hasher state.
fn encode_perm_link_message<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    row: RowIndex,
    challenges: &Challenges<E>,
    label: Felt,
) -> E {
    let state = main_trace.chiplet_hasher_state(row);
    let mut elems = [Felt::ZERO; 1 + STATE_WIDTH];
    elems[0] = label;
    elems[1..].copy_from_slice(&state);
    challenges.encode(elems)
}
