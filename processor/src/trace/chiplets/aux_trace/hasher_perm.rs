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

    // The hasher is always the first chiplet, so its trace starts at row 0.
    // This invariant is required for the cycle_pos calculation below.
    assert!(
        main_trace.is_hash_row(RowIndex::from(0u32)),
        "hasher chiplet must start at row 0"
    );

    // TODO: batch inversion
    for row_idx in 0..(num_rows - 1) {
        let row: RowIndex = (row_idx as u32).into();

        if !main_trace.is_hash_row(row) {
            running_sum[row_idx + 1] = running_sum[row_idx];
            continue;
        }

        let perm_seg = main_trace.chiplet_perm_seg(row);
        // Hasher-internal sub-selectors (only meaningful on controller rows):
        // s0 = chiplets[1] (input flag), s1 = chiplets[2].
        let s0 = main_trace.chiplet_selector_1(row);
        let s1 = main_trace.chiplet_selector_2(row);

        if perm_seg == Felt::ZERO {
            // Controller region
            if s0 == Felt::ONE {
                // Controller input row: +1/msg_in
                let msg_in = encode_perm_link_message(main_trace, row, challenges, LABEL_IN);
                running_sum[row_idx + 1] = running_sum[row_idx] + msg_in.inverse();
            } else if s0 == Felt::ZERO && s1 == Felt::ZERO {
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
                // Perm boundary row (row 15 in the packed 16-row cycle): -m/msg_out
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
    // Build message manually using alpha (not bus_prefix) to match the AIR constraint
    // in wiring.rs::encode_perm_link_message which also uses challenges.alpha directly.
    let mut acc = challenges.alpha;
    acc += challenges.beta_powers[0] * E::from(label);
    for (i, &s) in state.iter().enumerate().take(STATE_WIDTH) {
        acc += challenges.beta_powers[1 + i] * E::from(s);
    }
    acc
}
