//! Sibling-table bus test (MRUPDATE add/remove pairing).
//!
//! MRUPDATE verifies the old Merkle root (MV leg, adds to sibling table) and then recomputes
//! the new root (MU leg, removes from sibling table). Each of the 3 levels of a depth-3 tree
//! emits one add on the MV leg and one remove on the MU leg, matched by `(mrupdate_id,
//! node_index, sibling_word)`.
//!
//! The test iterates every hasher controller row, picks out the MV/MU sibling-emitting rows
//! via the `(s0, s1, s2)` sub-selectors, and attaches a `SiblingMsg` expectation tagged with
//! the direction bit. Column-blind — the subset matcher finds each message regardless of
//! where the M4/C2 packing puts it.
//!
//! The old `hasher_p1_mp_verify` null-check (MPVERIFY emits no sibling messages) does not
//! translate to subset semantics and is intentionally dropped; the balanced MRUPDATE test
//! exercises both add and remove paths through the sibling bus, which is the meaningful
//! coverage.

use alloc::vec::Vec;

use miden_air::logup::{SiblingBit, SiblingMsg};
use miden_core::{
    Felt, ONE, Word, ZERO,
    crypto::merkle::{MerkleStore, MerkleTree, NodeIndex},
    operations::Operation,
};
use rstest::rstest;

use super::{
    build_trace_from_ops_with_inputs,
    lookup_harness::{Expectations, InteractionLog},
};
use crate::{AdviceInputs, RowIndex, StackInputs};

/// Drive a depth-3 Merkle MRUPDATE and assert the sibling-table bus fires one add per MV
/// controller row and one remove per MU controller row (3 levels → 3 adds + 3 removes).
#[rstest]
#[case(5_u64)]
#[case(4_u64)]
fn mrupdate_emits_sibling_add_and_remove_per_level(#[case] index: u64) {
    let (tree, _) = build_merkle_tree();
    let old_node = tree.get_node(NodeIndex::new(3, index).unwrap()).unwrap();
    let new_node = init_leaf(11);

    // Build the program inputs the way the legacy test did.
    let mut init_stack = Vec::new();
    append_word(&mut init_stack, old_node);
    init_stack.extend_from_slice(&[3, index]);
    append_word(&mut init_stack, tree.root());
    append_word(&mut init_stack, new_node);
    let stack_inputs = StackInputs::try_from_ints(init_stack).unwrap();
    let store = MerkleStore::from(&tree);
    let advice_inputs = AdviceInputs::default().with_merkle_store(store);

    let ops = vec![Operation::MrUpdate];
    let trace = build_trace_from_ops_with_inputs(ops, stack_inputs, advice_inputs);
    let log = InteractionLog::new(&trace);
    let main = trace.main_trace();

    // Collect MV / MU controller rows. A row is a sibling-table add/remove site when
    // `chiplet_active.controller = 1` (s_ctrl column) AND the hasher internal
    // `(s0, s1, s2)` sub-selectors pick out the MV-all (`s0·s1·(1-s2)`) or MU-all
    // (`s0·s1·s2`) pattern. See `air/src/constraints/lookup/buses/hash_kernel.rs`.
    let mut mv_rows: Vec<RowIndex> = Vec::new();
    let mut mu_rows: Vec<RowIndex> = Vec::new();
    for row in 0..main.num_rows() {
        let idx = RowIndex::from(row);
        if main.chiplet_selector_0(idx) != ONE || main.chiplet_s_perm(idx) != ZERO {
            continue;
        }
        let hs0 = main.chiplet_selector_1(idx);
        let hs1 = main.chiplet_selector_2(idx);
        let hs2 = main.chiplet_selector_3(idx);
        if hs0 == ONE && hs1 == ONE && hs2 == ZERO {
            mv_rows.push(idx);
        } else if hs0 == ONE && hs1 == ONE && hs2 == ONE {
            mu_rows.push(idx);
        }
    }
    assert_eq!(mv_rows.len(), 3, "depth-3 MRUPDATE should emit 3 MV sibling adds");
    assert_eq!(mu_rows.len(), 3, "depth-3 MRUPDATE should emit 3 MU sibling removes");

    let mut exp = Expectations::new(&log);
    for &row in &mv_rows {
        push_sibling(&mut exp, &trace, row, main, SiblingSide::Add);
    }
    for &row in &mu_rows {
        push_sibling(&mut exp, &trace, row, main, SiblingSide::Remove);
    }

    log.assert_contains(&exp);
}

// HELPERS
// ================================================================================================

enum SiblingSide {
    Add,
    Remove,
}

fn push_sibling(
    exp: &mut Expectations<'_>,
    _trace: &super::ExecutionTrace,
    row: RowIndex,
    main: &miden_air::trace::MainTrace,
    side: SiblingSide,
) {
    let mrupdate_id = main.chiplet_mrupdate_id(row);
    let node_index = main.chiplet_node_index(row);
    let state = main.chiplet_hasher_state(row);
    let rate_0: [Felt; 4] = [state[0], state[1], state[2], state[3]];
    let rate_1: [Felt; 4] = [state[4], state[5], state[6], state[7]];

    // Direction bit drives which rate half the sibling lives in. The trace's
    // `chiplet_direction_bit` column carries the extracted bit on Merkle controller rows.
    let bit = main.chiplet_direction_bit(row);
    let row_usize = usize::from(row);
    let (bit_tag, h) = if bit == ZERO {
        (SiblingBit::Zero, rate_1)
    } else {
        (SiblingBit::One, rate_0)
    };
    let msg = SiblingMsg { bit: bit_tag, mrupdate_id, node_index, h };
    match side {
        SiblingSide::Add => exp.add(row_usize, &msg),
        SiblingSide::Remove => exp.remove(row_usize, &msg),
    };
}

fn build_merkle_tree() -> (MerkleTree, Vec<Word>) {
    let leaves = init_leaves(&[1, 2, 3, 4, 5, 6, 7, 8]);
    (MerkleTree::new(leaves.clone()).unwrap(), leaves)
}

fn init_leaves(values: &[u64]) -> Vec<Word> {
    values.iter().map(|&v| init_leaf(v)).collect()
}

fn init_leaf(value: u64) -> Word {
    [Felt::new_unchecked(value), ZERO, ZERO, ZERO].into()
}

fn append_word(target: &mut Vec<u64>, word: Word) {
    word.iter().for_each(|v| target.push(v.as_canonical_u64()));
}
