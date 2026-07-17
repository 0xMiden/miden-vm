use alloc::vec::Vec;
use core::{borrow::Borrow, ops::Range};

use miden_air::{
    CYCLE_INPUT_ROW, CYCLE_OUTPUT_ROW, ControllerCols, INITIAL_EXTERNAL_ROUND_END,
    INITIAL_EXTERNAL_ROUND_START, INTERNAL_PLUS_EXTERNAL_ROW, LAST_INTERNAL_ROUND_ARK_IDX,
    NUM_PACKED_INTERNAL_ROUND_ROWS, NUM_SBOX_WITNESSES, NUM_TRAILING_EXTERNAL_ROUND_ROWS,
    PACKED_INTERNAL_ROUND_START, Poseidon2PermutationCols,
    trace::{
        chiplets::hasher::{CONTROLLER_TRACE_ALIGNMENT, HASH_CYCLE_LEN, TRACE_WIDTH},
        poseidon2_permutation::NUM_POSEIDON2_PERMUTATION_COLS,
    },
};
use miden_core::{
    ONE, ZERO,
    chiplets::hasher,
    crypto::merkle::{MerkleTree, NodeIndex},
    field::PrimeCharacteristicRing,
    mast::OpBatch,
};
use miden_utils_testing::rand::rand_array;

use super::{
    ChipletTraceFragment, Digest, Felt, Hasher, HasherState, LINEAR_HASH, MP_VERIFY, MR_UPDATE_NEW,
    MR_UPDATE_OLD, RETURN_HASH, RETURN_STATE, Selectors, absorb_into_state, get_digest, init_state,
    init_state_from_words,
};

// SPONGE MODE TESTS
// ================================================================================================

#[test]
fn hasher_permute() {
    // --- test one permutation (HPERM) ---
    let mut hasher = Hasher::default();
    let init_state: HasherState = rand_array();

    let (addr, final_state) = hasher.permute(init_state);
    assert_eq!(ONE, addr);

    let expected_state = apply_permutation(init_state);
    assert_eq!(expected_state, final_state);

    let trace = build_trace(hasher);

    assert_eq!(trace.controller.len(), controller_len(2));
    assert_eq!(trace.poseidon2.len(), 2 * HASH_CYCLE_LEN);

    // Row 0: input (LINEAR_HASH, is_boundary=1)
    check_controller_input(&trace.controller, 0, LINEAR_HASH, &init_state, ZERO, ONE, ZERO, ZERO);
    // Row 1: output (RETURN_STATE, is_boundary=1)
    check_controller_output(&trace.controller, 1, RETURN_STATE, &expected_state, ZERO, ONE, ZERO);

    check_perm_segment(&trace.poseidon2, 0, &init_state, ONE);
}

#[test]
fn hasher_permute_two() {
    let mut hasher = Hasher::default();
    let init_state1: HasherState = rand_array();
    let init_state2: HasherState = rand_array();

    let (addr1, final_state1) = hasher.permute(init_state1);
    let (addr2, final_state2) = hasher.permute(init_state2);

    // Addresses are 2 rows apart (controller pairs)
    assert_eq!(ONE, addr1);
    assert_eq!(Felt::from_u8(3), addr2);

    assert_eq!(apply_permutation(init_state1), final_state1);
    assert_eq!(apply_permutation(init_state2), final_state2);

    let trace = build_trace(hasher);

    assert_eq!(trace.controller.len(), controller_len(4));
    assert_eq!(trace.poseidon2.len(), 3 * HASH_CYCLE_LEN);

    // Pair 1
    check_controller_input(&trace.controller, 0, LINEAR_HASH, &init_state1, ZERO, ONE, ZERO, ZERO);
    check_controller_output(&trace.controller, 1, RETURN_STATE, &final_state1, ZERO, ONE, ZERO);
    // Pair 2
    check_controller_input(&trace.controller, 2, LINEAR_HASH, &init_state2, ZERO, ONE, ZERO, ZERO);
    check_controller_output(&trace.controller, 3, RETURN_STATE, &final_state2, ZERO, ONE, ZERO);
}

// TREE MODE TESTS
// ================================================================================================

/// Merkle tree with 2 leaves (depth 1):
///
/// ```text
///     root
///    /    \
///  L0      L1
/// ```
///
/// Verifying the path from L0 to root requires 1 controller pair.
#[test]
fn hasher_build_merkle_root_depth_1() {
    let leaves = init_leaves(&[1, 2]);
    let tree = MerkleTree::new(&leaves).unwrap();

    let mut hasher = Hasher::default();
    let path0 = tree.get_path(NodeIndex::new(1, 0).unwrap()).unwrap();
    let (_, root) = hasher.build_merkle_root(leaves[0], &path0, ZERO);

    assert_eq!(root, tree.root());

    let trace = build_trace(hasher);

    // Row 0: input (MP_VERIFY, is_boundary=1, node_index=0)
    let init_state = init_state_from_words(&leaves[0], &path0[0]);
    check_controller_input(&trace.controller, 0, MP_VERIFY, &init_state, ZERO, ONE, ZERO, ZERO);
    // Row 1: output (RETURN_HASH, is_boundary=1, node_index=0)
    check_controller_output(
        &trace.controller,
        1,
        RETURN_HASH,
        &apply_permutation(init_state),
        ZERO,
        ONE,
        ZERO,
    );
}

/// Merkle tree with 8 leaves (depth 3):
///
/// ```text
///               root
///             /      \
///          N(1,0)    N(1,1)
///          /   \      /   \
///       N20    N21  N22   N23
///       / \   / \   / \   / \
///      L0 L1 L2 L3 L4 L5 L6 L7
/// ```
///
/// Verifying the path from L5 (node_index=5) to root requires 3 controller pairs.
/// The node_index shifts right by 1 at each level: 5 -> 2 -> 1 -> 0.
#[test]
fn hasher_build_merkle_root_depth_3() {
    let leaves = init_leaves(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(&leaves).unwrap();

    let mut hasher = Hasher::default();
    let path = tree.get_path(NodeIndex::new(3, 5).unwrap()).unwrap();
    let (_, root) = hasher.build_merkle_root(leaves[5], &path, Felt::from_u8(5));

    assert_eq!(root, tree.root());

    let trace = build_trace(hasher);

    // Depth 3: 3 controller pairs = 6 rows
    // Index=5 (binary 101): direction bits are LSBs at each level
    // Pair 0 (rows 0-1): node_index 5 -> 2, b_0=5&1=1, b_next=(5>>1)&1=0
    check_merkle_controller_pair(&trace.controller, 0, MP_VERIFY, 5, true, false, ZERO, ONE, ZERO);
    // Pair 1 (rows 2-3): node_index 2 -> 1, b_1=2&1=0, b_next=(2>>1)&1=1
    check_merkle_controller_pair(&trace.controller, 2, MP_VERIFY, 2, false, false, ZERO, ZERO, ONE);
    // Pair 2 (rows 4-5): node_index 1 -> 0, b_2=1&1=1, b_next=0 (last step)
    check_merkle_controller_pair(&trace.controller, 4, MP_VERIFY, 1, false, true, ZERO, ONE, ZERO);

    // Capacity is zero on all tree-mode input rows
    for row in [0, 2, 4] {
        for (i, value) in controller_row(&trace.controller, row).capacity().into_iter().enumerate()
        {
            assert_eq!(value, ZERO, "capacity[{i}] should be zero on tree input row {row}");
        }
    }
}

#[test]
fn hasher_update_merkle_root() {
    let leaves = init_leaves(&[1, 2, 3, 4]);
    let tree = MerkleTree::new(&leaves).unwrap();

    let mut hasher = Hasher::default();
    let index = 1u64;
    let path = tree.get_path(NodeIndex::new(2, index).unwrap()).unwrap();
    let new_leaf: Digest = [Felt::from_u8(100), ZERO, ZERO, ZERO].into();

    let update = hasher.update_merkle_root(
        leaves[index as usize],
        new_leaf,
        &path,
        Felt::new_unchecked(index),
    );

    assert_eq!(update.get_old_root(), tree.root());

    let trace = build_trace(hasher);

    // Depth 2: 2 pairs for MV (old path) + 2 pairs for MU (new path) = 8 controller rows.
    // All rows share mrupdate_id=1.

    // MV leg (old path): rows 0-3
    // Index=1 (binary 01): direction bits are LSBs at each level
    // Pair 0 (rows 0-1): node_index 1 -> 0, b_0=1&1=1, b_next=(1>>1)&1=0
    check_merkle_controller_pair(
        &trace.controller,
        0,
        MR_UPDATE_OLD,
        1,
        true,
        false,
        ONE,
        ONE,
        ZERO,
    );
    // Pair 1 (rows 2-3): node_index 0 -> 0, b_1=0&1=0, b_next=0 (last step)
    check_merkle_controller_pair(
        &trace.controller,
        2,
        MR_UPDATE_OLD,
        0,
        false,
        true,
        ONE,
        ZERO,
        ZERO,
    );

    // MU leg (new path): rows 4-7
    // Same index, same direction bits
    // Pair 0 (rows 4-5): node_index 1 -> 0, b_0=1&1=1, b_next=(1>>1)&1=0
    check_merkle_controller_pair(
        &trace.controller,
        4,
        MR_UPDATE_NEW,
        1,
        true,
        false,
        ONE,
        ONE,
        ZERO,
    );
    // Pair 1 (rows 6-7): node_index 0 -> 0, b_1=0&1=0, b_next=0 (last step)
    check_merkle_controller_pair(
        &trace.controller,
        6,
        MR_UPDATE_NEW,
        0,
        false,
        true,
        ONE,
        ZERO,
        ZERO,
    );
}

// POSEIDON2 TRACE TESTS
// ================================================================================================

#[test]
fn poseidon2_trace_structure() {
    // One request produces one multiplicity-1 cycle plus one zero-multiplicity padding cycle.
    let mut hasher = Hasher::default();
    let init_state: HasherState = rand_array();
    let (addr, result) = hasher.permute(init_state);

    // Verify returned address and permuted state
    assert_eq!(addr, ONE, "first permutation should start at address 1");
    assert_eq!(result, apply_permutation(init_state), "permuted state should match");

    let trace = build_trace(hasher);

    assert_eq!(trace.poseidon2.len(), 2 * HASH_CYCLE_LEN);
    let perm_start = 0;

    // Witness columns are zero on external rows. Packed-internal rows
    // (4-10) use all three witnesses; the mixed int+ext row (11) uses only witness 0.
    // Rows 1-3 and 12-14: witnesses should be zero.
    for offset in [1, 2, 3, 12, 13, 14] {
        let row = perm_start + offset;
        let cols = poseidon2_row(&trace.poseidon2, row);
        assert_eq!(cols.witnesses[0], ZERO, "perm row {row}: witness 0 should be zero");
        assert_eq!(cols.witnesses[1], ZERO, "perm row {row}: witness 1 should be zero");
        assert_eq!(cols.witnesses[2], ZERO, "perm row {row}: witness 2 should be zero");
    }
    // Rows 0 and 15 carry the link multiplicity in witness 0.
    for offset in [0, 15] {
        let row = perm_start + offset;
        let cols = poseidon2_row(&trace.poseidon2, row);
        assert_eq!(cols.witnesses[0], ONE, "perm row {row}: multiplicity mismatch");
        assert_eq!(cols.witnesses[1], ZERO, "perm row {row}: witness 1 should be zero");
        assert_eq!(cols.witnesses[2], ZERO, "perm row {row}: witness 2 should be zero");
    }
    // Row 11: witnesses 1 and 2 are zero.
    let row_11 = perm_start + 11;
    let row_11_cols = poseidon2_row(&trace.poseidon2, row_11);
    assert_eq!(
        row_11_cols.witnesses[1], ZERO,
        "perm row {row_11}: witness 1 should be zero on int+ext row"
    );
    assert_eq!(
        row_11_cols.witnesses[2], ZERO,
        "perm row {row_11}: witness 2 should be zero on int+ext row"
    );

    assert_eq!(poseidon2_row(&trace.poseidon2, perm_start).witnesses[0], ONE);
    assert_eq!(
        poseidon2_row(&trace.poseidon2, HASH_CYCLE_LEN).witnesses[0],
        ZERO,
        "the final Poseidon2 cycle closes the accumulator"
    );
    assert_eq!(poseidon2_row(&trace.poseidon2, perm_start).perm_id, ZERO);
    assert_eq!(poseidon2_row(&trace.poseidon2, HASH_CYCLE_LEN).perm_id, ONE);
}

#[test]
fn poseidon2_trace_deduplication() {
    // Two requests with the same input share one multiplicity-2 cycle.
    let mut hasher = Hasher::default();
    let init_state: HasherState = rand_array();
    let (addr1, result1) = hasher.permute(init_state);
    let (addr2, result2) = hasher.permute(init_state); // same state

    // Both should produce the same result but at different addresses
    assert_eq!(result1, result2, "same input should produce same output");
    assert_ne!(addr1, addr2, "second call should have a different address");

    let trace = build_trace(hasher);

    assert_eq!(trace.controller.len(), controller_len(4));
    assert_eq!(trace.poseidon2.len(), 2 * HASH_CYCLE_LEN);

    assert_eq!(poseidon2_row(&trace.poseidon2, 0).witnesses[0], Felt::from_u8(2));
}

// MEMOIZATION TESTS
// ================================================================================================

#[test]
fn hash_memoization_control_blocks() {
    let h1: Digest = rand_array::<Felt, 4>().into();
    let h2: Digest = rand_array::<Felt, 4>().into();
    let domain = Felt::from_u8(7); // arbitrary domain

    // Compute the expected hash
    let state = super::init_state_from_words_with_domain(&h1, &h2, domain);
    let permuted = apply_permutation(state);
    let expected_hash: Digest = get_digest(&permuted);

    let mut hasher = Hasher::default();

    let (addr1, digest1) = hasher.hash_control_block(h1, h2, domain, expected_hash);
    let (addr2, digest2) = hasher.hash_control_block(h1, h2, domain, expected_hash);

    assert_eq!(digest1, digest2);
    assert_eq!(digest1, expected_hash);
    // Second call uses memoized trace at a different address
    assert_ne!(addr1, addr2);

    let trace = build_trace(hasher);

    assert_eq!(trace.controller.len(), controller_len(4));
    assert_eq!(trace.poseidon2.len(), 2 * HASH_CYCLE_LEN);

    assert_eq!(poseidon2_row(&trace.poseidon2, 0).witnesses[0], Felt::from_u8(2));
}

// BASIC BLOCK MEMOIZATION TESTS
// ================================================================================================

#[test]
fn hash_memoization_basic_blocks_single_batch() {
    // Test that hashing the same single-batch basic block twice uses memoization:
    // the second call copies the controller rows and reuses the perm cycle (multiplicity 2).
    let mut hasher = Hasher::default();

    let batches = make_single_batch();
    let expected_hash = compute_basic_block_hash(&batches);

    let (addr1, digest1) = hasher.hash_basic_block(&batches, expected_hash);
    let (addr2, digest2) = hasher.hash_basic_block(&batches, expected_hash);

    assert_eq!(digest1, digest2, "memoized digest should match original");
    assert_eq!(digest1, expected_hash);
    assert_ne!(addr1, addr2, "memoized call should have a different address");

    let trace = build_trace(hasher);

    assert_eq!(trace.controller.len(), controller_len(4));
    assert_eq!(trace.poseidon2.len(), 2 * HASH_CYCLE_LEN);

    // Verify first call: rows 0-1
    check_controller_input(
        &trace.controller,
        0,
        LINEAR_HASH,
        &init_state(batches[0].groups(), ZERO),
        ZERO,
        ONE,
        ZERO,
        ZERO,
    );
    check_controller_output(
        &trace.controller,
        1,
        RETURN_HASH,
        &apply_permutation(init_state(batches[0].groups(), ZERO)),
        ZERO,
        ONE,
        ZERO,
    );

    // Verify memoized call: rows 2-3 should match rows 0-1 in selectors and state
    check_memoized_trace(&trace.controller, 0..2, 2..4);

    assert_eq!(poseidon2_row(&trace.poseidon2, 0).witnesses[0], Felt::from_u8(2));
}

#[test]
fn hash_memoization_basic_blocks_multi_batch() {
    // Test memoization of a multi-batch basic block (3 batches).
    // The second call should copy all 3 controller pairs and re-register all 3 perm requests.
    let mut hasher = Hasher::default();

    let batches = make_multi_batch(3);
    let expected_hash = compute_basic_block_hash(&batches);

    let (addr1, digest1) = hasher.hash_basic_block(&batches, expected_hash);
    let (addr2, digest2) = hasher.hash_basic_block(&batches, expected_hash);

    assert_eq!(digest1, digest2);
    assert_eq!(digest1, expected_hash);
    assert_ne!(addr1, addr2);

    let trace = build_trace(hasher);

    assert_eq!(trace.controller.len(), controller_len(12));
    assert_eq!(trace.poseidon2.len(), 4 * HASH_CYCLE_LEN);

    // Verify first call: rows 0-5 (3 pairs)
    // Row 0: first batch input, is_boundary=1 (start)
    assert_eq!(controller_row(&trace.controller, 0).is_boundary, ONE);
    assert_eq!(controller_row(&trace.controller, 0).direction_bit, ZERO);
    // Row 1: first batch output, is_boundary=0 (not final)
    assert_eq!(controller_row(&trace.controller, 1).is_boundary, ZERO);
    assert_eq!(controller_row(&trace.controller, 1).direction_bit, ZERO);
    // Row 2: second batch input, is_boundary=0 (continuation)
    assert_eq!(controller_row(&trace.controller, 2).is_boundary, ZERO);
    // Row 4: third batch input, is_boundary=0 (continuation)
    assert_eq!(controller_row(&trace.controller, 4).is_boundary, ZERO);
    // Row 5: third batch output, is_boundary=1 (final)
    assert_eq!(controller_row(&trace.controller, 5).is_boundary, ONE);

    // Verify memoized call: rows 6-11 should match rows 0-5
    check_memoized_trace(&trace.controller, 0..6, 6..12);

    // Perm segment: each of the 3 unique states should have multiplicity 2
    for i in 0..3 {
        let cycle_start = i * HASH_CYCLE_LEN;
        assert_eq!(
            poseidon2_row(&trace.poseidon2, cycle_start).witnesses[0],
            Felt::from_u8(2),
            "perm cycle {i} should have multiplicity 2"
        );
    }
}

#[test]
fn hash_memoization_basic_blocks_check() {
    // Tree structure:
    //
    //           Join1
    //          /    \
    //       Join2    BB2 (memoized from BB1)
    //       /  \
    //     BB1   Loop_body
    //
    // BB1 and BB2 are identical 2-batch basic blocks. When BB2 is hashed,
    // it should be memoized from BB1's trace, so BB1's perm states get multiplicity 2.
    //
    // Expected controller row layout:
    // Rows 0-3:   BB1 (2 batches = 2 pairs)
    // Rows 4-5:   Loop body (1 batch = 1 pair)
    // Rows 6-7:   Join2 (1 pair)
    // Rows 8-11:  BB2 memoized (2 pairs, copied from BB1)
    // Rows 12-13: Join1 (1 pair)
    let mut hasher = Hasher::default();

    let batches = make_multi_batch(2);
    let bb_hash = compute_basic_block_hash(&batches);

    // Hash a loop body (different block) to interleave
    let loop_body_batches = make_single_batch();
    let loop_body_hash = compute_basic_block_hash(&loop_body_batches);

    // BB1: 2-batch basic block
    let (bb1_addr, bb1_digest) = hasher.hash_basic_block(&batches, bb_hash);
    assert_eq!(bb1_digest, bb_hash);

    // Loop body: different block in between
    let (_loop_addr, loop_digest) = hasher.hash_basic_block(&loop_body_batches, loop_body_hash);
    assert_eq!(loop_digest, loop_body_hash);

    // Hash Join2 = hash(BB1, Loop)
    let join2_state =
        super::init_state_from_words_with_domain(&bb1_digest, &loop_digest, Felt::from_u8(7));
    let join2_permuted = apply_permutation(join2_state);
    let join2_hash = get_digest(&join2_permuted);
    let (_join2_addr, join2_digest) =
        hasher.hash_control_block(bb1_digest, loop_digest, Felt::from_u8(7), join2_hash);
    assert_eq!(join2_digest, join2_hash);

    // BB2: identical to BB1 -- should be memoized
    let (bb2_addr, bb2_digest) = hasher.hash_basic_block(&batches, bb_hash);
    assert_eq!(bb2_digest, bb_hash);
    assert_ne!(bb1_addr, bb2_addr, "memoized BB2 should have a different address");

    // Hash Join1 = hash(Join2, BB2)
    let join1_state =
        super::init_state_from_words_with_domain(&join2_digest, &bb2_digest, Felt::from_u8(7));
    let join1_permuted = apply_permutation(join1_state);
    let join1_hash = get_digest(&join1_permuted);
    let (_join1_addr, join1_digest) =
        hasher.hash_control_block(join2_digest, bb2_digest, Felt::from_u8(7), join1_hash);
    assert_eq!(join1_digest, join1_hash);

    let trace = build_trace(hasher);

    // Verify BB2's controller rows (the memoized copy) match BB1's original rows.
    // BB1 is at rows 0..4 (2 batches = 2 pairs = 4 rows).
    // Loop body is at rows 4..6 (1 batch = 1 pair = 2 rows).
    // Join2 is at rows 6..8 (1 pair).
    // BB2 (memoized) is at rows 8..12.
    // Join1 is at rows 12..14.
    let bb1_start = bb1_addr.as_canonical_u64() as usize - 1;
    let bb2_start = bb2_addr.as_canonical_u64() as usize - 1;
    check_memoized_trace(&trace.controller, bb1_start..bb1_start + 4, bb2_start..bb2_start + 4);

    // Verify perm multiplicities: BB1's 2 perm states should each have multiplicity 2
    // (original from BB1 + memoized from BB2). The loop body's perm state and the two
    // join perm states should each have multiplicity 1.
    // Count unique perm states: BB1 has 2 unique states (2 batches), loop body has 1,
    // join2 has 1, join1 has 1 = 5 unique states total (unless some coincide, which is
    // astronomically unlikely with random groups).
    // BB2 is memoized so its 2 states are the same as BB1's.
    // The Poseidon2 trace also contains one zero-multiplicity cycle for accumulator closure.

    let num_perm_cycles = trace.poseidon2.len() / HASH_CYCLE_LEN;

    // We should have at least 5 perm cycles (2 from BB + 1 loop + 2 joins)
    assert!(num_perm_cycles >= 5, "expected at least 5 perm cycles, got {num_perm_cycles}");

    // Count how many perm cycles have multiplicity 2 vs 1
    let mut mult_2_count = 0;
    let mut mult_1_count = 0;
    for i in 0..num_perm_cycles {
        let cycle_start = i * HASH_CYCLE_LEN;
        let mult = poseidon2_row(&trace.poseidon2, cycle_start).witnesses[0];
        if mult == Felt::from_u8(2) {
            mult_2_count += 1;
        } else if mult == ONE {
            mult_1_count += 1;
        }
    }

    // BB1's 2 perm states should have multiplicity 2 (from BB1 + BB2 memoized)
    assert_eq!(mult_2_count, 2, "expected 2 perm cycles with multiplicity 2 (BB1's states)");
    // The remaining states (loop body, join2, join1) should have multiplicity 1
    assert_eq!(mult_1_count, 3, "expected 3 perm cycles with multiplicity 1");
}

// HELPER FUNCTIONS
// ================================================================================================

struct HasherTestTrace {
    controller: Vec<[Felt; TRACE_WIDTH]>,
    poseidon2: Vec<[Felt; NUM_POSEIDON2_PERMUTATION_COLS]>,
}

fn controller_len(controller_rows: usize) -> usize {
    controller_rows.next_multiple_of(CONTROLLER_TRACE_ALIGNMENT)
}

/// Builds the hasher controller and Poseidon2-permutation traces.
fn build_trace(hasher: Hasher) -> HasherTestTrace {
    let trace_len = hasher.trace_len();
    let mut band = Felt::zero_vec(TRACE_WIDTH * trace_len);
    let mut fragment = ChipletTraceFragment::row_major(&mut band, TRACE_WIDTH, 0, TRACE_WIDTH);

    let poseidon2_len = hasher.poseidon2_permutation_trace_len();
    let mut poseidon2_band = Felt::zero_vec(NUM_POSEIDON2_PERMUTATION_COLS * poseidon2_len);

    hasher.fill_trace(&mut fragment, &mut poseidon2_band);

    let (controller, controller_remainder) = band.as_chunks::<TRACE_WIDTH>();
    debug_assert!(controller_remainder.is_empty());

    let (poseidon2, poseidon2_remainder) =
        poseidon2_band.as_chunks::<NUM_POSEIDON2_PERMUTATION_COLS>();
    debug_assert!(poseidon2_remainder.is_empty());

    HasherTestTrace {
        controller: controller.to_vec(),
        poseidon2: poseidon2.to_vec(),
    }
}

fn controller_row(trace: &[[Felt; TRACE_WIDTH]], row: usize) -> &ControllerCols<Felt> {
    trace[row][..].borrow()
}

fn poseidon2_row(
    trace: &[[Felt; NUM_POSEIDON2_PERMUTATION_COLS]],
    row: usize,
) -> &Poseidon2PermutationCols<Felt> {
    trace[row][..].borrow()
}

/// Checks a controller input row.
fn check_controller_input(
    trace: &[[Felt; TRACE_WIDTH]],
    row: usize,
    selectors: Selectors,
    state: &HasherState,
    node_index: Felt,
    is_boundary: Felt,
    mrupdate_id: Felt,
    direction_bit: Felt,
) {
    let cols = controller_row(trace, row);

    assert_eq!([cols.s0, cols.s1, cols.s2], selectors, "selectors at row {row}");
    assert_eq!(cols.state, *state, "state at row {row}");
    assert_eq!(cols.node_index, node_index, "node_index at row {row}");
    assert_eq!(cols.is_boundary, is_boundary, "is_boundary at row {row}");
    assert_eq!(cols.direction_bit, direction_bit, "direction_bit at row {row}");
    assert_eq!(cols.mrupdate_id, mrupdate_id, "mrupdate_id at row {row}");
}

/// Checks a controller output row.
fn check_controller_output(
    trace: &[[Felt; TRACE_WIDTH]],
    row: usize,
    selectors: Selectors,
    state: &HasherState,
    node_index: Felt,
    is_boundary: Felt,
    direction_bit: Felt,
) {
    let cols = controller_row(trace, row);
    let input_cols = controller_row(trace, row - 1);

    assert_eq!([cols.s0, cols.s1, cols.s2], selectors, "selectors at row {row}");
    assert_eq!(cols.state, *state, "state at row {row}");
    assert_eq!(cols.node_index, node_index, "node_index at row {row}");
    assert_eq!(cols.is_boundary, is_boundary, "is_boundary at row {row}");
    assert_eq!(cols.direction_bit, direction_bit, "direction_bit at row {row}");
    assert_eq!(
        cols.perm_id,
        input_cols.perm_id,
        "perm_id mismatch between controller rows {} and {row}",
        row - 1
    );
}

/// Checks both the input and output rows of a Merkle controller pair.
///
/// A Merkle pair consists of:
/// - Input row (`input_row`): has `input_selectors`, `node_index`, `is_boundary_input` flag.
/// - Output row (`input_row + 1`): has `node_index >> 1`, `is_boundary_output` flag.
///
/// Both rows must have the given `mrupdate_id`.
fn check_merkle_controller_pair(
    trace: &[[Felt; TRACE_WIDTH]],
    input_row: usize,
    input_selectors: Selectors,
    node_index: u64,
    is_boundary_input: bool,
    is_boundary_output: bool,
    mrupdate_id: Felt,
    input_direction_bit: Felt,
    output_direction_bit: Felt,
) {
    let output_row = input_row + 1;
    let is_boundary_input_felt = if is_boundary_input { ONE } else { ZERO };
    let is_boundary_output_felt = if is_boundary_output { ONE } else { ZERO };
    let input_cols = controller_row(trace, input_row);
    let output_cols = controller_row(trace, output_row);

    // Input row: selectors, node_index, is_boundary, direction_bit.
    assert_eq!(
        [input_cols.s0, input_cols.s1, input_cols.s2],
        input_selectors,
        "selectors at input row {input_row}"
    );
    assert_eq!(
        input_cols.node_index,
        Felt::new_unchecked(node_index),
        "node_index at input row {input_row}"
    );
    assert_eq!(
        input_cols.is_boundary, is_boundary_input_felt,
        "is_boundary at input row {input_row}"
    );
    assert_eq!(
        input_cols.direction_bit, input_direction_bit,
        "direction_bit at input row {input_row}"
    );
    assert_eq!(input_cols.mrupdate_id, mrupdate_id, "mrupdate_id at input row {input_row}");

    // Output row: node_index >> 1, is_boundary, direction_bit.
    assert_eq!(
        output_cols.node_index,
        Felt::new_unchecked(node_index >> 1),
        "node_index at output row {output_row}"
    );
    assert_eq!(
        output_cols.is_boundary, is_boundary_output_felt,
        "is_boundary at output row {output_row}"
    );
    assert_eq!(
        output_cols.direction_bit, output_direction_bit,
        "direction_bit at output row {output_row}"
    );
    assert_eq!(output_cols.mrupdate_id, mrupdate_id, "mrupdate_id at output row {output_row}");
    assert_eq!(
        output_cols.perm_id, input_cols.perm_id,
        "perm_id mismatch between input row {input_row} and output row {output_row}"
    );
}

/// Checks a 16-row permutation cycle in the Poseidon2-permutation trace.
///
/// The packed schedule records the PRE-transition state on each row:
/// - Row 0: initial state
/// - Row 1: state after init+ext1
/// - Rows 2-3: state after ext2, ext3
/// - Row 4: state after ext4
/// - Rows 5-10: state after each packed-internal triple
/// - Row 11: state after packed-internal triple 6
/// - Row 12: state after int22+ext5
/// - Rows 13-14: state after ext6, ext7
/// - Row 15: state after ext8 (= final permutation output)
fn check_perm_segment(
    trace: &[[Felt; NUM_POSEIDON2_PERMUTATION_COLS]],
    start_row: usize,
    init_state: &HasherState,
    expected_multiplicity: Felt,
) {
    use miden_core::chiplets::hasher::Hasher;

    let mut state = *init_state;

    let first_row = poseidon2_row(trace, start_row);
    assert_eq!(first_row.state, state, "state at perm row {CYCLE_INPUT_ROW} (row {start_row})");
    assert_eq!(first_row.witnesses[0], expected_multiplicity);
    assert_eq!(
        poseidon2_row(trace, start_row + CYCLE_OUTPUT_ROW).witnesses[0],
        expected_multiplicity
    );
    let expected_perm_id =
        Felt::new_unchecked((start_row / HASH_CYCLE_LEN).try_into().expect("perm id exceeds u64"));
    assert_eq!(first_row.perm_id, expected_perm_id);

    // Apply init+ext1, check row 1
    Hasher::apply_matmul_external(&mut state);
    Hasher::add_rc(&mut state, &Hasher::ARK_EXT_INITIAL[0]);
    Hasher::apply_sbox(&mut state);
    Hasher::apply_matmul_external(&mut state);
    check_state_at_row(trace, start_row + INITIAL_EXTERNAL_ROUND_START, &state, "after init+ext1");

    // Apply ext2-4, check rows 2-4
    for round in INITIAL_EXTERNAL_ROUND_START..INITIAL_EXTERNAL_ROUND_END {
        Hasher::add_rc(&mut state, &Hasher::ARK_EXT_INITIAL[round]);
        Hasher::apply_sbox(&mut state);
        Hasher::apply_matmul_external(&mut state);
        check_state_at_row(
            trace,
            start_row + round + 1,
            &state,
            &alloc::format!("after ext{}", round + 1),
        );
    }

    // Apply 7 packed internal triples, check rows 5-11
    for triple in 0..NUM_PACKED_INTERNAL_ROUND_ROWS {
        let base = triple * NUM_SBOX_WITNESSES;
        for k in 0..NUM_SBOX_WITNESSES {
            state[0] += Hasher::ARK_INT[base + k];
            state[0] = state[0].exp_const_u64::<7>();
            Hasher::matmul_internal(&mut state, Hasher::MAT_DIAG);
        }
        check_state_at_row(
            trace,
            start_row + PACKED_INTERNAL_ROUND_START + 1 + triple,
            &state,
            &alloc::format!("after int triple {triple}"),
        );
    }

    // Apply int22+ext5, check row 12
    state[0] += Hasher::ARK_INT[LAST_INTERNAL_ROUND_ARK_IDX];
    state[0] = state[0].exp_const_u64::<7>();
    Hasher::matmul_internal(&mut state, Hasher::MAT_DIAG);
    Hasher::add_rc(&mut state, &Hasher::ARK_EXT_TERMINAL[0]);
    Hasher::apply_sbox(&mut state);
    Hasher::apply_matmul_external(&mut state);
    check_state_at_row(
        trace,
        start_row + INTERNAL_PLUS_EXTERNAL_ROW + 1,
        &state,
        "after int22+ext5",
    );

    // Apply ext6-8, check rows 13-15
    for round in 1..=NUM_TRAILING_EXTERNAL_ROUND_ROWS {
        Hasher::add_rc(&mut state, &Hasher::ARK_EXT_TERMINAL[round]);
        Hasher::apply_sbox(&mut state);
        Hasher::apply_matmul_external(&mut state);
        check_state_at_row(
            trace,
            start_row + INTERNAL_PLUS_EXTERNAL_ROW + 1 + round,
            &state,
            &alloc::format!("after ext{}", round + 5),
        );
    }
}

/// Helper to check the hasher state at a specific trace row.
fn check_state_at_row(
    trace: &[[Felt; NUM_POSEIDON2_PERMUTATION_COLS]],
    row: usize,
    state: &HasherState,
    label: &str,
) {
    assert_eq!(poseidon2_row(trace, row).state, *state, "state at row {row} ({label})");
}

fn apply_permutation(mut state: HasherState) -> HasherState {
    hasher::apply_permutation(&mut state);
    state
}

fn init_leaves(values: &[u64]) -> Vec<Digest> {
    values.iter().map(|&v| init_leaf(v)).collect()
}

fn init_leaf(value: u64) -> Digest {
    [Felt::new_unchecked(value), ZERO, ZERO, ZERO].into()
}

/// Verifies that a memoized (copied) range of controller rows matches the original range.
///
/// Checks selectors (s0, s1, s2), state columns (h0..h11), and controller metadata.
/// Does NOT check mrupdate_id (which is overwritten by the hasher on copy).
fn check_memoized_trace(
    trace: &[[Felt; TRACE_WIDTH]],
    original: Range<usize>,
    copied: Range<usize>,
) {
    assert_eq!(
        original.len(),
        copied.len(),
        "original and copied ranges must have the same length"
    );

    for (orig_row, copy_row) in original.zip(copied) {
        let original = controller_row(trace, orig_row);
        let copied = controller_row(trace, copy_row);

        assert_eq!(
            [original.s0, original.s1, original.s2],
            [copied.s0, copied.s1, copied.s2],
            "selector mismatch: original row {orig_row} vs copied row {copy_row}"
        );
        assert_eq!(
            original.state, copied.state,
            "state mismatch: original row {orig_row} vs copied row {copy_row}"
        );
        assert_eq!(
            original.node_index, copied.node_index,
            "node_index mismatch: original row {orig_row} vs copied row {copy_row}"
        );
        assert_eq!(
            original.is_boundary, copied.is_boundary,
            "is_boundary mismatch: original row {orig_row} vs copied row {copy_row}"
        );
        assert_eq!(
            original.direction_bit, copied.direction_bit,
            "direction_bit mismatch: original row {orig_row} vs copied row {copy_row}"
        );
        assert_eq!(
            original.perm_id, copied.perm_id,
            "perm_id mismatch: original row {orig_row} vs copied row {copy_row}"
        );
    }
}

/// Creates a BasicBlockNode from the given operations and returns its op_batches.
///
/// This is a helper for tests that need `&[OpBatch]` without building a full MAST forest.
fn make_basic_block_batches(ops: Vec<miden_core::operations::Operation>) -> Vec<OpBatch> {
    use miden_core::mast::BasicBlockNodeBuilder;

    let node = BasicBlockNodeBuilder::new(ops).build().expect("failed to build basic block");
    node.op_batches().to_vec()
}

/// Creates a single OpBatch with a distinct operation (Pad) for testing.
///
/// Uses Pad instead of Noop to ensure the groups differ from those produced by `make_multi_batch`.
fn make_single_batch() -> Vec<OpBatch> {
    use miden_core::operations::Operation;
    make_basic_block_batches(vec![Operation::Pad])
}

/// Creates exactly `n` OpBatch objects for testing multi-batch basic blocks.
///
/// Uses Noop operations to fill batches. Each batch holds 8 groups * 9 ops = 72 ops.
/// To produce exactly `n` batches, we use 72*(n-1) + 1 operations.
fn make_multi_batch(n: usize) -> Vec<OpBatch> {
    use miden_core::operations::Operation;
    assert!(n >= 2, "use make_single_batch for n=1");

    // 72 ops fills exactly 1 batch. To get n batches, we need 72*(n-1) + 1 ops.
    let num_ops = 72 * (n - 1) + 1;
    let ops = vec![Operation::Noop; num_ops];

    let batches = make_basic_block_batches(ops);
    assert_eq!(batches.len(), n, "expected exactly {n} batches, got {}", batches.len());
    batches
}

/// Computes the expected hash for a basic block given its op batches.
///
/// Mirrors the logic in `Hasher::hash_basic_block` without recording a trace.
fn compute_basic_block_hash(batches: &[OpBatch]) -> Digest {
    assert!(!batches.is_empty());

    let mut state = init_state(batches[0].groups(), ZERO);
    hasher::apply_permutation(&mut state);

    for batch in batches.iter().skip(1) {
        absorb_into_state(&mut state, batch.groups());
        hasher::apply_permutation(&mut state);
    }

    get_digest(&state)
}
