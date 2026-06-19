use alloc::vec::Vec;
use core::ops::Range;

use miden_air::trace::{
    blakeg_compression::{IFACE_C_BASE_COL, IFACE_R_BASE_COL, NUM_BLAKEG_COMPRESSION_COLS},
    chiplets::hasher::{CONTROLLER_TRACE_ALIGNMENT, HASH_CYCLE_LEN, PADDING, TRACE_WIDTH},
};

// Chiplet-local column indices used by the hasher trace tests.
const STATE_COL_RANGE: Range<usize> = 3..15;
const ROW_DATA_COL_RANGE: Range<usize> = 15..19;
const NODE_INDEX_COL_IDX: usize = 15;
const NODE_INDEX_NEXT_COL_IDX: usize = 16;
const IS_START_COL_IDX: usize = 17;
const OP_FINAL_COL_IDX: usize = 19;
const MRUPDATE_ID_COL_IDX: usize = 20;
const CONTROLLER_MERKLE_OR_PADDING_COL_IDX: usize = TRACE_WIDTH - 1;
const TEST_TRACE_WIDTH: usize = NUM_BLAKEG_COMPRESSION_COLS;

fn controller_len(controller_rows: usize) -> usize {
    controller_rows.next_multiple_of(CONTROLLER_TRACE_ALIGNMENT)
}

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
    MR_UPDATE_OLD, MerklePath, RATE_LEN, Selectors, absorb_into_state, get_digest, init_state,
    init_state_from_words,
};

// SPONGE MODE TESTS
// ================================================================================================

#[test]
fn hasher_bcompress_one() {
    // --- test one controller compression ---
    let mut hasher = Hasher::default();
    let init_state = random_state();

    let (addr, final_state) = hasher.bcompress(init_state);
    assert_eq!(ONE, addr);

    let expected_state = compress_state(init_state);
    assert_eq!(expected_state, final_state);

    let trace = build_trace(hasher);

    // Controller region: 1 row, padded to the chiplet alignment boundary.
    // Compression segment: 1 real cycle plus one zero-multiplicity dummy cycle.
    let compression_start = controller_len(1);
    assert_eq!(trace[0].len(), compression_start + 2 * HASH_CYCLE_LEN);

    check_controller_row(&trace, 0, LINEAR_HASH, &init_state, ZERO, ONE, ZERO, ZERO, ONE);

    check_compression_block(&trace, compression_start, &init_state, ONE);
}

#[test]
fn hasher_bcompress_two() {
    let mut hasher = Hasher::default();
    let init_state1 = random_state();
    let init_state2 = random_state();

    let (addr1, final_state1) = hasher.bcompress(init_state1);
    let (addr2, final_state2) = hasher.bcompress(init_state2);

    assert_eq!(ONE, addr1);
    assert_eq!(Felt::from_u8(2), addr2);

    assert_eq!(compress_state(init_state1), final_state1);
    assert_eq!(compress_state(init_state2), final_state2);

    let trace = build_trace(hasher);

    // Controller region: two compression rows, padded to the chiplet alignment boundary.
    // Compression segment: 2 real cycles plus one zero-multiplicity dummy cycle.
    let compression_start = controller_len(2);
    assert_eq!(trace[0].len(), compression_start + 3 * HASH_CYCLE_LEN);

    check_controller_row(&trace, 0, LINEAR_HASH, &init_state1, ZERO, ONE, ZERO, ZERO, ONE);
    check_controller_row(&trace, 1, LINEAR_HASH, &init_state2, ZERO, ONE, ZERO, ZERO, ONE);
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
/// Verifying the path from L0 to root requires 1 controller row.
#[test]
fn hasher_build_merkle_root_depth_1() {
    let leaves = init_leaves(&[1, 2]);
    let tree = MerkleTree::new(&leaves).unwrap();

    let mut hasher = Hasher::default();
    let path0 = tree.get_path(NodeIndex::new(1, 0).unwrap()).unwrap();
    let (_, root) = hasher.build_merkle_root(leaves[0], &path0, ZERO);

    assert_eq!(root, compute_path_root(leaves[0], &path0, 0));

    let trace = build_trace(hasher);

    let init_state = init_state_from_words(&leaves[0], &path0[0]);
    check_controller_row(&trace, 0, MP_VERIFY, &init_state, ZERO, ONE, ZERO, ZERO, ONE);
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
/// Verifying the path from L5 (node_index=5) to root requires 3 controller rows.
/// The node_index shifts right by 1 at each level: 5 -> 2 -> 1 -> 0.
#[test]
fn hasher_build_merkle_root_depth_3() {
    let leaves = init_leaves(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(&leaves).unwrap();

    let mut hasher = Hasher::default();
    let path = tree.get_path(NodeIndex::new(3, 5).unwrap()).unwrap();
    let (_, root) = hasher.build_merkle_root(leaves[5], &path, Felt::from_u8(5));

    assert_eq!(root, compute_path_root(leaves[5], &path, 5));

    let trace = build_trace(hasher);

    // Depth 3: 3 controller rows.
    // Index=5 (binary 101): direction bits are LSBs at each level
    check_merkle_controller_row(&trace, 0, MP_VERIFY, 5, true, false, ZERO, ONE);
    check_merkle_controller_row(&trace, 1, MP_VERIFY, 2, false, false, ZERO, ZERO);
    check_merkle_controller_row(&trace, 2, MP_VERIFY, 1, false, true, ZERO, ONE);
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

    assert_eq!(update.get_old_root(), compute_path_root(leaves[index as usize], &path, index));

    let trace = build_trace(hasher);

    // Depth 2: two MV rows (old path) + two MU rows (new path) = four controller rows.
    // All rows share mrupdate_id=1.

    // MV leg (old path): rows 0-1
    // Index=1 (binary 01): direction bits are LSBs at each level
    check_merkle_controller_row(&trace, 0, MR_UPDATE_OLD, 1, true, false, ONE, ONE);
    check_merkle_controller_row(&trace, 1, MR_UPDATE_OLD, 0, false, true, ONE, ZERO);

    // MU leg (new path): rows 2-3
    // Same index, same direction bits
    check_merkle_controller_row(&trace, 2, MR_UPDATE_NEW, 1, true, false, ONE, ONE);
    check_merkle_controller_row(&trace, 3, MR_UPDATE_NEW, 0, false, true, ONE, ZERO);

    for row in 4..controller_len(4) {
        assert_eq!(trace[0][row], PADDING[0], "padding s0 at row {row}");
        assert_eq!(trace[1][row], PADDING[1], "padding s1 at row {row}");
        assert_eq!(trace[2][row], PADDING[2], "padding s2 at row {row}");
        for col in STATE_COL_RANGE.clone().chain(ROW_DATA_COL_RANGE.clone()) {
            assert_eq!(trace[col][row], ZERO, "padding payload col {col} at row {row}");
        }
        assert_eq!(trace[OP_FINAL_COL_IDX][row], ZERO, "padding op_final at row {row}");
        assert_eq!(trace[MRUPDATE_ID_COL_IDX][row], ONE, "padding mrupdate_id at row {row}");
        assert_eq!(
            trace[CONTROLLER_MERKLE_OR_PADDING_COL_IDX][row], ONE,
            "padding discriminator at row {row}"
        );
    }
}

// COMBINED COMPRESSION-BLOCK VIEW TESTS
// ================================================================================================

#[test]
fn compression_segment_structure() {
    // One BCOMPRESS yields one 64-row compression block with multiplicity 1.
    let mut hasher = Hasher::default();
    let init_state = random_state();
    let (addr, result) = hasher.bcompress(init_state);

    // Verify returned address and compressed state
    assert_eq!(addr, ONE, "first compression should start at address 1");
    assert_eq!(result, compress_state(init_state), "compressed state should match");

    let trace = build_trace(hasher);

    // The test view appends compression blocks after the padded controller rows.
    let compression_start = controller_len(1);

    assert_eq!(compression_multiplicity(&trace, compression_start), ONE);
    assert_eq!(compression_multiplicity(&trace, compression_start + HASH_CYCLE_LEN), ZERO);
    assert_eq!(compression_output_state(&trace, compression_start), compress_state(init_state));
}

#[test]
fn compression_deduplication() {
    // Two identical BCOMPRESS inputs collapse to one compression block with multiplicity 2.
    let mut hasher = Hasher::default();
    let init_state = random_state();
    let (addr1, result1) = hasher.bcompress(init_state);
    let (addr2, result2) = hasher.bcompress(init_state); // same state

    // Both should produce the same result but at different addresses
    assert_eq!(result1, result2, "same input should produce same output");
    assert_ne!(addr1, addr2, "second call should have a different address");

    let trace = build_trace(hasher);

    // Controller: two compression rows, padded to the chiplet alignment boundary.
    // Compression segment: 1 real cycle plus one zero-multiplicity dummy cycle.
    let compression_start = controller_len(2);
    assert_eq!(trace[0].len(), compression_start + 2 * HASH_CYCLE_LEN);

    // Compression segment: multiplicity should be 2.
    assert_eq!(compression_multiplicity(&trace, compression_start), Felt::from_u8(2));
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
    let compressed = compress_state(state);
    let expected_hash: Digest = get_digest(&compressed);

    let mut hasher = Hasher::default();

    let (addr1, digest1) = hasher.hash_control_block(h1, h2, domain, expected_hash);
    let (addr2, digest2) = hasher.hash_control_block(h1, h2, domain, expected_hash);

    assert_eq!(digest1, digest2);
    assert_eq!(digest1, expected_hash);
    // Second call uses memoized trace at a different address
    assert_ne!(addr1, addr2);

    let trace = build_trace(hasher);

    // Both calls produce one controller row each, but share compression requests.
    // Compression segment: 1 real cycle plus one zero-multiplicity dummy cycle.
    let compression_start = controller_len(2);
    assert_eq!(trace[0].len(), compression_start + 2 * HASH_CYCLE_LEN);

    // Compression segment has multiplicity 2 (two requests for same state)
    assert_eq!(compression_multiplicity(&trace, compression_start), Felt::from_u8(2));
}

// BASIC BLOCK MEMOIZATION TESTS
// ================================================================================================

#[test]
fn hash_memoization_basic_blocks_single_batch() {
    // Test that hashing the same single-batch basic block twice uses memoization:
    // the second call copies the controller rows and reuses the compression cycle
    // (multiplicity 2).
    let mut hasher = Hasher::default();

    let batches = make_single_batch();
    let expected_hash = compute_basic_block_hash(&batches);

    let (addr1, digest1) = hasher.hash_basic_block(&batches, expected_hash);
    let (addr2, digest2) = hasher.hash_basic_block(&batches, expected_hash);

    assert_eq!(digest1, digest2, "memoized digest should match original");
    assert_eq!(digest1, expected_hash);
    assert_ne!(addr1, addr2, "memoized call should have a different address");

    let trace = build_trace(hasher);

    // Single batch: one controller row per call, two rows total.
    // Compression segment: 1 real cycle plus one zero-multiplicity dummy cycle.
    let compression_start = controller_len(2);
    assert_eq!(trace[0].len(), compression_start + 2 * HASH_CYCLE_LEN);

    check_controller_row(
        &trace,
        0,
        LINEAR_HASH,
        &init_state(batches[0].groups(), num_basic_block_hash_groups(&batches) as u32),
        ZERO,
        ONE,
        ZERO,
        ZERO,
        ONE,
    );

    check_memoized_trace(&trace, 0..1, 1..2);

    // Compression segment: multiplicity should be 2 (original + memoized)
    assert_eq!(compression_multiplicity(&trace, compression_start), Felt::from_u8(2));
}

#[test]
fn hash_memoization_basic_blocks_multi_batch() {
    // Test memoization of a multi-batch basic block (3 batches).
    // The second call should copy all 3 controller rows and re-register all 3 compression
    // requests.
    let mut hasher = Hasher::default();

    let batches = make_multi_batch(3);
    let expected_hash = compute_basic_block_hash(&batches);

    let (addr1, digest1) = hasher.hash_basic_block(&batches, expected_hash);
    let (addr2, digest2) = hasher.hash_basic_block(&batches, expected_hash);

    assert_eq!(digest1, digest2);
    assert_eq!(digest1, expected_hash);
    assert_ne!(addr1, addr2);

    let trace = build_trace(hasher);

    // 3 batches -> 3 controller rows per call = 6 rows total.
    // 3 real compression states plus one zero-multiplicity dummy cycle.
    let compression_start = controller_len(6);
    assert_eq!(trace[0].len(), compression_start + 4 * HASH_CYCLE_LEN);

    assert_eq!([trace[0][0], trace[1][0], trace[2][0]], LINEAR_HASH);
    assert_eq!([trace[0][1], trace[1][1], trace[2][1]], super::HASH_ABSORB);
    assert_eq!([trace[0][2], trace[1][2], trace[2][2]], super::HASH_ABSORB);

    check_memoized_trace(&trace, 0..3, 3..6);

    // Compression segment: each of the 3 unique states should have multiplicity 2
    for i in 0..3 {
        let cycle_start = compression_start + i * HASH_CYCLE_LEN;
        assert_eq!(
            compression_multiplicity(&trace, cycle_start),
            Felt::from_u8(2),
            "compression cycle {i} should have multiplicity 2"
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
    // it should be memoized from BB1's trace, so BB1's compression states get multiplicity 2.
    //
    // Expected controller row layout:
    // Rows 0..2: BB1 (2 batches)
    // Row  2:    Loop body
    // Row  3:    Join2
    // Rows 4..6: BB2 memoized from BB1
    // Row  6:    Join1
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
    let join2_compressed = compress_state(join2_state);
    let join2_hash = get_digest(&join2_compressed);
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
    let join1_compressed = compress_state(join1_state);
    let join1_hash = get_digest(&join1_compressed);
    let (_join1_addr, join1_digest) =
        hasher.hash_control_block(join2_digest, bb2_digest, Felt::from_u8(7), join1_hash);
    assert_eq!(join1_digest, join1_hash);

    let trace = build_trace(hasher);

    // Verify BB2's controller rows (the memoized copy) match BB1's original rows.
    // BB1 is at rows 0..2.
    // Loop body is at row 2.
    // Join2 is at row 3.
    // BB2 (memoized) is at rows 4..6.
    // Join1 is at row 6.
    let bb1_start = bb1_addr.as_canonical_u64() as usize - 1;
    let bb2_start = bb2_addr.as_canonical_u64() as usize - 1;
    check_memoized_trace(&trace, bb1_start..bb1_start + 2, bb2_start..bb2_start + 2);

    // Verify compression multiplicities: BB1's 2 compression states should each have
    // multiplicity 2 (original from BB1 + memoized from BB2). The loop body's compression
    // state and the two join compression states should each have multiplicity 1.
    let controller_rows: usize = 7; // 2 + 1 + 1 + 2 + 1
    let controller_padded_len = controller_len(controller_rows);

    // Count unique compression states: BB1 has 2 unique states (2 batches), loop body has 1,
    // join2 has 1, join1 has 1 = 5 unique states total (unless some coincide, which is
    // astronomically unlikely with random groups).
    // BB2 is memoized so its 2 states are the same as BB1's.
    // Total compression cycles: at most 5 (could be less if join states happen to match).

    // Verify that the appended cycles have correct multiplicities.
    let compression_start = controller_padded_len;
    let total_len = trace[0].len();
    let num_compression_cycles = (total_len - compression_start) / HASH_CYCLE_LEN;

    // We should have at least 5 compression cycles (2 from BB + 1 loop + 2 joins)
    assert!(
        num_compression_cycles >= 5,
        "expected at least 5 compression cycles, got {num_compression_cycles}"
    );

    // Count how many compression cycles have multiplicity 2 vs 1
    let mut mult_2_count = 0;
    let mut mult_1_count = 0;
    for i in 0..num_compression_cycles {
        let cycle_start = compression_start + i * HASH_CYCLE_LEN;
        let mult = compression_multiplicity(&trace, cycle_start);
        if mult == Felt::from_u8(2) {
            mult_2_count += 1;
        } else if mult == ONE {
            mult_1_count += 1;
        }
    }

    // BB1's 2 compression states should have multiplicity 2 (from BB1 + BB2 memoized)
    assert_eq!(
        mult_2_count, 2,
        "expected 2 compression cycles with multiplicity 2 (BB1's states)"
    );
    // The remaining states (loop body, join2, join1) should have multiplicity 1
    assert_eq!(mult_1_count, 3, "expected 3 compression cycles with multiplicity 1");
}

// HELPER FUNCTIONS
// ================================================================================================

/// Builds a hasher test view with controller rows followed by standalone compression blocks.
fn build_trace(hasher: Hasher) -> Vec<Vec<Felt>> {
    let (controller_len, compression_len) = hasher.region_lengths();
    let trace_len = controller_len + compression_len;
    let mut band = Felt::zero_vec(TEST_TRACE_WIDTH * trace_len);
    let mut controller_trace = Felt::zero_vec(TRACE_WIDTH * controller_len);
    let mut blakeg_trace = Felt::zero_vec(NUM_BLAKEG_COMPRESSION_COLS * compression_len);

    {
        let mut fragment =
            ChipletTraceFragment::row_major(&mut controller_trace, TRACE_WIDTH, 0, TRACE_WIDTH);
        hasher.fill_trace(&mut fragment, &mut blakeg_trace);
    }

    for row in 0..controller_len {
        let dst = row * TEST_TRACE_WIDTH;
        let src = row * TRACE_WIDTH;
        band[dst..dst + TRACE_WIDTH].copy_from_slice(&controller_trace[src..src + TRACE_WIDTH]);
    }

    for row in 0..compression_len {
        let dst = (controller_len + row) * TEST_TRACE_WIDTH;
        let src = row * NUM_BLAKEG_COMPRESSION_COLS;
        band[dst..dst + NUM_BLAKEG_COMPRESSION_COLS]
            .copy_from_slice(&blakeg_trace[src..src + NUM_BLAKEG_COMPRESSION_COLS]);
    }

    (0..TEST_TRACE_WIDTH)
        .map(|c| (0..trace_len).map(|r| band[r * TEST_TRACE_WIDTH + c]).collect())
        .collect()
}

/// Checks one controller row.
fn check_controller_row(
    trace: &[Vec<Felt>],
    row: usize,
    selectors: Selectors,
    state: &HasherState,
    node_index: Felt,
    is_start: Felt,
    mrupdate_id: Felt,
    expected_bit: Felt,
    op_final: Felt,
) {
    assert_eq!(trace[0][row], selectors[0], "s0 at row {row}");
    assert_eq!(trace[1][row], selectors[1], "s1 at row {row}");
    assert_eq!(trace[2][row], selectors[2], "s2 at row {row}");

    let output = compress_state(*state);
    if is_merkle_selector(selectors) {
        for i in 0..8 {
            assert_eq!(trace[STATE_COL_RANGE.start + i][row], state[i], "state[{i}] at row {row}");
        }
        for i in 0..4 {
            assert_eq!(
                trace[STATE_COL_RANGE.start + 8 + i][row],
                output[8 + i],
                "merkle digest[{i}] at row {row}"
            );
        }
        assert_eq!(trace[NODE_INDEX_COL_IDX][row], node_index, "node_index at row {row}");
        assert_eq!(
            trace[NODE_INDEX_NEXT_COL_IDX][row],
            Felt::new_unchecked(node_index.as_canonical_u64() >> 1),
            "node_index_next at row {row}"
        );
        assert_eq!(trace[IS_START_COL_IDX][row], is_start, "is_start at row {row}");
        assert_eq!(
            trace[NODE_INDEX_COL_IDX][row] - trace[NODE_INDEX_NEXT_COL_IDX][row].double(),
            expected_bit,
            "virtual direction_bit at row {row}"
        );
    } else {
        for (i, &val) in state.iter().enumerate() {
            assert_eq!(trace[STATE_COL_RANGE.start + i][row], val, "state[{i}] at row {row}");
        }
        for i in 0..4 {
            assert_eq!(
                trace[ROW_DATA_COL_RANGE.start + i][row],
                output[8 + i],
                "hash digest[{i}] at row {row}"
            );
        }
    }

    assert_eq!(trace[MRUPDATE_ID_COL_IDX][row], mrupdate_id, "mrupdate_id at row {row}");
    assert_eq!(trace[OP_FINAL_COL_IDX][row], op_final, "op_final at row {row}");
    assert_eq!(
        trace[CONTROLLER_MERKLE_OR_PADDING_COL_IDX][row],
        if is_merkle_selector(selectors) { ONE } else { ZERO },
        "controller discriminator at row {row}"
    );
}

/// Checks one Merkle controller row.
fn check_merkle_controller_row(
    trace: &[Vec<Felt>],
    row: usize,
    selectors: Selectors,
    node_index: u64,
    is_start: bool,
    is_final: bool,
    mrupdate_id: Felt,
    direction_bit: Felt,
) {
    assert_eq!(trace[0][row], selectors[0], "s0 at Merkle row {row}");
    assert_eq!(trace[1][row], selectors[1], "s1 at Merkle row {row}");
    assert_eq!(trace[2][row], selectors[2], "s2 at Merkle row {row}");
    assert_eq!(
        trace[NODE_INDEX_COL_IDX][row],
        Felt::new_unchecked(node_index),
        "node_index at Merkle row {row}"
    );
    assert_eq!(
        trace[NODE_INDEX_NEXT_COL_IDX][row],
        Felt::new_unchecked(node_index >> 1),
        "node_index_next at Merkle row {row}"
    );
    assert_eq!(
        trace[IS_START_COL_IDX][row],
        if is_start { ONE } else { ZERO },
        "is_start at Merkle row {row}"
    );
    assert_eq!(
        trace[NODE_INDEX_COL_IDX][row] - trace[NODE_INDEX_NEXT_COL_IDX][row].double(),
        direction_bit,
        "virtual direction_bit at Merkle row {row}"
    );
    assert_eq!(trace[MRUPDATE_ID_COL_IDX][row], mrupdate_id, "mrupdate_id at Merkle row {row}");
    assert_eq!(
        trace[OP_FINAL_COL_IDX][row],
        if is_final { ONE } else { ZERO },
        "op_final at Merkle row {row}"
    );
    assert_eq!(
        trace[CONTROLLER_MERKLE_OR_PADDING_COL_IDX][row], ONE,
        "controller discriminator at Merkle row {row}"
    );
}

fn is_merkle_selector(selectors: Selectors) -> bool {
    selectors == MP_VERIFY || selectors == MR_UPDATE_OLD || selectors == MR_UPDATE_NEW
}

/// Checks one 64-row BlakeG compression block in the combined test view.
///
/// The packed schedule records the PRE-transition state on each row:
fn check_compression_block(
    trace: &[Vec<Felt>],
    start_row: usize,
    init_state: &HasherState,
    expected_multiplicity: Felt,
) {
    assert_eq!(compression_multiplicity(trace, start_row), expected_multiplicity);
    assert_eq!(compression_input_state(trace, start_row), *init_state);
    assert_eq!(compression_output_state(trace, start_row), compress_state(*init_state));
}

fn compression_multiplicity(trace: &[Vec<Felt>], start_row: usize) -> Felt {
    trace[super::blakeg_trace::IFACE_MULTIPLICITY_COL]
        [start_row + super::blakeg_trace::IFACE_INPUT_ROW]
}

fn compression_input_state(trace: &[Vec<Felt>], start_row: usize) -> HasherState {
    let row = start_row + super::blakeg_trace::IFACE_INPUT_ROW;
    core::array::from_fn(|i| {
        if i < RATE_LEN {
            trace[IFACE_R_BASE_COL + i][row]
        } else {
            trace[IFACE_C_BASE_COL + i - RATE_LEN][row]
        }
    })
}

fn compression_output_state(trace: &[Vec<Felt>], start_row: usize) -> HasherState {
    core::array::from_fn(|i| trace[i][start_row + super::blakeg_trace::IFACE_OUTPUT_ROW])
}

fn compress_state(mut state: HasherState) -> HasherState {
    hasher::compress_state(&mut state);
    state
}

fn random_state() -> HasherState {
    rand_array()
}

fn compute_path_root(value: Digest, path: &MerklePath, mut index: u64) -> Digest {
    let mut root = value;
    for &sibling in path.iter() {
        let state = match index & 1 {
            0 => init_state_from_words(&root, &sibling),
            1 => init_state_from_words(&sibling, &root),
            _ => unreachable!(),
        };
        root = get_digest(&compress_state(state));
        index >>= 1;
    }
    root
}

fn init_leaves(values: &[u64]) -> Vec<Digest> {
    values.iter().map(|&v| init_leaf(v)).collect()
}

fn init_leaf(value: u64) -> Digest {
    [Felt::new_unchecked(value), ZERO, ZERO, ZERO].into()
}

/// Verifies that a memoized (copied) range of controller rows matches the original range.
///
/// Checks controller columns copied by memoization.
/// Does NOT check mrupdate_id (which is overwritten by the hasher on copy).
fn check_memoized_trace(trace: &[Vec<Felt>], original: Range<usize>, copied: Range<usize>) {
    assert_eq!(
        original.len(),
        copied.len(),
        "original and copied ranges must have the same length"
    );

    for (orig_row, copy_row) in original.zip(copied) {
        for col in 0..3 {
            assert_eq!(
                trace[col][orig_row], trace[col][copy_row],
                "selector col {col} mismatch: original row {orig_row} vs copied row {copy_row}"
            );
        }

        for col in STATE_COL_RANGE
            .clone()
            .chain(ROW_DATA_COL_RANGE.clone())
            .chain(core::iter::once(OP_FINAL_COL_IDX))
            .chain(core::iter::once(CONTROLLER_MERKLE_OR_PADDING_COL_IDX))
        {
            assert_eq!(
                trace[col][orig_row], trace[col][copy_row],
                "controller col {col} mismatch: original row {orig_row} vs copied row {copy_row}"
            );
        }
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

    let mut state = init_state(batches[0].groups(), num_basic_block_hash_groups(batches) as u32);
    hasher::compress_state(&mut state);

    for batch in batches.iter().skip(1) {
        absorb_into_state(&mut state, batch.groups());
        hasher::compress_state(&mut state);
    }

    get_digest(&state)
}

fn num_basic_block_hash_groups(batches: &[OpBatch]) -> usize {
    let Some((last, prefix)) = batches.split_last() else {
        return 0;
    };
    prefix.len() * RATE_LEN + last.num_groups().next_power_of_two()
}
