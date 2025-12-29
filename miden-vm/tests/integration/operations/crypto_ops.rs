use miden_core::QuadFelt;
use miden_processor::{ExecutionError, MemoryError};
use miden_utils_testing::{
    Felt, build_expected_hash, build_expected_perm, build_op_test, build_test,
    crypto::{MerkleTree, NodeIndex, init_merkle_leaf, init_merkle_store},
    proptest::prelude::*,
    rand::rand_vector,
};

// TESTS
// ================================================================================================

#[test]
fn hash() {
    let asm_op = "hash";

    // --- test hashing 4 random values -----------------------------------------------------------
    let random_values = rand_vector::<u64>(4);
    let expected = build_expected_hash(&random_values);

    let test = build_op_test!(asm_op, &random_values);
    let last_state = test.get_last_stack_state();

    assert_eq!(expected, &last_state[..4]);
}

#[test]
fn hperm() {
    let asm_op = "hperm";

    // --- test hashing 8 random values -----------------------------------------------------------
    let mut values = rand_vector::<u64>(8);
    let capacity: Vec<u64> = vec![0, 0, 0, 0];
    values.extend_from_slice(&capacity);
    let expected = build_expected_perm(&values);

    let test = build_op_test!(asm_op, &values);
    let last_state = test.get_last_stack_state();

    assert_eq!(expected, &last_state[0..12]);

    // --- test hashing # of values that's not a multiple of the rate: [ONE, ONE] -----------------
    #[rustfmt::skip]
    let values: Vec<u64> = vec![
        1, 0, 0, 0,      // capacity: first element set to 1 because padding is used
        1, 1,            // data: [ONE, ONE]
        1, 0, 0, 0, 0, 0 // padding: ONE followed by the necessary ZEROs
    ];
    let expected = build_expected_perm(&values);

    let test = build_op_test!(asm_op, &values);
    let last_state = test.get_last_stack_state();

    assert_eq!(expected, &last_state[0..12]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let mut stack_inputs: Vec<u64> = vec![1, 2, 3, 4];
    let expected_stack_slice =
        stack_inputs.iter().rev().map(|&v| Felt::new(v)).collect::<Vec<Felt>>();

    let values_to_hash: Vec<u64> = vec![1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0];
    stack_inputs.extend_from_slice(&values_to_hash);

    let test = build_op_test!(asm_op, &stack_inputs);
    let last_state = test.get_last_stack_state();

    assert_eq!(expected_stack_slice, &last_state[12..16]);
}

#[test]
fn hmerge() {
    let asm_op = "hmerge";

    // --- test hashing [ONE, ONE, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO] ----------------------------
    let values = [1, 1, 0, 0, 0, 0, 0, 0];
    let expected = build_expected_hash(&values);

    let test = build_op_test!(asm_op, &values);
    let last_state = test.get_last_stack_state();

    assert_eq!(expected, &last_state[..4]);

    // --- test hashing 8 random values -----------------------------------------------------------
    let values = rand_vector::<u64>(8);
    let expected = build_expected_hash(&values);

    let test = build_op_test!(asm_op, &values);
    let last_state = test.get_last_stack_state();

    assert_eq!(expected, &last_state[..4]);

    // --- test that the rest of the stack isn't affected -----------------------------------------
    let mut stack_inputs: Vec<u64> = vec![1, 2, 3, 4];
    let expected_stack_slice =
        stack_inputs.iter().rev().map(|&v| Felt::new(v)).collect::<Vec<Felt>>();

    let values_to_hash: Vec<u64> = vec![1, 1, 0, 0, 0, 0, 0, 0];
    stack_inputs.extend_from_slice(&values_to_hash);

    let test = build_op_test!(asm_op, &stack_inputs);
    let last_state = test.get_last_stack_state();

    assert_eq!(expected_stack_slice, &last_state[4..8]);
}

#[test]
fn mtree_get() {
    let asm_op = "mtree_get";

    let index = 3usize;
    let (leaves, store) = init_merkle_store(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(leaves.clone()).unwrap();

    let stack_inputs = [
        tree.root()[0].as_int(),
        tree.root()[1].as_int(),
        tree.root()[2].as_int(),
        tree.root()[3].as_int(),
        index as u64,
        tree.depth() as u64,
    ];

    let final_stack = [
        leaves[index][3].as_int(),
        leaves[index][2].as_int(),
        leaves[index][1].as_int(),
        leaves[index][0].as_int(),
        tree.root()[3].as_int(),
        tree.root()[2].as_int(),
        tree.root()[1].as_int(),
        tree.root()[0].as_int(),
    ];

    let test = build_op_test!(asm_op, &stack_inputs, &[], store);
    test.expect_stack(&final_stack);
}

#[test]
fn mtree_verify() {
    let asm_op = "mtree_verify";

    let index = 3_usize;
    let (leaves, store) = init_merkle_store(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(leaves.clone()).unwrap();

    let stack_inputs = [
        tree.root()[0].as_int(),
        tree.root()[1].as_int(),
        tree.root()[2].as_int(),
        tree.root()[3].as_int(),
        index as u64,
        tree.depth() as u64,
        leaves[index][0].as_int(),
        leaves[index][1].as_int(),
        leaves[index][2].as_int(),
        leaves[index][3].as_int(),
    ];

    let final_stack = [
        leaves[index][3].as_int(),
        leaves[index][2].as_int(),
        leaves[index][1].as_int(),
        leaves[index][0].as_int(),
        tree.depth() as u64,
        index as u64,
        tree.root()[3].as_int(),
        tree.root()[2].as_int(),
        tree.root()[1].as_int(),
        tree.root()[0].as_int(),
    ];

    let test = build_op_test!(asm_op, &stack_inputs, &[], store);
    test.expect_stack(&final_stack);
}

#[test]
#[should_panic]
fn mtree_verify_negative() {
    let asm_op = "mtree_verify";

    let index = 3_usize;
    let tampered_index = 2_usize;
    let (leaves, store) = init_merkle_store(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(leaves.clone()).unwrap();

    let stack_inputs = [
        tree.root()[0].as_int(),
        tree.root()[1].as_int(),
        tree.root()[2].as_int(),
        tree.root()[3].as_int(),
        tampered_index as u64,
        tree.depth() as u64,
        leaves[index][0].as_int(),
        leaves[index][1].as_int(),
        leaves[index][2].as_int(),
        leaves[index][3].as_int(),
    ];

    let final_stack = [
        leaves[index][3].as_int(),
        leaves[index][2].as_int(),
        leaves[index][1].as_int(),
        leaves[index][0].as_int(),
        tree.depth() as u64,
        index as u64,
        tree.root()[3].as_int(),
        tree.root()[2].as_int(),
        tree.root()[1].as_int(),
        tree.root()[0].as_int(),
    ];

    let test = build_op_test!(asm_op, &stack_inputs, &[], store);
    test.expect_stack(&final_stack);
}

#[test]
fn mtree_update() {
    let index = 5usize;
    let (leaves, store) = init_merkle_store(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(leaves.clone()).unwrap();

    let new_node = init_merkle_leaf(9);
    let mut new_leaves = leaves.clone();
    new_leaves[index] = new_node;
    let new_tree = MerkleTree::new(new_leaves).unwrap();

    let stack_inputs = [
        new_node[0].as_int(),
        new_node[1].as_int(),
        new_node[2].as_int(),
        new_node[3].as_int(),
        tree.root()[0].as_int(),
        tree.root()[1].as_int(),
        tree.root()[2].as_int(),
        tree.root()[3].as_int(),
        index as u64,
        tree.depth() as u64,
    ];

    // --- mtree_set ----------------------------------------------------------------------
    // update a node value and replace the old root
    let asm_op = "mtree_set";

    let old_node = tree
        .get_node(NodeIndex::new(tree.depth(), index as u64).unwrap())
        .expect("Value should have been set on initialization");

    // expected state has the new leaf and the new root of the tree
    let final_stack = [
        old_node[3].as_int(),
        old_node[2].as_int(),
        old_node[1].as_int(),
        old_node[0].as_int(),
        new_tree.root()[3].as_int(),
        new_tree.root()[2].as_int(),
        new_tree.root()[1].as_int(),
        new_tree.root()[0].as_int(),
    ];

    let test = build_op_test!(asm_op, &stack_inputs, &[], store.clone());
    test.expect_stack(&final_stack);
}

#[test]
fn crypto_stream_basic() {
    // Test crypto_stream instruction by setting up plaintext in memory,
    // a keystream on stack, and verifying encryption works correctly

    let asm_op = "
        # Initialize memory with plaintext [1,2,3,4,5,6,7,8] at address 1000
        push.1.2.3.4 push.1000 mem_storew_be dropw
        push.5.6.7.8 push.1004 mem_storew_be dropw

        # Setup stack: [rate(8), capacity(4), src, dst]
        # Rate is keystream [1,2,3,4,5,6,7,8]
        push.2000           # dst_ptr
        push.1000           # src_ptr
        push.0.0.0.0        # capacity
        push.1.2.3.4        # rate[0-3]
        push.5.6.7.8        # rate[4-7]

        crypto_stream

        # Verify ciphertext written to memory
        padw push.1000 mem_loadw_be
        push.2000 mem_loadw_be
    ";

    let test = build_op_test!(asm_op, &[]);
    let stack = test.get_last_stack_state();

    // Expected: plaintext + keystream
    // [1,2,3,4] + [1,2,3,4] = [2,4,6,8]
    // [5,6,7,8] + [5,6,7,8] = [10,12,14,16]

    let c2 = [stack[3], stack[2], stack[1], stack[0]];
    let c1 = [stack[7], stack[6], stack[5], stack[4]];

    assert_eq!(c2, [Felt::new(2), Felt::new(4), Felt::new(6), Felt::new(8)]);
    assert_eq!(c1, [Felt::new(10), Felt::new(12), Felt::new(14), Felt::new(16)]);
}

#[test]
fn crypto_stream_rejects_in_place() {
    let asm_op = "
        push.1.2.3.4 push.1000 mem_storew_be dropw
        push.5.6.7.8 push.1004 mem_storew_be dropw

        push.1000           # dst_ptr (in-place)
        push.1000           # src_ptr
        push.0.0.0.0        # capacity
        push.1.2.3.4        # rate[0-3]
        push.5.6.7.8        # rate[4-7]

        crypto_stream
    ";

    let test = build_op_test!(asm_op, &[]);
    let err = test.execute().expect_err("crypto_stream should reject in-place encryption");
    assert!(matches!(
        err,
        ExecutionError::MemoryError(MemoryError::IllegalMemoryAccess { .. })
    ));
}

#[test]
fn crypto_stream_rejects_partial_overlap() {
    // Test that crypto_stream rejects partial overlaps between source and destination
    //
    // crypto_stream reads 2 words (8 elements) from [src, src+8) and writes 2 words to [dst, dst+8)
    // and we need to make sure that we are not reading and writing to the same word at the same
    // cycle

    // Test case 1: dst starts within src range (src=1000, dst=1004)
    // src: [1000..1008), dst: [1004..1012) - overlaps by 1 word
    let asm_op_case1 = "
        push.1.2.3.4 push.1000 mem_storew_be dropw
        push.5.6.7.8 push.1004 mem_storew_be dropw

        push.1004           # dst_ptr (partial overlap)
        push.1000           # src_ptr
        push.0.0.0.0        # capacity
        push.1.2.3.4        # rate[0-3]
        push.5.6.7.8        # rate[4-7]

        crypto_stream
    ";

    let test = build_op_test!(asm_op_case1, &[]);
    let err = test
        .execute()
        .expect_err("crypto_stream should reject partial overlap (dst within src)");
    assert!(matches!(
        err,
        ExecutionError::MemoryError(MemoryError::IllegalMemoryAccess { .. })
    ));

    // Test case 2: src starts within dst range (src=1004, dst=1000)
    // src: [1004..1012), dst: [1000..1008) - overlaps by 1 word
    let asm_op_case2 = "
        push.1.2.3.4 push.1000 mem_storew_be dropw
        push.5.6.7.8 push.1004 mem_storew_be dropw

        push.1000           # dst_ptr
        push.1004           # src_ptr (partial overlap)
        push.0.0.0.0        # capacity
        push.1.2.3.4        # rate[0-3]
        push.5.6.7.8        # rate[4-7]

        crypto_stream
    ";

    let test = build_op_test!(asm_op_case2, &[]);
    let err = test
        .execute()
        .expect_err("crypto_stream should reject partial overlap (src within dst)");
    assert!(matches!(
        err,
        ExecutionError::MemoryError(MemoryError::IllegalMemoryAccess { .. })
    ));
}

#[test]
fn crypto_stream_rejects_src_range_overflow() {
    // src_end = src + 8 overflows u32 when src = 0xFFFF_FFFC (4294967292)
    // Expect AddressOutOfBounds before any memory access occurs.
    let asm_op = "
        # Setup stack: [rate(8), capacity(4), src, dst]
        push.0               # dst_ptr (valid)
        push.4294967292      # src_ptr (u32::MAX - 3, aligned), src+8 overflows
        push.0.0.0.0         # capacity
        push.1.2.3.4         # rate[0-3]
        push.5.6.7.8         # rate[4-7]

        crypto_stream
    ";

    let test = build_op_test!(asm_op, &[]);
    let err = test.execute().expect_err("crypto_stream should reject when src+8 overflows");
    assert!(matches!(
        err,
        ExecutionError::MemoryError(MemoryError::AddressOutOfBounds { .. })
    ));
}

#[test]
fn crypto_stream_rejects_dst_range_overflow() {
    // dst_end = dst + 8 overflows u32 when dst = 0xFFFF_FFFC (4294967292)
    // Expect AddressOutOfBounds before any memory access occurs.
    let asm_op = "
        # Setup stack: [rate(8), capacity(4), src, dst]
        push.4294967292      # dst_ptr (u32::MAX - 3, aligned), dst+8 overflows
        push.0               # src_ptr (valid)
        push.0.0.0.0         # capacity
        push.1.2.3.4         # rate[0-3]
        push.5.6.7.8         # rate[4-7]

        crypto_stream
    ";

    let test = build_op_test!(asm_op, &[]);
    let err = test.execute().expect_err("crypto_stream should reject when dst+8 overflows");
    assert!(matches!(
        err,
        ExecutionError::MemoryError(MemoryError::AddressOutOfBounds { .. })
    ));
}

#[test]
fn crypto_stream_rejects_unaligned_src() {
    // Unaligned src pointer should be rejected with UnalignedWordAccess
    let asm_op = "
        push.2000           # dst_ptr (aligned)
        push.1002           # src_ptr (unaligned)
        push.0.0.0.0        # capacity
        push.1.2.3.4        # rate[0-3]
        push.5.6.7.8        # rate[4-7]

        crypto_stream
    ";

    let test = build_op_test!(asm_op, &[]);
    let err = test.execute().expect_err("crypto_stream should reject unaligned src");
    assert!(matches!(
        err,
        ExecutionError::MemoryError(MemoryError::UnalignedWordAccess { .. })
    ));
}

#[test]
fn crypto_stream_rejects_unaligned_dst() {
    // Unaligned dst pointer should be rejected with UnalignedWordAccess
    let asm_op = "
        push.2002           # dst_ptr (unaligned)
        push.1000           # src_ptr (aligned)
        push.0.0.0.0        # capacity
        push.1.2.3.4        # rate[0-3]
        push.5.6.7.8        # rate[4-7]

        crypto_stream
    ";

    let test = build_op_test!(asm_op, &[]);
    let err = test.execute().expect_err("crypto_stream should reject unaligned dst");
    assert!(matches!(
        err,
        ExecutionError::MemoryError(MemoryError::UnalignedWordAccess { .. })
    ));
}

#[test]
fn crypto_stream_allows_adjacent_after() {
    // Adjacent ranges should be allowed (no overlap): dst = src + 8
    // src: [1000..1008), dst: [1008..1016)
    let asm_op = "
        # Plaintext at src
        push.1.2.3.4 push.1000 mem_storew_be dropw
        push.5.6.7.8 push.1004 mem_storew_be dropw

        # Setup stack: [rate(8), capacity(4), src, dst]
        push.1008           # dst_ptr (adjacent after)
        push.1000           # src_ptr
        push.0.0.0.0        # capacity
        push.1.2.3.4        # rate[0-3]
        push.5.6.7.8        # rate[4-7]

        crypto_stream
    ";

    let test = build_op_test!(asm_op, &[]);
    // Should execute without error
    test.execute().unwrap();
}

#[test]
fn crypto_stream_allows_adjacent_before() {
    // Adjacent ranges should be allowed (no overlap): dst = src - 8
    // src: [1008..1016), dst: [1000..1008)
    let asm_op = "
        # Plaintext at src
        push.1.2.3.4 push.1008 mem_storew_be dropw
        push.5.6.7.8 push.1012 mem_storew_be dropw

        # Setup stack: [rate(8), capacity(4), src, dst]
        push.1000           # dst_ptr (adjacent before)
        push.1008           # src_ptr
        push.0.0.0.0        # capacity
        push.1.2.3.4        # rate[0-3]
        push.5.6.7.8        # rate[4-7]

        crypto_stream
    ";

    let test = build_op_test!(asm_op, &[]);
    // Should execute without error
    test.execute().unwrap();
}

// HORNER EVALUATION TESTS
// ================================================================================================

// Constants for stack positions
const ALPHA_ADDR_INDEX: usize = 13;
const ACC_HIGH_INDEX: usize = 14;
const ACC_LOW_INDEX: usize = 15;

proptest! {
    #[test]
    fn prove_verify_horner_base(
        // 8 coefficients (c0-c7) - top 8 stack elements
        c0 in any::<u64>(),
        c1 in any::<u64>(),
        c2 in any::<u64>(),
        c3 in any::<u64>(),
        c4 in any::<u64>(),
        c5 in any::<u64>(),
        c6 in any::<u64>(),
        c7 in any::<u64>(),
        // Middle stack elements (8-12) - use small values to avoid issues
        s8 in 0u64..1000,
        s9 in 0u64..1000,
        s10 in 0u64..1000,
        s11 in 0u64..1000,
        s12 in 0u64..1000,
        // alpha evaluation point (stored in memory via advice stack)
        alpha_0 in any::<u64>(),
        alpha_1 in any::<u64>(),
        // initial accumulator
        acc_0 in any::<u64>(),
        acc_1 in any::<u64>(),
    ) {
        let source = "
            begin
                # Load the evaluation point from the advice stack and store it at `alpha_addr`
                padw
                adv_loadw
                push.1000
                mem_storew_be
                dropw

                # Execute
                horner_eval_base
            end
        ";

        // Build stack inputs array following the original test pattern:
        // Original: inputs[0..7] = coefficients, inputs[ALPHA_ADDR_INDEX] = 1000, etc.
        // Then inputs.reverse() is called before use
        let mut inputs = [0u64; 16];
        inputs[0] = c7;
        inputs[1] = c6;
        inputs[2] = c5;
        inputs[3] = c4;
        inputs[4] = c3;
        inputs[5] = c2;
        inputs[6] = c1;
        inputs[7] = c0;
        inputs[8] = s8;
        inputs[9] = s9;
        inputs[10] = s10;
        inputs[11] = s11;
        inputs[12] = s12;
        inputs[ALPHA_ADDR_INDEX] = 1000; // alpha_addr
        inputs[ACC_HIGH_INDEX] = acc_1;
        inputs[ACC_LOW_INDEX] = acc_0;

        // Compute expected result using the original algorithm
        let alpha = QuadFelt::new(Felt::new(alpha_0), Felt::new(alpha_1));
        let acc_old = QuadFelt::new(Felt::new(acc_0), Felt::new(acc_1));

        // The Horner evaluation: acc_new = fold over [c0..c7] with |acc, coef| coef + alpha * acc
        // coefficients are at inputs[0..8], taken in order and reversed
        let acc_new = inputs[0..8]
            .iter()
            .rev()
            .fold(acc_old, |acc, &coef| QuadFelt::from(Felt::new(coef)) + alpha * acc);

        // Reverse inputs for build_test! (it expects bottom-first order)
        inputs.reverse();

        // Prepare the advice stack with alpha values: [alpha_0, alpha_1, 0, 0]
        let adv_stack: Vec<u64> = vec![alpha_0, alpha_1, 0, 0];

        // Create the expected operand stack (top-first order for expect_stack)
        // The accumulator values are updated; rest of stack unchanged
        let mut expected = Vec::new();
        // Updated accumulators first (they are at the "bottom" of the visible stack, positions 14-15)
        expected.push(acc_new.to_base_elements()[0].as_int()); // acc_low
        expected.push(acc_new.to_base_elements()[1].as_int()); // acc_high
        // The rest of the stack (from position 2 onwards in reversed inputs = positions 0-13 original)
        expected.extend_from_slice(&inputs[2..]);
        // Reverse to get top-first order
        expected.reverse();

        let test = build_test!(source, &inputs, &adv_stack);
        test.expect_stack(&expected);

        let pub_inputs: Vec<u64> = inputs.to_vec();
        test.prove_and_verify(pub_inputs, false);
    }

    #[test]
    fn prove_verify_horner_ext(
        // 4 extension field coefficients (c0-c3), each is 2 base elements
        // Stack layout: [c0_1, c0_0, c1_1, c1_0, c2_1, c2_0, c3_1, c3_0, ...]
        c0_0 in any::<u64>(),
        c0_1 in any::<u64>(),
        c1_0 in any::<u64>(),
        c1_1 in any::<u64>(),
        c2_0 in any::<u64>(),
        c2_1 in any::<u64>(),
        c3_0 in any::<u64>(),
        c3_1 in any::<u64>(),
        // Middle stack elements (8-12) - use small values to avoid issues
        s8 in 0u64..1000,
        s9 in 0u64..1000,
        s10 in 0u64..1000,
        s11 in 0u64..1000,
        s12 in 0u64..1000,
        // alpha evaluation point (stored in memory via advice stack)
        alpha_0 in any::<u64>(),
        alpha_1 in any::<u64>(),
        // initial accumulator
        acc_0 in any::<u64>(),
        acc_1 in any::<u64>(),
    ) {
        let source = "
            begin
                # Load the evaluation point from the advice stack and store it at `alpha_addr`
                padw
                adv_loadw
                push.1000
                mem_storew_be
                dropw

                # Execute
                horner_eval_ext
            end
        ";

        // Build stack inputs array (top-first before reversal)
        let mut inputs = [0u64; 16];
        inputs[0] = c0_1;
        inputs[1] = c0_0;
        inputs[2] = c1_1;
        inputs[3] = c1_0;
        inputs[4] = c2_1;
        inputs[5] = c2_0;
        inputs[6] = c3_1;
        inputs[7] = c3_0;
        inputs[8] = s8;
        inputs[9] = s9;
        inputs[10] = s10;
        inputs[11] = s11;
        inputs[12] = s12;
        inputs[ALPHA_ADDR_INDEX] = 1000; // alpha_addr
        inputs[ACC_HIGH_INDEX] = acc_1;
        inputs[ACC_LOW_INDEX] = acc_0;

        // Compute expected result
        let alpha = QuadFelt::new(Felt::new(alpha_0), Felt::new(alpha_1));
        let acc_old = QuadFelt::new(Felt::new(acc_0), Felt::new(acc_1));

        // Build extension field coefficients: chunks of 2, QuadFelt::new(chunk[1], chunk[0])
        let acc_new = inputs[0..8]
            .chunks(2)
            .map(|chunk| QuadFelt::new(Felt::new(chunk[1]), Felt::new(chunk[0])))
            .rev()
            .fold(acc_old, |acc, coef| coef + alpha * acc);

        // Reverse inputs for build_test!
        inputs.reverse();

        // Prepare the advice stack with alpha values: [alpha_0, alpha_1, 0, 0]
        let adv_stack: Vec<u64> = vec![alpha_0, alpha_1, 0, 0];

        // Create the expected operand stack
        let mut expected = Vec::new();
        expected.push(acc_new.to_base_elements()[0].as_int()); // acc_low
        expected.push(acc_new.to_base_elements()[1].as_int()); // acc_high
        expected.extend_from_slice(&inputs[2..]);
        expected.reverse();

        let test = build_test!(source, &inputs, &adv_stack);
        test.expect_stack(&expected);

        let pub_inputs: Vec<u64> = inputs.to_vec();
        test.prove_and_verify(pub_inputs, false);
    }
}
