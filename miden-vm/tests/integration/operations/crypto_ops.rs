use miden_processor::{ExecutionError, MemoryError};
use miden_utils_testing::{
    Felt, build_expected_hash, build_expected_perm, build_op_test,
    crypto::{MerkleTree, NodeIndex, init_merkle_leaf, init_merkle_store},
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
