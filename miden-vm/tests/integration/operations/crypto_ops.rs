use miden_core::{PrimeCharacteristicRing, PrimeField64};
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
        stack_inputs.iter().rev().map(|&v| Felt::from_u64(v)).collect::<Vec<Felt>>();

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
        stack_inputs.iter().rev().map(|&v| Felt::from_u64(v)).collect::<Vec<Felt>>();

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
