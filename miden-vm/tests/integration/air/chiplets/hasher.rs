use miden_utils_testing::{
    PrimeField64, Word, build_op_test,
    crypto::{MerkleStore, MerkleTree, Rpo256, init_merkle_leaf, init_merkle_store},
    rand::rand_vector,
};

#[test]
fn hperm() {
    let asm_op = "hperm";
    let pub_inputs = rand_vector::<u64>(8);

    build_op_test!(asm_op, &pub_inputs).prove_and_verify(pub_inputs, false);
}

#[test]
fn hmerge() {
    let asm_op = "hmerge";
    let pub_inputs = rand_vector::<u64>(8);

    build_op_test!(asm_op, &pub_inputs).prove_and_verify(pub_inputs, false);
}

#[test]
fn mtree_get() {
    let asm_op = "mtree_get";

    let index = 3usize;
    let (leaves, store) = init_merkle_store(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(leaves.clone()).unwrap();

    let stack_inputs = [
        tree.depth() as u64,
        index as u64,
        tree.root()[0].as_canonical_u64(),
        tree.root()[1].as_canonical_u64(),
        tree.root()[2].as_canonical_u64(),
        tree.root()[3].as_canonical_u64(),
    ];

    build_op_test!(asm_op, &stack_inputs, &[], store)
        .prove_and_verify(stack_inputs.to_vec(), false);
}

#[test]
fn mtree_set() {
    let asm_op = "mtree_set";
    let (stack_inputs, store, _leaves) = build_mtree_update_test_inputs();

    build_op_test!(asm_op, &stack_inputs, &[], store)
        .prove_and_verify(stack_inputs.to_vec(), false);
}

#[test]
fn mtree_verify() {
    let asm_op = "mtree_verify";

    let index = 3_usize;
    let (leaves, store) = init_merkle_store(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(leaves.clone()).unwrap();

    let stack_inputs = [
        leaves[index][0].as_canonical_u64(),
        leaves[index][1].as_canonical_u64(),
        leaves[index][2].as_canonical_u64(),
        leaves[index][3].as_canonical_u64(),
        tree.depth() as u64,
        index as u64,
        tree.root()[0].as_canonical_u64(),
        tree.root()[1].as_canonical_u64(),
        tree.root()[2].as_canonical_u64(),
        tree.root()[3].as_canonical_u64(),
    ];

    build_op_test!(asm_op, &stack_inputs, &[], store)
        .prove_and_verify(stack_inputs.to_vec(), false);
}

#[test]
fn mtree_merge() {
    let asm_op = "mtree_merge";

    let leaves_a = init_merkle_store(&[1, 2, 3, 4, 5, 6, 7, 8]).0;
    let leaves_b = init_merkle_store(&[9, 10, 11, 12, 13, 14, 15, 16]).0;
    let tree_a = MerkleTree::new(leaves_a.clone()).unwrap();
    let tree_b = MerkleTree::new(leaves_b.clone()).unwrap();
    let root_a = tree_a.root();
    let root_b = tree_b.root();
    let root_merged = Rpo256::merge(&[root_a, root_b]);
    let mut store = MerkleStore::default();
    store.extend(tree_a.inner_nodes());
    store.extend(tree_b.inner_nodes());

    let stack_inputs = vec![
        0xbeef,
        0xdead,
        root_a[0].as_canonical_u64(),
        root_a[1].as_canonical_u64(),
        root_a[2].as_canonical_u64(),
        root_a[3].as_canonical_u64(),
        root_b[0].as_canonical_u64(),
        root_b[1].as_canonical_u64(),
        root_b[2].as_canonical_u64(),
        root_b[3].as_canonical_u64(),
    ];

    let stack_outputs = vec![
        0xbeef,
        0xdead,
        root_merged[0].as_canonical_u64(),
        root_merged[1].as_canonical_u64(),
        root_merged[2].as_canonical_u64(),
        root_merged[3].as_canonical_u64(),
    ];

    build_op_test!(asm_op, &stack_inputs, &stack_outputs, store)
        .prove_and_verify(stack_inputs, false);
}

/// Helper function that builds a test stack and Merkle tree for testing mtree updates.
fn build_mtree_update_test_inputs() -> (Vec<u64>, MerkleStore, Vec<Word>) {
    let index = 5_usize;
    let (leaves, store) = init_merkle_store(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let tree = MerkleTree::new(leaves.clone()).unwrap();

    let new_node = init_merkle_leaf(9);
    let mut new_leaves = leaves.clone();
    new_leaves[index] = new_node;

    let stack_inputs = vec![
        tree.depth() as u64,
        index as u64,
        tree.root()[0].as_canonical_u64(),
        tree.root()[1].as_canonical_u64(),
        tree.root()[2].as_canonical_u64(),
        tree.root()[3].as_canonical_u64(),
        new_node[0].as_canonical_u64(),
        new_node[1].as_canonical_u64(),
        new_node[2].as_canonical_u64(),
        new_node[3].as_canonical_u64(),
    ];

    (stack_inputs, store, leaves)
}
